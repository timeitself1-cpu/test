from __future__ import annotations

import contextvars
import copy
import functools
import hashlib
import json
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Final, Literal, ParamSpec, TypeVar

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from .enums import EvalMode, FailureCode, ViolationRuleId
from .failures import ClassifiedFailure
from .policy import RegressionCheck, normalize_checks
from .redaction import (
    PRODUCTION_OMITTED_TEXT,
    PRODUCTION_SANITIZED_FAILURE,
    RedactionContext,
    get_redaction_key,
    production_safe_checks,
    production_safe_identifier,
    production_safe_parsed_output,
    production_safe_provider,
    production_safe_system_input,
    redact_string,
    redact_value,
    sanitize_request_id,
)

REPLAY_SCHEMA_VERSION: Final[Literal["1.1"]] = "1.1"
P = ParamSpec("P")
R = TypeVar("R")


class InvocationTrace(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    prompt_version: str
    provider: str
    model: str
    system_input: dict[str, JsonValue]
    human_message: str
    raw_output: str | None = None
    parsed_output: dict[str, JsonValue] | None = None
    provider_request_id: str | None = None
    failure_class: str | None = None
    failure_code: FailureCode | None = Field(default=None, strict=False)
    failure_message: str | None = None
    timestamp_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ReplayFixture(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.1"]
    test_name: str
    eval_mode: EvalMode = Field(strict=False)
    checks: list[RegressionCheck]
    failure_class: str
    failure_code: FailureCode = Field(strict=False)
    failure_message: str | None
    timestamp_utc: str
    invocations: list[InvocationTrace]


class ReplayRecorder:
    def __init__(self) -> None:
        self.invocations: list[InvocationTrace] = []

    def record(self, trace: InvocationTrace) -> None:
        self.invocations.append(trace)


_current_recorder: contextvars.ContextVar[ReplayRecorder | None] = contextvars.ContextVar(
    "current_replay_recorder", default=None
)


def active_recorder() -> ReplayRecorder | None:
    return _current_recorder.get()


def record_invocation(trace: InvocationTrace) -> None:
    recorder = active_recorder()
    if recorder is not None:
        recorder.record(trace)


def derive_failure_code(exc: BaseException) -> FailureCode:
    if isinstance(exc, ClassifiedFailure):
        return exc.failure_code
    if isinstance(exc, AssertionError):
        return FailureCode.SEMANTIC_POLICY_VIOLATION
    return FailureCode.UNKNOWN_TEST_FAILURE


def sanitize_fixture(fixture: ReplayFixture, eval_mode: EvalMode) -> ReplayFixture:
    copied = fixture.model_copy(deep=True)
    copied.eval_mode = eval_mode
    ctx = RedactionContext(get_redaction_key())

    if eval_mode is EvalMode.PRODUCTION:
        copied.checks = [
            RegressionCheck(rule_id=ViolationRuleId(item["rule_id"]))
            for item in production_safe_checks(
                [check.model_dump(mode="json") for check in copied.checks]
            )
            if item["rule_id"] != "INVALID_OR_UNKNOWN"
        ]
        copied.failure_message = None
        copied.failure_class = PRODUCTION_SANITIZED_FAILURE
    else:
        copied.failure_message = (
            redact_string(copied.failure_message, ctx) if copied.failure_message else None
        )

    sanitized_invocations: list[InvocationTrace] = []
    for invocation in copied.invocations:
        inv = invocation.model_copy(deep=True)
        if eval_mode is EvalMode.PRODUCTION:
            inv.failure_message = None
            inv.failure_class = PRODUCTION_SANITIZED_FAILURE if inv.failure_class else None
            inv.provider = production_safe_provider(inv.provider)
            inv.model = production_safe_identifier(inv.model)
            inv.prompt_version = production_safe_identifier(inv.prompt_version)
            inv.system_input = production_safe_system_input(inv.system_input)
            inv.human_message = PRODUCTION_OMITTED_TEXT
            inv.raw_output = None
            inv.parsed_output = production_safe_parsed_output(inv.parsed_output)
            inv.provider_request_id = sanitize_request_id(inv.provider_request_id, ctx)
        else:
            inv.failure_message = redact_string(inv.failure_message, ctx) if inv.failure_message else None
            inv.system_input = redact_value(inv.system_input, ctx)
            inv.human_message = redact_string(inv.human_message, ctx)
            inv.raw_output = redact_string(inv.raw_output, ctx) if inv.raw_output else None
            inv.parsed_output = redact_value(inv.parsed_output, ctx) if inv.parsed_output else None
            inv.provider_request_id = sanitize_request_id(inv.provider_request_id, ctx)
        sanitized_invocations.append(inv)

    copied.invocations = sanitized_invocations
    return copied


def _stable_regression_family_id(fixture: ReplayFixture) -> str:
    canonical = {
        "test_name": fixture.test_name,
        "checks": [check.model_dump(mode="json") for check in fixture.checks],
        "prompt_versions": [inv.prompt_version for inv in fixture.invocations],
    }
    encoded = json.dumps(canonical, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:12]


def persist_replay_fixture(
    *,
    test_name: str,
    checks: Sequence[RegressionCheck | Mapping[str, object]],
    exc: BaseException,
    recorder: ReplayRecorder,
    eval_mode: EvalMode = EvalMode.SYNTHETIC_EVAL,
    output_dir: str | Path = "artifacts/replay_failures",
) -> Path:
    normalized_checks = normalize_checks(checks)
    raw_fixture = ReplayFixture(
        schema_version=REPLAY_SCHEMA_VERSION,
        test_name=test_name,
        eval_mode=eval_mode,
        checks=normalized_checks,
        failure_class=type(exc).__name__,
        failure_code=derive_failure_code(exc),
        failure_message=str(exc),
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        invocations=copy.deepcopy(recorder.invocations),
    )
    safe_fixture = sanitize_fixture(raw_fixture, eval_mode)

    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    family_id = _stable_regression_family_id(safe_fixture)
    occurrence_id = uuid.uuid4().hex[:12]
    safe_test_name = (
        test_name.replace("::", "__").replace("/", "_").replace("\\", "_").replace(" ", "_")
    )
    path = directory / f"{safe_test_name}__{family_id}__{occurrence_id}.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(safe_fixture.model_dump_json(indent=2), encoding="utf-8")
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    temporary.replace(path)
    return path


@contextmanager
def capture_replay_context(
    *,
    test_name: str,
    checks: Sequence[RegressionCheck | Mapping[str, object]],
    eval_mode: EvalMode = EvalMode.SYNTHETIC_EVAL,
    output_dir: str | Path = "artifacts/replay_failures",
) -> Iterator[None]:
    recorder = ReplayRecorder()
    token = _current_recorder.set(recorder)
    try:
        yield
    except Exception as exc:
        path = persist_replay_fixture(
            test_name=test_name,
            checks=checks,
            exc=exc,
            recorder=recorder,
            eval_mode=eval_mode,
            output_dir=output_dir,
        )
        print(f"\nReplay artifact written: {path}")
        raise
    finally:
        _current_recorder.reset(token)


def capture_replay_on_failure(
    *,
    checks: Sequence[RegressionCheck | Mapping[str, object]],
    eval_mode: EvalMode = EvalMode.SYNTHETIC_EVAL,
    output_dir: str | Path = "artifacts/replay_failures",
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorator(test_func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(test_func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            with capture_replay_context(
                test_name=test_func.__qualname__,
                checks=checks,
                eval_mode=eval_mode,
                output_dir=output_dir,
            ):
                return test_func(*args, **kwargs)

        return wrapper

    return decorator
