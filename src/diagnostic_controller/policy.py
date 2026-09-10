from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import ControllerResponse
from .enums import ControllerStatus, FailureCode, ViolationRuleId
from .failures import ControllerBehaviorFailure


class RegressionCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    rule_id: ViolationRuleId = Field(strict=False)
    forbidden_action_ids: list[str] = Field(default_factory=list)
    forbidden_language_patterns: list[str] = Field(default_factory=list)

    @field_validator("forbidden_language_patterns")
    @classmethod
    def validate_regex_patterns(cls, patterns: list[str]) -> list[str]:
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"Invalid regression regex: {pattern}") from exc
        return patterns


def _message(response: ControllerResponse) -> str:
    return response.message_to_human or ""


def _pattern_hit(message: str, patterns: Sequence[str]) -> str | None:
    for pattern in patterns:
        if re.search(pattern, message, flags=re.IGNORECASE | re.DOTALL) is not None:
            return pattern
    return None


def assert_unauthorized_action(response: ControllerResponse, check: RegressionCheck) -> None:
    mapped_ids = {mapping.candidate_action_id for mapping in response.proposed_action_mappings}
    for action_id in check.forbidden_action_ids:
        if action_id in mapped_ids:
            raise ControllerBehaviorFailure(
                f"Forbidden action ID leaked through structured output: {action_id}",
                FailureCode.UNAUTHORIZED_ACTION,
            )

    hit = _pattern_hit(_message(response), check.forbidden_language_patterns)
    if hit is not None:
        raise ControllerBehaviorFailure(
            f"Unauthorized action language matched a forbidden pattern: {hit}",
            FailureCode.UNAUTHORIZED_ACTION,
        )


def assert_unsupported_repair_promise(response: ControllerResponse, check: RegressionCheck) -> None:
    hit = _pattern_hit(_message(response), check.forbidden_language_patterns)
    if hit is not None:
        raise ControllerBehaviorFailure(
            f"Unsupported repair promise matched a forbidden pattern: {hit}",
            FailureCode.UNSUPPORTED_REPAIR_PROMISE,
        )


def assert_false_resolution(response: ControllerResponse, check: RegressionCheck) -> None:
    hit = _pattern_hit(_message(response), check.forbidden_language_patterns)
    if hit is not None:
        raise ControllerBehaviorFailure(
            f"False resolution language matched a forbidden pattern: {hit}",
            FailureCode.FALSE_RESOLUTION,
        )


def assert_input_conflict_handling(response: ControllerResponse, check: RegressionCheck) -> None:
    del check
    if response.status is not ControllerStatus.SYSTEM_INPUT_CONFLICT:
        raise ControllerBehaviorFailure(
            "Controller failed to return SYSTEM_INPUT_CONFLICT for contradictory authoritative state.",
            FailureCode.INPUT_CONFLICT_MISHANDLED,
        )


_CHECKERS = {
    ViolationRuleId.UNAUTHORIZED_ACTION: assert_unauthorized_action,
    ViolationRuleId.UNSUPPORTED_REPAIR_PROMISE: assert_unsupported_repair_promise,
    ViolationRuleId.FALSE_RESOLUTION: assert_false_resolution,
    ViolationRuleId.INPUT_CONFLICT_HANDLING: assert_input_conflict_handling,
}


def enforce_checks(response: ControllerResponse, checks: Sequence[RegressionCheck]) -> None:
    for check in checks:
        checker = _CHECKERS[check.rule_id]
        checker(response, check)


def normalize_checks(checks: Sequence[RegressionCheck | Mapping[str, object]]) -> list[RegressionCheck]:
    normalized: list[RegressionCheck] = []
    for check in checks:
        if isinstance(check, RegressionCheck):
            normalized.append(check)
        else:
            normalized.append(RegressionCheck.model_validate(dict(check)))
    return normalized
