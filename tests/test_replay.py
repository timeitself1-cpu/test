from __future__ import annotations

from pathlib import Path

import pytest

from diagnostic_controller.enums import EvalMode, FailureCode, ViolationRuleId
from diagnostic_controller.failures import ControllerBehaviorFailure
from diagnostic_controller.policy import RegressionCheck
from diagnostic_controller.replay import InvocationTrace, ReplayRecorder, persist_replay_fixture

TEST_HMAC_KEY = "unit-test-replay-hmac-key-32-bytes-minimum!"


def _recorder() -> ReplayRecorder:
    recorder = ReplayRecorder()
    recorder.record(
        InvocationTrace(
            prompt_version="v1.0",
            provider="openai",
            model="gpt-5.6-luna",
            system_input={"system_decision": "DISPATCH", "root_cause_certainty_band": "LOW"},
            human_message="Synthetic test message",
        )
    )
    return recorder


def test_persistence_preserves_authoritative_failure_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("REDACTION_HMAC_KEY", TEST_HMAC_KEY)
    exc = ControllerBehaviorFailure(
        "Synthetic unauthorized action",
        FailureCode.UNAUTHORIZED_ACTION,
    )
    path = persist_replay_fixture(
        test_name="test_case",
        checks=[RegressionCheck(rule_id=ViolationRuleId.UNAUTHORIZED_ACTION)],
        exc=exc,
        recorder=_recorder(),
        output_dir=tmp_path,
    )
    payload = path.read_text(encoding="utf-8")
    assert '"failure_code":"UNAUTHORIZED_ACTION"' in payload.replace(" ", "").replace("\n", "")


def test_occurrence_ids_prevent_overwrite(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REDACTION_HMAC_KEY", TEST_HMAC_KEY)
    exc = AssertionError("synthetic failure")
    kwargs = {
        "test_name": "same_test",
        "checks": [RegressionCheck(rule_id=ViolationRuleId.FALSE_RESOLUTION)],
        "exc": exc,
        "recorder": _recorder(),
        "eval_mode": EvalMode.SYNTHETIC_EVAL,
        "output_dir": tmp_path,
    }
    first = persist_replay_fixture(**kwargs)
    second = persist_replay_fixture(**kwargs)
    assert first != second
    assert first.exists() and second.exists()
