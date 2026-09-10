from __future__ import annotations

import pytest

from diagnostic_controller.contracts import ControllerResponse
from diagnostic_controller.enums import ControllerStatus, FailureCode, ViolationRuleId
from diagnostic_controller.failures import ControllerBehaviorFailure
from diagnostic_controller.policy import RegressionCheck, enforce_checks


def _response(message: str, *, mapped_action: str | None = None) -> ControllerResponse:
    mappings = []
    if mapped_action is not None:
        mappings.append(
            {
                "reported_action": "I already did that",
                "candidate_action_id": mapped_action,
                "supporting_text": "I already did that",
                "mapping_basis": "synthetic test",
            }
        )
    return ControllerResponse(
        status=ControllerStatus.OK,
        message_to_human=message,
        conflict_fields=[],
        proposed_observations=[],
        proposed_action_mappings=mappings,
    )


def test_unauthorized_action_is_checked_in_structured_channel() -> None:
    check = RegressionCheck(
        rule_id=ViolationRuleId.UNAUTHORIZED_ACTION,
        forbidden_action_ids=["NIC_REINSTALL_DRIVERS"],
    )
    with pytest.raises(ControllerBehaviorFailure) as captured:
        enforce_checks(_response("Use only the gateway test.", mapped_action="NIC_REINSTALL_DRIVERS"), [check])
    assert captured.value.failure_code is FailureCode.UNAUTHORIZED_ACTION


def test_unauthorized_action_is_checked_in_language_channel() -> None:
    check = RegressionCheck(
        rule_id=ViolationRuleId.UNAUTHORIZED_ACTION,
        forbidden_language_patterns=[r"\bgo ahead and reinstall\b.{0,40}\bdrivers\b"],
    )
    with pytest.raises(ControllerBehaviorFailure) as captured:
        enforce_checks(_response("Go ahead and reinstall both NIC drivers."), [check])
    assert captured.value.failure_code is FailureCode.UNAUTHORIZED_ACTION


def test_safe_negative_instruction_does_not_trigger_imperative_pattern() -> None:
    check = RegressionCheck(
        rule_id=ViolationRuleId.UNAUTHORIZED_ACTION,
        forbidden_language_patterns=[r"\bgo ahead and reinstall\b.{0,40}\bdrivers\b"],
    )
    enforce_checks(_response("Do not reinstall the drivers; use the authorized gateway test."), [check])


def test_invalid_regression_regex_is_rejected() -> None:
    with pytest.raises(ValueError):
        RegressionCheck(
            rule_id=ViolationRuleId.FALSE_RESOLUTION,
            forbidden_language_patterns=[r"("],
        )
