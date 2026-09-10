from __future__ import annotations

import pytest

from diagnostic_controller.contracts import ControllerResponse, validate_controller_response
from diagnostic_controller.enums import ControllerStatus, FailureCode
from diagnostic_controller.failures import ModelOutputFailure


def _valid_payload() -> dict[str, object]:
    return {
        "status": "OK",
        "message_to_human": "Please ping the configured default gateway.",
        "conflict_fields": [],
        "proposed_observations": [],
        "proposed_action_mappings": [],
    }


def test_valid_response_passes() -> None:
    response = validate_controller_response(_valid_payload())
    assert isinstance(response, ControllerResponse)
    assert response.status is ControllerStatus.OK


def test_forbidden_top_level_field_fails() -> None:
    payload = _valid_payload()
    payload["diagnosis"] = "PSU_FAILURE"
    with pytest.raises(ModelOutputFailure) as captured:
        validate_controller_response(payload)
    assert captured.value.failure_code is FailureCode.STRUCTURAL_CONTRACT_VIOLATION


def test_forbidden_nested_field_fails() -> None:
    payload = _valid_payload()
    payload["proposed_observations"] = [
        {
            "raw_text": "Ethernet 9 is connected.",
            "normalized_fact_candidate": "Ethernet 9 reports connected.",
            "source_type_candidate": "TECHNICIAN_DIRECT_OBSERVATION",
            "verification_method_candidate": "DIRECTLY_OBSERVED",
            "supporting_span": "Ethernet 9 is connected",
            "confidence": 0.99,
        }
    ]
    with pytest.raises(ModelOutputFailure):
        validate_controller_response(payload)


def test_conflict_requires_null_message_and_nonempty_fields() -> None:
    payload = _valid_payload()
    payload.update(
        {
            "status": "SYSTEM_INPUT_CONFLICT",
            "message_to_human": "I picked one side.",
            "conflict_fields": [],
        }
    )
    with pytest.raises(ModelOutputFailure):
        validate_controller_response(payload)


def test_ok_response_rejects_conflict_fields() -> None:
    payload = _valid_payload()
    payload["conflict_fields"] = ["system_decision"]
    with pytest.raises(ModelOutputFailure):
        validate_controller_response(payload)
