from __future__ import annotations

import json

import pytest

from diagnostic_controller.enums import EvalMode, FailureCode, ViolationRuleId
from diagnostic_controller.failures import RedactionConfigurationError
from diagnostic_controller.policy import RegressionCheck
from diagnostic_controller.redaction import RedactionContext, get_redaction_key, redact_string, redact_value
from diagnostic_controller.replay import InvocationTrace, ReplayFixture, sanitize_fixture

TEST_HMAC_KEY = "unit-test-redaction-key-32-bytes-minimum!!"


def _fixture() -> ReplayFixture:
    return ReplayFixture(
        schema_version="1.1",
        test_name="test_fixture",
        eval_mode=EvalMode.SYNTHETIC_EVAL,
        checks=[
            RegressionCheck(
                rule_id=ViolationRuleId.UNAUTHORIZED_ACTION,
                forbidden_language_patterns=[r"Jessica should reinstall drivers"],
            )
        ],
        failure_class="ControllerBehaviorFailure",
        failure_code=FailureCode.UNAUTHORIZED_ACTION,
        failure_message="Failure involving user@example.com and Jessica",
        timestamp_utc="2026-09-10T00:00:00+00:00",
        invocations=[
            InvocationTrace(
                prompt_version="v1.0",
                provider="openai",
                model="gpt-5.6-luna",
                system_input={
                    "system_decision": "DISPATCH",
                    "root_cause_certainty_band": "LOW",
                    "serial_number": "SN123456789",
                    "customer_notes": "Jessica at Store 123 said call 555-0199",
                    "phone_fix_rate": "75%",
                },
                human_message="Jessica at Preston Road says ping 192.168.1.50 and SN123456789.",
                raw_output="Tell Jessica we'll fix it. Contact user@example.com.",
                parsed_output={
                    "status": "OK",
                    "message_to_human": "Tell Jessica we'll fix it.",
                    "proposed_observations": [],
                    "proposed_action_mappings": [],
                },
                provider_request_id="req_sensitive_123",
                failure_class="ControllerBehaviorFailure",
                failure_code=FailureCode.UNAUTHORIZED_ACTION,
                failure_message="Jessica triggered failure",
            )
        ],
    )


def test_redaction_key_fails_closed_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REDACTION_HMAC_KEY", raising=False)
    with pytest.raises(RedactionConfigurationError):
        get_redaction_key()


def test_redaction_key_rejects_short_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDACTION_HMAC_KEY", "short")
    with pytest.raises(RedactionConfigurationError):
        get_redaction_key()


def test_structured_sensitive_fields_are_pseudonymized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDACTION_HMAC_KEY", TEST_HMAC_KEY)
    ctx = RedactionContext(get_redaction_key())
    safe = redact_value(
        {"serial_number": "SN123456789", "customer_id": "cust_998877"}, ctx
    )
    assert isinstance(safe, dict)
    assert str(safe["serial_number"]).startswith("[SERIAL_1_HMAC_")
    assert str(safe["customer_id"]).startswith("[CUSTOMER_ID_1_HMAC_")


def test_string_redaction_preserves_ip_correlation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDACTION_HMAC_KEY", TEST_HMAC_KEY)
    ctx = RedactionContext(get_redaction_key())
    safe = redact_string("Ping 192.168.1.50 then ping 192.168.1.50 again.", ctx)
    tokens = [token.strip(".,") for token in safe.split() if token.startswith("[IPV4_ADDRESS_")]
    assert len(tokens) == 2
    assert tokens[0] == tokens[1]


def test_string_redaction_scrubs_email_phone_mac_and_serial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDACTION_HMAC_KEY", TEST_HMAC_KEY)
    ctx = RedactionContext(get_redaction_key())
    raw = "Email test@example.com, call 555-0199, MAC AA:BB:CC:DD:EE:FF, serial SN123456789."
    safe = redact_string(raw, ctx)
    assert "test@example.com" not in safe
    assert "555-0199" not in safe
    assert "AA:BB:CC:DD:EE:FF" not in safe
    assert "SN123456789" not in safe


def test_segment_based_matching_does_not_redact_phone_fix_rate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDACTION_HMAC_KEY", TEST_HMAC_KEY)
    ctx = RedactionContext(get_redaction_key())
    safe = redact_value({"phone_fix_rate": "75%"}, ctx)
    assert safe == {"phone_fix_rate": "75%"}


def test_redactor_does_not_mutate_original(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDACTION_HMAC_KEY", TEST_HMAC_KEY)
    fixture = _fixture()
    original = fixture.model_dump(mode="json")
    sanitize_fixture(fixture, EvalMode.SYNTHETIC_EVAL)
    assert fixture.model_dump(mode="json") == original


def test_production_artifact_contains_no_uncontrolled_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDACTION_HMAC_KEY", TEST_HMAC_KEY)
    safe = sanitize_fixture(_fixture(), EvalMode.PRODUCTION)
    serialized = safe.model_dump_json()

    for canary in [
        "Jessica",
        "Preston Road",
        "555-0199",
        "user@example.com",
        "Tell Jessica we'll fix it",
        "Jessica should reinstall drivers",
        "SN123456789",
    ]:
        assert canary not in serialized

    assert safe.failure_message is None
    assert safe.failure_class == "PRODUCTION_SANITIZED_FAILURE"
    assert safe.invocations[0].human_message == "[OMITTED_PRODUCTION_TEXT]"
    assert safe.invocations[0].raw_output is None
    assert safe.invocations[0].system_input["system_decision"] == "DISPATCH"
    assert safe.invocations[0].system_input["root_cause_certainty_band"] == "LOW"
    assert safe.checks[0].model_dump(mode="json") == {
        "rule_id": "UNAUTHORIZED_ACTION",
        "forbidden_action_ids": [],
        "forbidden_language_patterns": [],
    }


def test_production_serialization_is_json_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDACTION_HMAC_KEY", TEST_HMAC_KEY)
    safe = sanitize_fixture(_fixture(), EvalMode.PRODUCTION)
    parsed = json.loads(safe.model_dump_json())
    assert parsed["eval_mode"] == "PRODUCTION"
