from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import os
import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any, Final, TypeVar

from pydantic import JsonValue

from .enums import (
    ActionKind,
    CertaintyBand,
    ControllerStatus,
    EvalMode,
    ExecutionAuthorization,
    ReasonCode,
    RemediationClass,
    SystemDecision,
    ViolationRuleId,
)
from .failures import RedactionConfigurationError

E = TypeVar("E", bound=StrEnum)

MIN_HMAC_KEY_BYTES: Final[int] = 32
PRODUCTION_OMITTED_TEXT: Final[str] = "[OMITTED_PRODUCTION_TEXT]"
PRODUCTION_SANITIZED_FAILURE: Final[str] = "PRODUCTION_SANITIZED_FAILURE"
INVALID_OR_UNKNOWN: Final[str] = "INVALID_OR_UNKNOWN"

PSEUDONYMIZED_FIELD_KEYS: Final[set[str]] = {
    "account_id",
    "case_id",
    "customer_id",
    "device_id",
    "ip_address",
    "mac_address",
    "serial_number",
    "ticket_id",
}

REDACTED_FIELD_KEYS: Final[set[str]] = {
    "contact_name",
    "customer_name",
    "email",
    "phone",
    "site_address",
    "street_address",
}

EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_REGEX = re.compile(
    r"(?<!\w)(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]\d{4}(?!\w)"
)
SERIAL_REGEX = re.compile(r"\b(?:SN|SERIAL)[-_]?[A-Za-z0-9]{6,24}\b", re.IGNORECASE)
MAC_REGEX = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
IPV4_CANDIDATE_REGEX = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_CANDIDATE_REGEX = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")


class RedactionContext:
    def __init__(self, hmac_key: bytes) -> None:
        self.hmac_key = hmac_key
        self._maps: dict[str, dict[str, str]] = {}
        self._counters: dict[str, int] = {}

    def pseudonymize(self, kind: str, raw_value: str) -> str:
        normalized_kind = re.sub(r"[^A-Z0-9]+", "_", kind.upper()).strip("_") or "IDENTIFIER"
        value_map = self._maps.setdefault(normalized_kind, {})
        existing = value_map.get(raw_value)
        if existing is not None:
            return existing

        counter = self._counters.get(normalized_kind, 0) + 1
        self._counters[normalized_kind] = counter
        digest = hmac.new(self.hmac_key, raw_value.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
        token = f"[{normalized_kind}_{counter}_HMAC_{digest}]"
        value_map[raw_value] = token
        return token


def get_redaction_key() -> bytes:
    raw = os.getenv("REDACTION_HMAC_KEY", "")
    key = raw.encode("utf-8")
    if len(key) < MIN_HMAC_KEY_BYTES:
        raise RedactionConfigurationError(
            f"REDACTION_HMAC_KEY must be configured with at least {MIN_HMAC_KEY_BYTES} bytes; persistence fails closed."
        )
    return key


def _replace_valid_ip(match: re.Match[str], ctx: RedactionContext) -> str:
    candidate = match.group(0)
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    kind = "IPV4_ADDRESS" if address.version == 4 else "IPV6_ADDRESS"
    return ctx.pseudonymize(kind, candidate)


def redact_string(text: str, ctx: RedactionContext) -> str:
    if not text:
        return text
    output = EMAIL_REGEX.sub("[REDACTED_EMAIL]", text)
    output = PHONE_REGEX.sub("[REDACTED_PHONE]", output)
    output = MAC_REGEX.sub(lambda m: ctx.pseudonymize("MAC_ADDRESS", m.group(0)), output)
    output = SERIAL_REGEX.sub(lambda m: ctx.pseudonymize("SERIAL", m.group(0)), output)
    output = IPV4_CANDIDATE_REGEX.sub(lambda m: _replace_valid_ip(m, ctx), output)
    output = IPV6_CANDIDATE_REGEX.sub(lambda m: _replace_valid_ip(m, ctx), output)
    return output


def redact_value(value: Any, ctx: RedactionContext, *, current_key: str | None = None) -> Any:
    normalized_key = current_key.casefold() if current_key is not None else None
    if normalized_key in REDACTED_FIELD_KEYS:
        return "[REDACTED_FIELD]"
    if normalized_key in PSEUDONYMIZED_FIELD_KEYS:
        if isinstance(value, str):
            kind = "SERIAL" if normalized_key == "serial_number" else normalized_key.upper()
            return ctx.pseudonymize(kind, value)
        return "[REDACTED_FIELD]"

    if isinstance(value, str):
        return redact_string(value, ctx)
    if isinstance(value, Mapping):
        return {
            str(key): redact_value(child, ctx, current_key=str(key))
            for key, child in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact_value(child, ctx) for child in value]
    return copy.deepcopy(value)


def _safe_enum_value(value: Any, enum_type: type[E]) -> str:
    try:
        return enum_type(value).value
    except (TypeError, ValueError):
        return INVALID_OR_UNKNOWN


def _safe_optional_enum_value(value: Any, enum_type: type[E]) -> str | None:
    if value is None:
        return None
    return _safe_enum_value(value, enum_type)


def production_safe_checks(checks: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "rule_id": _safe_enum_value(check.get("rule_id"), ViolationRuleId),
        }
        for check in checks
    ]


def production_safe_system_input(system_input: Mapping[str, Any]) -> dict[str, JsonValue]:
    return {
        "system_decision": _safe_enum_value(system_input.get("system_decision"), SystemDecision),
        "reason_code": _safe_optional_enum_value(system_input.get("reason_code"), ReasonCode),
        "root_cause_certainty_band": _safe_enum_value(
            system_input.get("root_cause_certainty_band"), CertaintyBand
        ),
        "action_kind": _safe_optional_enum_value(system_input.get("action_kind"), ActionKind),
        "remediation_class": _safe_optional_enum_value(
            system_input.get("remediation_class"), RemediationClass
        ),
        "execution_authorization": _safe_enum_value(
            system_input.get("execution_authorization"), ExecutionAuthorization
        ),
    }


def production_safe_parsed_output(parsed: Mapping[str, Any] | None) -> dict[str, JsonValue] | None:
    if parsed is None:
        return None
    observations = parsed.get("proposed_observations")
    action_mappings = parsed.get("proposed_action_mappings")
    return {
        "status": _safe_enum_value(parsed.get("status"), ControllerStatus),
        "observation_count": len(observations) if isinstance(observations, list) else 0,
        "action_mapping_count": len(action_mappings) if isinstance(action_mappings, list) else 0,
    }


_SAFE_IDENTIFIER_REGEX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def production_safe_identifier(value: str) -> str:
    return value if _SAFE_IDENTIFIER_REGEX.fullmatch(value) is not None else INVALID_OR_UNKNOWN


def production_safe_provider(value: str) -> str:
    return value if value == "openai" else INVALID_OR_UNKNOWN


def sanitize_request_id(request_id: str | None, ctx: RedactionContext) -> str | None:
    if not request_id:
        return None
    return ctx.pseudonymize("PROVIDER_REQUEST_ID", request_id)


def validate_eval_mode(value: EvalMode | str) -> EvalMode:
    return value if isinstance(value, EvalMode) else EvalMode(value)
