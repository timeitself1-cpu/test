from __future__ import annotations

from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

from .enums import (
    ActionKind,
    CertaintyBand,
    ControllerStatus,
    ExecutionAuthorization,
    RemediationClass,
    ReasonCode,
    SystemDecision,
)
from .enums import FailureCode
from .failures import ModelOutputFailure


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class HypothesisState(StrictModel):
    id: str = Field(min_length=1)
    status: str = Field(min_length=1)


class AuthorizedAction(StrictModel):
    action_id: str = Field(min_length=1)
    action_kind: ActionKind = Field(strict=False)
    instructions: str = Field(min_length=1)
    remote_executable: bool = True


class DiagnosticControllerInput(StrictModel):
    system_decision: SystemDecision = Field(strict=False)
    authorized_action_id: str | None = None
    authorized_action: AuthorizedAction | None = None
    action_kind: ActionKind | None = Field(default=None, strict=False)
    remediation_class: RemediationClass | None = Field(default=None, strict=False)
    reason_code: ReasonCode | None = Field(default=None, strict=False)
    case_state: dict[str, JsonValue] = Field(default_factory=dict)
    evidence_ledger: list[dict[str, JsonValue]] = Field(default_factory=list)
    hypotheses: list[HypothesisState] = Field(default_factory=list)
    root_cause_certainty_band: CertaintyBand = Field(default=CertaintyBand.LOW, strict=False)
    next_action_certainty: dict[str, JsonValue] = Field(default_factory=dict)
    frontier: dict[str, JsonValue] = Field(default_factory=dict)
    conflict_state: JsonValue | None = None
    policy_constraints: dict[str, JsonValue] = Field(default_factory=dict)
    execution_authorization: ExecutionAuthorization = Field(default=ExecutionAuthorization.NOT_REQUIRED, strict=False)
    allowed_observation_types: list[str] = Field(default_factory=list)
    allowed_alias_candidates: list[str] = Field(default_factory=list)
    interaction_mode: str = "TEXT"

    @model_validator(mode="after")
    def enforce_authorized_action_consistency(self) -> "DiagnosticControllerInput":
        if self.authorized_action is not None:
            if self.authorized_action_id != self.authorized_action.action_id:
                raise ValueError("authorized_action_id must match authorized_action.action_id")
            if self.action_kind != self.authorized_action.action_kind:
                raise ValueError("action_kind must match authorized_action.action_kind")
        return self


class ObservationCandidate(StrictModel):
    raw_text: str
    normalized_fact_candidate: str
    source_type_candidate: str
    verification_method_candidate: str
    supporting_span: str


class ActionMappingCandidate(StrictModel):
    reported_action: str
    candidate_action_id: str
    supporting_text: str
    mapping_basis: str


class ControllerResponse(StrictModel):
    status: ControllerStatus = Field(strict=False)
    message_to_human: str | None
    conflict_fields: list[str]
    proposed_observations: list[ObservationCandidate]
    proposed_action_mappings: list[ActionMappingCandidate]

    @model_validator(mode="after")
    def enforce_status_contract(self) -> "ControllerResponse":
        if self.status is ControllerStatus.SYSTEM_INPUT_CONFLICT:
            if self.message_to_human is not None:
                raise ValueError("SYSTEM_INPUT_CONFLICT requires message_to_human=null")
            if not self.conflict_fields:
                raise ValueError("SYSTEM_INPUT_CONFLICT requires at least one conflict field")
            if self.proposed_observations or self.proposed_action_mappings:
                raise ValueError("SYSTEM_INPUT_CONFLICT cannot include proposals")
        elif self.conflict_fields:
            raise ValueError("conflict_fields must be empty unless status=SYSTEM_INPUT_CONFLICT")

        if self.status is ControllerStatus.AUTHORIZED_ACTION_MISSING and self.message_to_human is not None:
            raise ValueError("AUTHORIZED_ACTION_MISSING requires message_to_human=null")
        return self


CONTROLLER_RESPONSE_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "status": {
            "type": "string",
            "enum": [status.value for status in ControllerStatus],
        },
        "message_to_human": {
            "anyOf": [
                {"type": "string"},
                {"type": "null"},
            ]
        },
        "conflict_fields": {
            "type": "array",
            "items": {"type": "string"},
        },
        "proposed_observations": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "raw_text": {"type": "string"},
                    "normalized_fact_candidate": {"type": "string"},
                    "source_type_candidate": {"type": "string"},
                    "verification_method_candidate": {"type": "string"},
                    "supporting_span": {"type": "string"},
                },
                "required": [
                    "raw_text",
                    "normalized_fact_candidate",
                    "source_type_candidate",
                    "verification_method_candidate",
                    "supporting_span",
                ],
            },
        },
        "proposed_action_mappings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "reported_action": {"type": "string"},
                    "candidate_action_id": {"type": "string"},
                    "supporting_text": {"type": "string"},
                    "mapping_basis": {"type": "string"},
                },
                "required": [
                    "reported_action",
                    "candidate_action_id",
                    "supporting_text",
                    "mapping_basis",
                ],
            },
        },
    },
    "required": [
        "status",
        "message_to_human",
        "conflict_fields",
        "proposed_observations",
        "proposed_action_mappings",
    ],
}


def validate_controller_response(payload: Mapping[str, Any]) -> ControllerResponse:
    """Validate model output without repairing, dropping, or coercing forbidden fields."""
    try:
        return ControllerResponse.model_validate(dict(payload))
    except ValidationError as exc:
        raise ModelOutputFailure(
            "Model output violated the Diagnostic Controller response contract.",
            FailureCode.STRUCTURAL_CONTRACT_VIOLATION,
        ) from exc
