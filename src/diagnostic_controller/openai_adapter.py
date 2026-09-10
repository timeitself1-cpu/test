from __future__ import annotations

import json
from typing import Any

from openai import APIConnectionError, APIError, APIStatusError, APITimeoutError, OpenAI, RateLimitError

from .adapter import DiagnosticController
from .contracts import (
    CONTROLLER_RESPONSE_JSON_SCHEMA,
    ControllerResponse,
    DiagnosticControllerInput,
    validate_controller_response,
)
from .enums import FailureCode
from .failures import ModelOutputFailure, ProviderFailure
from .prompts import SYSTEM_PROMPT_V1, SYSTEM_PROMPT_VERSION
from .replay import InvocationTrace, record_invocation
from .settings import OpenAISettings


class OpenAIAdapter(DiagnosticController):
    """OpenAI Responses API implementation with no output-repair middleware."""

    def __init__(self, settings: OpenAISettings | None = None) -> None:
        self.settings = settings or OpenAISettings.from_env()
        self.client = OpenAI(
            api_key=self.settings.api_key,
            timeout=self.settings.timeout_seconds,
            max_retries=0,
        )

    def invoke(
        self,
        *,
        system_input: DiagnosticControllerInput,
        human_message: str,
    ) -> ControllerResponse:
        authoritative_json = json.dumps(
            system_input.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        instructions = (
            f"{SYSTEM_PROMPT_V1}\n\n"
            "AUTHORITATIVE SYSTEM INPUT (immutable JSON):\n"
            f"{authoritative_json}"
        )
        trace = InvocationTrace(
            prompt_version=SYSTEM_PROMPT_VERSION,
            provider="openai",
            model=self.settings.model,
            system_input=system_input.model_dump(mode="json"),
            human_message=human_message,
        )

        try:
            response = self.client.responses.create(
                model=self.settings.model,
                instructions=instructions,
                input=human_message,
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "diagnostic_controller_response",
                        "description": "Strict response contract for the bounded Diagnostic Controller.",
                        "strict": True,
                        "schema": CONTROLLER_RESPONSE_JSON_SCHEMA,
                    }
                },
                reasoning={"effort": self.settings.reasoning_effort},
                temperature=self.settings.temperature,
                top_p=self.settings.top_p,
                max_output_tokens=self.settings.max_output_tokens,
                store=False,
            )
            trace.provider_request_id = getattr(response, "_request_id", None)
            trace.model = str(getattr(response, "model", self.settings.model))
        except RateLimitError as exc:
            trace.failure_class = type(exc).__name__
            trace.failure_code = FailureCode.PROVIDER_RATE_LIMIT
            trace.failure_message = "Provider rate limit exceeded."
            trace.provider_request_id = getattr(exc, "request_id", None)
            record_invocation(trace)
            raise ProviderFailure(
                "OpenAI rate limit exceeded.", FailureCode.PROVIDER_RATE_LIMIT
            ) from exc
        except (APITimeoutError, APIConnectionError) as exc:
            trace.failure_class = type(exc).__name__
            trace.failure_code = FailureCode.PROVIDER_TRANSPORT_FAILURE
            trace.failure_message = "Provider transport or timeout failure."
            trace.provider_request_id = getattr(exc, "request_id", None)
            record_invocation(trace)
            raise ProviderFailure(
                "OpenAI transport request failed.", FailureCode.PROVIDER_TRANSPORT_FAILURE
            ) from exc
        except APIStatusError as exc:
            failure_code = (
                FailureCode.PROVIDER_TRANSPORT_FAILURE
                if exc.status_code >= 500
                else FailureCode.PROVIDER_REQUEST_FAILURE
            )
            trace.failure_class = type(exc).__name__
            trace.failure_code = failure_code
            trace.failure_message = f"Provider returned HTTP status {exc.status_code}."
            trace.provider_request_id = getattr(exc, "request_id", None)
            record_invocation(trace)
            raise ProviderFailure(
                f"OpenAI returned HTTP status {exc.status_code}.",
                failure_code,
            ) from exc
        except APIError as exc:
            trace.failure_class = type(exc).__name__
            trace.failure_code = FailureCode.PROVIDER_REQUEST_FAILURE
            trace.failure_message = "Provider API request failed."
            record_invocation(trace)
            raise ProviderFailure(
                "OpenAI API request failed.",
                FailureCode.PROVIDER_REQUEST_FAILURE,
            ) from exc

        raw_output = response.output_text
        trace.raw_output = raw_output
        if not raw_output:
            trace.failure_class = "EmptyModelOutput"
            trace.failure_code = FailureCode.MALFORMED_JSON
            trace.failure_message = "Model produced no output text."
            record_invocation(trace)
            raise ModelOutputFailure(
                "Model produced no output text.", FailureCode.MALFORMED_JSON
            )

        try:
            decoded: Any = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            trace.failure_class = type(exc).__name__
            trace.failure_code = FailureCode.MALFORMED_JSON
            trace.failure_message = "Model output was not valid JSON."
            record_invocation(trace)
            raise ModelOutputFailure(
                "Model output was not valid JSON.", FailureCode.MALFORMED_JSON
            ) from exc

        if not isinstance(decoded, dict):
            trace.failure_class = "NonObjectJSON"
            trace.failure_code = FailureCode.STRUCTURAL_CONTRACT_VIOLATION
            trace.failure_message = "Model output JSON root was not an object."
            record_invocation(trace)
            raise ModelOutputFailure(
                "Model output JSON root must be an object.",
                FailureCode.STRUCTURAL_CONTRACT_VIOLATION,
            )

        trace.parsed_output = decoded
        try:
            validated = validate_controller_response(decoded)
        except ModelOutputFailure as exc:
            trace.failure_class = type(exc).__name__
            trace.failure_code = exc.failure_code
            trace.failure_message = str(exc)
            record_invocation(trace)
            raise

        record_invocation(trace)
        return validated
