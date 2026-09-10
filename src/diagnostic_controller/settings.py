from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final, Literal, cast

from dotenv import load_dotenv

load_dotenv(override=False)

ReasoningEffort = Literal["none", "low", "medium", "high", "xhigh", "max"]
_VALID_REASONING_EFFORTS: Final[set[str]] = {
    "none",
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
}
DEFAULT_OPENAI_MODEL: Final[str] = "gpt-5.6-luna"
DEFAULT_TEMPERATURE: Final[float] = 0.0
DEFAULT_TOP_P: Final[float] = 1.0
DEFAULT_REASONING_EFFORT: Final[ReasoningEffort] = "none"
DEFAULT_MAX_OUTPUT_TOKENS: Final[int] = 1400
DEFAULT_TIMEOUT_SECONDS: Final[float] = 45.0


@dataclass(frozen=True, slots=True)
class OpenAISettings:
    api_key: str
    model: str = DEFAULT_OPENAI_MODEL
    temperature: float = DEFAULT_TEMPERATURE
    top_p: float = DEFAULT_TOP_P
    reasoning_effort: ReasoningEffort = DEFAULT_REASONING_EFFORT
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    @classmethod
    def from_env(cls) -> "OpenAISettings":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is required for live model execution")

        model = os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip() or DEFAULT_OPENAI_MODEL
        temperature = _parse_float(
            "OPENAI_TEMPERATURE",
            DEFAULT_TEMPERATURE,
            minimum=0.0,
            maximum=2.0,
        )
        top_p = _parse_float(
            "OPENAI_TOP_P",
            DEFAULT_TOP_P,
            minimum=0.0,
            maximum=1.0,
        )
        max_output_tokens = _parse_int(
            "OPENAI_MAX_OUTPUT_TOKENS",
            DEFAULT_MAX_OUTPUT_TOKENS,
            minimum=128,
        )
        timeout_seconds = _parse_float(
            "OPENAI_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
            minimum=1.0,
            maximum=600.0,
        )
        reasoning_raw = (
            os.getenv("OPENAI_REASONING_EFFORT", DEFAULT_REASONING_EFFORT).strip()
            or DEFAULT_REASONING_EFFORT
        )
        if reasoning_raw not in _VALID_REASONING_EFFORTS:
            raise ValueError("OPENAI_REASONING_EFFORT is invalid")

        return cls(
            api_key=api_key,
            model=model,
            temperature=temperature,
            top_p=top_p,
            reasoning_effort=cast(ReasoningEffort, reasoning_raw),
            max_output_tokens=max_output_tokens,
            timeout_seconds=timeout_seconds,
        )


def _parse_float(
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float | None = None,
) -> float:
    raw = os.getenv(name)
    value = default if raw is None or not raw.strip() else float(raw)
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{name} is outside the permitted range")
    return value


def _parse_int(name: str, default: int, *, minimum: int) -> int:
    raw = os.getenv(name)
    value = default if raw is None or not raw.strip() else int(raw)
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value
