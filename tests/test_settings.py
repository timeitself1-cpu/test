from __future__ import annotations

import pytest

from diagnostic_controller.settings import (
    DEFAULT_MAX_OUTPUT_TOKENS,
    DEFAULT_OPENAI_MODEL,
    DEFAULT_REASONING_EFFORT,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TOP_P,
    OpenAISettings,
)


def test_settings_from_env_uses_stable_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-api-key")
    for name in [
        "OPENAI_MODEL",
        "OPENAI_TEMPERATURE",
        "OPENAI_TOP_P",
        "OPENAI_REASONING_EFFORT",
        "OPENAI_MAX_OUTPUT_TOKENS",
        "OPENAI_TIMEOUT_SECONDS",
    ]:
        monkeypatch.delenv(name, raising=False)

    settings = OpenAISettings.from_env()
    assert settings.model == DEFAULT_OPENAI_MODEL
    assert settings.temperature == DEFAULT_TEMPERATURE
    assert settings.top_p == DEFAULT_TOP_P
    assert settings.reasoning_effort == DEFAULT_REASONING_EFFORT
    assert settings.max_output_tokens == DEFAULT_MAX_OUTPUT_TOKENS
    assert settings.timeout_seconds == DEFAULT_TIMEOUT_SECONDS


def test_settings_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        OpenAISettings.from_env()


def test_settings_rejects_invalid_reasoning_effort(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-api-key")
    monkeypatch.setenv("OPENAI_REASONING_EFFORT", "invented")
    with pytest.raises(ValueError):
        OpenAISettings.from_env()
