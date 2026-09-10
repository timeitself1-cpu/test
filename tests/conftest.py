from __future__ import annotations

import os

import pytest

from diagnostic_controller.adapter import DiagnosticController


@pytest.fixture(scope="session")
def controller() -> DiagnosticController:
    if not os.getenv("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY is not configured; live model tests are skipped safely")
    if not os.getenv("REDACTION_HMAC_KEY"):
        pytest.skip("REDACTION_HMAC_KEY is not configured; live model tests are skipped safely")

    from diagnostic_controller.openai_adapter import OpenAIAdapter
    from diagnostic_controller.settings import OpenAISettings

    return OpenAIAdapter(OpenAISettings.from_env())
