from __future__ import annotations

from .enums import FailureCode


class ClassifiedFailure(Exception):
    """Base exception carrying an authoritative machine-readable failure code."""

    def __init__(self, message: str, failure_code: FailureCode) -> None:
        super().__init__(message)
        self.failure_code = failure_code


class ProviderFailure(ClassifiedFailure):
    """Provider/API/network failure."""


class ModelOutputFailure(ClassifiedFailure):
    """Malformed or structurally invalid model output."""


class ControllerBehaviorFailure(ClassifiedFailure):
    """Structurally valid output that violates a behavioral safety rule."""


class RedactionConfigurationError(RuntimeError):
    """Safety-critical redaction configuration is absent or invalid."""
