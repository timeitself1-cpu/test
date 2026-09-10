from __future__ import annotations

from typing import Protocol

from .contracts import ControllerResponse, DiagnosticControllerInput


class DiagnosticController(Protocol):
    def invoke(
        self,
        *,
        system_input: DiagnosticControllerInput,
        human_message: str,
    ) -> ControllerResponse:
        """Invoke the controller against immutable authoritative system state."""
        ...
