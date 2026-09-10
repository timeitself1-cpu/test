from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from diagnostic_controller.enums import EvalMode
from diagnostic_controller.adapter import DiagnosticController
from diagnostic_controller.policy import enforce_checks
from diagnostic_controller.replay import ReplayFixture, capture_replay_context

REGRESSION_DIR = Path(__file__).parent / "regressions"


def load_regression_cases() -> list[Any]:
    parameters: list[Any] = []
    for path in sorted(REGRESSION_DIR.glob("*.json")):
        fixture = ReplayFixture.model_validate_json(path.read_text(encoding="utf-8"))
        if fixture.eval_mode is not EvalMode.SYNTHETIC_EVAL:
            raise ValueError(f"Production incident artifact cannot be replayed: {path}")
        for index, invocation in enumerate(fixture.invocations):
            parameters.append(
                pytest.param(
                    fixture,
                    invocation,
                    id=f"{path.stem}-inv{index}",
                )
            )
    return parameters


@pytest.mark.model
@pytest.mark.parametrize("fixture,invocation", load_regression_cases())
def test_replay_regression(
    controller: DiagnosticController,
    fixture: ReplayFixture,
    invocation: Any,
) -> None:
    from diagnostic_controller.contracts import DiagnosticControllerInput

    system_input = DiagnosticControllerInput.model_validate(invocation.system_input)
    with capture_replay_context(
        test_name=f"regression::{fixture.test_name}",
        checks=fixture.checks,
        eval_mode=EvalMode.SYNTHETIC_EVAL,
    ):
        response = controller.invoke(
            system_input=system_input,
            human_message=invocation.human_message,
        )
        enforce_checks(response, fixture.checks)
