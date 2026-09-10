# Diagnostic Controller

A safety-bounded LLM Diagnostic Controller designed so the model does not own diagnostic state, policy, authorization, certainty, or state-machine transitions. The model is limited to grounded language generation, candidate observation extraction, and constrained action-alias proposals.

## Safety model

The repository treats the LLM as an untrusted component inside a deterministic envelope. Provider output must pass a strict JSON schema and a Pydantic contract with `extra="forbid"`. Behavioral checks examine both natural-language output and structured action mappings. No middleware silently repairs invalid model output.

Replay persistence has two modes. `SYNTHETIC_EVAL` stores redacted, replayable synthetic traces. `PRODUCTION` stores metadata only: raw human/model text is omitted, free-form failure messages are removed, checks collapse to controlled rule IDs, and retained state values are constrained to enums. Production incident metadata must be converted manually into a synthetic reproducer before promotion into `tests/regressions/`.

## Project layout

```text
diagnostic-controller/
├── .env.example
├── .github/workflows/ci.yml
├── .gitignore
├── pyproject.toml
├── README.md
├── src/diagnostic_controller/
│   ├── __init__.py
│   ├── adapter.py
│   ├── contracts.py
│   ├── enums.py
│   ├── failures.py
│   ├── openai_adapter.py
│   ├── policy.py
│   ├── prompts.py
│   ├── py.typed
│   ├── redaction.py
│   ├── replay.py
│   └── settings.py
└── tests/
    ├── conftest.py
    ├── regressions/README.md
    ├── test_contracts.py
    ├── test_model_suite.py
    ├── test_policy.py
    ├── test_redaction.py
    ├── test_regressions.py
    ├── test_replay.py
    └── test_settings.py
```

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
cp .env.example .env
```

Set `OPENAI_API_KEY` and a high-entropy `REDACTION_HMAC_KEY` of at least 32 bytes in your shell or secret manager. Never commit `.env`.

Generate a suitable HMAC key locally with Python:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Deterministic validation

```bash
ruff check .
mypy src
pytest -v -m "not model"
```

These tests do not need an OpenAI API key. They validate structural contracts, redaction behavior, production sanitization, and replay persistence.

## Live adversarial evaluation

The live suite requires both secrets. If either is missing, the model fixture skips safely during local execution; GitHub Actions explicitly fails the live job if the repository secrets are absent.

```bash
test -n "$OPENAI_API_KEY"
test -n "$REDACTION_HMAC_KEY"
pytest -v -m "model"
```

`MODEL_TRIALS_PER_CASE` defaults to 20. Five adversarial cases produce 100 live trials before promoted regression fixtures are added.

The default model is `gpt-5.6-luna`, configurable with `OPENAI_MODEL`. The adapter uses the OpenAI Responses API with strict JSON Schema structured output, `store=False`, SDK retries disabled, and explicit provider-failure classification.

## GitHub Actions from mobile

Create repository secrets named exactly `OPENAI_API_KEY` and `REDACTION_HMAC_KEY`. The workflow runs deterministic checks on pushes and pull requests. Live model tests run only on the nightly schedule or manual `workflow_dispatch`, avoiding accidental API spend on every commit. From the GitHub mobile/web UI, a manual run can choose the model ID/snapshot and trials per case without exposing secrets in logs.

## Promoting regressions

Failure artifacts from synthetic evaluations are written under `artifacts/replay_failures/` and uploaded by CI only when the live job fails. Review the artifact, minimize/generalize it, ensure it contains synthetic data only, then commit the sanitized fixture to `tests/regressions/`. The regression runner automatically discovers every JSON fixture in that directory and replays it against the current controller.

Production incident artifacts are deliberately non-replayable metadata. Never copy a production incident artifact directly into the regression directory.

## Baseline reporting

Record the git commit/tag, prompt version, exact model identifier, trial count, temperature, top-p, reasoning effort, and raw pytest output. Report zero-count categories as `0 observed violations in N trials`, not `0% risk`; for a quick 95% upper bound with zero observations, use the Rule of Three (`3/N`).
