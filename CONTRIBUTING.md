# Contributing to NEXUS

Thanks for helping improve NEXUS. Keep contributions aligned with the repository's bounded,
evidence-driven prototype scope.

## Before opening a change

1. Use an issue for a material feature or architecture proposal so scope and threat boundaries are
   explicit.
2. Do not include company code, customer data, access tokens, model credentials, or proprietary
   fixtures.
3. Keep live external integrations opt-in and make deterministic offline tests the default.
4. Preserve tenant isolation, exact-plan governance, human approval, and audit evidence. Do not
   weaken a control merely to simplify a demonstration.

## Development setup

```powershell
uv sync --all-packages --frozen
npm ci --ignore-scripts
```

Use `.env.example` only as a template. Local `.env*`, evidence artifacts, logs, and work files are
ignored and must stay untracked.

## Required checks

```powershell
uv run python scripts/generate_contracts.py --check
uv run ruff check .
uv run mypy apps packages
uv run pytest packages/contracts/tests packages/prototype/tests tests/unit tests/contract tests/security -q
node --test apps/api/src/nexus_api/static/prototype/prototype.behavior.test.cjs
uv run pip-audit
```

Tests that require Docker, a database, an identity provider, OPA, or an LLM must remain explicitly
guarded and must clean up only resources they created.

## Pull requests

- Explain the user-visible outcome and the security or governance impact.
- Add focused tests for behavior changes and show the failing test before the implementation when
  practical.
- Update generated contracts and documentation when public interfaces change.
- State which checks were run and identify any skipped live prerequisites honestly.
- Keep commits free of generated local evidence and internal agent/review journals.

Security vulnerabilities belong in the private channel described in [SECURITY.md](SECURITY.md),
not in a public pull request or issue.
