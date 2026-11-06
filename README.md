# NEXUS

## Operational planning workspaces

The authenticated `/operations` application is the current integration path. It keeps the
planning engine domain-agnostic, with construction as its first use case and manufacturing
as a second domain pack. It accepts your JSON or CSV data, versions its provenance, computes
resource/material constrained schedules, compares branches and persists an approved plan revision.
An independent account must approve the exact plan before its author can apply it.

Labelled historical outcomes now trigger real local ML training and validation-gated
retraining. The trained model can propose durations for the scheduler; Nemotron 3 Ultra
explains the metrics. See the [automatic learning guide](docs/LEARNING_GUIDE.md).

```powershell
uv sync --all-packages --frozen
uv run python scripts/run_operations.py
```

Open <http://127.0.0.1:8090/operations> and create the first owner account. Add a separate
approver account, create a workspace, then import data or load the explicitly synthetic sample.
See the [operations guide](docs/OPERATIONS_GUIDE.md) for CSV format, live NVIDIA/Open-Meteo
integrations, PostgreSQL, verification and modelling limits.

Applying a decision updates the actual Nexus plan. It does not place a purchase order or
instruct an external contractor. Forecast percentiles are modelled uncertainty, not calibrated
real-world completion guarantees. This is a bounded graduate project, not an enterprise platform.

## Earlier academic demonstration

NEXUS is a bounded operational-intelligence prototype that connects a typed business graph,
deterministic risk signals, concurrent specialist agents, a non-authoritative LLM briefing, and
human approval for a simulated high-risk action. Four controlled scenarios cover an overlapping
Chennai port and checkout incident, stable supply, an IT-heavy incident and a supply-heavy disruption.

The repository is public for evaluation and collaboration. It is not a hosted service or a
production deployment.

## What works today

| Capability | Current implementation |
|---|---|
| Operational graph | Seeded, typed, read-only projection with supply-chain and IT entities |
| Risk signals | Versioned rule-based scores calculated from scenario inputs with cited graph evidence |
| Agent orchestration | Two specialist analyses fan out concurrently, followed by a decision critic |
| Generative AI | Bounded readable advisory with validated citations, output screening and a fact-only fallback |
| Governance | Tenant-scoped authorization, exact-plan approval, optimistic preconditions, and append-only audit evidence |
| Action | R3 shipment reroute simulation only; no external connector is invoked |
| Verification | Calculated baseline/final delay comparison, persisted evidence and reproducible evaluation |

The specialist agents do not learn online, the graph is not an authoritative Neo4j ontology, and
the risk indices are not live forecasts or calibrated probabilities. The LLM cannot change scores, policy, action
parameters, approval state, or execution state. These are deliberate prototype boundaries.

## Run the complete academic demonstration

Requires Python 3.11.9 and `uv`. Docker, Node.js and an LLM endpoint are optional for this mode.

```powershell
uv sync --all-packages --frozen
uv run python scripts/run_academic_demo.py
```

Open <http://127.0.0.1:8080/prototype>. Choose **Analyst / proposer**, select a scenario and
create a run. Switch to **Independent approver** to approve or reject the exact plan, then
switch back to the proposer to execute the simulation. Inspect the graph evidence, readable
advisory, comparison options, calculated outcome and audit history. SQLite preserves runs
across restarts in the ignored `artifacts/academic-demo.sqlite3` file.

This mode binds only to loopback. Its public demonstration role selectors are deliberately
different from the separately authenticated Keycloak/OPA deployment. It shares the same scenario,
scoring, orchestration and simulation code; it does not call external action connectors.
The reroute model assumes a 50% delay reduction, which is a simulation assumption, not an
observed improvement in a real port.

For optional live advisory integration, configure the endpoint described below and add `--live-llm`.
Provider failures retain the fact-only workflow. The academic evaluation does not require an LLM:

```powershell
uv run python scripts/evaluate_academic.py --repetitions 5 --markdown docs/EVALUATION.md
```

Read the [user guide and demonstration script](docs/ACADEMIC_GUIDE.md),
[technical project report](docs/ACADEMIC_REPORT.md) and [executed evaluation](docs/EVALUATION.md).

## Architecture

```text
seeded events -> typed projection -> deterministic signals
                                      |             |
                              supply specialist   IT specialist
                                      \             /
                                       decision critic
                                              |
                                  cited advisory LLM (optional)
                                              |
                               immutable R3 simulated plan
                                              |
                             OPA authorization + human approval
                                              |
                              simulated execution + audit chain
```

In the full governed deployment, PostgreSQL is authoritative for state and the append-only audit chain. OPA makes
authorization decisions, Keycloak supplies local test identities, and the dashboard presents the
result. Neo4j, Redpanda, Temporal, MinIO, Redis, OpenTelemetry, Prometheus, Grafana, and MLflow are
included in the broader local-development stack; the bounded prototype does not claim to exercise
all of them end to end.

## Full governed deployment prerequisites

- Git
- Python 3.11.9 and [`uv`](https://docs.astral.sh/uv/)
- Node.js 22.17.0 and npm 10
- Docker Engine or Docker Desktop with Docker Compose 2.24.4 or later
- For the live-LLM acceptance path, an OpenAI-compatible endpoint at
  `http://127.0.0.1:9997/v1` exposing the exact model
  `deepseek-ai/DeepSeek-V4-Flash-0731`

All published Compose ports bind to `127.0.0.1`. The stack remains local-development software;
do not place it on an untrusted host or reuse the example credentials.

## Read-only dashboard preview

This is the quickest way to inspect the representative interface. It does not authenticate,
persist, call the governance endpoints, or write an audit record.

```powershell
git clone https://github.com/Anitej05/Nexus.git
Set-Location Nexus
uv sync --all-packages --frozen
uv run python -m http.server 8080 --bind 127.0.0.1 --directory apps/api/src/nexus_api/static/prototype
```

Open <http://127.0.0.1:8080/>. The page labels this mode as demo data and keeps all mutations
disabled.

## Governed acceptance run

The managed acceptance command is an automated, disposable verification workflow—not an
interactive deployment. It starts only the required services on random loopback ports, creates
temporary tenants and principals, exercises available and unavailable LLM paths, records approval
and simulated execution, writes sanitized evidence, and tears its owned services down. It never
removes unrelated Compose projects or volumes.

Start the OpenAI-compatible proxy first and confirm that `/v1/models` contains the exact model.
Then run the following from PowerShell:

```powershell
uv sync --all-packages --frozen
npm ci --ignore-scripts
npx --no-install playwright install chromium
Copy-Item .env.example .env

$env:NEXUS_RUN_COMPOSE_TESTS = "1"
$env:NEXUS_PROTOTYPE_E2E_MANAGED = "1"
$env:NEXUS_KEYCLOAK_ADMIN = "admin"
$env:NEXUS_POSTGRES_PASSWORD = [guid]::NewGuid().ToString("N")
$env:NEXUS_RUNTIME_DATABASE_PASSWORD = [guid]::NewGuid().ToString("N")
$env:NEXUS_MIGRATION_DATABASE_PASSWORD = [guid]::NewGuid().ToString("N")
$env:NEXUS_AUDIT_RECOVERY_DATABASE_PASSWORD = [guid]::NewGuid().ToString("N")
$env:NEXUS_KEYCLOAK_ADMIN_PASSWORD = [guid]::NewGuid().ToString("N")
$env:NEXUS_KEYCLOAK_TEST_ADMIN_PASSWORD = [guid]::NewGuid().ToString("N")
$env:NEXUS_KEYCLOAK_TEST_VIEWER_PASSWORD = [guid]::NewGuid().ToString("N")
$env:NEXUS_OIDC_WORKER_CLIENT_SECRET = [guid]::NewGuid().ToString("N")

Invoke-RestMethod http://127.0.0.1:9997/v1/models | ConvertTo-Json -Depth 5
uv run python scripts/prototype/run_e2e_managed.py --dry-run
uv run python scripts/prototype/run_e2e_managed.py
```

Successful acceptance writes sanitized, ignored local artifacts:

```text
artifacts/prototype/storm-and-checkout-shift-v1.json
artifacts/prototype/storm-and-checkout-shift-v1.png
```

The command requires the managed runner included in the integrated prototype release. If that
file is absent from a development branch, that branch is not the governed release candidate; use
the read-only preview and local test suite instead.

## Verification

The default CI gate is offline and does not contact the LLM proxy or start the live Compose test
runtime:

```powershell
uv lock --check
uv sync --all-packages --frozen
npm ci --ignore-scripts
uv run python scripts/generate_contracts.py --check
uv run ruff check .
uv run mypy apps packages
uv run pytest packages/contracts/tests packages/prototype/tests tests/unit tests/contract tests/security -q
node --test apps/api/src/nexus_api/static/prototype/prototype.behavior.test.cjs
uv run pip-audit
```

Live LLM, database, OPA, Keycloak, and managed acceptance checks stay explicitly opt-in.

## Repository map

- `apps/api` — FastAPI routes, prototype service, and static dashboard
- `apps/worker` — worker process boundary
- `packages/contracts` — immutable platform and prototype contracts
- `packages/llm` — bounded OpenAI-compatible structured-output adapter
- `packages/prototype` — evidence and deterministic scoring logic
- `packages/security` — OIDC, policy, tenancy, outbox, and audit controls
- `infrastructure` — local Compose, OPA, Keycloak, and observability configuration
- `scripts/prototype` — guarded acceptance tools
- `tests` — unit, contract, security, integration, and live opt-in tests

## Security and contributing

Review [SECURITY.md](SECURITY.md) before running the local stack or reporting a vulnerability.
Contribution expectations are in [CONTRIBUTING.md](CONTRIBUTING.md).

Licensed under the [Apache License 2.0](LICENSE).
