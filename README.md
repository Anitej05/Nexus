# NEXUS

NEXUS is a bounded operational-intelligence prototype that connects a typed business graph,
deterministic risk signals, concurrent specialist agents, a non-authoritative LLM briefing, and
human approval for a simulated high-risk action. The current demonstration follows one frozen
cross-domain scenario: a Chennai port disruption and an overlapping checkout incident.

The repository is public for evaluation and collaboration. It is not a hosted service or a
production deployment.

## What works today

| Capability | Current implementation |
|---|---|
| Operational graph | Seeded, typed, read-only projection with supply-chain and IT entities |
| Risk signals | Deterministic demonstration scorers with fixed versions, features, thresholds, and evidence |
| Agent orchestration | Two specialist analyses fan out concurrently, followed by a decision critic |
| Generative AI | Bounded OpenAI-compatible advisory with structured output, evidence citations, and safe fallback |
| Governance | Tenant-scoped authorization, exact-plan approval, optimistic preconditions, and append-only audit evidence |
| Action | R3 shipment reroute simulation only; no external connector is invoked |
| Verification | Deterministic representative outcome, evidence artifact, and dashboard screenshot |

The specialist agents do not learn online, the graph is not an authoritative Neo4j ontology, and
the two fixed signal values are not live forecasts. The LLM cannot change scores, policy, action
parameters, approval state, or execution state. These are deliberate prototype boundaries.

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

PostgreSQL is authoritative for governed state and the append-only audit chain. OPA makes
authorization decisions, Keycloak supplies local test identities, and the dashboard presents the
result. Neo4j, Redpanda, Temporal, MinIO, Redis, OpenTelemetry, Prometheus, Grafana, and MLflow are
included in the broader local-development stack; the bounded prototype does not claim to exercise
all of them end to end.

## Prerequisites

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
