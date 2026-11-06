# Nexus operational planning

Nexus provides a shared planning engine and workflow. Domain packs supply initial terminology
and examples. Construction is the first validation use case; manufacturing exercises the same
imports, graph, forecast, branch comparison and approval code.

## Run and accounts

Run `uv sync --all-packages --frozen`, then `uv run python scripts/run_operations.py`.
Open http://127.0.0.1:8090/operations. The server binds to loopback. Bootstrap the first owner
locally with a unique password of at least 12 characters. The owner creates planner, approver
and viewer accounts. Passwords use salted PBKDF2; sessions use opaque, server-side tokens,
HttpOnly cookies, expiry and CSRF protection. This account system belongs to `/operations`;
the older `/prototype` demonstration has separate demo identities.

Local SQLite persists in ignored `artifacts/operations/operations.sqlite`. For PostgreSQL:

```powershell
$env:NEXUS_OPERATIONS_DATABASE_URL = 'postgresql+asyncpg://USER:PASSWORD@HOST/DATABASE'
uv run python scripts/run_operations.py
```

Use your own database credentials. The application creates `operations_state`, holding a locked,
checksummed JSON state row with a 10 MiB maximum. This deliberately bounded design gives atomic
writeback and restart persistence; it is not designed for enterprise throughput. Back up the
database before migrations or deletion. A checksum detects corruption, not a malicious database
administrator. Requests are capped at 1 MiB.

## Import real input

Each workspace has a domain and monotonically increasing plan revision. Import JSON containing
`name`, `start_date`, `projects`, `resources`, `materials` and `tasks`; optional fields include
`budget`, `horizon_days`, `working_days` and `weather_delays`. Download/copy the sample from the
dataset editor as a schema example. IDs connect projects, tasks, dependencies, resources and
materials. Explicit units and productivity remain the user's responsibility.

A CSV bundle consists of exactly `settings.json`, `projects.csv`, `resources.csv`, `materials.csv`
and `tasks.csv`. Select all five files in the file input. Nested task dependencies, resource
demands, material demands and material deliveries are JSON inside quoted CSV cells. The
[synthetic fixture](../tests/fixtures/operations_engine_construction_sample/README.md) documents
the format. Unknown/duplicate columns, malformed numbers, invalid references and dependency
cycles are rejected. Changing a filename or provenance label does not turn synthetic inputs
into observed data; retain the true origin when importing research datasets.

Imports preserve source name, source kind, SHA256 and timestamp. Previous datasets and analyses
remain in workspace versions. To record actual progress, update remaining quantities and current
stock/delivery assumptions, then save a new version and recompute. Material task quantities mean
remaining material demands, so revise those together with progress. This is manual observed input,
not an automatic connection to a building site.

## Forecast and branch workflow

The scheduler respects dependency precedence, shared resource capacity, remaining material stock,
dated deliveries, work calendars, explicit weather blackout dates and task productivity. It uses
an input-order, non-preemptive dispatch heuristic. Its feasible result is not a proof of an optimal
schedule. Supplier lead days are informational; expected delivery day controls availability.

Monte Carlo runs perturb task durations within imported uncertainty and preserve hard minimum
durations. P50/P80 describe that assumed model. They have not been calibrated against real
construction outcomes. Infeasible samples beyond the horizon remain failures rather than being
silently removed. The displayed critical indicator measures overall-finish sensitivity to an
extra working day, rather than strict unconstrained CPM criticality.

Create a branch with ID-addressed changes, for example:

```json
[{"path":"/resources/crew/capacity","value":2}]
```

Both baseline and branch use the same seed and sample count. Cost totals come from imported task
costs. Extra crew/equipment capacity is not automatically priced; update relevant costs explicitly
before making a budget claim. A branch must be feasible and based on the current revision before
proposal. A different owner/approver reviews the exact plan hash. Only its author can apply the
approved branch, and stale revisions are rejected. Applying increments the actual working plan
revision. Events retain actor, timestamp and linked hashes. No LLM can approve or apply a plan.

## Real external services

Weather retrieval calls Open-Meteo's actual forecast endpoint for the entered coordinates. The
result is stored as connected evidence. It does not silently translate rain into construction
delays; weather impacts require explicit scheduling assumptions. Provider failures are errors,
not sample responses.

NVIDIA model discovery and advisory use https://integrate.api.nvidia.com/v1. Configure
`NVIDIA_API_KEY` in the process environment, or in ignored `.env.operations`. Set
`NEXUS_LLM_MODEL` to override the default `stepfun-ai/step-5-preview`. Never commit the key.
The launcher reads only those two names from that file. The advisor receives the current
analysis and your question; use synthetic/non-sensitive inputs when evaluating hosted models.
It is read-only, and validates that cited graph IDs actually exist. Citation validation does not
prove every natural-language claim correct; a person should assess its reasoning. Invalid or
unavailable responses are explicit integration failures.

The initial live check selected Step 5 Preview after it returned validated evidence references;
Mistral Large 4 timed out in the same comparison. This is a single evaluation, not a latency
benchmark or an availability guarantee. Provider behaviour and model availability can change.
See NVIDIA's [Step 5 Preview reference](https://build.nvidia.com/stepfun-ai/step-5-preview/build).

## Verification

```powershell
uv run pytest tests/unit/operations tests/unit/test_operations_engine.py -q
npm run test:operations-ui
npm run test:operations-browser
```

The browser harness owns its server and isolated database. It exercises account setup, separate
approval identities, JSON/CSV import, analysis, branch comparison, persisted writeback, a second
domain and restart recovery at desktop/mobile sizes. It does not mock the application API.
Use `NEXUS_OPERATIONS_TEST_DATABASE_URL` only for a disposable test database: storage tests
intentionally reset and corrupt the state table. CI supplies real PostgreSQL and runs the browser
workflow separately against another PostgreSQL database. Provider-contract unit tests use mock
HTTP responses; live external checks are separate evidence and require working credentials/network.
