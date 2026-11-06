# Nexus academic user guide

## Setup and launch

Install Git, Python 3.11.9 and uv. In the repository root:

```powershell
uv sync --all-packages --frozen
uv run python scripts/run_academic_demo.py
```

Visit `http://127.0.0.1:8080/prototype`. Stop with Ctrl+C. An alternate port is available with
`--port 8086`. Run history is saved in `artifacts/academic-demo.sqlite3`; use `--database path`
to keep a separate demonstration dataset. Database files are ignored by Git.

The local app has public demonstration identities and accepts loopback requests only. It rejects
cross-origin requests and nonlocal hosts. Do not publish this launcher through a reverse proxy.
The separate full deployment uses OIDC identities, OPA policies and PostgreSQL.

## Demonstration sequence

1. Select **Analyst / proposer** in the local identity selector.
2. Select **Port and checkout disruption** (or the first scenario) and create a run.
3. Read the supply and IT signals, feature values, specialist findings and uncertainty.
4. Inspect typed graph entities and relationships. For the new scenarios, numeric input nodes
   form part of the evidence and seed digest.
5. Read the advisory, citations and provider status. Offline mode produces a fact-only explanation.
6. Compare no action with simulated rerouting. The displayed delay reduction follows the declared
   simulation model. The action requires R3 approval even when the risk index is low.
7. Switch to **Independent approver** and approve the exact plan, or reject it. Rejection ends the run.
8. Switch back to **Analyst / proposer** and execute the approved simulation.
9. Read baseline, final delay and reduction separately. Inspect the eleven recorded audit events.
10. Repeat with **Supply disruption** and **IT incident**. The scores, evidence, findings and outcomes change.
11. Stop and restart the server, paste the saved run ID into the connection field and reload the run.

The approver cannot propose or execute in the local demonstration. The proposer cannot approve.
The viewer can inspect runs but cannot change them. Switching or clearing identity invalidates
pending UI requests. A stale response cannot restore old controls.

## Scenarios

| Scenario | Delay input | Affected shipments | Checkout latency shift |
|---|---:|---:|---:|
| Port and checkout disruption | 28 h | 3 | 4 min |
| Stable supply | 8 h | 1 | 1 min |
| IT incident | 12 h | 1 | 8 min |
| Supply disruption | 48 h | 3 | 1 min |

These are controlled synthetic inputs. Their purpose is repeatable technical evaluation.

## Optional LLM

The default run uses deterministic advice. To try the configured OpenAI-compatible endpoint:

```powershell
uv run python scripts/run_academic_demo.py --live-llm
```

The current adapter expects the exact model documented in the main README. Environment settings
can configure the endpoint, model and key. Never put keys into Git or browser URLs. Unavailable,
timed-out, malformed or uncited output degrades safely. Displayed model conclusions are bounded
and screened. Advice never approves, executes or changes calculated scores and plan parameters.

## Verification

```powershell
uv run ruff check .
uv run mypy apps packages
uv run python scripts/generate_contracts.py --check
uv run pytest packages/contracts/tests packages/prototype/tests tests/unit tests/contract tests/security -q
node --test apps/api/src/nexus_api/static/prototype/prototype.behavior.test.cjs
uv run python scripts/evaluate_academic.py --repetitions 5 --markdown docs/EVALUATION.md
```

Docker Compose CLI checks skip explicitly when that CLI is absent. Live PostgreSQL/OPA/OIDC and
provider tests are separately opt-in. The default suite still executes the complete SQLite-backed
academic workflow, role checks, exact-plan preconditions, replay, persistence and tamper cases.

For browser verification, install Node.js 22.17.0/npm10 and then:

```powershell
npm ci --ignore-scripts
npx playwright install chromium
npm run test:academic-browser
```

## Troubleshooting

- If the port is occupied, choose a different `--port` and use its printed URL.
- If controls are locked, select the correct identity and reconnect the current run.
- If a run is rejected, create another run; rejection is terminal.
- If an integrity check fails, retain the database for investigation and start with a new named
  `--database` file. Do not edit stored approvals or hashes to bypass a failed check.
- A model outage affects advisory wording, not scenario analysis or the approval simulation.

## Scope of completion

The academic deliverable is a working, evaluated local prototype with controlled scenario data,
explainable rules, concurrent specialist analysis, cited advice, human approval and persisted
simulated outcomes. It does not claim learned predictive models, live logistics feeds, causal
proof, external operational execution or enterprise deployment readiness.
