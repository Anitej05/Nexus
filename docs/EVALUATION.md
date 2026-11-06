# Academic evaluation

Generated: 2026-11-06T14:09:08.322826+00:00

This report records executed acceptance workflows against the shared analysis engine and SQLite-backed local application.

| Scenario | Supply risk index | IT risk index | Baseline delay | Final delay | Reduction | Audit events |
|---|---:|---:|---:|---:|---:|---:|
| storm-and-checkout-shift-v1 | 0.91 | 0.94 | 28 h | 14 h | 14 h | 11 |
| supply-stable-v1 | 0.34 | 0.46 | 8 h | 4 h | 4 h | 11 |
| it-heavy-v1 | 0.42 | 1.00 | 12 h | 6 h | 6 h | 11 |
| supply-heavy-v1 | 1.00 | 0.46 | 48 h | 24 h | 24 h | 11 |

- Completed workflows: 20
- Rejected invalid governance operations: 60
- Citation/evidence checks: 20
- Restart persistence and scenario-specific plan repeatability passed
- Median workflow: 63.13 ms
- P95 workflow: 74.05 ms

Measurement scope: In-process HTTP + SQLite full workflow including negative checks; no network or live LLM latency

## Interpretation

Passing these cases establishes controlled academic acceptance, not general model accuracy or enterprise readiness.

- Four controlled synthetic scenarios, not external validation data
- Rule-based risk indices, not calibrated probabilities or trained ML
- Reroute assumes 50% reduction; calculated simulation, not measured logistics
- Local role selectors are not production authentication
- OIDC/OPA/PostgreSQL deployment remains a separate opt-in integration

## Reproduction

```powershell
uv sync --all-packages --frozen
uv run python scripts/evaluate_academic.py --repetitions 5 --markdown docs/EVALUATION.md
```
