# Automatic learning and synthetic evaluation

The operations application now actually trains two local scikit-learn ExtraTrees estimators:
activity duration regression and activity-delay classification. Nemotron 3 Ultra explains the
recorded results. Its hosted weights are not trained or fine-tuned by this workflow.

## Automatic workflow

1. Create a workspace and import historical outcomes through the learning panel or
   `POST /api/v1/operations/workspaces/{id}/learning/history`.
2. Each row supplies pre-execution features plus measured `actual_duration` and a `delayed`
   label. Uploading a future plan without outcomes does not trigger supervised learning.
3. With at least 120 rows, 12 project groups and sufficient training/validation/test cohorts,
   the server automatically fits a candidate. Afterwards, 50 additional labelled rows and
   three new project groups trigger another fit. A manual retry is also available.
4. A candidate must improve validation duration MAE by at least 5% over both a mean baseline
   and planned duration, pass the delay Brier-score check and compare favourably with the
   active model. Test metrics never decide promotion. A failed gate retains the active model.
5. The registry records candidate status, trigger, data digest, recipe/dependency versions,
   cohort counts, metrics and artifact digest. It retains three recent JSON artifacts,
   preserving the active one, and twenty run summaries.
6. Use the active model to create a scenario. Predicted durations become separate duration
   assumptions and pass through the resource/material/calendar constraint scheduler.
   A different account still approves the exact plan before its author applies it.
   Observed productivity is preserved. An estimate records its remaining-quantity basis and
   scales with subsequent progress; repeated prediction does not feed an adjusted rate back
   into the model as if it were a new observation.

Training runs in a worker thread outside the database transaction; it is a bounded synchronous
HTTP workflow, not a distributed training service. A history revision check rejects stale
results. Restart persistence stores fitted tree arrays as JSON, without loading uploaded
pickle files or executing model-generated Python. There is no arbitrary-code training agent.

## Data and evaluation

Historical JSON has `schema_version: 1`, `kind: "synthetic"` or `"user_upload"`, and `rows`.
Each row contains `id`, `project_id`, `domain`, `features`, `actual_duration` and `delayed`.
Features are `planned_duration`, `quantity`, `productivity`, `resource_capacity`,
`material_coverage`, `supplier_delay_days`, `weather_risk` and `complexity`.

IDs must be stable. Identical duplicate rows do not retrain; changed existing outcomes require
explicit history replacement. Mixed synthetic/user-upload append provenance is rejected.
Replacement deliberately clears the prior training state. History is limited to 2,000 rows
per workspace and the installation retains its existing 10 MiB state limit.

A stable SHA-256 project-group split assigns approximately 60% of projects to training,
20% to validation and 20% to testing. Activities from one project stay together; appending
projects does not move old training projects into validation or test. Identifiers and targets
are not model features. Repeated selection against one validation cohort can still overfit
that cohort. Fresh external evaluation therefore uses disjoint projects and does not feed
outcomes into training. Test results must not be used for repeated tuning.

Operational feature extraction currently uses stock-only material coverage, supplier lead
time as a delay proxy, and explicit weather-delay fraction as a weather-risk proxy. These
are modelling assumptions, not validated real-world feature definitions. Context effects in
predicted durations can overlap with explicit scheduling constraints; integrated forecasting
accuracy needs real outcome data and a consistent measurement protocol.

The delay classifier estimates an activity-level label, not a calibrated project deadline
probability. Out-of-training-range feature warnings do not establish statistical confidence.

## Reproduce the evaluation

```powershell
uv run python scripts/generate_operations_data.py
uv run python scripts/evaluate_operations_learning.py
uv run python scripts/evaluate_operations_learning.py --live-llm
```

The generator writes JSON/CSV histories, shifted-distribution histories, fourteen operational
cases across two domains, and a SHA256 manifest under ignored `artifacts/operations/synthetic`.
Outcomes come from a documented latent project-effect/noise process independent of the
scheduling engine. Cases include material shortage, zero capacity, budget overrun, adverse
calendar, shared resources and completed progress.

The evaluator starts its own real HTTP server with disposable accounts and database. It
verifies below-threshold waiting, automatic initial training, retraining after a later batch,
held-out metrics, safe artifact reload, shifted-data evaluation, scenario generation, separate
approval and actual plan writeback. `--live-llm` also calls the actual configured NVIDIA service
and validates the cited trained-model graph ID. No provider success is fabricated.

Results are written to `artifacts/operations-learning-evaluation.json`. CI runs the deterministic
evaluation and the actual browser workflow against SQLite and PostgreSQL; live provider calls
are separate checks requiring local credentials and network availability.

Synthetic results verify computation and integration. They do not establish accuracy on real
construction or manufacturing operations. Under distribution shift, duration errors rise;
high classification accuracy can reflect a nearly all-delayed dataset, so inspect Brier scores,
class balance and baselines too.
