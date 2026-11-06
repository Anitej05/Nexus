"""Measure controlled scenario correctness and the complete local HTTP workflow."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import platform
import statistics
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from nexus_api.academic_demo import create_demo_app

# Independent acceptance values for the published scenario dataset, not learned labels.
EXPECTED = {
    "storm-and-checkout-shift-v1": (0.91, 0.94, 28.0, 14.0),
    "supply-stable-v1": (0.34, 0.46, 8.0, 4.0),
    "it-heavy-v1": (0.42, 1.0, 12.0, 6.0),
    "supply-heavy-v1": (1.0, 0.46, 48.0, 24.0),
}


def _headers(role: str, key: str, digest: str | None = None) -> dict[str, str]:
    result = {"Authorization": f"Bearer academic-{role}", "Idempotency-Key": key}
    if digest is not None:
        result["If-Match"] = f'"{digest}"'
    return result


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


async def evaluate(repetitions: int = 5) -> dict[str, Any]:
    if not 1 <= repetitions <= 100:
        raise ValueError("repetitions must be between 1 and 100")
    durations: list[float] = []
    rows: list[dict[str, Any]] = []
    negative_checks = citation_checks = 0
    hashes: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="nexus-evaluation-") as directory:
        database = Path(directory) / "evaluation.sqlite3"
        app = create_demo_app(database)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 30000)),
            base_url="http://127.0.0.1:8080",
        ) as client:
            for scenario_id, expected in EXPECTED.items():
                for repeat in range(repetitions):
                    key = f"{scenario_id}-{repeat}"
                    start = time.perf_counter()
                    response = await client.post(
                        "/api/v1/prototype/runs",
                        json={"scenario_id": scenario_id},
                        headers=_headers("proposer", key),
                    )
                    _check(response.status_code == 201, "run creation failed")
                    run = response.json()
                    run_url = "/api/v1/prototype/runs/" + run["run_id"]
                    digest = run["plan"]["plan_hash"]
                    scores = tuple(signal["score"] for signal in run["signals"])
                    _check(
                        scores == expected[:2],
                        "risk score differs from independent acceptance value",
                    )
                    _check(
                        digest == hashes.setdefault(scenario_id, digest), "plan is not repeatable"
                    )
                    summary = run["llm"]["summary"]
                    _check(
                        bool(summary)
                        and hashlib.sha256(summary.encode()).hexdigest()
                        == run["llm"]["summary_sha256"],
                        "advisory digest mismatch",
                    )
                    graph = (
                        await client.get(run_url + "/graph", headers=_headers("viewer", key))
                    ).json()
                    node_ids = {node["id"] for node in graph["nodes"]}
                    cited = run["llm"]["citation_node_ids"]
                    _check(bool(cited) and set(cited) <= node_ids, "invalid advisory citation")
                    for item in (*run["signals"], *run["findings"]):
                        _check(
                            set(item["evidence_node_ids"]) <= node_ids, "invalid finding evidence"
                        )
                    citation_checks += 1
                    body = {"plan_hash": digest}
                    blocked = await client.post(
                        run_url + "/execute", json=body, headers=_headers("proposer", key, digest)
                    )
                    _check(blocked.status_code == 409, "execution bypassed approval")
                    blocked = await client.post(
                        run_url + "/approval",
                        json={**body, "decision": "approve"},
                        headers=_headers("proposer", key, digest),
                    )
                    _check(blocked.status_code == 403, "proposer approved its own plan")
                    blocked = await client.post(
                        run_url + "/approval",
                        json={**body, "decision": "approve"},
                        headers=_headers("approver", key, "0" * 64),
                    )
                    _check(blocked.status_code == 412, "stale approval hash was accepted")
                    negative_checks += 3
                    approved = await client.post(
                        run_url + "/approval",
                        json={**body, "decision": "approve"},
                        headers=_headers("approver", key, digest),
                    )
                    _check(approved.status_code == 200, "approval failed")
                    execution = await client.post(
                        run_url + "/execute", json=body, headers=_headers("proposer", key, digest)
                    )
                    _check(execution.status_code == 200, "simulation failed")
                    final = execution.json()
                    verification = final["verification"]
                    _check(final["status"] == "verified", "missing verification")
                    _check(
                        (
                            verification["baseline_delay_hours"],
                            verification["delay_reduction_hours"],
                        )
                        == expected[2:],
                        "calculated simulation differs from acceptance value",
                    )
                    _check(
                        verification["observed_delay_hours"] == expected[2] - expected[3],
                        "baseline/final/reduction arithmetic failed",
                    )
                    trace = (
                        await client.get(run_url + "/trace", headers=_headers("viewer", key))
                    ).json()
                    _check(len(trace["events"]) == 11, "incomplete audit workflow")
                    elapsed = (time.perf_counter() - start) * 1000
                    durations.append(elapsed)
                    if repeat == 0:
                        rows.append(
                            {
                                "scenario_id": scenario_id,
                                "supply_score": scores[0],
                                "it_score": scores[1],
                                **verification,
                                "audit_events": len(trace["events"]),
                                "checks_passed": True,
                            }
                        )
            _check(len(set(hashes.values())) == len(EXPECTED), "scenarios share approval hashes")
            # Reopen the SQLite-backed application, not merely its current in-memory objects.
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(
                    app=create_demo_app(database), client=("127.0.0.1", 30000)
                ),
                base_url="http://127.0.0.1:8080",
            ) as restarted:
                loaded = await restarted.get(run_url, headers=_headers("viewer", "restart"))
                _check(
                    loaded.status_code == 200 and loaded.json() == final, "restart lost run state"
                )
    ordered = sorted(durations)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "platform": platform.system(),
        "provider_mode": "deterministic_fallback",
        "all_checks_passed": True,
        "workflow_count": len(durations),
        "repetitions_per_scenario": repetitions,
        "negative_checks": negative_checks,
        "citation_checks": citation_checks,
        "restart_persistence": True,
        "scenarios": rows,
        "latency_ms": {
            "median": round(statistics.median(durations), 2),
            "p95": round(ordered[math.ceil(len(ordered) * 0.95) - 1], 2),
        },
        "measurement_scope": (
            "In-process HTTP + SQLite full workflow including negative checks; "
            "no network or live LLM latency"
        ),
        "limitations": [
            "Four controlled synthetic scenarios, not external validation data",
            "Rule-based risk indices, not calibrated probabilities or trained ML",
            "Reroute assumes 50% reduction; calculated simulation, not measured logistics",
            "Local role selectors are not production authentication",
            "OIDC/OPA/PostgreSQL deployment remains a separate opt-in integration",
        ],
    }


def markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Academic evaluation",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "This report records executed acceptance workflows against the shared analysis engine "
        "and SQLite-backed local application.",
        "",
        "| Scenario | Supply risk index | IT risk index | Baseline delay | "
        "Final delay | Reduction | Audit events |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["scenarios"]:
        lines.append(
            f"| {row['scenario_id']} | {row['supply_score']:.2f} | {row['it_score']:.2f} | "
            f"{row['baseline_delay_hours']:g} h | {row['observed_delay_hours']:g} h | "
            f"{row['delay_reduction_hours']:g} h | {row['audit_events']} |"
        )
    lines.extend(
        [
            "",
            f"- Completed workflows: {report['workflow_count']}",
            f"- Rejected invalid governance operations: {report['negative_checks']}",
            f"- Citation/evidence checks: {report['citation_checks']}",
            "- Restart persistence and scenario-specific plan repeatability passed",
            f"- Median workflow: {report['latency_ms']['median']} ms",
            f"- P95 workflow: {report['latency_ms']['p95']} ms",
            "",
            f"Measurement scope: {report['measurement_scope']}",
            "",
            "## Interpretation",
            "",
            "Passing these cases establishes controlled academic acceptance, "
            "not general model accuracy or enterprise readiness.",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.extend(
        [
            "",
            "## Reproduction",
            "",
            "```powershell",
            "uv sync --all-packages --frozen",
            "uv run python scripts/evaluate_academic.py --repetitions 5 "
            "--markdown docs/EVALUATION.md",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--output", type=Path, default=Path("artifacts/academic-evaluation.json"))
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()
    report = asyncio.run(evaluate(args.repetitions))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown(report), encoding="utf-8")
    print(
        f"Passed {report['workflow_count']} workflows and "
        f"{report['negative_checks']} negative governance checks"
    )
    print(f"Results: {args.output}")


if __name__ == "__main__":
    main()
