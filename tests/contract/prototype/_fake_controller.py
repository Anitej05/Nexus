"""In-memory controller port used only to prove real FastAPI dependency wiring."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
from uuid import UUID

RUN_ID = UUID("019fe476-8380-7000-8000-000000000100")
PLAN_HASH = "a" * 64
PROPOSER_ID = UUID("018f0000-0000-7000-8000-000000000002")


def graph_payload() -> dict[str, Any]:
    return json.loads(
        Path("tests/fixtures/prototype/storm-and-checkout-shift-v1.json").read_text(
            encoding="utf-8"
        )
    )


def run_payload(*, status: str = "awaiting_approval") -> dict[str, Any]:
    approval = None
    execution = None
    verification = None
    if status in {"approved", "verified"}:
        approval = {
            "status": "approved",
            "plan_hash": PLAN_HASH,
            "approver_id": "018f0000-0000-7000-8000-000000000003",
        }
    if status == "verified":
        execution = {
            "plan_hash": PLAN_HASH,
            "status": "simulated",
            "receipt_id": "sim-receipt-001",
            "connector_kind": "in_process_simulator",
        }
        verification = {
            "receipt_id": "sim-receipt-001",
            "status": "verified",
            "verified_effect": "delay_reduced",
            "observed_delay_hours": 12.0,
        }
    record_count = 8 if status == "awaiting_approval" else 9 if status == "approved" else 11
    return {
        "schema_version": "1.0.0",
        "run_id": str(RUN_ID),
        "tenant_id": "018f0000-0000-7000-8000-000000000001",
        "tenant_name": "Authenticated tenant",
        "scenario_id": "storm-and-checkout-shift-v1",
        "seed_digest": graph_payload()["seed_digest"],
        "status": status,
        "proposer_id": str(PROPOSER_ID),
        "signals": [
            {
                "domain": "supply",
                "model_version": "demo.supply-delay.v1",
                "target_id": "SHP-0042",
                "score": 0.91,
                "threshold": 0.80,
                "feature_map": {
                    "port_closed": 1.0,
                    "affected_shipments": 3.0,
                    "component_risk": 1.0,
                },
                "evidence_node_ids": [
                    "PORT-MAA",
                    "SHP-0042",
                    "SHP-0047",
                    "SHP-0051",
                    "CMP-SENSOR-A",
                    "PO-1107",
                    "PO-1112",
                ],
            },
            {
                "domain": "it",
                "model_version": "demo.incident-risk.v1",
                "target_id": "svc-checkout",
                "score": 0.94,
                "threshold": 0.80,
                "feature_map": {"deployment_precedes_latency": 1.0, "p95_shift_minutes": 4.0},
                "evidence_node_ids": ["DEP-882", "svc-checkout", "svc-payments", "db-ledger"],
            },
        ],
        "findings": [
            {
                "agent_role": "supply_risk_analyst",
                "status": "completed",
                "finding_code": "supply_delay_threshold_exceeded",
                "evidence_node_ids": [
                    "PORT-MAA",
                    "SHP-0042",
                    "SHP-0047",
                    "SHP-0051",
                    "CMP-SENSOR-A",
                    "PO-1107",
                    "PO-1112",
                ],
                "uncertainty_code": "Deterministic projection; no live logistics telemetry",
            },
            {
                "agent_role": "it_incident_analyst",
                "status": "completed",
                "finding_code": "incident_risk_threshold_exceeded",
                "evidence_node_ids": ["DEP-882", "svc-checkout", "svc-payments", "db-ledger"],
                "uncertainty_code": "Temporal association; not a deployment root-cause proof",
            },
            {
                "agent_role": "decision_critic",
                "status": "completed",
                "finding_code": "cross_domain_priority_correlated",
                "evidence_node_ids": ["shift-2026-08-09", "PORT-MAA", "DEP-882"],
                "uncertainty_code": "Correlated operational priority, not a proven causal link",
            },
        ],
        "llm": {
            "provider_status": "unavailable",
            "summary_sha256": "b" * 64,
            "citation_node_ids": ["PORT-MAA", "DEP-882"],
            "model_id": "deepseek-ai/DeepSeek-V4-Flash-0731",
            "prompt_version": "prototype-briefing.v1",
        },
        "plan": {
            "action_kind": "simulated_reroute",
            "target_id": "SHP-0042",
            "destination": "sim://reroute/PORT-MAA",
            "risk_class": "R3",
            "expected_effect": "reduce_predicted_delay_by_14_hours",
            "plan_hash": PLAN_HASH,
            "status": "awaiting_approval",
        },
        "approval": approval,
        "execution": execution,
        "verification": verification,
        "audit_events": [
            {
                "event_id": f"019fe476-8380-7000-8000-{index:012x}",
                "sequence": index,
                "event_type": "prototype.run.created" if index == 1 else "prototype.event.recorded",
                "hash": f"{index:064x}",
            }
            for index in range(1, record_count + 1)
        ],
    }


def trace_payload() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "run_id": str(RUN_ID),
        "events": [
            {
                "event_id": "019fe476-8380-7000-8000-000000000111",
                "sequence": 1,
                "occurred_at": "2026-08-09T03:00:00Z",
                "actor_id": str(PROPOSER_ID),
                "event_type": "prototype.run.created",
                "hash": "e" * 64,
                "public_payload": {
                    "scenario_id": "storm-and-checkout-shift-v1",
                    "seed_digest": graph_payload()["seed_digest"],
                    "status": "created",
                    "policy_operation": "action.propose",
                },
            }
        ],
    }


class RecordingController:
    """Behavioral fake for request projection; idempotency itself is tested live."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Any, tuple[Any, ...]]] = []
        self.failure: BaseException | None = None

    def _record(self, name: str, context: Any, *arguments: Any) -> None:
        self.calls.append((name, context, arguments))
        if self.failure is not None:
            raise self.failure

    async def create_run(self, context, request, idempotency_key):
        self._record("create_run", context, request, idempotency_key)
        return copy.deepcopy(run_payload())

    async def get_run(self, context, run_id):
        self._record("get_run", context, run_id)
        return copy.deepcopy(run_payload())

    async def get_graph(self, context, run_id):
        self._record("get_graph", context, run_id)
        return copy.deepcopy(graph_payload())

    async def get_trace(self, context, run_id):
        self._record("get_trace", context, run_id)
        return copy.deepcopy(trace_payload())

    async def approve(self, context, run_id, command, idempotency_key, if_match):
        self._record("approve", context, run_id, command, idempotency_key, if_match)
        return copy.deepcopy(run_payload(status="approved"))

    async def execute(self, context, run_id, command, idempotency_key, if_match):
        self._record("execute", context, run_id, command, idempotency_key, if_match)
        return copy.deepcopy(run_payload(status="verified"))
