"""Pure frozen projection models for the compact cross-domain prototype graph."""

from __future__ import annotations

from nexus_api.prototype.models import PrototypeGraph, PrototypeSignal
from nexus_api.prototype.seed import build_prototype_graph


def _require_nodes(graph: PrototypeGraph, expected: tuple[str, ...]) -> None:
    if graph != build_prototype_graph():
        raise ValueError("prototype graph does not match the frozen scenario")
    present = {node.id for node in graph.nodes}
    if not set(expected) <= present:
        raise ValueError("prototype graph is missing required model evidence")


def supply_risk_signal(graph: PrototypeGraph) -> PrototypeSignal:
    evidence = (
        "PORT-MAA",
        "SHP-0042",
        "SHP-0047",
        "SHP-0051",
        "CMP-SENSOR-A",
        "PO-1107",
        "PO-1112",
    )
    _require_nodes(graph, evidence)
    return PrototypeSignal(
        domain="supply",
        model_version="demo.supply-delay.v1",
        target_id="SHP-0042",
        score=0.91,
        threshold=0.80,
        feature_map={"port_closed": 1.0, "affected_shipments": 3.0, "component_risk": 1.0},
        evidence_node_ids=evidence,
    )


def incident_risk_signal(graph: PrototypeGraph) -> PrototypeSignal:
    evidence = ("DEP-882", "svc-checkout", "svc-payments", "db-ledger")
    _require_nodes(graph, evidence)
    return PrototypeSignal(
        domain="it",
        model_version="demo.incident-risk.v1",
        target_id="svc-checkout",
        score=0.94,
        threshold=0.80,
        feature_map={"deployment_precedes_latency": 1.0, "p95_shift_minutes": 4.0},
        evidence_node_ids=evidence,
    )
