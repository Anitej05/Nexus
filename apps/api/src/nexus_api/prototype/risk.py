"""Pure frozen projection models for the compact cross-domain prototype graph."""

from __future__ import annotations

from nexus_api.prototype.models import PrototypeGraph, PrototypeSignal
from nexus_api.prototype.seed import SCENARIO_ID, build_projection, projection_inputs


def _require_nodes(graph: PrototypeGraph, expected: tuple[str, ...]) -> None:
    if graph != build_projection(graph.scenario_id):
        raise ValueError("prototype graph does not match the frozen scenario")
    present = {node.id for node in graph.nodes}
    if not set(expected) <= present:
        raise ValueError("prototype graph is missing required model evidence")


def supply_risk_signal(graph: PrototypeGraph) -> PrototypeSignal:
    evidence: tuple[str, ...] = (
        "PORT-MAA",
        "SHP-0042",
        "SHP-0047",
        "SHP-0051",
        "CMP-SENSOR-A",
        "PO-1107",
        "PO-1112",
    )
    if graph.scenario_id != SCENARIO_ID:
        affected = {edge.target for edge in graph.edges if edge.source == "PORT-MAA"}
        evidence = tuple(
            node for node in evidence if not node.startswith("SHP-") or node in affected
        )
        evidence += ("input-delay-hours", "input-affected-shipments")
    _require_nodes(graph, evidence)
    delay, shipments, _ = projection_inputs(graph)
    return PrototypeSignal(
        domain="supply",
        model_version="demo.supply-delay.v1",
        target_id="SHP-0042",
        score=min(1.0, round(0.1 + delay * 0.02 + shipments * 0.0833333333, 2)),
        threshold=0.80,
        feature_map={
            "port_closed": 1.0,
            "affected_shipments": shipments,
            "component_risk": 1.0,
            **(
                {"baseline_delay_hours": delay}
                if graph.scenario_id != "storm-and-checkout-shift-v1"
                else {}
            ),
        },
        evidence_node_ids=evidence,
    )


def incident_risk_signal(graph: PrototypeGraph) -> PrototypeSignal:
    evidence: tuple[str, ...] = ("DEP-882", "svc-checkout", "svc-payments", "db-ledger")
    if graph.scenario_id != SCENARIO_ID:
        evidence += ("input-latency-minutes",)
    _require_nodes(graph, evidence)
    _, _, latency = projection_inputs(graph)
    return PrototypeSignal(
        domain="it",
        model_version="demo.incident-risk.v1",
        target_id="svc-checkout",
        score=min(1.0, round(0.3 + latency * 0.16, 2)),
        threshold=0.80,
        feature_map={"deployment_precedes_latency": 1.0, "p95_shift_minutes": latency},
        evidence_node_ids=evidence,
    )
