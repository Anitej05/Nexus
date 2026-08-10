"""Deterministic read-only graph projection for the single prototype scenario."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Final

from nexus_security.audit import canonical_json_bytes

from nexus_api.prototype.models import (
    PrototypeGraph,
    PrototypeGraphEdge,
    PrototypeGraphNode,
    ScenarioId,
)

SCENARIO_ID: Final[ScenarioId] = "storm-and-checkout-shift-v1"

_NODES = (
    PrototypeGraphNode(id="shift-2026-08-09", type="OperationalShift", label="Operational shift"),
    PrototypeGraphNode(id="PORT-MAA", type="Port", label="Maa port closure"),
    PrototypeGraphNode(id="SHP-0042", type="Shipment", label="Shipment 0042"),
    PrototypeGraphNode(id="SHP-0047", type="Shipment", label="Shipment 0047"),
    PrototypeGraphNode(id="SHP-0051", type="Shipment", label="Shipment 0051"),
    PrototypeGraphNode(id="CMP-SENSOR-A", type="Component", label="Sensor component A"),
    PrototypeGraphNode(id="PO-1107", type="PurchaseOrder", label="Purchase order 1107"),
    PrototypeGraphNode(id="PO-1112", type="PurchaseOrder", label="Purchase order 1112"),
    PrototypeGraphNode(id="DEP-882", type="Deployment", label="Deployment 882"),
    PrototypeGraphNode(id="svc-checkout", type="Service", label="Checkout service"),
    PrototypeGraphNode(id="svc-payments", type="Service", label="Payments service"),
    PrototypeGraphNode(id="db-ledger", type="Database", label="Ledger database"),
)

_EDGES = (
    PrototypeGraphEdge(source="shift-2026-08-09", type="prioritizes", target="PORT-MAA"),
    PrototypeGraphEdge(source="shift-2026-08-09", type="prioritizes", target="DEP-882"),
    PrototypeGraphEdge(source="PORT-MAA", type="affects", target="SHP-0042"),
    PrototypeGraphEdge(source="PORT-MAA", type="affects", target="SHP-0047"),
    PrototypeGraphEdge(source="PORT-MAA", type="affects", target="SHP-0051"),
    PrototypeGraphEdge(source="SHP-0042", type="contains", target="CMP-SENSOR-A"),
    PrototypeGraphEdge(source="CMP-SENSOR-A", type="required_by", target="PO-1107"),
    PrototypeGraphEdge(source="CMP-SENSOR-A", type="required_by", target="PO-1112"),
    PrototypeGraphEdge(source="DEP-882", type="precedes_latency", target="svc-checkout"),
    PrototypeGraphEdge(source="svc-checkout", type="depends_on", target="svc-payments"),
    PrototypeGraphEdge(source="svc-payments", type="depends_on", target="db-ledger"),
)


def build_prototype_graph() -> PrototypeGraph:
    material = {
        "schema_version": "1.0.0",
        "projection_kind": "seeded_read_only_prototype",
        "scenario_id": SCENARIO_ID,
        "nodes": [node.model_dump(mode="json") for node in _NODES],
        "edges": [edge.model_dump(mode="json") for edge in _EDGES],
    }
    return PrototypeGraph(
        scenario_id=SCENARIO_ID,
        seed_digest=hashlib.sha256(canonical_json_bytes(material)).hexdigest(),
        nodes=_NODES,
        edges=_EDGES,
    )


def build_projection(scenario_id: str) -> PrototypeGraph:
    if scenario_id != SCENARIO_ID:
        raise ValueError("unsupported prototype scenario")
    return build_prototype_graph()


def canonical_seed_bytes(value: PrototypeGraph | Mapping[str, Any]) -> bytes:
    material = value.model_dump(mode="json") if isinstance(value, PrototypeGraph) else dict(value)
    material.pop("seed_digest", None)
    return bytes(canonical_json_bytes(material))


def seed_digest(value: PrototypeGraph) -> str:
    return hashlib.sha256(canonical_seed_bytes(value)).hexdigest()
