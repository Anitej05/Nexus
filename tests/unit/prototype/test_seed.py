"""Acceptance fixture tests that stay green before the prototype implementation exists."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

FIXTURE = Path("tests/fixtures/prototype/storm-and-checkout-shift-v1.json")
EXPECTED_NODE_IDS = frozenset(
    {
        "shift-2026-08-09",
        "PORT-MAA",
        "SHP-0042",
        "SHP-0047",
        "SHP-0051",
        "CMP-SENSOR-A",
        "PO-1107",
        "PO-1112",
        "DEP-882",
        "svc-checkout",
        "svc-payments",
        "db-ledger",
    }
)


def _fixture() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_cross_domain_seed_fixture_is_complete_and_byte_stable() -> None:
    """The checked-in fixture is the exact disposable read-only graph projection."""
    payload = _fixture()
    nodes = payload["nodes"]
    assert isinstance(nodes, list)
    assert {node["id"] for node in nodes} == EXPECTED_NODE_IDS
    assert payload["scenario_id"] == "storm-and-checkout-shift-v1"
    assert payload["schema_version"] == "1.0.0"
    assert (
        payload["seed_digest"] == "ab6630b92c813392964fad431fe7aba5e2b68f0742e800523d6ceec3196f0e06"
    )
    digest_material = {key: value for key, value in payload.items() if key != "seed_digest"}
    canonical = json.dumps(
        digest_material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert hashlib.sha256(canonical).hexdigest() == payload["seed_digest"]


def test_cross_domain_seed_fixture_has_only_internal_nodes_and_closed_edges() -> None:
    """A seed edge cannot cite a missing node or accidentally carry a public sensitivity."""
    payload = _fixture()
    nodes = payload["nodes"]
    edges = payload["edges"]
    assert isinstance(nodes, list)
    assert isinstance(edges, list)
    ids = {node["id"] for node in nodes}
    assert all(node["sensitivity"] == "internal" for node in nodes)
    assert all(edge["source"] in ids and edge["target"] in ids for edge in edges)
    assert {"source": "svc-payments", "type": "depends_on", "target": "db-ledger"} in edges
