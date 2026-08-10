"""Pure scoring contracts for the one bounded prototype scenario."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from _contract import require_module
from nexus_contracts.platform import ResourceRef
from nexus_contracts.prototype import PortClosureRiskInput
from nexus_prototype.fixtures import (
    FIXTURE_SEED,
    TENANT_ID,
    build_fixture_events,
    build_fixture_snapshot,
)
from nexus_prototype.scoring import DeterministicPortClosureScorer

FIXED_TIME = datetime(2026, 8, 9, 3, 20, tzinfo=UTC)
FIXED_SIGNAL_ID = UUID("0198a7f0-3f00-7000-8000-000000000001")
EXPECTED_GRAPH = json.loads(
    Path("tests/fixtures/prototype/storm-and-checkout-shift-v1.json").read_text(encoding="utf-8")
)
SUPPLY_EVIDENCE = (
    "PORT-MAA",
    "SHP-0042",
    "SHP-0047",
    "SHP-0051",
    "CMP-SENSOR-A",
    "PO-1107",
    "PO-1112",
)
INCIDENT_EVIDENCE = ("DEP-882", "svc-checkout", "svc-payments", "db-ledger")


def _reviewed_scorer(events, *, tenant_id=TENANT_ID) -> DeterministicPortClosureScorer:
    return DeterministicPortClosureScorer(
        events,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_SIGNAL_ID,
        subject_ref=ResourceRef(
            tenant_id=tenant_id,
            kind="ontology.port",
            id=UUID("019fe476-8380-7000-8000-000000000101"),
            version=1,
        ),
        model_version_ref=ResourceRef(
            tenant_id=tenant_id,
            kind="prototype.model",
            id=UUID("019fe476-8380-7000-8000-000000000201"),
            version=1,
        ),
    )


def _reviewed_input() -> PortClosureRiskInput:
    events = build_fixture_events(seed=FIXTURE_SEED)
    return PortClosureRiskInput(
        event=events[0],
        snapshot=build_fixture_snapshot(TENANT_ID),
        idempotency_key="prototype-review-risk",
    )


def _projection() -> object:
    return require_module("nexus_api.prototype.seed").build_projection(
        "storm-and-checkout-shift-v1"
    )


def test_frozen_supply_and_incident_signals_are_exact_and_explainable() -> None:
    """The demo signals must be deterministic facts, not an advisory-model decision."""
    risk = require_module("nexus_api.prototype.risk")
    projection = _projection()
    supply = risk.supply_risk_signal(projection)
    incident = risk.incident_risk_signal(projection)

    assert (supply.score, supply.threshold, supply.target_id) == (0.91, 0.80, "SHP-0042")
    assert (incident.score, incident.threshold, incident.target_id) == (0.94, 0.80, "svc-checkout")
    assert supply.model_version and incident.model_version
    assert supply.feature_map and incident.feature_map
    assert tuple(supply.evidence_node_ids) == SUPPLY_EVIDENCE
    assert tuple(incident.evidence_node_ids) == INCIDENT_EVIDENCE
    assert projection.scenario_id == EXPECTED_GRAPH["scenario_id"]
    assert projection.seed_digest == EXPECTED_GRAPH["seed_digest"]
    assert len({node.id for node in projection.nodes}) == len(EXPECTED_GRAPH["nodes"])
    assert {(edge.source, edge.type, edge.target) for edge in projection.edges} == {
        (edge["source"], edge["type"], edge["target"]) for edge in EXPECTED_GRAPH["edges"]
    }


def test_frozen_scores_and_seed_digest_do_not_change_with_repeated_evaluation() -> None:
    """Wall clock, random IDs, and LLM availability cannot affect signal provenance."""
    risk = require_module("nexus_api.prototype.risk")
    seed = require_module("nexus_api.prototype.seed")
    first = (risk.supply_risk_signal(_projection()), risk.incident_risk_signal(_projection()))
    second = (risk.supply_risk_signal(_projection()), risk.incident_risk_signal(_projection()))
    assert second == first
    digest = seed.seed_digest(_projection())
    assert isinstance(digest, str) and len(digest) == 64
    assert digest == hashlib.sha256(seed.canonical_seed_bytes(_projection())).hexdigest()


def test_reviewed_scorer_rejects_cross_tenant_evidence_with_typed_reason() -> None:
    """Cross-tenant evidence fails specifically for tenant mismatch, not a generic error."""
    foreign = UUID("018f0000-0000-7000-8000-000000000010")
    with pytest.raises(ValueError, match="tenant"):
        _reviewed_scorer(build_fixture_events(tenant_id=foreign)).score(_reviewed_input())


def test_reviewed_scorer_deduplicates_valid_tenant_delivery_and_order() -> None:
    """A valid duplicate delivery cannot inflate the signal or its evidence set."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    original = _reviewed_scorer(events).score(_reviewed_input())
    replay = _reviewed_scorer((*reversed(events), events[0])).score(_reviewed_input())
    assert replay.score == original.score
    assert replay.evidence_refs == original.evidence_refs


def test_reviewed_scorer_applies_the_exact_late_event_watermark() -> None:
    """Exactly ten minutes is on-time while a later ingestion sets the late feature."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    boundary = tuple(
        event.model_copy(update={"ingested_at": event.occurred_at + timedelta(minutes=10)})
        if event.ingested_at - event.occurred_at > timedelta(minutes=10)
        else event
        for event in events
    )
    on_time = _reviewed_scorer(boundary).score(_reviewed_input())
    late = _reviewed_scorer(events).score(_reviewed_input())
    assert on_time.feature_values["late_event_flag"] == 0.0
    assert late.feature_values["late_event_flag"] == 1.0
    assert late.score > on_time.score


def _contaminated_projections(projection):
    node_type = type(projection.nodes[0])
    edge_type = type(projection.edges[0])
    yield projection.model_copy(update={"scenario_id": "substituted-scenario"})
    yield projection.model_copy(update={"seed_digest": "0" * 64})
    yield projection.model_copy(update={"nodes": projection.nodes[:-1]})
    yield projection.model_copy(update={"nodes": (*projection.nodes, projection.nodes[0])})
    yield projection.model_copy(
        update={
            "nodes": (
                *projection.nodes,
                node_type(
                    id="EXTRA-NODE",
                    type="Service",
                    label="Injected extra node",
                    sensitivity="internal",
                ),
            )
        }
    )
    yield projection.model_copy(update={"edges": projection.edges[:-1]})
    yield projection.model_copy(update={"edges": (*projection.edges, projection.edges[0])})
    yield projection.model_copy(
        update={
            "edges": (
                *projection.edges,
                edge_type(source="PORT-MAA", type="fabricated", target="db-ledger"),
            )
        }
    )


@pytest.mark.parametrize("scorer_name", ["supply_risk_signal", "incident_risk_signal"])
def test_api_risk_functions_reject_every_contaminated_fixed_projection(scorer_name: str) -> None:
    """Both API scorers validate the entire frozen graph, not only their target node."""
    risk = require_module("nexus_api.prototype.risk")
    scorer = getattr(risk, scorer_name)
    for contaminated in _contaminated_projections(_projection()):
        with pytest.raises(ValueError):
            scorer(contaminated)
