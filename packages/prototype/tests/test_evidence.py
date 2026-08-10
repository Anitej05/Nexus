"""Tests for evidence bundles built from the deterministic signal inputs."""

# ruff: noqa: S101

from datetime import UTC, datetime
from uuid import UUID

import pytest
from nexus_contracts.platform import EventEnvelope, ResourceRef
from nexus_contracts.prototype import PortClosureRiskInput
from nexus_prototype.evidence import build_evidence_bundle
from nexus_prototype.fixtures import (
    FIXTURE_SEED,
    TENANT_ID,
    build_fixture_events,
    build_fixture_snapshot,
)
from nexus_prototype.scoring import DeterministicPortClosureScorer

FIXED_TIME = datetime(2026, 8, 9, 3, 20, tzinfo=UTC)
FIXED_SIGNAL_ID = UUID("0198a7f0-3f00-7000-8000-000000000001")
FIXED_BUNDLE_ID = UUID("0198a7f0-3f00-7000-8000-000000000002")
OTHER_BUNDLE_ID = UUID("0198a7f0-3f00-7000-8000-000000000003")
PORT_SUBJECT_ID = UUID("019fe476-8380-7000-8000-000000000101")
MODEL_VERSION_ID = UUID("019fe476-8380-7000-8000-000000000201")


def _ref(kind: str, identifier: UUID) -> ResourceRef:
    return ResourceRef(tenant_id=TENANT_ID, kind=kind, id=identifier, version=1)


def _scorer(events: tuple[EventEnvelope, ...]) -> DeterministicPortClosureScorer:
    return DeterministicPortClosureScorer(
        events,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_SIGNAL_ID,
        subject_ref=_ref("ontology.port", PORT_SUBJECT_ID),
        model_version_ref=_ref("prototype.model", MODEL_VERSION_ID),
    )


def test_evidence_bundle_keeps_only_the_six_unique_scoring_facts() -> None:
    """The duplicate and unrelated events must not become fabricated causal evidence."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    input_value = PortClosureRiskInput(
        event=events[0],
        snapshot=build_fixture_snapshot(TENANT_ID),
        idempotency_key="bundle-port-maa-1",
    )
    signal = _scorer(events).score(input_value)
    bundle = build_evidence_bundle(input_value, signal, events, id_factory=lambda: FIXED_BUNDLE_ID)

    assert tuple(fact.predicate for fact in bundle.facts) == (
        "port_status",
        "shipment",
        "shipment",
        "shipment",
        "component_shortage",
        "inventory",
    )
    assert bundle.events == signal.evidence_refs
    assert bundle.content_sha256 == (
        "8b4b5a4f929aee5a4c9b1be93504d5108cd70bcc15ac2134bfa4a87e775739ac"
    )


def test_evidence_bundle_hash_is_stable_when_the_input_delivery_order_changes() -> None:
    """Bundle provenance must address facts, rather than consumer delivery order."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    input_value = PortClosureRiskInput(
        event=events[0],
        snapshot=build_fixture_snapshot(TENANT_ID),
        idempotency_key="bundle-port-maa-2",
    )
    signal = _scorer(events).score(input_value)

    first = build_evidence_bundle(input_value, signal, events, id_factory=lambda: FIXED_BUNDLE_ID)
    second = build_evidence_bundle(
        input_value,
        signal,
        tuple(reversed(events)),
        id_factory=lambda: FIXED_BUNDLE_ID,
    )

    assert second.content_sha256 == first.content_sha256
    assert second.facts == first.facts


def test_evidence_bundle_rejects_snapshot_substitution() -> None:
    """A bundle cannot claim one snapshot while hashing the signal's original snapshot."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    input_value = PortClosureRiskInput(
        event=events[0],
        snapshot=build_fixture_snapshot(TENANT_ID),
        idempotency_key="bundle-port-maa-snapshot",
    )
    signal = _scorer(events).score(input_value)
    substituted = input_value.model_copy(
        update={"snapshot": input_value.snapshot.model_copy(update={"content_hash": "b" * 64})}
    )

    with pytest.raises(ValueError, match="snapshot"):
        build_evidence_bundle(substituted, signal, events, id_factory=lambda: FIXED_BUNDLE_ID)


def test_evidence_hash_binds_the_bundle_sensitivity() -> None:
    """Changing access classification must change the content address and bundle identity."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    input_value = PortClosureRiskInput(
        event=events[0],
        snapshot=build_fixture_snapshot(TENANT_ID),
        idempotency_key="bundle-port-maa-sensitivity",
    )
    signal = _scorer(events).score(input_value)
    restricted_input = input_value.model_copy(
        update={"event": input_value.event.model_copy(update={"sensitivity": {"restricted"}})}
    )

    internal = build_evidence_bundle(
        input_value, signal, events, id_factory=lambda: FIXED_BUNDLE_ID
    )
    restricted = build_evidence_bundle(
        restricted_input, signal, events, id_factory=lambda: OTHER_BUNDLE_ID
    )

    assert restricted.content_sha256 != internal.content_sha256
    assert restricted.bundle_id != internal.bundle_id


def test_bundle_builder_requires_an_explicit_uuid_factory() -> None:
    """Bundle identity generation must be injected for deterministic replay."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    input_value = PortClosureRiskInput(
        event=events[0],
        snapshot=build_fixture_snapshot(TENANT_ID),
        idempotency_key="bundle-port-maa-id-factory",
    )
    signal = _scorer(events).score(input_value)

    with pytest.raises(TypeError):
        build_evidence_bundle(input_value, signal, events)  # type: ignore[call-arg]
