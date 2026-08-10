"""Content-addressed evidence bundle construction for deterministic risk signals."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from uuid import UUID

from nexus_contracts.platform import EventEnvelope, JsonValue, OntologySnapshotRef, ResourceRef
from nexus_contracts.prototype import EvidenceBundle, EvidenceFact, PortClosureRiskInput, RiskSignal

from nexus_prototype.models import canonical_json_bytes, event_ref, validated_new_id


def build_evidence_bundle(
    input_value: PortClosureRiskInput,
    signal: RiskSignal,
    events: Iterable[EventEnvelope],
    *,
    id_factory: Callable[[], UUID],
) -> EvidenceBundle:
    """Build a hash-stable bundle from exactly the signal's cited event references."""
    if signal.tenant_id != input_value.event.tenant_id:
        raise ValueError("signal tenant does not match input tenant")
    if signal.snapshot != input_value.snapshot:
        raise ValueError("signal snapshot does not match input snapshot")
    expected = set(signal.evidence_refs)
    available: dict[ResourceRef, EventEnvelope] = {}
    for event in events:
        if event.tenant_id != signal.tenant_id:
            raise ValueError("evidence event tenant does not match signal tenant")
        reference = event_ref(signal.tenant_id, event.event_id)
        if reference not in expected:
            continue
        previous = available.setdefault(reference, event)
        if _event_bytes(previous) != _event_bytes(event):
            raise ValueError("duplicate event id has conflicting evidence")
    if set(available) != expected:
        raise ValueError("signal cited evidence is absent from the supplied events")
    ordered = tuple(
        sorted(available.items(), key=lambda item: (item[1].occurred_at, str(item[1].event_id)))
    )
    facts = tuple(
        EvidenceFact(
            ref=reference,
            occurred_at=event.occurred_at,
            predicate=_predicate(event),
            value=dict(_payload(event)),
        )
        for reference, event in ordered
    )
    signal_ref = ResourceRef(
        tenant_id=signal.tenant_id,
        kind="prototype.signal",
        id=signal.signal_id,
        version=1,
    )
    event_refs = tuple(reference for reference, _ in ordered)
    sensitivity = input_value.event.sensitivity
    content = _content_bytes(
        signal_ref=signal_ref,
        snapshot=input_value.snapshot,
        events=event_refs,
        facts=facts,
        sensitivity=sensitivity,
    )
    return EvidenceBundle(
        bundle_id=validated_new_id(id_factory),
        tenant_id=signal.tenant_id,
        signal_ref=signal_ref,
        snapshot=input_value.snapshot,
        events=event_refs,
        facts=facts,
        content_sha256=hashlib.sha256(content).hexdigest(),
        sensitivity=sensitivity,
    )


def _predicate(event: EventEnvelope) -> str:
    value = _payload(event).get("fact")
    if not isinstance(value, str) or not value:
        raise ValueError("evidence event is missing a fact predicate")
    return value


def _content_bytes(
    *,
    signal_ref: ResourceRef,
    snapshot: OntologySnapshotRef,
    events: tuple[ResourceRef, ...],
    facts: tuple[EvidenceFact, ...],
    sensitivity: frozenset[str],
) -> bytes:
    payload = {
        "schema_version": "1.0.0",
        "signal_ref": signal_ref.model_dump(mode="json"),
        "snapshot": snapshot.model_dump(mode="json"),
        "events": [reference.model_dump(mode="json") for reference in events],
        "facts": [fact.model_dump(mode="json") for fact in facts],
        "sensitivity": sorted(sensitivity),
    }
    return canonical_json_bytes(payload)


def _event_bytes(event: EventEnvelope) -> bytes:
    return canonical_json_bytes(event.model_dump(mode="json"))


def _payload(event: EventEnvelope) -> Mapping[str, JsonValue]:
    if not isinstance(event.payload, dict):
        raise ValueError("event payload must be an object")
    return event.payload
