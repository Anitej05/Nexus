"""Inspectable deterministic baseline for a port-closure risk signal."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta
from uuid import UUID

from nexus_contracts.platform import EventEnvelope, JsonValue, ResourceRef
from nexus_contracts.prototype import PortClosureRiskInput, RiskSignal

from nexus_prototype.models import canonical_json_bytes, event_ref, validated_new_id

RULE_VERSION = "port-closure-risk.v1"
_MODEL_RESOURCE_VERSION = 1
_WATERMARK = timedelta(minutes=10)


class RiskSignalNotRaised(ValueError):
    """The deterministic features did not reach the high-risk threshold."""


class DeterministicPortClosureScorer:
    """Score a port closure with duplicate-safe, snapshot-bound fixture evidence."""

    def __init__(
        self,
        events: Iterable[EventEnvelope],
        *,
        clock: Callable[[], datetime],
        id_factory: Callable[[], UUID],
        subject_ref: ResourceRef,
        model_version_ref: ResourceRef,
    ) -> None:
        self._events = tuple(events)
        self._clock = clock
        self._id_factory = id_factory
        self._subject_ref = subject_ref
        self._model_version_ref = model_version_ref

    def score(self, input_value: PortClosureRiskInput) -> RiskSignal:
        """Emit a high risk only when the fixed, explainable threshold is reached."""
        tenant_id = input_value.event.tenant_id
        events = self._unique_ordered_events(tenant_id)
        matching = {event.event_id: event for event in events}.get(input_value.event.event_id)
        if matching is None:
            raise ValueError("input event is absent from the evidence collection")
        if _event_bytes(matching) != _event_bytes(input_value.event):
            raise ValueError("input event conflicts with the evidence collection")
        port_event = matching
        self._validate_provenance(input_value, port_event)
        if not _is_closed_port(port_event):
            raise RiskSignalNotRaised("input event is not a closed port observation")
        port_id = _port_id(port_event)
        shipments_by_id: dict[str, EventEnvelope] = {}
        for event in events:
            payload = _payload(event)
            shipment_id = payload.get("shipment_id")
            if (
                payload.get("fact") == "shipment"
                and payload.get("port_id") == port_id
                and isinstance(shipment_id, str)
                and shipment_id
            ):
                shipments_by_id.setdefault(shipment_id, event)
        shipments = tuple(shipments_by_id.values())
        component_events = tuple(
            event
            for event in events
            if _payload(event).get("fact") == "component_shortage"
            and _payload(event).get("component_id") == "CMP-SENSOR-A"
        )
        late_events = tuple(
            event for event in events if event.ingested_at - event.occurred_at > _WATERMARK
        )
        feature_values = {
            "port_closed": 1.0,
            "affected_shipment_count": float(len(shipments)),
            "component_shortage": float(bool(component_events)),
            "late_event_flag": float(bool(late_events)),
        }
        score = min(
            1.0,
            0.55 * feature_values["port_closed"]
            + 0.25 * min(feature_values["affected_shipment_count"], 3.0) / 3.0
            + 0.15 * feature_values["component_shortage"]
            + 0.05 * feature_values["late_event_flag"],
        )
        if score < 0.70:
            raise RiskSignalNotRaised("port closure features did not reach the high-risk threshold")
        evidence = _ordered_unique((port_event, *shipments, *component_events, *late_events))
        created_at = self._clock()
        return RiskSignal(
            signal_id=validated_new_id(self._id_factory),
            tenant_id=tenant_id,
            subject=self._subject_ref,
            signal_type="supply.port_closure_risk",
            severity="high",
            score=score,
            rule_version=RULE_VERSION,
            feature_values=feature_values,
            evidence_refs=tuple(event_ref(tenant_id, event.event_id) for event in evidence),
            snapshot=input_value.snapshot,
            model_version=self._model_version_ref,
            created_at=created_at,
        )

    def _validate_provenance(
        self, input_value: PortClosureRiskInput, port_event: EventEnvelope
    ) -> None:
        tenant_id = input_value.event.tenant_id
        if self._subject_ref.tenant_id != tenant_id:
            raise ValueError("subject tenant does not match the input tenant")
        if self._subject_ref.kind != "ontology.port":
            raise ValueError("subject kind must be ontology.port")
        if self._subject_ref.version is None:
            raise ValueError("subject version must be immutable")
        if self._subject_ref.id == port_event.event_id:
            raise ValueError("subject identity cannot reuse the closure event id")
        if self._model_version_ref.tenant_id != tenant_id:
            raise ValueError("model tenant does not match the input tenant")
        if self._model_version_ref.kind != "prototype.model":
            raise ValueError("model kind must be prototype.model")
        if self._model_version_ref.version != _MODEL_RESOURCE_VERSION:
            raise ValueError("model version must match port-closure-risk.v1")
        if self._model_version_ref.id == input_value.snapshot.schema_version_id:
            raise ValueError("model identity cannot reuse the ontology schema version id")

    def _unique_ordered_events(self, tenant_id: UUID) -> tuple[EventEnvelope, ...]:
        deduplicated: dict[UUID, EventEnvelope] = {}
        for event in self._events:
            if event.tenant_id != tenant_id:
                raise ValueError("evidence event tenant does not match the input tenant")
            previous = deduplicated.setdefault(event.event_id, event)
            if _event_bytes(previous) != _event_bytes(event):
                raise ValueError("duplicate event id has conflicting evidence")
        return tuple(sorted(deduplicated.values(), key=_event_order_key))


def _is_closed_port(event: EventEnvelope) -> bool:
    payload = _payload(event)
    return (
        payload.get("fact") == "port_status"
        and payload.get("port_id") == "PORT-MAA"
        and payload.get("value") == "closed"
    )


def _port_id(event: EventEnvelope) -> str:
    value = _payload(event).get("port_id")
    if not isinstance(value, str):
        raise RiskSignalNotRaised("input event is missing a port identifier")
    return value


def _payload(event: EventEnvelope) -> Mapping[str, JsonValue]:
    if not isinstance(event.payload, dict):
        raise ValueError("event payload must be an object")
    return event.payload


def _event_bytes(event: EventEnvelope) -> bytes:
    return canonical_json_bytes(event.model_dump(mode="json"))


def _ordered_unique(events: Iterable[EventEnvelope]) -> tuple[EventEnvelope, ...]:
    values = {event.event_id: event for event in events}
    return tuple(sorted(values.values(), key=_event_order_key))


def _event_order_key(event: EventEnvelope) -> tuple[datetime, str]:
    return event.occurred_at, str(event.event_id)
