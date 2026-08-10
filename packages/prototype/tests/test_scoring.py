"""Tests for the deterministic port-closure risk baseline."""

# ruff: noqa: S101

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from nexus_contracts.platform import EventEnvelope, JsonValue, ResourceRef
from nexus_contracts.prototype import PortClosureRiskInput
from nexus_prototype import models as prototype_models
from nexus_prototype.fixtures import (
    FIXTURE_SEED,
    TENANT_ID,
    build_fixture_events,
    build_fixture_snapshot,
)
from nexus_prototype.scoring import DeterministicPortClosureScorer, RiskSignalNotRaised

FIXED_TIME = datetime(2026, 8, 9, 3, 20, tzinfo=UTC)
FIXED_SIGNAL_ID = UUID("0198a7f0-3f00-7000-8000-000000000001")
PORT_SUBJECT_ID = UUID("019fe476-8380-7000-8000-000000000101")
MODEL_VERSION_ID = UUID("019fe476-8380-7000-8000-000000000201")


def _input() -> PortClosureRiskInput:
    events = build_fixture_events(seed=FIXTURE_SEED)
    return PortClosureRiskInput(
        event=events[0],
        snapshot=build_fixture_snapshot(TENANT_ID),
        idempotency_key="score-port-maa-1",
    )


def _scorer(events: tuple[EventEnvelope, ...]) -> DeterministicPortClosureScorer:
    return DeterministicPortClosureScorer(
        events,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_SIGNAL_ID,
        subject_ref=_subject_ref(),
        model_version_ref=_model_version_ref(),
    )


def _payload(event: EventEnvelope) -> dict[str, JsonValue]:
    assert isinstance(event.payload, dict)
    return event.payload


def _subject_ref(
    *,
    tenant_id: UUID = TENANT_ID,
    kind: str = "ontology.port",
    identifier: UUID = PORT_SUBJECT_ID,
    version: int | None = 1,
) -> ResourceRef:
    return ResourceRef(
        tenant_id=tenant_id,
        kind=kind,
        id=identifier,
        version=version,
    )


def _model_version_ref(
    *,
    tenant_id: UUID = TENANT_ID,
    kind: str = "prototype.model",
    identifier: UUID = MODEL_VERSION_ID,
    version: int | None = 1,
) -> ResourceRef:
    return ResourceRef(
        tenant_id=tenant_id,
        kind=kind,
        id=identifier,
        version=version,
    )


def test_port_closure_fixture_emits_the_hand_checked_high_risk_signal() -> None:
    """Removing any scored condition must make the expected 1.0-risk signal fail."""
    signal = _scorer(build_fixture_events(seed=FIXTURE_SEED)).score(_input())

    assert signal.score == 1.0
    assert signal.severity == "high"
    assert signal.feature_values == {
        "affected_shipment_count": 3.0,
        "component_shortage": 1.0,
        "late_event_flag": 1.0,
        "port_closed": 1.0,
    }
    assert len(signal.evidence_refs) == 6


def test_signal_subject_is_the_stable_port_resource_not_the_closure_event() -> None:
    """The closure observation remains evidence and cannot become the ontology port identity."""
    signal = _scorer(build_fixture_events(seed=FIXTURE_SEED)).score(_input())

    assert signal.subject == _subject_ref()
    assert signal.subject.id != _input().event.event_id


def test_signal_model_version_is_distinct_from_the_snapshot_schema_version() -> None:
    """Scoring-model provenance must remain independent of ontology schema provenance."""
    signal = _scorer(build_fixture_events(seed=FIXTURE_SEED)).score(_input())

    assert signal.model_version == _model_version_ref()
    assert signal.model_version.id != _input().snapshot.schema_version_id


@pytest.mark.parametrize(
    ("subject_ref", "model_version_ref", "message"),
    [
        (
            _subject_ref(tenant_id=UUID("018f0000-0000-7000-8000-000000000010")),
            _model_version_ref(),
            "subject tenant",
        ),
        (_subject_ref(version=None), _model_version_ref(), "subject version"),
        (_subject_ref(kind="prototype.event"), _model_version_ref(), "subject kind"),
        (
            _subject_ref(identifier=build_fixture_events(seed=FIXTURE_SEED)[0].event_id),
            _model_version_ref(),
            "subject identity",
        ),
        (
            _subject_ref(),
            _model_version_ref(tenant_id=UUID("018f0000-0000-7000-8000-000000000010")),
            "model tenant",
        ),
        (_subject_ref(), _model_version_ref(version=None), "model version"),
        (_subject_ref(), _model_version_ref(version=2), "model version"),
        (_subject_ref(), _model_version_ref(kind="ontology.schema"), "model kind"),
        (
            _subject_ref(),
            _model_version_ref(identifier=build_fixture_snapshot(TENANT_ID).schema_version_id),
            "model identity",
        ),
    ],
)
def test_scorer_rejects_invalid_subject_and_model_provenance(
    subject_ref: ResourceRef,
    model_version_ref: ResourceRef,
    message: str,
) -> None:
    """Both injected identities require the expected tenant, kind, and immutable version."""
    scorer = DeterministicPortClosureScorer(
        build_fixture_events(seed=FIXTURE_SEED),
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_SIGNAL_ID,
        subject_ref=subject_ref,
        model_version_ref=model_version_ref,
    )

    with pytest.raises(ValueError, match=message):
        scorer.score(_input())


def test_duplicate_delivery_and_input_order_do_not_change_the_risk_signal() -> None:
    """A duplicate event or consumer ordering must not inflate the deterministic score."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    input_value = _input()
    first = _scorer(events).score(input_value)
    second = _scorer(tuple(reversed(events))).score(input_value)

    assert second.score == first.score == 1.0
    assert second.evidence_refs == first.evidence_refs


def test_scorer_rejects_evidence_from_a_different_tenant() -> None:
    """A tenant-mixed evidence collection must fail before it can be scored."""
    foreign_tenant = UUID("018f0000-0000-7000-8000-000000000010")
    with pytest.raises(ValueError, match="tenant"):
        _scorer(build_fixture_events(tenant_id=foreign_tenant)).score(_input())


def test_scorer_rejects_an_input_event_missing_from_the_evidence_collection() -> None:
    """The trigger event must be one of the exact snapshot-bound evidence records."""
    input_value = _input()
    events = tuple(
        event
        for event in build_fixture_events(seed=FIXTURE_SEED)
        if event.event_id != input_value.event.event_id
    )

    with pytest.raises(ValueError, match="input event"):
        _scorer(events).score(input_value)


def test_scorer_rejects_a_conflicting_copy_of_the_input_event() -> None:
    """A closed trigger cannot be scored when evidence with the same ID says open."""
    input_value = _input()
    open_event = input_value.event.model_copy(
        update={"payload": {**_payload(input_value.event), "value": "open"}}
    )
    events = tuple(
        open_event if event.event_id == input_value.event.event_id else event
        for event in build_fixture_events(seed=FIXTURE_SEED)
    )

    with pytest.raises(ValueError, match="input event"):
        _scorer(events).score(input_value)


def test_scorer_requires_closed_port_semantics_for_the_bound_input() -> None:
    """An exact evidence-bound input still cannot trigger unless its status is closed."""
    input_value = _input()
    open_event = input_value.event.model_copy(
        update={"payload": {**_payload(input_value.event), "value": "open"}}
    )
    open_input = input_value.model_copy(update={"event": open_event})
    events = tuple(
        open_event if event.event_id == open_event.event_id else event
        for event in build_fixture_events(seed=FIXTURE_SEED)
    )

    with pytest.raises(RiskSignalNotRaised, match="closed port"):
        _scorer(events).score(open_input)


def test_distinct_shipment_ids_are_counted_instead_of_event_rows() -> None:
    """Three observations for one shipment contribute one affected shipment."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    shipment_events = [event for event in events if _payload(event).get("fact") == "shipment"]
    repeated_id = "SHP-0042"
    replacements = {
        event.event_id: event.model_copy(
            update={"payload": {**_payload(event), "shipment_id": repeated_id}}
        )
        for event in shipment_events
        if _payload(event).get("port_id") == "PORT-MAA"
    }
    logical_duplicates = tuple(replacements.get(event.event_id, event) for event in events)

    signal = _scorer(logical_duplicates).score(_input())

    assert signal.feature_values["affected_shipment_count"] == 1.0
    assert len(signal.evidence_refs) == 4


def test_exactly_ten_minutes_late_does_not_cross_the_watermark() -> None:
    """Only events later than the fixed ten-minute watermark set the late flag."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    boundary_events = tuple(
        event.model_copy(update={"ingested_at": event.occurred_at + timedelta(minutes=10)})
        if event.ingested_at - event.occurred_at > timedelta(minutes=10)
        else event
        for event in events
    )

    signal = _scorer(boundary_events).score(_input())

    assert signal.feature_values["late_event_flag"] == 0.0
    assert signal.score == pytest.approx(0.95)


def test_exact_threshold_is_emitted_and_a_lower_score_is_not() -> None:
    """A score of 0.70 is inclusive while a port-only score of 0.55 is suppressed."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    port = _input().event
    component = next(
        event for event in events if _payload(event).get("fact") == "component_shortage"
    )

    threshold = _scorer((port, component)).score(_input())
    assert threshold.score == pytest.approx(0.70)
    with pytest.raises(RiskSignalNotRaised):
        _scorer((port,)).score(_input())


def test_scorer_requires_explicit_clock_and_uuid_factory() -> None:
    """A deterministic scorer cannot silently consult wall-clock or random identifier state."""
    with pytest.raises(TypeError):
        DeterministicPortClosureScorer(  # type: ignore[call-arg]
            build_fixture_events(seed=FIXTURE_SEED)
        )


def test_complete_signal_is_identical_with_frozen_dependencies() -> None:
    """Every RiskSignal field must replay byte-for-byte with fixed clock and UUID inputs."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    first = DeterministicPortClosureScorer(
        events,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_SIGNAL_ID,
        subject_ref=_subject_ref(),
        model_version_ref=_model_version_ref(),
    ).score(_input())
    second = DeterministicPortClosureScorer(
        tuple(reversed(events)),
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_SIGNAL_ID,
        subject_ref=_subject_ref(),
        model_version_ref=_model_version_ref(),
    ).score(_input())

    assert second == first
    assert second.model_dump_json() == first.model_dump_json()


def test_uuid_factory_rejects_a_non_uuid7_result() -> None:
    """Injected identifiers must pass the same UUIDv7 validator as public contracts."""
    with pytest.raises(ValueError, match="UUID version 7"):
        prototype_models.validated_new_id(lambda: uuid4())


def test_repository_uuid_factory_produces_a_valid_uuid7() -> None:
    """The default production boundary delegates to the repository UUIDv7 generator."""
    assert prototype_models.validated_new_id().version == 7
