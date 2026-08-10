"""Behavioral contract checks for the bounded prototype signal slice."""

import json
import math
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from nexus_contracts.platform import EventEnvelope, OntologySnapshotRef, ResourceRef
from nexus_contracts.prototype import (
    ApprovalCommand,
    EvidenceBundle,
    EvidenceFact,
    PortClosureRiskInput,
    Recommendation,
    RiskSignal,
    SpecialistFinding,
)
from pydantic import ValidationError

TENANT_ID = UUID("018f0000-0000-7000-8000-000000000001")
OTHER_TENANT_ID = UUID("018f0000-0000-7000-8000-000000000010")
EVENT_ID = UUID("018f0000-0000-7000-8000-000000000002")
SOURCE_ID = UUID("018f0000-0000-7000-8000-000000000003")
SNAPSHOT_ID = UUID("018f0000-0000-7000-8000-000000000004")
MODEL_ID = UUID("018f0000-0000-7000-8000-000000000005")
SIGNAL_ID = UUID("018f0000-0000-7000-8000-000000000006")


def _ref(tenant_id: UUID, identifier: UUID, kind: str) -> ResourceRef:
    return ResourceRef(tenant_id=tenant_id, kind=kind, id=identifier, version=1)


def _event() -> EventEnvelope:
    return EventEnvelope(
        event_id=EVENT_ID,
        event_type="prototype.port.closed",
        tenant_id=TENANT_ID,
        source=_ref(TENANT_ID, SOURCE_ID, "connector.synthetic"),
        subject="PORT-MAA",
        occurred_at=datetime(2026, 8, 9, 3, tzinfo=UTC),
        ingested_at=datetime(2026, 8, 9, 3, tzinfo=UTC),
        correlation_id=SOURCE_ID,
        sensitivity=frozenset({"internal"}),
        payload={"fact": "port_status", "port_id": "PORT-MAA", "value": "closed"},
    )


def _snapshot(tenant_id: UUID) -> OntologySnapshotRef:
    return OntologySnapshotRef(
        snapshot_id=SNAPSHOT_ID,
        tenant_id=tenant_id,
        schema_version_id=SOURCE_ID,
        transaction_time=datetime(2026, 8, 9, 3, tzinfo=UTC),
        valid_time=datetime(2026, 8, 9, 3, tzinfo=UTC),
        event_watermark=12,
        content_hash="a" * 64,
    )


def test_port_closure_input_rejects_a_snapshot_from_another_tenant() -> None:
    """A tenant mismatch must not let one event query another tenant snapshot."""
    with pytest.raises(ValidationError):
        PortClosureRiskInput(
            event=_event(),
            snapshot=_snapshot(OTHER_TENANT_ID),
            idempotency_key="prototype-signal-1",
        )


def test_risk_signal_rejects_cross_tenant_evidence() -> None:
    """A signal cannot claim evidence from another tenant."""
    with pytest.raises(ValidationError):
        RiskSignal(
            signal_id=SIGNAL_ID,
            tenant_id=TENANT_ID,
            subject=_ref(TENANT_ID, SOURCE_ID, "ontology.port"),
            signal_type="supply.port_closure_risk",
            severity="high",
            score=1.0,
            rule_version="port-closure-risk.v1",
            feature_values={"port_closed": 1.0},
            evidence_refs=(_ref(OTHER_TENANT_ID, EVENT_ID, "prototype.event"),),
            snapshot=_snapshot(TENANT_ID),
            model_version=_ref(TENANT_ID, MODEL_ID, "prototype.model"),
            created_at=datetime(2026, 8, 9, 3, tzinfo=UTC),
        )


def test_prototype_contracts_are_frozen_and_forbid_unknown_fields() -> None:
    """Wire values must not accept ambiguous fields or allow mutation after validation."""
    fact = EvidenceFact(
        ref=_ref(TENANT_ID, EVENT_ID, "prototype.event"),
        occurred_at=datetime(2026, 8, 9, 3, tzinfo=UTC),
        predicate="port_status",
        value="closed",
    )
    with pytest.raises(ValidationError):
        EvidenceFact.model_validate({**fact.model_dump(), "untrusted": True})
    with pytest.raises(ValidationError):
        fact.predicate = "override_policy"


@pytest.mark.parametrize(
    "unsafe_value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        -0.0,
        9_007_199_254_740_992,
        {"nested": [1.0, float("nan")]},
        {"e\u0301": 1, "\u00e9": 2},
    ],
)
def test_evidence_fact_rejects_recursive_non_ijson_values(unsafe_value: object) -> None:
    """Public evidence cannot carry numbers that canonical I-JSON cannot represent."""
    with pytest.raises(ValidationError):
        EvidenceFact(
            ref=_ref(TENANT_ID, EVENT_ID, "prototype.event"),
            occurred_at=datetime(2026, 8, 9, 3, tzinfo=UTC),
            predicate="unsafe",
            value=unsafe_value,  # type: ignore[arg-type]
        )


def test_public_prototype_contracts_are_in_the_canonical_schema_bundle() -> None:
    """Exporting a model without freezing its public schema must fail this contract gate."""
    schema_path = Path(__file__).parents[1] / "generated" / "platform-1.0.0.json"
    document = json.loads(schema_path.read_text(encoding="utf-8"))
    expected = {
        model.__name__
        for model in (
            ApprovalCommand,
            EvidenceBundle,
            EvidenceFact,
            PortClosureRiskInput,
            Recommendation,
            RiskSignal,
            SpecialistFinding,
        )
    }

    assert expected <= set(document["models"])


def test_risk_signal_rejects_nonfinite_features_recursively() -> None:
    """All feature values must remain finite at the public wire boundary."""
    with pytest.raises(ValidationError):
        RiskSignal(
            signal_id=SIGNAL_ID,
            tenant_id=TENANT_ID,
            subject=_ref(TENANT_ID, SOURCE_ID, "ontology.port"),
            signal_type="supply.port_closure_risk",
            severity="high",
            score=math.nan,
            rule_version="port-closure-risk.v1",
            feature_values={"port_closed": math.nan},
            evidence_refs=(_ref(TENANT_ID, EVENT_ID, "prototype.event"),),
            snapshot=_snapshot(TENANT_ID),
            model_version=_ref(TENANT_ID, MODEL_ID, "prototype.model"),
            created_at=datetime(2026, 8, 9, 3, tzinfo=UTC),
        )
