import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from nexus_contracts.actions import ActionRequest
from nexus_contracts.agents import (
    ArtifactEnvelope,
    ArtifactProvenance,
    AutonomyClass,
    CapabilityScope,
    DelegatedTask,
    ExecutionBudget,
)
from nexus_contracts.platform import (
    EntityDecisionReceipt,
    EventEnvelope,
    OntologyObservation,
    OntologySnapshotRef,
    RequestContext,
    ResourceRef,
)
from pydantic import ValidationError

TENANT_ID = UUID("018f0000-0000-7000-8000-000000000001")
ACTOR_ID = UUID("018f0000-0000-7000-8000-000000000002")
CORRELATION_ID = UUID("018f0000-0000-7000-8000-000000000003")
OTHER_TENANT_ID = UUID("018f0000-0000-7000-8000-000000000010")


def resource_ref() -> ResourceRef:
    return ResourceRef(tenant_id=TENANT_ID, kind="ontology.object", id=ACTOR_ID)


def other_tenant_ref() -> ResourceRef:
    return ResourceRef(tenant_id=OTHER_TENANT_ID, kind="ontology.object", id=ACTOR_ID)


def snapshot_ref() -> OntologySnapshotRef:
    return OntologySnapshotRef(
        snapshot_id=ACTOR_ID,
        tenant_id=TENANT_ID,
        schema_version_id=CORRELATION_ID,
        transaction_time=datetime(2026, 8, 9, tzinfo=UTC),
        valid_time=datetime(2026, 8, 9, tzinfo=UTC),
        event_watermark=0,
        content_hash="a" * 64,
    )


def test_contract_models_are_immutable_and_forbid_extra_fields() -> None:
    context = RequestContext(
        tenant_id=TENANT_ID,
        actor_id=ACTOR_ID,
        correlation_id=CORRELATION_ID,
        roles=frozenset({"viewer"}),
        scopes=frozenset({"ontology.read"}),
        sensitivity_clearances=frozenset({"internal"}),
    )

    with pytest.raises(ValidationError):
        RequestContext.model_validate({**context.model_dump(), "unknown": True})
    with pytest.raises(ValidationError):
        context.actor_id = TENANT_ID


def test_time_bearing_contracts_reject_naive_datetimes() -> None:
    with pytest.raises(ValidationError):
        OntologySnapshotRef(
            snapshot_id=ACTOR_ID,
            tenant_id=TENANT_ID,
            schema_version_id=CORRELATION_ID,
            transaction_time=datetime(2026, 8, 9),
            valid_time=datetime(2026, 8, 9),
            event_watermark=0,
            content_hash="a" * 64,
        )


def test_contracts_reject_non_utc_datetimes_and_non_v7_identifiers() -> None:
    with pytest.raises(ValidationError):
        RequestContext(
            tenant_id=uuid4(),
            actor_id=ACTOR_ID,
            correlation_id=CORRELATION_ID,
            roles=frozenset({"viewer"}),
            scopes=frozenset({"ontology.read"}),
            sensitivity_clearances=frozenset({"internal"}),
        )
    with pytest.raises(ValidationError):
        OntologySnapshotRef(
            snapshot_id=ACTOR_ID,
            tenant_id=TENANT_ID,
            schema_version_id=CORRELATION_ID,
            transaction_time=datetime(2026, 8, 9, tzinfo=timezone(timedelta(hours=5, minutes=30))),
            valid_time=datetime(2026, 8, 9, tzinfo=UTC),
            event_watermark=0,
            content_hash="a" * 64,
        )


def test_utc_timestamps_serialize_with_a_canonical_z_suffix() -> None:
    serialized = snapshot_ref().model_dump_json()

    assert '"transaction_time":"2026-08-09T00:00:00Z"' in serialized
    assert '"valid_time":"2026-08-09T00:00:00Z"' in serialized


def test_event_and_action_contracts_carry_canonical_wire_fields() -> None:
    event = EventEnvelope(
        event_id=ACTOR_ID,
        event_type="ontology.observed",
        tenant_id=TENANT_ID,
        source=resource_ref(),
        subject="018f0000-0000-7000-8000-000000000002",
        occurred_at=datetime(2026, 8, 9, tzinfo=UTC),
        ingested_at=datetime(2026, 8, 9, tzinfo=UTC),
        correlation_id=CORRELATION_ID,
        sensitivity=frozenset({"internal"}),
        payload={"value": "ok"},
    )
    assert event.schema_version == "1.0.0"

    assert "requested_risk_class" not in ActionRequest.model_fields
    assert "risk_class" not in ActionRequest.model_fields


def test_event_envelope_rejects_a_cross_tenant_source() -> None:
    with pytest.raises(ValidationError):
        EventEnvelope(
            event_id=ACTOR_ID,
            event_type="ontology.observed",
            tenant_id=TENANT_ID,
            source=other_tenant_ref(),
            subject="018f0000-0000-7000-8000-000000000002",
            occurred_at=datetime(2026, 8, 9, tzinfo=UTC),
            ingested_at=datetime(2026, 8, 9, tzinfo=UTC),
            correlation_id=CORRELATION_ID,
            sensitivity=frozenset({"internal"}),
            payload={"value": "ok"},
        )


def test_ontology_observation_and_receipt_reject_cross_tenant_references() -> None:
    with pytest.raises(ValidationError):
        OntologyObservation(
            observation_id=ACTOR_ID,
            tenant_id=TENANT_ID,
            subject=resource_ref(),
            source_record=other_tenant_ref(),
            properties={"status": "observed"},
            observed_at=datetime(2026, 8, 9, tzinfo=UTC),
            ingested_at=datetime(2026, 8, 9, tzinfo=UTC),
        )
    with pytest.raises(ValidationError):
        EntityDecisionReceipt(
            receipt_id=ACTOR_ID,
            tenant_id=TENANT_ID,
            decision_ref=resource_ref(),
            applied_ref=other_tenant_ref(),
            inverse_payload={},
        )


def test_action_request_rejects_cross_tenant_resources() -> None:
    with pytest.raises(ValidationError):
        ActionRequest(
            action_request_id=ACTOR_ID,
            tenant_id=TENANT_ID,
            action_type=resource_ref(),
            target_refs=(other_tenant_ref(),),
            parameters={},
            ontology_snapshot_ref=snapshot_ref(),
            expected_effects=(),
            external_destination=None,
            idempotency_key="action-1",
            evidence_artifact_refs=(),
        )


def test_delegated_task_and_artifact_reject_cross_tenant_inputs() -> None:
    scope = CapabilityScope(
        tools=frozenset(),
        object_types=frozenset(),
        properties=frozenset(),
        actions=frozenset(),
        external_destinations=frozenset(),
    )
    budget = ExecutionBudget(
        max_tokens=0,
        max_cost_micros=0,
        max_tool_calls=0,
        deadline=datetime(2026, 8, 9, tzinfo=UTC),
    )
    with pytest.raises(ValidationError):
        DelegatedTask(
            task_id=ACTOR_ID,
            tenant_id=TENANT_ID,
            objective_id=ACTOR_ID,
            situation_id=None,
            parent_task_id=None,
            priority=0,
            budget=budget,
            input_artifact_refs=(other_tenant_ref(),),
            ontology_snapshot_ref=snapshot_ref(),
            capability_scope=scope,
            output_schema_uri="https://example.test/output",
            evidence_requirements=(),
            autonomy_class=AutonomyClass.R0,
            escalation_policy_id=ACTOR_ID,
            agent_version_id=ACTOR_ID,
            prompt_version_id=ACTOR_ID,
            tool_version_ids=(),
            workflow_version_id=ACTOR_ID,
            model_id="nexus-test",
        )
    with pytest.raises(ValidationError):
        ArtifactEnvelope(
            artifact_id=ACTOR_ID,
            tenant_id=TENANT_ID,
            objective_id=None,
            situation_id=None,
            task_id=None,
            artifact_type="observation",
            schema_uri="https://example.test/artifact",
            payload={},
            provenance=ArtifactProvenance(
                creator=other_tenant_ref(),
                input_artifact_refs=(),
                ontology_snapshot_ref=snapshot_ref(),
                version_ids={},
                tool_call_ids=(),
                correlation_id=CORRELATION_ID,
            ),
            sensitivity=frozenset(),
            evidence_refs=(),
            created_at=datetime(2026, 8, 9, tzinfo=UTC),
        )


def _resolve_local_reference(document: object, reference: str) -> object:
    node = document
    for token in reference.removeprefix("#/").split("/"):
        assert isinstance(node, dict)
        node = node[token.replace("~1", "/").replace("~0", "~")]
    return node


def _local_references(node: object) -> list[str]:
    if isinstance(node, list):
        return [reference for item in node for reference in _local_references(item)]
    if isinstance(node, dict):
        references = [node["$ref"]] if isinstance(node.get("$ref"), str) else []
        return references + [
            reference
            for value in node.values()
            for reference in _local_references(value)
        ]
    return []


def test_generated_schema_resolves_every_local_reference() -> None:
    schema_path = Path(__file__).parents[1] / "generated" / "platform-1.0.0.json"
    document = json.loads(schema_path.read_text(encoding="utf-8"))

    for reference in _local_references(document):
        if reference.startswith("#/"):
            assert _resolve_local_reference(document, reference) is not None
