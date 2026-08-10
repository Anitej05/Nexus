"""Canonical audit-domain hashing and public-payload safety contracts."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from nexus_contracts.platform import PolicyDecision, ResourceRef
from nexus_security.audit import (
    GENESIS_HASH,
    AuditActor,
    AuditEvent,
    AuditPayloadRegistry,
    AuditPayloadSchema,
    AuditPolicyEvidence,
    ProtectedPayloadEvidence,
    audit_event_from_mapping,
    canonical_json_bytes,
    compute_event_hash,
    compute_request_fingerprint,
)
from nexus_security.ids import new_id
from nexus_security.policy import AuthorizationEvidence


def _event() -> AuditEvent:
    tenant_id = new_id()
    return AuditEvent(
        id=new_id(),
        tenant_id=tenant_id,
        sequence=1,
        occurred_at=datetime(2026, 8, 10, 1, 2, 3, 456789, tzinfo=UTC),
        actor=AuditActor(actor_id=new_id()),
        event_type="ontology.object.created",
        resource=ResourceRef(tenant_id=tenant_id, kind="ontology.object", id=new_id(), version=1),
        correlation_id=new_id(),
        public_payload={"field": "status", "count": 1},
        previous_hash=GENESIS_HASH,
        hash="0" * 64,
    )


def test_official_rfc8785_number_vector() -> None:
    assert canonical_json_bytes([333333333.33333329, 1e30, 4.50, 2e-3, 1e-27]) == (
        b"[333333333.3333333,1e+30,4.5,0.002,1e-27]"
    )


def test_canonical_bytes_ignore_mapping_insertion_order() -> None:
    assert canonical_json_bytes({"b": 2, "a": 1}) == canonical_json_bytes({"a": 1, "b": 2})


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), -float("inf"), -0.0, 2**53, object(), "\ud800"],
)
def test_canonical_json_rejects_non_interoperable_values(value: object) -> None:
    with pytest.raises((TypeError, ValueError, UnicodeError)):
        canonical_json_bytes({"value": value})


def test_canonical_json_rejects_duplicate_normalized_keys_and_excess_depth() -> None:
    with pytest.raises(ValueError, match="normalized"):
        canonical_json_bytes({"e\u0301": 1, "\u00e9": 2})
    nested: object = None
    for _ in range(20):
        nested = [nested]
    with pytest.raises(ValueError, match="depth"):
        canonical_json_bytes(nested)


def test_event_rejects_non_utc_and_cross_tenant_references() -> None:
    event = _event()
    data = event.model_dump()
    data["occurred_at"] = datetime.now(timezone(timedelta(hours=1)))
    with pytest.raises(ValueError, match="UTC"):
        AuditEvent.model_validate(data)
    data = event.model_dump()
    data["resource"] = ResourceRef(
        tenant_id=new_id(), kind="ontology.object", id=new_id(), version=1
    )
    with pytest.raises(ValueError, match="tenant"):
        AuditEvent.model_validate(data)


def test_protected_evidence_requires_object_version_one_and_digest() -> None:
    tenant_id = new_id()
    with pytest.raises(ValueError):
        ProtectedPayloadEvidence(
            ref=ResourceRef(tenant_id=tenant_id, kind="blob", id=new_id(), version=1),
            sha256="a" * 64,
        )
    with pytest.raises(ValueError):
        ProtectedPayloadEvidence(
            ref=ResourceRef(tenant_id=tenant_id, kind="object", id=new_id(), version=2),
            sha256="a" * 64,
        )


def test_policy_evidence_is_strict_and_structural() -> None:
    evidence = AuditPolicyEvidence(
        decision=PolicyDecision(decision_id=new_id(), allow=True, reason_codes=("explicit_grant",)),
        policy_revision="1.0.0",
        canonical_input_sha256="b" * 64,
    )
    assert evidence.decision.allow is True
    with pytest.raises(ValueError):
        AuditPolicyEvidence.model_validate({**evidence.model_dump(), "raw_input": {"token": "x"}})


def test_audit_policy_evidence_copies_the_trusted_authorization_operation() -> None:
    authorization = AuthorizationEvidence(
        decision=PolicyDecision(
            decision_id=new_id(), allow=True, effective_class="R3", reason_codes=("allowed",)
        ),
        policy_revision="1.0.0",
        canonical_input_sha256="c" * 64,
        operation="action.execute",
    )

    evidence = AuditPolicyEvidence.from_authorization(authorization)

    assert evidence.operation == "action.execute"


def test_payload_registry_is_allowlist_and_requires_policy_evidence() -> None:
    registry = AuditPayloadRegistry(
        {
            "ontology.object.created": AuditPayloadSchema(
                fields={"field": str, "count": int},
                policy_evidence_required=True,
            )
        }
    )
    with pytest.raises(ValueError, match="policy evidence"):
        registry.sanitize("ontology.object.created", {"field": "status", "count": 1}, None)
    with pytest.raises(ValueError, match="not registered"):
        registry.sanitize(
            "ontology.object.created", {"field": "status", "count": 1, "token": "x"}, object()
        )
    assert registry.sanitize(
        "ontology.object.created", {"count": 1, "field": "status"}, object()
    ) == {"count": 1, "field": "status"}


def test_request_fingerprint_excludes_correlation_but_includes_semantics() -> None:
    event = _event()
    first = compute_request_fingerprint(
        actor=event.actor,
        event_type=event.event_type,
        resource=event.resource,
        public_payload=event.public_payload,
        protected_payload=None,
        policy_evidence=None,
    )
    clone = event.model_copy(update={"correlation_id": new_id(), "id": new_id(), "sequence": 99})
    second = compute_request_fingerprint(
        actor=clone.actor,
        event_type=clone.event_type,
        resource=clone.resource,
        public_payload=clone.public_payload,
        protected_payload=None,
        policy_evidence=None,
    )
    changed = compute_request_fingerprint(
        actor=clone.actor,
        event_type=clone.event_type,
        resource=clone.resource,
        public_payload={"field": "priority", "count": 1},
        protected_payload=None,
        policy_evidence=None,
    )
    assert first == second
    assert changed != first


def test_domain_hash_changes_for_every_stored_semantic_field() -> None:
    base = _event()
    event = base.model_copy(
        update={
            "actor": AuditActor(actor_id=base.actor.actor_id, agent_id=new_id()),
            "policy_evidence": AuditPolicyEvidence(
                decision=PolicyDecision(decision_id=new_id(), allow=True),
                policy_revision="1.0.0",
                canonical_input_sha256="a" * 64,
                operation="ontology.create",
            ),
            "protected_payload": ProtectedPayloadEvidence(
                ref=ResourceRef(
                    tenant_id=base.tenant_id,
                    kind="object",
                    id=new_id(),
                    version=1,
                ),
                sha256="b" * 64,
            ),
        }
    )
    idempotency_digest = "1" * 64
    request_digest = "2" * 64
    baseline = compute_event_hash(event, idempotency_digest, request_digest)
    assert event.policy_evidence is not None
    assert event.protected_payload is not None
    other_tenant = new_id()
    mutations = (
        event.model_copy(update={"schema_version": 2}),
        event.model_copy(update={"id": new_id()}),
        event.model_copy(
            update={
                "tenant_id": other_tenant,
                "resource": event.resource.model_copy(update={"tenant_id": other_tenant}),
                "protected_payload": event.protected_payload.model_copy(
                    update={
                        "ref": event.protected_payload.ref.model_copy(
                            update={"tenant_id": other_tenant}
                        )
                    }
                ),
            }
        ),
        event.model_copy(update={"sequence": 2}),
        event.model_copy(update={"occurred_at": event.occurred_at + timedelta(microseconds=1)}),
        event.model_copy(
            update={"actor": AuditActor(actor_id=new_id(), agent_id=event.actor.agent_id)}
        ),
        event.model_copy(update={"actor": AuditActor(actor_id=event.actor.actor_id)}),
        event.model_copy(update={"event_type": "ontology.object.updated"}),
        event.model_copy(
            update={
                "resource": event.resource.model_copy(update={"kind": "ontology.asset"})
            }
        ),
        event.model_copy(update={"resource": event.resource.model_copy(update={"id": new_id()})}),
        event.model_copy(
            update={"resource": event.resource.model_copy(update={"version": 2})}
        ),
        event.model_copy(
            update={
                "policy_evidence": event.policy_evidence.model_copy(
                    update={"policy_revision": "1.0.1"}
                )
            }
        ),
        event.model_copy(
            update={
                "policy_evidence": event.policy_evidence.model_copy(
                    update={"operation": "ontology.update"}
                )
            }
        ),
        event.model_copy(update={"correlation_id": new_id()}),
        event.model_copy(update={"previous_hash": "3" * 64}),
        event.model_copy(update={"public_payload": {"field": "priority", "count": 1}}),
        event.model_copy(
            update={
                "protected_payload": event.protected_payload.model_copy(
                    update={"sha256": "c" * 64}
                )
            }
        ),
        event.model_copy(
            update={
                "protected_payload": event.protected_payload.model_copy(
                    update={
                        "ref": event.protected_payload.ref.model_copy(update={"id": new_id()})
                    }
                )
            }
        ),
    )
    assert baseline == compute_event_hash(event.model_copy(), idempotency_digest, request_digest)
    assert all(
        compute_event_hash(item, idempotency_digest, request_digest) != baseline
        for item in mutations
    )
    assert compute_event_hash(event, "4" * 64, request_digest) != baseline
    assert compute_event_hash(event, idempotency_digest, "5" * 64) != baseline
    assert not math.isnan(float(int(baseline[:8], 16)))


def test_independently_pinned_nexus_event_digest() -> None:
    tenant_id = UUID("019fe7dc-3f7f-7d0f-a0c6-269a562475f3")
    event = AuditEvent(
        id=UUID("019fe7dc-3f80-719f-9288-7ae99a5e6746"),
        tenant_id=tenant_id,
        sequence=1,
        occurred_at=datetime(2026, 8, 10, 1, 2, 3, 456789, tzinfo=UTC),
        actor=AuditActor(actor_id=UUID("019fe7dc-3f81-7061-87a8-c6317d47b9eb")),
        event_type="ontology.object.created",
        resource=ResourceRef(
            tenant_id=tenant_id,
            kind="ontology.object",
            id=UUID("019fe7dc-3f82-73fb-bf06-63b3502b7503"),
            version=1,
        ),
        correlation_id=UUID("019fe7dc-3f83-7e4f-b80a-bb81d6b693fc"),
        public_payload={"field": "status", "count": 1},
        previous_hash=GENESIS_HASH,
        hash=GENESIS_HASH,
    )
    assert compute_event_hash(event, "1" * 64, "2" * 64) == (
        "0f8cffe07ab58c0333a54f53912d1a2141b9ddb43511dbeb4ad2ce98dc1bba06"
    )
    historical_with_policy = event.model_copy(
        update={
            "policy_evidence": AuditPolicyEvidence(
                decision=PolicyDecision(
                    decision_id=UUID("019fe7dc-3f84-7000-8000-000000000001"),
                    allow=True,
                    effective_class="R0",
                    reason_codes=("explicit_grant",),
                ),
                policy_revision="1.0.0",
                canonical_input_sha256="a" * 64,
            )
        }
    )
    assert compute_event_hash(historical_with_policy, "1" * 64, "2" * 64) == (
        "9955dbbc2e28c4d6985a02c000744a8ffd8c71974a03741d74a81bc67ecb3086"
    )


def test_audit_row_round_trips_bound_operation_and_accepts_historical_absence() -> None:
    event = _event()
    decision = PolicyDecision(
        decision_id=new_id(), allow=True, effective_class="R3", reason_codes=("allowed",)
    )
    row = {
        "id": event.id,
        "tenant_id": event.tenant_id,
        "sequence": event.sequence,
        "occurred_at": event.occurred_at,
        "actor_id": event.actor.actor_id,
        "agent_id": None,
        "event_type": event.event_type,
        "resource_kind": event.resource.kind,
        "resource_id": event.resource.id,
        "resource_version": event.resource.version,
        "policy_decision": {
            **decision.model_dump(mode="json"),
            "operation": "action.execute",
        },
        "policy_revision": "1.0.0",
        "policy_input_sha256": "d" * 64,
        "correlation_id": event.correlation_id,
        "public_payload": event.public_payload,
        "protected_ref_kind": None,
        "protected_ref_id": None,
        "protected_ref_version": None,
        "protected_payload_sha256": None,
        "hash_domain_version": event.hash_domain_version,
        "previous_hash": event.previous_hash,
        "hash": event.hash,
    }

    current = audit_event_from_mapping(row)
    historical_row = {**row, "policy_decision": decision.model_dump(mode="json")}
    historical = audit_event_from_mapping(historical_row)

    assert current.policy_evidence is not None
    assert current.policy_evidence.operation == "action.execute"
    assert historical.policy_evidence is not None
    assert historical.policy_evidence.operation is None


def test_hash_domain_version_is_explicit_and_changes_the_hash() -> None:
    event = _event()
    assert event.hash_domain_version == "1"
    unsupported = event.model_copy(update={"hash_domain_version": "2"})
    with pytest.raises(ValueError, match="unsupported audit hash domain"):
        compute_event_hash(unsupported, "1" * 64, "2" * 64)
