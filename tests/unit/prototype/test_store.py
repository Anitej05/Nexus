"""Fail-closed ledger reducer and public audit-schema contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from _contract import require_module
from nexus_contracts.platform import PolicyDecision, ResourceRef
from nexus_security.audit import AuditActor, AuditEvent, AuditPolicyEvidence

TENANT_ID = UUID("018f0000-0000-7000-8000-000000000001")
ACTOR_ID = UUID("018f0000-0000-7000-8000-000000000002")
RUN_ID = UUID("019fe476-8380-7000-8000-000000000100")
PLAN_HASH = "a" * 64
SUMMARY_HASH = "b" * 64
POLICY_HASH = "c" * 64

PAYLOADS: dict[str, dict[str, object]] = {
    "prototype.run.created": {
        "scenario_id": "storm-and-checkout-shift-v1",
        "seed_digest": "ab6630b92c813392964fad431fe7aba5e2b68f0742e800523d6ceec3196f0e06",
        "status": "created",
        "policy_operation": "action.propose",
    },
    "prototype.signal.published": {
        "domain": "supply",
        "model_version": "demo.supply-delay.v1",
        "target_id": "SHP-0042",
        "score": 0.91,
        "threshold": 0.80,
        "evidence_node_ids": [
            "PORT-MAA",
            "SHP-0042",
            "SHP-0047",
            "SHP-0051",
            "CMP-SENSOR-A",
            "PO-1107",
            "PO-1112",
        ],
        "policy_operation": "action.propose",
    },
    "prototype.agent.completed": {
        "agent_role": "supply_risk_analyst",
        "status": "completed",
        "finding_code": "supply_delay_threshold_exceeded",
        "evidence_node_ids": [
            "PORT-MAA",
            "SHP-0042",
            "SHP-0047",
            "SHP-0051",
            "CMP-SENSOR-A",
            "PO-1107",
            "PO-1112",
        ],
        "uncertainty_code": "Deterministic projection; no live logistics telemetry",
        "policy_operation": "action.propose",
    },
    "prototype.briefing.generated": {
        "provider_status": "unavailable",
        "summary_sha256": SUMMARY_HASH,
        "citation_node_ids": ["PORT-MAA", "DEP-882"],
        "model_id": "reviewed/custom-model",
        "prompt_version": "prototype-briefing.v1",
        "policy_operation": "action.propose",
    },
    "prototype.plan.prepared": {
        "action_kind": "simulated_reroute",
        "target_id": "SHP-0042",
        "destination": "sim://reroute/PORT-MAA",
        "risk_class": "R3",
        "plan_hash": "8814a2fce863a6a334f323da9fa1ce4f5bdb7958be1fea618bef21d230110cca",
        "status": "awaiting_approval",
        "policy_operation": "action.propose",
    },
    "prototype.approval.recorded": {
        "plan_hash": "8814a2fce863a6a334f323da9fa1ce4f5bdb7958be1fea618bef21d230110cca",
        "approver_id": str(UUID("018f0000-0000-7000-8000-000000000003")),
        "status": "approved",
        "reason_sha256": None,
        "policy_operation": "action.approve",
    },
    "prototype.action.executed": {
        "plan_hash": "8814a2fce863a6a334f323da9fa1ce4f5bdb7958be1fea618bef21d230110cca",
        "receipt_id": "sim-receipt-001",
        "connector_kind": "in_process_simulator",
        "status": "simulated",
        "policy_operation": "action.execute",
    },
    "prototype.verification.completed": {
        "receipt_id": "sim-receipt-001",
        "status": "verified",
        "verified_effect": "delay_reduced",
        "observed_delay_hours": 14.0,
        "policy_operation": "action.execute",
    },
}


def _policy(event_type: str) -> AuditPolicyEvidence:
    return AuditPolicyEvidence(
        decision=PolicyDecision(
            decision_id=UUID("019fe476-8380-7000-8000-000000000090"),
            allow=True,
            effective_class="R3"
            if event_type.startswith("prototype.action")
            or event_type.startswith("prototype.verification")
            else "R0",
        ),
        policy_revision="prototype-policy-v1",
        canonical_input_sha256=POLICY_HASH,
        operation=PAYLOADS[event_type]["policy_operation"],
    )


def _event(sequence: int, event_type: str, payload: dict[str, object]) -> AuditEvent:
    return AuditEvent(
        id=UUID(f"019fe476-8380-7000-8000-{sequence:012x}"),
        tenant_id=TENANT_ID,
        sequence=sequence,
        occurred_at=datetime(2026, 8, 9, 3, sequence, tzinfo=UTC),
        actor=AuditActor(
            actor_id=UUID("018f0000-0000-7000-8000-000000000003")
            if event_type == "prototype.approval.recorded"
            else ACTOR_ID
        ),
        event_type=event_type,
        resource=ResourceRef(tenant_id=TENANT_ID, kind="prototype.run", id=RUN_ID, version=1),
        policy_evidence=_policy(event_type),
        correlation_id=UUID("019fe476-8380-7000-8000-000000000091"),
        public_payload=payload,
        previous_hash=f"{sequence - 1:064x}",
        hash=f"{sequence:064x}",
    )


def _successful_events() -> tuple[AuditEvent, ...]:
    definitions = (
        ("prototype.run.created", PAYLOADS["prototype.run.created"]),
        ("prototype.signal.published", PAYLOADS["prototype.signal.published"]),
        (
            "prototype.signal.published",
            {
                **PAYLOADS["prototype.signal.published"],
                "domain": "it",
                "model_version": "demo.incident-risk.v1",
                "target_id": "svc-checkout",
                "score": 0.94,
                "evidence_node_ids": ["DEP-882", "svc-checkout", "svc-payments", "db-ledger"],
            },
        ),
        ("prototype.agent.completed", PAYLOADS["prototype.agent.completed"]),
        (
            "prototype.agent.completed",
            {
                **PAYLOADS["prototype.agent.completed"],
                "agent_role": "it_incident_analyst",
                "finding_code": "incident_risk_threshold_exceeded",
                "evidence_node_ids": ["DEP-882", "svc-checkout", "svc-payments", "db-ledger"],
                "uncertainty_code": "Temporal association; not a deployment root-cause proof",
            },
        ),
        (
            "prototype.agent.completed",
            {
                **PAYLOADS["prototype.agent.completed"],
                "agent_role": "decision_critic",
                "finding_code": "cross_domain_priority_correlated",
                "evidence_node_ids": ["shift-2026-08-09", "PORT-MAA", "DEP-882"],
                "uncertainty_code": ("Correlated operational priority, not a proven causal link"),
            },
        ),
        ("prototype.briefing.generated", PAYLOADS["prototype.briefing.generated"]),
        ("prototype.plan.prepared", PAYLOADS["prototype.plan.prepared"]),
        ("prototype.approval.recorded", PAYLOADS["prototype.approval.recorded"]),
        ("prototype.action.executed", PAYLOADS["prototype.action.executed"]),
        ("prototype.verification.completed", PAYLOADS["prototype.verification.completed"]),
    )
    return tuple(
        _event(sequence, event_type, payload)
        for sequence, (event_type, payload) in enumerate(definitions, start=1)
    )


def test_reducer_folds_every_valid_state_through_verification() -> None:
    """The full eleven-event sequence produces only the exact final verified state."""
    store = require_module("nexus_api.prototype.store")
    view = store.reduce_prototype_events(_successful_events())
    assert view.status == "verified"
    assert [(item.score, item.threshold) for item in view.signals] == [(0.91, 0.80), (0.94, 0.80)]
    assert view.approval.status == "approved"
    assert view.execution.status == "simulated"
    assert view.verification.status == "verified"


def test_reducer_accepts_rejection_as_a_terminal_state() -> None:
    """A legitimate rejection is readable but cannot imply action or verification."""
    store = require_module("nexus_api.prototype.store")
    events = list(_successful_events()[:8])
    rejected_payload = {**PAYLOADS["prototype.approval.recorded"], "status": "rejected"}
    events.append(_event(9, "prototype.approval.recorded", rejected_payload))
    view = store.reduce_prototype_events(tuple(events))
    assert view.status == "rejected"
    assert view.approval.status == "rejected"
    assert view.execution is None and view.verification is None


@pytest.mark.parametrize(
    "events",
    [
        (_successful_events()[1],),
        _successful_events()[:8] + (_successful_events()[9],),
        _successful_events()[:9]
        + (_event(10, "prototype.signal.published", PAYLOADS["prototype.signal.published"]),),
        _successful_events()[:6]
        + (_event(7, "prototype.agent.completed", PAYLOADS["prototype.agent.completed"]),),
    ],
)
def test_reducer_rejects_missing_prerequisites_late_and_duplicate_records(
    events: tuple[AuditEvent, ...],
) -> None:
    store = require_module("nexus_api.prototype.store")
    with pytest.raises(store.PrototypeStateError, match="sequence"):
        store.reduce_prototype_events(events)


def test_exact_eight_payload_schemas_require_policy_and_reject_unregistered_fields() -> None:
    """Every public prototype event has one exact safe allowlist and mandatory Task 5 evidence."""
    route = require_module("nexus_api.routes.prototype")
    registry = route.PROTOTYPE_AUDIT_REGISTRY
    assert set(registry._schemas) == set(PAYLOADS)  # noqa: SLF001 -- exact registry is the contract.
    for event_type, payload in PAYLOADS.items():
        assert registry.sanitize(event_type, payload, _policy(event_type)) == dict(
            sorted(payload.items())
        )
        with pytest.raises(ValueError, match="policy evidence"):
            registry.sanitize(event_type, payload, None)
        with pytest.raises(ValueError, match="not registered"):
            registry.sanitize(
                event_type, {**payload, "prompt": "PROMPT-NEEDLE"}, _policy(event_type)
            )
