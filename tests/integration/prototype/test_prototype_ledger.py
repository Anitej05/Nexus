"""Task 6 ledger/outbox semantics for the prototype's exact public events."""

from __future__ import annotations

import json
from importlib import import_module
from types import ModuleType
from uuid import UUID

import pytest
from nexus_contracts.platform import PolicyDecision, ResourceRef
from nexus_security.audit import AuditPolicyEvidence, AuditWriter
from nexus_security.outbox import OutboxWriter
from nexus_security.policy import AuthorizationEvidence
from sqlalchemy import text

RUN_ID = UUID("019fe476-8380-7000-8000-000000000100")
ROLLBACK_RUN_ID = UUID("019fe476-8380-7000-8000-000000000101")
PAYLOADS = {
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
        "summary_sha256": "b" * 64,
        "citation_node_ids": ["PORT-MAA"],
        "model_id": "deepseek-ai/DeepSeek-V4-Flash-0731",
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
        "approver_id": "018f0000-0000-7000-8000-000000000003",
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
SENTINELS = (
    "PROMPT-NEEDLE",
    "MODEL-OUTPUT-NEEDLE",
    "POLICY-INPUT-NEEDLE",
    "API-KEY-NEEDLE",
    "BEARER-NEEDLE",
)


def _require_module(name: str) -> ModuleType:
    try:
        return import_module(name)
    except ModuleNotFoundError as exc:
        pytest.fail(f"prototype contract is not implemented: missing {name} ({exc.name})")


def _policy(event_type: str) -> AuditPolicyEvidence:
    return AuditPolicyEvidence(
        decision=PolicyDecision(
            decision_id=UUID("019fe476-8380-7000-8000-000000000090"),
            allow=True,
            effective_class="R3"
            if event_type in {"prototype.action.executed", "prototype.verification.completed"}
            else "R0",
        ),
        policy_revision="prototype-policy-v1",
        canonical_input_sha256="c" * 64,
        operation=PAYLOADS[event_type]["policy_operation"],
    )


async def _counts(sessions, context) -> tuple[int, int]:
    async with sessions.begin(context) as session:
        return (
            int(await session.scalar(text("select count(*) from audit_events")) or 0),
            int(await session.scalar(text("select count(*) from outbox_events")) or 0),
        )


@pytest.mark.asyncio
async def test_exact_registry_policy_resource_and_audit_outbox_atomicity(
    prototype_session, prototype_context
) -> None:
    """Every allowed append is evidenced and rollback leaves neither audit nor outbox residue."""
    from nexus_api.routes.prototype import PROTOTYPE_AUDIT_REGISTRY

    assert set(PROTOTYPE_AUDIT_REGISTRY._schemas) == set(PAYLOADS)  # noqa: SLF001
    resource = ResourceRef(
        tenant_id=prototype_context.tenant_id,
        kind="prototype.run",
        id=RUN_ID,
        version=1,
    )
    async with prototype_session.begin(prototype_context) as session:
        writer = AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=PROTOTYPE_AUDIT_REGISTRY
        )
        for index, (event_type, payload) in enumerate(PAYLOADS.items(), start=1):
            await writer.append(
                prototype_context,
                event_type,
                resource,
                payload,
                f"prototype-ledger-success-{index}",
                policy_evidence=_policy(event_type),
            )

    assert await _counts(prototype_session, prototype_context) == (8, 8)

    async with prototype_session.begin(prototype_context) as session:
        rows = (
            (
                await session.execute(
                    text(
                        "select event_type, resource_kind, resource_id, resource_version, "
                        "policy_decision, policy_revision, policy_input_sha256, public_payload "
                        "from audit_events order by sequence"
                    )
                )
            )
            .mappings()
            .all()
        )
        outbox = (
            (
                await session.execute(
                    text("select envelope from outbox_events order by created_at, id")
                )
            )
            .scalars()
            .all()
        )
    assert [row["event_type"] for row in rows] == list(PAYLOADS)
    for row in rows:
        assert (row["resource_kind"], row["resource_id"], row["resource_version"]) == (
            "prototype.run",
            RUN_ID,
            1,
        )
        expected_policy = _policy(row["event_type"])
        assert row["policy_decision"] == {
            **expected_policy.decision.model_dump(mode="json"),
            "operation": expected_policy.operation,
        }
        assert row["policy_revision"] == "prototype-policy-v1"
        assert row["policy_input_sha256"] == "c" * 64
        assert row["public_payload"] == PAYLOADS[row["event_type"]]
    normalized_outbox = [
        json.loads(envelope) if isinstance(envelope, str) else envelope for envelope in outbox
    ]
    normalized_outbox.sort(key=lambda envelope: envelope["payload"]["sequence"])
    assert [envelope["event_type"] for envelope in normalized_outbox] == ["nexus.audit.v1"] * 8
    for row, envelope in zip(rows, normalized_outbox, strict=True):
        assert envelope["tenant_id"] == str(prototype_context.tenant_id)
        assert envelope["payload"]["event_type"] == row["event_type"]
        assert envelope["payload"]["resource"] == {
            "tenant_id": str(prototype_context.tenant_id),
            "kind": "prototype.run",
            "id": str(RUN_ID),
            "version": 1,
        }
    serialized = json.dumps({"audit": rows, "outbox": normalized_outbox}, default=str)
    assert not any(sentinel in serialized for sentinel in SENTINELS)

    for field, sentinel in zip(
        ("prompt", "model_output", "raw_policy_input", "api_key", "bearer"),
        SENTINELS,
        strict=True,
    ):
        with pytest.raises(ValueError, match="not registered"):
            async with prototype_session.begin(prototype_context) as session:
                writer = AuditWriter(
                    session,
                    outbox=OutboxWriter(),
                    payload_registry=PROTOTYPE_AUDIT_REGISTRY,
                )
                await writer.append(
                    prototype_context,
                    "prototype.run.created",
                    resource,
                    {**PAYLOADS["prototype.run.created"], field: sentinel},
                    f"prototype-ledger-leak-{field}",
                    policy_evidence=_policy("prototype.run.created"),
                )
        assert await _counts(prototype_session, prototype_context) == (8, 8)

    rollback_resource = resource.model_copy(update={"id": ROLLBACK_RUN_ID})
    with pytest.raises(RuntimeError, match="deliberate rollback"):
        async with prototype_session.begin(prototype_context) as session:
            writer = AuditWriter(
                session, outbox=OutboxWriter(), payload_registry=PROTOTYPE_AUDIT_REGISTRY
            )
            await writer.append(
                prototype_context,
                "prototype.run.created",
                rollback_resource,
                PAYLOADS["prototype.run.created"],
                "prototype-ledger-rollback",
                policy_evidence=_policy("prototype.run.created"),
            )
            raise RuntimeError("deliberate rollback")
    assert await _counts(prototype_session, prototype_context) == (8, 8)


class _AllowPolicy:
    async def authorize(self, context, operation, **facts) -> AuthorizationEvidence:
        del context, facts
        return AuthorizationEvidence(
            decision=PolicyDecision(
                decision_id=UUID("019fe476-8380-7000-8000-000000000092"),
                allow=True,
                effective_class="R3" if operation == "action.execute" else "R0",
            ),
            policy_revision="1.0.0",
            canonical_input_sha256="f" * 64,
            operation=operation,
        )


class _InjectedAppendFailure(RuntimeError):
    pass


@pytest.mark.asyncio
async def test_controller_creation_failure_after_real_append_rolls_back_audit_and_outbox(
    prototype_session, prototype_context, monkeypatch
) -> None:
    """The controller rolls back a staged Task 6 audit/outbox pair on its second append."""
    models = _require_module("nexus_api.prototype.models")
    orchestrator = _require_module("nexus_api.prototype.orchestrator")
    service = _require_module("nexus_api.prototype.service")
    original_append = AuditWriter.append
    append_count = 0

    async def append_then_fail(self, *args, **kwargs):
        nonlocal append_count
        append_count += 1
        if append_count == 2:
            raise _InjectedAppendFailure("failure after the first real audit and outbox append")
        return await original_append(self, *args, **kwargs)

    monkeypatch.setattr(AuditWriter, "append", append_then_fail)
    controller = service.PrototypeController(
        prototype_session,
        _AllowPolicy(),
        orchestrator.DeterministicAdvisoryFacade(),
    )
    request = models.CreatePrototypeRunRequest(scenario_id="storm-and-checkout-shift-v1")

    with pytest.raises(_InjectedAppendFailure, match="after the first real audit and outbox"):
        await controller.create_run(prototype_context, request, "rollback-after-first-append")

    assert append_count == 2
    assert await _counts(prototype_session, prototype_context) == (0, 0)
