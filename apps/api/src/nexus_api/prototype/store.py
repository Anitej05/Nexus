"""Strict audit-ledger adapter and fail-closed prototype state reducer."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any, cast

from nexus_contracts.platform import JsonValue, RequestContext, ResourceRef
from nexus_security.audit import (
    AUDIT_SELECT_COLUMNS,
    AuditEvent,
    AuditPayloadRegistry,
    AuditPayloadSchema,
    AuditPolicyEvidence,
    AuditWriter,
    audit_event_from_mapping,
)
from nexus_security.outbox import OutboxWriter
from pydantic import UUID7, ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from nexus_api.prototype.models import (
    PrototypeAdvisory,
    PrototypeAgentFinding,
    PrototypeApproval,
    PrototypeAuditRef,
    PrototypeExecution,
    PrototypePlan,
    PrototypeRunView,
    PrototypeSignal,
    PrototypeTrace,
    PrototypeTraceEvent,
    PrototypeVerification,
    RunStatus,
)
from nexus_api.prototype.orchestrator import build_prototype_plan
from nexus_api.prototype.risk import incident_risk_signal, supply_risk_signal
from nexus_api.prototype.seed import build_prototype_graph


class PrototypeStateError(RuntimeError):
    pass


def prototype_payload_registry() -> AuditPayloadRegistry:
    schemas: dict[str, Mapping[str, type[Any] | tuple[type[Any], ...]]] = {
        "prototype.run.created": {
            "scenario_id": str,
            "seed_digest": str,
            "status": str,
            "policy_operation": str,
        },
        "prototype.signal.published": {
            "domain": str,
            "model_version": str,
            "target_id": str,
            "score": float,
            "threshold": float,
            "evidence_node_ids": list,
            "policy_operation": str,
        },
        "prototype.agent.completed": {
            "agent_role": str,
            "status": str,
            "finding_code": str,
            "evidence_node_ids": list,
            "uncertainty_code": str,
            "policy_operation": str,
        },
        "prototype.briefing.generated": {
            "provider_status": str,
            "summary_sha256": str,
            "citation_node_ids": list,
            "model_id": str,
            "prompt_version": str,
            "policy_operation": str,
        },
        "prototype.plan.prepared": {
            "action_kind": str,
            "target_id": str,
            "destination": str,
            "risk_class": str,
            "plan_hash": str,
            "status": str,
            "policy_operation": str,
        },
        "prototype.approval.recorded": {
            "plan_hash": str,
            "approver_id": str,
            "status": str,
            "reason_sha256": (str, type(None)),
            "policy_operation": str,
        },
        "prototype.action.executed": {
            "plan_hash": str,
            "receipt_id": str,
            "connector_kind": str,
            "status": str,
            "policy_operation": str,
        },
        "prototype.verification.completed": {
            "receipt_id": str,
            "status": str,
            "verified_effect": str,
            "observed_delay_hours": float,
            "policy_operation": str,
        },
    }
    return AuditPayloadRegistry(
        {
            name: AuditPayloadSchema(fields=fields, policy_evidence_required=True)
            for name, fields in schemas.items()
        }
    )


_BASE_SEQUENCE = (
    "prototype.run.created",
    "prototype.signal.published",
    "prototype.signal.published",
    "prototype.agent.completed",
    "prototype.agent.completed",
    "prototype.agent.completed",
    "prototype.briefing.generated",
    "prototype.plan.prepared",
)

_POLICY_SEMANTICS = {
    "prototype.run.created": ("action.propose", "R0"),
    "prototype.signal.published": ("action.propose", "R0"),
    "prototype.agent.completed": ("action.propose", "R0"),
    "prototype.briefing.generated": ("action.propose", "R0"),
    "prototype.plan.prepared": ("action.propose", "R0"),
    "prototype.approval.recorded": ("action.approve", "R0"),
    "prototype.action.executed": ("action.execute", "R3"),
    "prototype.verification.completed": ("action.execute", "R3"),
}


def _model_payload(event: AuditEvent) -> dict[str, JsonValue]:
    return {key: value for key, value in event.public_payload.items() if key != "policy_operation"}


def _validate_policy_semantics(event: AuditEvent) -> None:
    evidence = event.policy_evidence
    expected_operation, expected_class = _POLICY_SEMANTICS[event.event_type]
    if (
        evidence is None
        or not evidence.decision.allow
        or evidence.decision.effective_class != expected_class
        or evidence.operation != expected_operation
        or event.public_payload.get("policy_operation") != expected_operation
    ):
        raise PrototypeStateError("prototype policy evidence is semantically invalid")


def _validate_sequence(event_types: Sequence[str]) -> None:
    if len(event_types) < len(_BASE_SEQUENCE) or tuple(event_types[:8]) != _BASE_SEQUENCE:
        raise PrototypeStateError("invalid prototype event sequence")
    tail = tuple(event_types[8:])
    if tail not in (
        (),
        ("prototype.approval.recorded",),
        (
            "prototype.approval.recorded",
            "prototype.action.executed",
            "prototype.verification.completed",
        ),
    ):
        raise PrototypeStateError("invalid prototype event sequence")


def reduce_prototype_events(
    events: Sequence[AuditEvent | tuple[str, Mapping[str, JsonValue]]],
) -> PrototypeRunView | None:
    """Validate sequence first; fold real audit events into the typed view."""
    _validate_sequence(
        [event.event_type if isinstance(event, AuditEvent) else event[0] for event in events]
    )
    if not events or not isinstance(events[0], AuditEvent):
        return None
    if not all(isinstance(event, AuditEvent) for event in events):
        raise PrototypeStateError("mixed prototype event representations")
    audited = cast(Sequence[AuditEvent], events)
    created = audited[0]
    graph = build_prototype_graph()
    if any(
        event.tenant_id != created.tenant_id
        or event.resource.tenant_id != created.tenant_id
        or event.resource.kind != "prototype.run"
        or event.resource.id != created.resource.id
        or event.resource.version != 1
        for event in audited
    ):
        raise PrototypeStateError("prototype event provenance is invalid")
    for event in audited:
        if event.event_type not in _POLICY_SEMANTICS:
            raise PrototypeStateError("prototype event type is not registered")
        _validate_policy_semantics(event)
    if created.public_payload != {
        "scenario_id": graph.scenario_id,
        "seed_digest": graph.seed_digest,
        "status": "created",
        "policy_operation": "action.propose",
    }:
        raise PrototypeStateError("invalid prototype created payload")
    expected_signals = (supply_risk_signal(graph), incident_risk_signal(graph))
    signals: list[PrototypeSignal] = []
    for event, expected in zip(audited[1:3], expected_signals, strict=True):
        try:
            signal = PrototypeSignal.model_validate(
                {**_model_payload(event), "feature_map": expected.feature_map}
            )
        except ValidationError as error:
            raise PrototypeStateError("invalid prototype signal payload") from error
        if signal != expected:
            raise PrototypeStateError("prototype signal does not match frozen model")
        signals.append(signal)
    findings: list[PrototypeAgentFinding] = []
    for event in audited[3:6]:
        try:
            findings.append(PrototypeAgentFinding.model_validate(_model_payload(event)))
        except ValidationError as error:
            raise PrototypeStateError("invalid prototype agent payload") from error
    expected_findings = (
        PrototypeAgentFinding(
            agent_role="supply_risk_analyst",
            status="completed",
            finding_code="supply_delay_threshold_exceeded",
            evidence_node_ids=expected_signals[0].evidence_node_ids,
            uncertainty_code="Deterministic projection; no live logistics telemetry",
        ),
        PrototypeAgentFinding(
            agent_role="it_incident_analyst",
            status="completed",
            finding_code="incident_risk_threshold_exceeded",
            evidence_node_ids=expected_signals[1].evidence_node_ids,
            uncertainty_code="Temporal association; not a deployment root-cause proof",
        ),
        PrototypeAgentFinding(
            agent_role="decision_critic",
            status="completed",
            finding_code="cross_domain_priority_correlated",
            evidence_node_ids=("shift-2026-08-09", "PORT-MAA", "DEP-882"),
            uncertainty_code="Correlated operational priority, not a proven causal link",
        ),
    )
    if tuple(findings) != expected_findings:
        raise PrototypeStateError("invalid prototype specialist order")
    try:
        advisory = PrototypeAdvisory.model_validate(_model_payload(audited[6]))
        plan = PrototypePlan.model_validate(
            {
                **_model_payload(audited[7]),
                "expected_effect": "reduce_predicted_delay_by_14_hours",
            }
        )
    except ValidationError as error:
        raise PrototypeStateError("invalid prototype briefing or plan") from error
    if not set(advisory.citation_node_ids) <= {node.id for node in graph.nodes}:
        raise PrototypeStateError("prototype briefing cites unknown evidence")
    if plan != build_prototype_plan():
        raise PrototypeStateError("prototype plan does not match frozen plan")
    approval = None
    execution = None
    verification = None
    status: RunStatus = "awaiting_approval"
    if len(audited) >= 9:
        try:
            approval = PrototypeApproval.model_validate(_model_payload(audited[8]))
        except ValidationError as error:
            raise PrototypeStateError("invalid prototype approval") from error
        if approval.plan_hash != plan.plan_hash:
            raise PrototypeStateError("approval is not bound to plan")
        if (
            approval.approver_id != audited[8].actor.actor_id
            or approval.approver_id == created.actor.actor_id
        ):
            raise PrototypeStateError("approval separation is invalid")
        status = approval.status
    if len(audited) == 11:
        if approval is None or approval.status != "approved":
            raise PrototypeStateError("action requires approval")
        try:
            execution = PrototypeExecution.model_validate(_model_payload(audited[9]))
            verification = PrototypeVerification.model_validate(_model_payload(audited[10]))
        except ValidationError as error:
            raise PrototypeStateError("invalid execution or verification") from error
        if execution.plan_hash != plan.plan_hash or verification.receipt_id != execution.receipt_id:
            raise PrototypeStateError("execution provenance mismatch")
        if (
            audited[9].actor.actor_id != created.actor.actor_id
            or audited[10].actor.actor_id != created.actor.actor_id
        ):
            raise PrototypeStateError("execution actor is invalid")
        if verification.observed_delay_hours != 14.0:
            raise PrototypeStateError("verification does not match fixed simulator")
        status = "verified"
    return PrototypeRunView(
        run_id=created.resource.id,
        tenant_id=created.tenant_id,
        scenario_id=graph.scenario_id,
        seed_digest=graph.seed_digest,
        status=status,
        proposer_id=created.actor.actor_id,
        signals=(signals[0], signals[1]),
        findings=(findings[0], findings[1], findings[2]),
        llm=advisory,
        plan=plan,
        approval=approval,
        execution=execution,
        verification=verification,
        audit_events=tuple(
            PrototypeAuditRef(
                event_id=event.id,
                sequence=event.sequence,
                event_type=event.event_type,
                hash=event.hash,
            )
            for event in audited
        ),
    )


class PrototypeStore:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.writer = AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=prototype_payload_registry()
        )

    async def lock_tenant(self, tenant_id: UUID7) -> None:
        await self.session.execute(
            text("select pg_advisory_xact_lock(hashtextextended(:tenant, 0))"),
            {"tenant": str(tenant_id)},
        )

    async def find_command(self, context: RequestContext, command_key: str) -> AuditEvent | None:
        digest = hashlib.sha256(command_key.encode()).hexdigest()
        row = (
            (
                await self.session.execute(
                    text(
                        f"select {AUDIT_SELECT_COLUMNS} from audit_events "  # noqa: S608
                        "where tenant_id=:tenant and idempotency_key_sha256=:digest"
                    ),
                    {"tenant": context.tenant_id, "digest": digest},
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else audit_event_from_mapping(row)

    async def load_events(self, context: RequestContext, run_id: UUID7) -> tuple[AuditEvent, ...]:
        rows = (
            (
                await self.session.execute(
                    text(
                        f"select {AUDIT_SELECT_COLUMNS} from audit_events "  # noqa: S608
                        "where tenant_id=:tenant and resource_kind='prototype.run' "
                        "and resource_id=:run order by sequence"
                    ),
                    {"tenant": context.tenant_id, "run": run_id},
                )
            )
            .mappings()
            .all()
        )
        return tuple(audit_event_from_mapping(row) for row in rows)

    async def load(self, context: RequestContext, run_id: UUID7) -> PrototypeRunView | None:
        events = await self.load_events(context, run_id)
        return None if not events else cast(PrototypeRunView, reduce_prototype_events(events))

    async def trace(self, context: RequestContext, run_id: UUID7) -> PrototypeTrace | None:
        events = await self.load_events(context, run_id)
        if not events:
            return None
        reduce_prototype_events(events)
        return PrototypeTrace(
            run_id=run_id,
            events=tuple(
                PrototypeTraceEvent(
                    event_id=event.id,
                    sequence=event.sequence,
                    occurred_at=event.occurred_at,
                    actor_id=event.actor.actor_id,
                    event_type=event.event_type,
                    public_payload=event.public_payload,
                    hash=event.hash,
                )
                for event in events
            ),
        )

    async def append(
        self,
        context: RequestContext,
        run_id: UUID7,
        event_type: str,
        payload: Mapping[str, JsonValue],
        command_key: str,
        evidence: AuditPolicyEvidence,
    ) -> AuditEvent:
        return await self.writer.append(
            context,
            event_type,
            ResourceRef(tenant_id=context.tenant_id, kind="prototype.run", id=run_id, version=1),
            payload,
            command_key,
            policy_evidence=evidence,
            operation=_POLICY_SEMANTICS[event_type][0],
        )
