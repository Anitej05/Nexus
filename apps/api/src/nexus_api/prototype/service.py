"""Governed ledger-backed controller for the bounded cross-domain prototype."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Protocol

from nexus_contracts.platform import JsonValue, RequestContext
from nexus_security.audit import (
    AuditIdempotencyConflict,
    AuditPolicyEvidence,
)
from nexus_security.ids import new_id
from nexus_security.policy import AuthorizationEvidence
from nexus_security.tenancy import TenantSession
from pydantic import UUID7

from nexus_api.prototype.models import (
    CreatePrototypeRunRequest,
    PrototypeApprovalCommand,
    PrototypeExecutionCommand,
    PrototypeGraph,
    PrototypeRunView,
    PrototypeTrace,
)
from nexus_api.prototype.orchestrator import AdvisoryFacade, PrototypeOrchestrator
from nexus_api.prototype.seed import build_prototype_graph
from nexus_api.prototype.store import PrototypeStateError, PrototypeStore


class _SafePrototypeError(RuntimeError):
    code: str

    def __init__(self) -> None:
        super().__init__(self.code)


class PrototypeNotFound(_SafePrototypeError):
    code = "prototype_not_found"


class PrototypeForbidden(_SafePrototypeError):
    code = "prototype_forbidden"


class PrototypeConflict(_SafePrototypeError):
    code = "prototype_conflict"


class PrototypePreconditionFailed(_SafePrototypeError):
    code = "prototype_precondition_failed"


class PrototypeValidationError(_SafePrototypeError):
    code = "prototype_validation_failed"


class PrototypeDependencyUnavailable(_SafePrototypeError):
    code = "prototype_dependency_unavailable"


class PrototypePolicy(Protocol):
    async def authorize(
        self,
        context: RequestContext,
        operation: str,
        *,
        run_id: UUID7 | None,
        plan_hash: str | None,
        proposer_id: UUID7 | None,
        approver_id: UUID7 | None,
        approval_consumed: bool | None = None,
    ) -> AuthorizationEvidence: ...


def _command_key(raw_key: str, stage: str) -> str:
    if not raw_key or len(raw_key.encode()) > 128:
        raise PrototypeValidationError()
    return f"prototype:{hashlib.sha256(raw_key.encode()).hexdigest()}:{stage}"


def _require_authorized(
    evidence: AuthorizationEvidence, expected_operation: str
) -> AuditPolicyEvidence:
    if (
        "policy_unavailable" in evidence.decision.reason_codes
        or evidence.policy_revision is None
        or evidence.canonical_input_sha256 is None
    ):
        raise PrototypeDependencyUnavailable()
    if not evidence.decision.allow:
        raise PrototypeForbidden()
    if evidence.operation != expected_operation:
        raise PrototypeDependencyUnavailable()
    try:
        return AuditPolicyEvidence.from_authorization(evidence)
    except ValueError as error:
        raise PrototypeDependencyUnavailable() from error


class SimulatedRerouteConnector:
    def execute(self, run_id: UUID7, plan_hash: str) -> str:
        return "sim-" + hashlib.sha256(f"{run_id}:{plan_hash}".encode()).hexdigest()[:32]


class PrototypeController:
    def __init__(
        self,
        sessions: TenantSession,
        policy: PrototypePolicy,
        advisory: AdvisoryFacade,
    ) -> None:
        self._sessions = sessions
        self._policy = policy
        self._orchestrator = PrototypeOrchestrator(advisory)
        self._connector = SimulatedRerouteConnector()

    async def create_run(
        self,
        context: RequestContext,
        request: CreatePrototypeRunRequest,
        idempotency_key: str,
    ) -> PrototypeRunView:
        evidence = _require_authorized(
            await self._policy.authorize(
                context,
                "action.propose",
                run_id=None,
                plan_hash=None,
                proposer_id=context.actor_id,
                approver_id=None,
            ),
            "action.propose",
        )
        create_key = _command_key(idempotency_key, "created")
        async with self._sessions.begin(context) as session:
            store = PrototypeStore(session)
            await store.lock_tenant(context.tenant_id)
            existing = await store.find_command(context, create_key)
            if existing is not None:
                if (
                    existing.event_type != "prototype.run.created"
                    or existing.public_payload.get("scenario_id") != request.scenario_id
                    or existing.actor.actor_id != context.actor_id
                ):
                    raise PrototypeConflict()
                view = await store.load(context, existing.resource.id)
                if view is None:
                    raise PrototypeConflict()
                return view

        graph = build_prototype_graph()
        result = await self._orchestrator.run(
            graph, context=context, idempotency_key=idempotency_key
        )
        async with self._sessions.begin(context) as session:
            store = PrototypeStore(session)
            await store.lock_tenant(context.tenant_id)
            existing = await store.find_command(context, create_key)
            if existing is not None:
                if (
                    existing.public_payload.get("scenario_id") != request.scenario_id
                    or existing.actor.actor_id != context.actor_id
                ):
                    raise PrototypeConflict()
                view = await store.load(context, existing.resource.id)
                if view is None:
                    raise PrototypeConflict()
                return view
            run_id = new_id()
            staged: list[tuple[str, Mapping[str, JsonValue]]] = [
                (
                    "prototype.run.created",
                    {
                        "scenario_id": request.scenario_id,
                        "seed_digest": graph.seed_digest,
                        "status": "created",
                        "policy_operation": "action.propose",
                    },
                ),
            ]
            for signal in result.signals:
                staged.append(
                    (
                        "prototype.signal.published",
                        {
                            "domain": signal.domain,
                            "model_version": signal.model_version,
                            "target_id": signal.target_id,
                            "score": signal.score,
                            "threshold": signal.threshold,
                            "evidence_node_ids": list(signal.evidence_node_ids),
                            "policy_operation": "action.propose",
                        },
                    )
                )
            for finding in result.findings:
                staged.append(
                    (
                        "prototype.agent.completed",
                        {
                            "agent_role": finding.agent_role,
                            "status": finding.status,
                            "finding_code": finding.finding_code,
                            "evidence_node_ids": list(finding.evidence_node_ids),
                            "uncertainty_code": finding.uncertainty_code,
                            "policy_operation": "action.propose",
                        },
                    )
                )
            staged.extend(
                (
                    (
                        "prototype.briefing.generated",
                        {
                            "provider_status": result.advisory.provider_status,
                            "summary_sha256": result.advisory.summary_sha256,
                            "citation_node_ids": list(result.advisory.citation_node_ids),
                            "model_id": result.advisory.model_id,
                            "prompt_version": result.advisory.prompt_version,
                            "policy_operation": "action.propose",
                        },
                    ),
                    (
                        "prototype.plan.prepared",
                        {
                            "action_kind": result.plan.action_kind,
                            "target_id": result.plan.target_id,
                            "destination": result.plan.destination,
                            "risk_class": result.plan.risk_class,
                            "plan_hash": result.plan.plan_hash,
                            "status": result.plan.status,
                            "policy_operation": "action.propose",
                        },
                    ),
                )
            )
            try:
                for index, (event_type, payload) in enumerate(staged):
                    key = (
                        create_key
                        if index == 0
                        else _command_key(idempotency_key, f"create-{index}")
                    )
                    await store.append(context, run_id, event_type, payload, key, evidence)
            except (AuditIdempotencyConflict, ValueError, PrototypeStateError) as error:
                raise PrototypeConflict() from error
            view = await store.load(context, run_id)
            if view is None:
                raise PrototypeDependencyUnavailable()
            return view

    async def get_run(self, context: RequestContext, run_id: UUID7) -> PrototypeRunView:
        _require_authorized(
            await self._policy.authorize(
                context,
                "action.read",
                run_id=run_id,
                plan_hash=None,
                proposer_id=None,
                approver_id=None,
            ),
            "action.read",
        )
        async with self._sessions.begin(context) as session:
            try:
                view = await PrototypeStore(session).load(context, run_id)
            except PrototypeStateError as error:
                raise PrototypeDependencyUnavailable() from error
        if view is None:
            raise PrototypeNotFound()
        return view

    async def get_graph(self, context: RequestContext, run_id: UUID7) -> PrototypeGraph:
        await self.get_run(context, run_id)
        return build_prototype_graph()

    async def get_trace(self, context: RequestContext, run_id: UUID7) -> PrototypeTrace:
        _require_authorized(
            await self._policy.authorize(
                context,
                "action.read",
                run_id=run_id,
                plan_hash=None,
                proposer_id=None,
                approver_id=None,
            ),
            "action.read",
        )
        async with self._sessions.begin(context) as session:
            try:
                trace = await PrototypeStore(session).trace(context, run_id)
            except PrototypeStateError as error:
                raise PrototypeDependencyUnavailable() from error
        if trace is None:
            raise PrototypeNotFound()
        return trace

    async def approve(
        self,
        context: RequestContext,
        run_id: UUID7,
        command: PrototypeApprovalCommand,
        idempotency_key: str,
        if_match: str,
    ) -> PrototypeRunView:
        view = await self._load_unchecked(context, run_id)
        if context.actor_id == view.proposer_id:
            raise PrototypeForbidden()
        if if_match != command.plan_hash or command.plan_hash != view.plan.plan_hash:
            raise PrototypePreconditionFailed()
        evidence = _require_authorized(
            await self._policy.authorize(
                context,
                "action.approve",
                run_id=run_id,
                plan_hash=command.plan_hash,
                proposer_id=view.proposer_id,
                approver_id=context.actor_id,
            ),
            "action.approve",
        )
        key = _command_key(idempotency_key, "approval")
        payload: Mapping[str, JsonValue] = {
            "plan_hash": command.plan_hash,
            "approver_id": str(context.actor_id),
            "status": "approved" if command.decision == "approve" else "rejected",
            "reason_sha256": (
                hashlib.sha256(command.reason.encode()).hexdigest()
                if command.reason is not None
                else None
            ),
            "policy_operation": "action.approve",
        }
        async with self._sessions.begin(context) as session:
            store = PrototypeStore(session)
            await store.lock_tenant(context.tenant_id)
            current = await store.load(context, run_id)
            if current is None:
                raise PrototypeNotFound()
            replay = await store.find_command(context, key)
            if replay is not None:
                if replay.resource.id != run_id or replay.public_payload != payload:
                    raise PrototypeConflict()
                return current
            if current.approval is not None or current.status != "awaiting_approval":
                raise PrototypeConflict()
            try:
                await store.append(
                    context, run_id, "prototype.approval.recorded", payload, key, evidence
                )
            except AuditIdempotencyConflict as error:
                raise PrototypeConflict() from error
            updated = await store.load(context, run_id)
            if updated is None:
                raise PrototypeDependencyUnavailable()
            return updated

    async def execute(
        self,
        context: RequestContext,
        run_id: UUID7,
        command: PrototypeExecutionCommand,
        idempotency_key: str,
        if_match: str,
    ) -> PrototypeRunView:
        key = _command_key(idempotency_key, "execute")
        receipt = self._connector.execute(run_id, command.plan_hash)
        action_payload: Mapping[str, JsonValue] = {
            "plan_hash": command.plan_hash,
            "receipt_id": receipt,
            "connector_kind": "in_process_simulator",
            "status": "simulated",
            "policy_operation": "action.execute",
        }
        async with self._sessions.begin(context) as session:
            store = PrototypeStore(session)
            await store.lock_tenant(context.tenant_id)
            view = await store.load(context, run_id)
            if view is None:
                raise PrototypeNotFound()
            if if_match != command.plan_hash or command.plan_hash != view.plan.plan_hash:
                raise PrototypePreconditionFailed()
            if view.approval is None or view.approval.status != "approved":
                raise PrototypeConflict()
            if context.actor_id != view.proposer_id:
                raise PrototypeForbidden()
            replay = await store.find_command(context, key)
            if replay is not None:
                if replay.resource.id != run_id or replay.public_payload != action_payload:
                    raise PrototypeConflict()
                replay_view = view
            else:
                replay_view = None
            approval = view.approval
            consumed = view.execution is not None

        if replay_view is not None:
            _require_authorized(
                await self._policy.authorize(
                    context,
                    "action.read",
                    run_id=run_id,
                    plan_hash=command.plan_hash,
                    proposer_id=view.proposer_id,
                    approver_id=approval.approver_id,
                    approval_consumed=consumed,
                ),
                "action.read",
            )
            return replay_view

        evidence = _require_authorized(
            await self._policy.authorize(
                context,
                "action.execute",
                run_id=run_id,
                plan_hash=command.plan_hash,
                proposer_id=view.proposer_id,
                approver_id=approval.approver_id,
                approval_consumed=consumed,
            ),
            "action.execute",
        )
        async with self._sessions.begin(context) as session:
            store = PrototypeStore(session)
            await store.lock_tenant(context.tenant_id)
            current = await store.load(context, run_id)
            if current is None:
                raise PrototypeNotFound()
            replay = await store.find_command(context, key)
            if replay is not None:
                if replay.resource.id != run_id or replay.public_payload != action_payload:
                    raise PrototypeConflict()
                return current
            if current.execution is not None or current.approval is None:
                raise PrototypeConflict()
            if current.approval != approval or current.proposer_id != view.proposer_id:
                raise PrototypeConflict()
            await store.append(
                context, run_id, "prototype.action.executed", action_payload, key, evidence
            )
            await store.append(
                context,
                run_id,
                "prototype.verification.completed",
                {
                    "receipt_id": receipt,
                    "status": "verified",
                    "verified_effect": "delay_reduced",
                    "observed_delay_hours": 14.0,
                    "policy_operation": "action.execute",
                },
                _command_key(idempotency_key, "verification"),
                evidence,
            )
            updated = await store.load(context, run_id)
            if updated is None:
                raise PrototypeDependencyUnavailable()
            return updated

    async def _load_unchecked(self, context: RequestContext, run_id: UUID7) -> PrototypeRunView:
        async with self._sessions.begin(context) as session:
            try:
                view = await PrototypeStore(session).load(context, run_id)
            except PrototypeStateError as error:
                raise PrototypeDependencyUnavailable() from error
        if view is None:
            raise PrototypeNotFound()
        return view

    async def aclose(self) -> None:
        await self._sessions.dispose()
