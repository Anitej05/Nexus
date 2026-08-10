"""Authenticated, OPA-authorized bounded audit-ledger reads."""

from __future__ import annotations

import hashlib
import os
from collections.abc import AsyncIterator, Mapping
from datetime import datetime, timedelta
from typing import Annotated, Literal, Protocol
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from nexus_contracts.platform import JsonValue, Problem, RequestContext, ResourceRef
from nexus_security.audit import (
    AUDIT_SELECT_COLUMNS,
    AuditEvent,
    AuditPayloadRegistry,
    AuditPayloadSchema,
    AuditPolicyEvidence,
    AuditWriter,
    audit_event_from_mapping,
    canonical_json_bytes,
)
from nexus_security.dependencies import require_context
from nexus_security.ids import new_id
from nexus_security.outbox import OutboxWriter
from nexus_security.policy import (
    ActorIdentity,
    AuthorizationEvidence,
    AuthorizationInput,
    PolicyClient,
    TrustedPolicyFacts,
)
from nexus_security.tenancy import TenantSession
from pydantic import UUID7, BaseModel, ConfigDict, Field
from sqlalchemy import text


class AuditProblemRoute(APIRoute):
    """Project only canonical, non-reflective validation failures for this route."""

    def get_route_handler(self):  # type: ignore[no-untyped-def]
        original = super().get_route_handler()

        async def handler(request: Request):  # type: ignore[no-untyped-def]
            try:
                return await original(request)
            except RequestValidationError:
                raw = request.headers.get("X-Correlation-ID")
                try:
                    correlation = UUID(raw) if raw is not None else new_id()
                    if correlation.version != 7:
                        correlation = new_id()
                except ValueError:
                    correlation = new_id()
                problem = Problem(
                    type="https://nexus.local/problems/invalid-audit-query",
                    title="Invalid audit query",
                    status=422,
                    code="invalid_audit_query",
                    correlation_id=correlation,
                )
                return JSONResponse(
                    status_code=422,
                    content=problem.model_dump(mode="json", exclude={"schema_version"}),
                    media_type="application/problem+json",
                )

        return handler


router = APIRouter(prefix="/api/v1/audit", tags=["audit"], route_class=AuditProblemRoute)


class AuditEventPage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0.0"] = "1.0.0"
    events: tuple[AuditEvent, ...]
    snapshot_sequence: int = Field(ge=0)
    next_after_sequence: int = Field(ge=0)


class AuditReadPolicy(Protocol):
    async def authorize(
        self, context: RequestContext, attributes: Mapping[str, JsonValue]
    ) -> AuthorizationEvidence: ...


class OpaAuditReadPolicy:
    async def authorize(
        self, context: RequestContext, attributes: Mapping[str, JsonValue]
    ) -> AuthorizationEvidence:
        request = AuthorizationInput(
            decision_id=context.correlation_id,
            actor=ActorIdentity(
                actor_id=context.actor_id,
                agent_id=context.agent_id,
                roles=context.roles,
                scopes=context.scopes,
                sensitivity_clearances=context.sensitivity_clearances,
            ),
            tenant_id=context.tenant_id,
            resources=(),
            operation="audit.read",
            attributes=attributes,
            trusted_facts=TrustedPolicyFacts(
                resource_sensitivity=frozenset({"internal"}),
                configured_base_risk="R0",
                contextual_risk="R0",
            ),
        )
        async with httpx.AsyncClient() as client:
            return await PolicyClient(
                client,
                os.getenv(
                    "NEXUS_OPA_DECISION_URL",
                    "http://opa:8181/v1/data/nexus/authz/decision",
                ),
            ).authorize_with_evidence(request)


class AuditRouteDependencies:
    def __init__(self, sessions: TenantSession, policy: AuditReadPolicy) -> None:
        self.sessions = sessions
        self.policy = policy
        self.payload_registry = AuditPayloadRegistry(
            {
                "audit.read": AuditPayloadSchema(
                    fields={
                        "after_sequence": int,
                        "snapshot_sequence": (int, type(None)),
                        "limit": int,
                        "event_type": (str, type(None)),
                        "resource_kind": (str, type(None)),
                        "resource_id": (str, type(None)),
                        "actor_id": (str, type(None)),
                        "correlation_id": (str, type(None)),
                        "occurred_from": (str, type(None)),
                        "occurred_to": (str, type(None)),
                        "executed_snapshot_sequence": int,
                        "executed_limit": int,
                        "returned_from": (int, type(None)),
                        "returned_to": (int, type(None)),
                        "returned_count": int,
                    },
                    policy_evidence_required=True,
                )
            }
        )


async def get_audit_dependencies(request: Request) -> AsyncIterator[AuditRouteDependencies]:
    configured = getattr(request.app.state, "audit_dependencies", None)
    if isinstance(configured, AuditRouteDependencies):
        yield configured
        return
    database_url = os.getenv("NEXUS_DATABASE_URL")
    if not database_url:
        raise RuntimeError("NEXUS_DATABASE_URL is required for audit reads")
    dependencies = AuditRouteDependencies(TenantSession(database_url), OpaAuditReadPolicy())
    try:
        yield dependencies
    finally:
        await dependencies.sessions.dispose()


def _problem(context: RequestContext, status: int, code: str, title: str) -> JSONResponse:
    problem = Problem(
        type=f"https://nexus.local/problems/{code.replace('_', '-')}",
        title=title,
        status=status,
        code=code,
        correlation_id=context.correlation_id,
    )
    return JSONResponse(
        status_code=status,
        content=problem.model_dump(mode="json", exclude={"schema_version"}),
        media_type="application/problem+json",
    )


def _max_rows(obligations: tuple[str, ...], requested: int) -> int | None:
    effective = requested
    for obligation in obligations:
        if obligation.startswith("max_rows:"):
            raw = obligation.removeprefix("max_rows:")
            if not raw.isdigit() or raw.startswith("0"):
                return None
            effective = min(effective, int(raw))
        else:
            return None
    return effective


def _normalized_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@router.get(
    "/events",
    operation_id="getAuditLedger",
    response_model=AuditEventPage,
    responses={403: {"model": Problem}, 503: {"model": Problem}},
)
async def get_audit_ledger(
    context: Annotated[RequestContext, Depends(require_context)],
    dependencies: Annotated[AuditRouteDependencies, Depends(get_audit_dependencies)],
    after_sequence: Annotated[int, Query(ge=0)] = 0,
    snapshot_sequence: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    event_type: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    resource_kind: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    resource_id: UUID7 | None = None,
    actor_id: UUID7 | None = None,
    correlation_id: UUID7 | None = None,
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
) -> AuditEventPage | JSONResponse:
    if occurred_from is not None and (
        occurred_from.tzinfo is None or occurred_from.utcoffset() != timedelta(0)
    ):
        return _problem(context, 400, "invalid_audit_range", "Invalid audit range")
    if occurred_to is not None and (
        occurred_to.tzinfo is None or occurred_to.utcoffset() != timedelta(0)
    ):
        return _problem(context, 400, "invalid_audit_range", "Invalid audit range")
    if occurred_from is not None and occurred_to is not None and occurred_from > occurred_to:
        return _problem(context, 400, "invalid_audit_range", "Invalid audit range")
    request_criteria: dict[str, JsonValue] = {
        "after_sequence": after_sequence,
        "snapshot_sequence": snapshot_sequence,
        "limit": limit,
        "event_type": event_type,
        "resource_kind": resource_kind,
        "resource_id": str(resource_id) if resource_id else None,
        "actor_id": str(actor_id) if actor_id else None,
        "correlation_id": str(correlation_id) if correlation_id else None,
        "occurred_from": _normalized_time(occurred_from),
        "occurred_to": _normalized_time(occurred_to),
    }
    attributes: dict[str, JsonValue] = {"criteria": request_criteria}
    authorization = await dependencies.policy.authorize(context, attributes)
    decision = authorization.decision
    if (
        "policy_unavailable" in decision.reason_codes
        or authorization.policy_revision is None
        or authorization.canonical_input_sha256 is None
    ):
        return _problem(context, 503, "policy_unavailable", "Policy service unavailable")
    if not decision.allow:
        return _problem(context, 403, "audit_read_denied", "Audit read denied")
    effective_limit = _max_rows(decision.obligations, limit)
    if effective_limit is None:
        return _problem(context, 403, "unsupported_policy_obligation", "Audit read denied")
    evidence = AuditPolicyEvidence.from_authorization(authorization)
    async with dependencies.sessions.begin(context) as session:
        high_water = int(
            await session.scalar(
                text(
                    "select coalesce(max(sequence), 0) "
                    "from audit_events where tenant_id=:tenant"
                ),
                {"tenant": context.tenant_id},
            )
            or 0
        )
        snapshot = high_water if snapshot_sequence is None else snapshot_sequence
        if snapshot > high_water or after_sequence > snapshot:
            return _problem(context, 400, "invalid_audit_cursor", "Invalid audit cursor")
        clauses = ["tenant_id=:tenant", "sequence>:after", "sequence<=:snapshot"]
        parameters: dict[str, object] = {
            "tenant": context.tenant_id,
            "after": after_sequence,
            "snapshot": snapshot,
            "limit": effective_limit,
        }
        for name, value in (
            ("event_type", event_type),
            ("resource_kind", resource_kind),
            ("resource_id", resource_id),
            ("actor_id", actor_id),
            ("correlation_id", correlation_id),
        ):
            if value is not None:
                clauses.append(f"{name}=:{name}")
                parameters[name] = value
        if occurred_from is not None:
            clauses.append("occurred_at>=:occurred_from")
            parameters["occurred_from"] = occurred_from
        if occurred_to is not None:
            clauses.append("occurred_at<=:occurred_to")
            parameters["occurred_to"] = occurred_to
        rows = (
            (
                await session.execute(
                    text(  # noqa: S608 -- clauses use only fixed column names above.
                        f"select {AUDIT_SELECT_COLUMNS} from audit_events where "  # noqa: S608
                        + " and ".join(clauses)
                        + " order by sequence limit :limit"
                    ),
                    parameters,
                )
            )
            .mappings()
            .all()
        )
        events = tuple(audit_event_from_mapping(row) for row in rows)
        returned_from = events[0].sequence if events else None
        returned_to = events[-1].sequence if events else None
        criteria: dict[str, JsonValue] = {
            **request_criteria,
            "executed_snapshot_sequence": snapshot,
            "executed_limit": effective_limit,
            "returned_from": returned_from,
            "returned_to": returned_to,
            "returned_count": len(events),
        }
        writer = AuditWriter(
            session,
            outbox=OutboxWriter(),
            payload_registry=dependencies.payload_registry,
        )
        criteria_digest = hashlib.sha256(canonical_json_bytes(criteria)).hexdigest()
        await writer.append(
            context,
            "audit.read",
            ResourceRef(
                tenant_id=context.tenant_id,
                kind="audit.ledger",
                id=context.tenant_id,
                version=1,
            ),
            criteria,
            f"audit-read:{context.correlation_id}:{criteria_digest}",
            policy_evidence=evidence,
        )
        return AuditEventPage(
            events=events,
            snapshot_sequence=snapshot,
            next_after_sequence=returned_to if returned_to is not None else after_sequence,
        )
