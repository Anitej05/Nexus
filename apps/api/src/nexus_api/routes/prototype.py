"""Authenticated governance surface for the bounded NEXUS prototype."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable
from pathlib import Path
from typing import Annotated, TypeVar
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.routing import APIRoute
from nexus_contracts.platform import JsonValue, Problem, RequestContext, ResourceRef
from nexus_llm import OpenAICompatibleStructuredOutput
from nexus_security.dependencies import require_context
from nexus_security.ids import new_id
from nexus_security.policy import (
    ActorIdentity,
    ApprovalFacts,
    AuthorizationEvidence,
    AuthorizationInput,
    PolicyClient,
    TrustedPolicyFacts,
)
from nexus_security.tenancy import TenantSession
from pydantic import UUID7

from nexus_api.prototype.llm import StructuredAdvisoryFacade, prototype_llm_settings
from nexus_api.prototype.models import (
    CreatePrototypeRunRequest,
    PrototypeApprovalCommand,
    PrototypeExecutionCommand,
    PrototypeGraph,
    PrototypeRunView,
    PrototypeTrace,
)
from nexus_api.prototype.service import (
    PrototypeConflict,
    PrototypeController,
    PrototypeDependencyUnavailable,
    PrototypeForbidden,
    PrototypeNotFound,
    PrototypePreconditionFailed,
    PrototypeValidationError,
)
from nexus_api.prototype.store import prototype_payload_registry

PROTOTYPE_AUDIT_REGISTRY = prototype_payload_registry()


class _InvalidIdempotencyKey(ValueError):
    pass


def _correlation(request: Request) -> UUID7:
    raw = request.headers.get("X-Correlation-ID")
    try:
        value = UUID(raw) if raw else new_id()
        return value if value.version == 7 else new_id()
    except ValueError:
        return new_id()


def _problem_response(
    correlation_id: UUID7, status: int, code: str, title: str, detail: str
) -> JSONResponse:
    problem = Problem(
        type=f"https://nexus.local/problems/{code.replace('_', '-')}",
        title=title,
        status=status,
        detail=detail,
        code=code,
        correlation_id=correlation_id,
    )
    return JSONResponse(
        status_code=status,
        content=problem.model_dump(mode="json", exclude={"schema_version"}),
        media_type="application/problem+json",
    )


class PrototypeProblemRoute(APIRoute):
    def get_route_handler(self):  # type: ignore[no-untyped-def]
        original = super().get_route_handler()

        async def handler(request: Request):  # type: ignore[no-untyped-def]
            try:
                return await original(request)
            except _InvalidIdempotencyKey:
                return _problem_response(
                    _correlation(request),
                    400,
                    "invalid_idempotency_key",
                    "Invalid idempotency key",
                    "The idempotency key is malformed.",
                )
            except RequestValidationError as error:
                invalid_if_match = any(
                    len(item.get("loc", ())) >= 2
                    and item["loc"][0] == "header"
                    and str(item["loc"][1]).lower() == "if-match"
                    for item in error.errors()
                )
                return _problem_response(
                    _correlation(request),
                    400 if invalid_if_match else 422,
                    "invalid_if_match" if invalid_if_match else "invalid_prototype_request",
                    "Invalid If-Match" if invalid_if_match else "Invalid prototype request",
                    "The If-Match header is malformed."
                    if invalid_if_match
                    else "The prototype request is malformed.",
                )
            except PrototypeDependencyUnavailable:
                return _problem_response(
                    _correlation(request),
                    503,
                    "prototype_dependency_unavailable",
                    "Prototype dependency unavailable",
                    "A required prototype dependency is unavailable.",
                )

        return handler


router = APIRouter(tags=["prototype"], route_class=PrototypeProblemRoute)


class OpaPrototypePolicy:
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
    ) -> AuthorizationEvidence:
        resources = (
            ()
            if run_id is None
            else (
                ResourceRef(
                    tenant_id=context.tenant_id, kind="prototype.run", id=run_id, version=1
                ),
            )
        )
        approval = None
        if operation == "action.execute" and run_id and plan_hash and proposer_id and approver_id:
            approval = ApprovalFacts(
                tenant_id=context.tenant_id,
                action_id=run_id,
                action_version=1,
                plan_hash=plan_hash,
                approver_id=approver_id,
                requester_id=proposer_id,
                proposer_id=proposer_id,
                executor_id=context.actor_id,
                consumed=bool(approval_consumed),
            )
        facts = TrustedPolicyFacts(
            resource_sensitivity=frozenset({"internal"}),
            configured_base_risk="R3" if operation == "action.execute" else "R0",
            contextual_risk="R3" if operation == "action.execute" else "R0",
            approval=approval,
            action_id=run_id if operation == "action.execute" else None,
            action_version=1 if operation == "action.execute" else None,
            plan_hash=plan_hash if operation == "action.execute" else None,
        )
        attributes: dict[str, JsonValue] = {}
        if plan_hash is not None:
            attributes["plan_hash"] = plan_hash
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
            resources=resources,
            operation=operation,
            attributes=attributes,
            trusted_facts=facts,
        )
        async with httpx.AsyncClient() as client:
            return await PolicyClient(
                client,
                os.getenv("NEXUS_OPA_DECISION_URL", "http://opa:8181/v1/data/nexus/authz/decision"),
            ).authorize_with_evidence(request)


async def get_prototype_controller(request: Request) -> AsyncIterator[PrototypeController]:
    configured = getattr(request.app.state, "prototype_controller", None)
    if isinstance(configured, PrototypeController):
        yield configured
        return
    database_url = os.getenv("NEXUS_DATABASE_URL")
    if not database_url:
        raise PrototypeDependencyUnavailable()
    settings = prototype_llm_settings()
    controller = PrototypeController(
        TenantSession(database_url),
        OpaPrototypePolicy(),
        StructuredAdvisoryFacade(
            OpenAICompatibleStructuredOutput(settings), model_id=settings.model_id
        ),
    )
    try:
        yield controller
    finally:
        await controller.aclose()


ResultT = TypeVar("ResultT", PrototypeRunView, PrototypeGraph, PrototypeTrace)


def _require_idempotency_key(
    value: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> str:
    if value is None or not value or len(value.encode("utf-8")) > 128:
        raise _InvalidIdempotencyKey
    return value


async def _project(context: RequestContext, result: Awaitable[ResultT]) -> ResultT | JSONResponse:
    try:
        return await result
    except PrototypeNotFound:
        return _problem_response(
            context.correlation_id,
            404,
            "prototype_not_found",
            "Prototype not found",
            "The prototype run was not found.",
        )
    except PrototypeForbidden:
        return _problem_response(
            context.correlation_id,
            403,
            "prototype_forbidden",
            "Prototype request forbidden",
            "The prototype request is not permitted.",
        )
    except PrototypeConflict:
        return _problem_response(
            context.correlation_id,
            409,
            "prototype_conflict",
            "Prototype state conflict",
            "The prototype command conflicts with current state.",
        )
    except PrototypePreconditionFailed:
        return _problem_response(
            context.correlation_id,
            412,
            "prototype_precondition_failed",
            "Prototype precondition failed",
            "The immutable plan precondition did not match.",
        )
    except PrototypeValidationError:
        return _problem_response(
            context.correlation_id,
            422,
            "prototype_validation_failed",
            "Prototype validation failed",
            "The prototype command failed validation.",
        )
    except PrototypeDependencyUnavailable:
        return _problem_response(
            context.correlation_id,
            503,
            "prototype_dependency_unavailable",
            "Prototype dependency unavailable",
            "A required prototype dependency is unavailable.",
        )
    except Exception:
        return _problem_response(
            context.correlation_id,
            503,
            "prototype_dependency_unavailable",
            "Prototype dependency unavailable",
            "A required prototype dependency is unavailable.",
        )


@router.post(
    "/api/v1/prototype/runs",
    operation_id="createPrototypeRun",
    response_model=PrototypeRunView,
    status_code=201,
)
async def create_prototype_run(
    request: CreatePrototypeRunRequest,
    context: Annotated[RequestContext, Depends(require_context)],
    controller: Annotated[PrototypeController, Depends(get_prototype_controller)],
    idempotency_key: Annotated[str, Depends(_require_idempotency_key)],
) -> PrototypeRunView | JSONResponse:
    return await _project(context, controller.create_run(context, request, idempotency_key))


@router.get(
    "/api/v1/prototype/runs/{run_id}",
    operation_id="getPrototypeRun",
    response_model=PrototypeRunView,
)
async def get_prototype_run(
    run_id: UUID7,
    context: Annotated[RequestContext, Depends(require_context)],
    controller: Annotated[PrototypeController, Depends(get_prototype_controller)],
) -> PrototypeRunView | JSONResponse:
    return await _project(context, controller.get_run(context, run_id))


@router.get(
    "/api/v1/prototype/runs/{run_id}/graph",
    operation_id="getPrototypeGraph",
    response_model=PrototypeGraph,
)
async def get_prototype_graph(
    run_id: UUID7,
    context: Annotated[RequestContext, Depends(require_context)],
    controller: Annotated[PrototypeController, Depends(get_prototype_controller)],
) -> PrototypeGraph | JSONResponse:
    return await _project(context, controller.get_graph(context, run_id))


@router.get(
    "/api/v1/prototype/runs/{run_id}/trace",
    operation_id="getPrototypeTrace",
    response_model=PrototypeTrace,
)
async def get_prototype_trace(
    run_id: UUID7,
    context: Annotated[RequestContext, Depends(require_context)],
    controller: Annotated[PrototypeController, Depends(get_prototype_controller)],
) -> PrototypeTrace | JSONResponse:
    return await _project(context, controller.get_trace(context, run_id))


@router.post(
    "/api/v1/prototype/runs/{run_id}/approval",
    operation_id="approvePrototypeRun",
    response_model=PrototypeRunView,
)
async def approve_prototype_run(
    run_id: UUID7,
    command: PrototypeApprovalCommand,
    context: Annotated[RequestContext, Depends(require_context)],
    controller: Annotated[PrototypeController, Depends(get_prototype_controller)],
    idempotency_key: Annotated[str, Depends(_require_idempotency_key)],
    if_match: Annotated[
        str,
        Header(
            alias="If-Match",
            min_length=66,
            max_length=66,
            pattern=r'^"[0-9a-f]{64}"$',
        ),
    ],
) -> PrototypeRunView | JSONResponse:
    return await _project(
        context,
        controller.approve(context, run_id, command, idempotency_key, if_match[1:-1]),
    )


@router.post(
    "/api/v1/prototype/runs/{run_id}/execute",
    operation_id="executePrototypeRun",
    response_model=PrototypeRunView,
)
async def execute_prototype_run(
    run_id: UUID7,
    command: PrototypeExecutionCommand,
    context: Annotated[RequestContext, Depends(require_context)],
    controller: Annotated[PrototypeController, Depends(get_prototype_controller)],
    idempotency_key: Annotated[str, Depends(_require_idempotency_key)],
    if_match: Annotated[
        str,
        Header(
            alias="If-Match",
            min_length=66,
            max_length=66,
            pattern=r'^"[0-9a-f]{64}"$',
        ),
    ],
) -> PrototypeRunView | JSONResponse:
    return await _project(
        context,
        controller.execute(context, run_id, command, idempotency_key, if_match[1:-1]),
    )


@router.get("/prototype", operation_id="getPrototypeDashboard")
async def get_prototype_dashboard() -> FileResponse:
    return FileResponse(Path(__file__).parents[1] / "static" / "prototype" / "index.html")
