"""Actual-app audit route surface contract."""

from __future__ import annotations

from typing import Any, cast

import httpx
import pytest
from nexus_api.main import app
from nexus_api.routes.audit import (
    AuditRouteDependencies,
    OpaAuditReadPolicy,
    get_audit_dependencies,
    router,
)
from nexus_contracts.platform import PolicyDecision, RequestContext
from nexus_security.dependencies import require_context
from nexus_security.ids import new_id
from nexus_security.policy import AuthorizationEvidence
from nexus_security.tenancy import TenantSession


@pytest.mark.asyncio
async def test_actual_app_registers_bounded_audit_route() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/v1/audit/events")
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")


def test_audit_route_query_bounds_are_in_openapi_route_model() -> None:
    route = next(
        route for route in router.routes if getattr(route, "path", None) == "/api/v1/audit/events"
    )
    names = {field.name: field for field in route.dependant.query_params}
    assert names["after_sequence"].field_info.default == 0
    assert names["limit"].field_info.default == 100
    assert names["snapshot_sequence"].field_info.default is None


class _FixedPolicy:
    def __init__(self, evidence: AuthorizationEvidence) -> None:
        self.evidence = evidence

    async def authorize(self, context, attributes):
        return self.evidence


class _CapturingDenyPolicy:
    def __init__(self) -> None:
        self.attributes = None

    async def authorize(self, context, attributes):
        self.attributes = attributes
        return AuthorizationEvidence(
            decision=PolicyDecision(
                decision_id=new_id(), allow=False, reason_codes=("role_not_granted",)
            ),
            policy_revision="1.0.0",
            canonical_input_sha256="d" * 64,
        )


def _context() -> RequestContext:
    return RequestContext(
        tenant_id=new_id(),
        actor_id=new_id(),
        correlation_id=new_id(),
        roles=frozenset({"viewer"}),
        scopes=frozenset({"audit.read"}),
        sensitivity_clearances=frozenset({"internal"}),
    )


async def _request_with(evidence: AuthorizationEvidence):
    context = _context()
    dependencies = AuditRouteDependencies(
        cast(TenantSession, cast(Any, object())), _FixedPolicy(evidence)
    )
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[get_audit_dependencies] = lambda: dependencies
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.get("/api/v1/audit/events")
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_policy_denial_and_outage_have_typed_nonleaking_problems() -> None:
    denied = await _request_with(
        AuthorizationEvidence(
            decision=PolicyDecision(
                decision_id=new_id(), allow=False, reason_codes=("role_not_granted",)
            ),
            policy_revision="1.0.0",
            canonical_input_sha256="a" * 64,
        )
    )
    assert denied.status_code == 403
    assert denied.headers["content-type"].startswith("application/problem+json")
    assert denied.json()["code"] == "audit_read_denied"
    outage = await _request_with(
        AuthorizationEvidence(
            decision=PolicyDecision(
                decision_id=new_id(), allow=False, reason_codes=("policy_unavailable",)
            ),
            policy_revision=None,
        )
    )
    assert outage.status_code == 503
    assert outage.json()["code"] == "policy_unavailable"
    assert "decision_id" not in outage.text


@pytest.mark.asyncio
async def test_unknown_or_redaction_obligations_fail_closed_before_database_io() -> None:
    for obligation in ("unknown:value", "redact_properties:public_payload"):
        response = await _request_with(
            AuthorizationEvidence(
                decision=PolicyDecision(
                    decision_id=new_id(), allow=True, obligations=(obligation,)
                ),
                policy_revision="1.0.0",
                canonical_input_sha256="b" * 64,
            )
        )
        assert response.status_code == 403
        assert response.json()["code"] == "unsupported_policy_obligation"


@pytest.mark.asyncio
async def test_invalid_query_uses_canonical_nonleaking_problem() -> None:
    context = _context()
    dependencies = AuditRouteDependencies(
        cast(TenantSession, cast(Any, object())),
        _FixedPolicy(
            AuthorizationEvidence(
                decision=PolicyDecision(decision_id=new_id(), allow=True),
                policy_revision="1.0.0",
                canonical_input_sha256="c" * 64,
            )
        ),
    )
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[get_audit_dependencies] = lambda: dependencies
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/audit/events", params={"limit": 501})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "invalid_audit_query"
    assert "input" not in response.text


@pytest.mark.asyncio
async def test_policy_evidence_receives_every_normalized_query_filter() -> None:
    context = _context()
    policy = _CapturingDenyPolicy()
    dependencies = AuditRouteDependencies(cast(TenantSession, cast(Any, object())), policy)
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[get_audit_dependencies] = lambda: dependencies
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/api/v1/audit/events",
                params={
                    "after_sequence": 3,
                    "snapshot_sequence": 9,
                    "limit": 7,
                    "event_type": "test.event",
                    "resource_kind": "test.subject",
                    "resource_id": str(context.actor_id),
                    "actor_id": str(context.actor_id),
                    "correlation_id": str(context.correlation_id),
                    "occurred_from": "2026-08-10T00:00:00Z",
                    "occurred_to": "2026-08-10T01:00:00Z",
                },
            )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 403
    assert policy.attributes == {
        "criteria": {
            "after_sequence": 3,
            "snapshot_sequence": 9,
            "limit": 7,
            "event_type": "test.event",
            "resource_kind": "test.subject",
            "resource_id": str(context.actor_id),
            "actor_id": str(context.actor_id),
            "correlation_id": str(context.correlation_id),
            "occurred_from": "2026-08-10T00:00:00.000000Z",
            "occurred_to": "2026-08-10T01:00:00.000000Z",
        }
    }


@pytest.mark.asyncio
async def test_opa_audit_decision_identity_is_retry_stable(monkeypatch) -> None:
    context = _context()
    requests = []

    async def authorize_with_evidence(_client, request):
        requests.append(request)
        return AuthorizationEvidence(
            decision=PolicyDecision(decision_id=request.decision_id, allow=True),
            policy_revision="1.0.0",
            canonical_input_sha256="e" * 64,
        )

    monkeypatch.setattr(
        "nexus_api.routes.audit.PolicyClient.authorize_with_evidence",
        authorize_with_evidence,
    )
    policy = OpaAuditReadPolicy()
    criteria = {"criteria": {"after_sequence": 0, "snapshot_sequence": 7}}
    first = await policy.authorize(context, criteria)
    second = await policy.authorize(context, criteria)

    assert first.decision.decision_id == context.correlation_id
    assert second.decision.decision_id == context.correlation_id
    assert [request.decision_id for request in requests] == [
        context.correlation_id,
        context.correlation_id,
    ]
