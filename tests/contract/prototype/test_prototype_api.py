"""Authenticated real-application contract for all seven prototype operations."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, get_args
from uuid import UUID

import httpx
import pytest
from _contract import require_module
from _fake_controller import PLAN_HASH, RUN_ID, RecordingController
from nexus_contracts.platform import RequestContext
from nexus_security.dependencies import require_context
from pydantic import BaseModel

OPERATIONS = {
    ("POST", "/api/v1/prototype/runs"): "createPrototypeRun",
    ("GET", "/api/v1/prototype/runs/{run_id}"): "getPrototypeRun",
    ("GET", "/api/v1/prototype/runs/{run_id}/graph"): "getPrototypeGraph",
    ("GET", "/api/v1/prototype/runs/{run_id}/trace"): "getPrototypeTrace",
    ("POST", "/api/v1/prototype/runs/{run_id}/approval"): "approvePrototypeRun",
    ("POST", "/api/v1/prototype/runs/{run_id}/execute"): "executePrototypeRun",
    ("GET", "/prototype"): "getPrototypeDashboard",
}
PROBLEM_FIELDS = {
    "type",
    "title",
    "status",
    "detail",
    "instance",
    "code",
    "correlation_id",
}
SENTINELS = (
    "PROMPT-NEEDLE",
    "MODEL-OUTPUT-NEEDLE",
    "POLICY-INPUT-NEEDLE",
    "API-KEY-NEEDLE",
    "BEARER-NEEDLE",
)
EXPECTED_GRAPH = json.loads(
    Path("tests/fixtures/prototype/storm-and-checkout-shift-v1.json").read_text(encoding="utf-8")
)


def _context(kind: str) -> RequestContext:
    values = {
        "operator": ("001", {"operator"}, {"action.propose", "action.read", "action.execute"}),
        "approver": ("002", {"approver"}, {"action.read", "action.approve"}),
        "other": ("003", {"operator"}, {"action.propose", "action.read", "action.execute"}),
    }
    suffix, roles, scopes = values[kind]
    tenant_suffix = "001" if kind != "other" else "999"
    return RequestContext(
        tenant_id=UUID(f"018f0000-0000-7000-8000-000000000{tenant_suffix}"),
        actor_id=UUID(f"018f0000-0000-7000-8000-000000000{suffix}"),
        correlation_id=UUID(f"019fe476-8380-7000-8000-000000000{suffix}"),
        roles=frozenset(roles),
        scopes=frozenset(scopes),
        sensitivity_clearances=frozenset({"internal"}),
    )


def _app_and_route() -> tuple[Any, Any]:
    prototype = require_module("nexus_api.routes.prototype")
    return require_module("nexus_api.main").app, prototype


@contextmanager
def _overrides(context: RequestContext, controller: RecordingController) -> Iterator[Any]:
    app, prototype = _app_and_route()
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[prototype.get_prototype_controller] = lambda: controller
    try:
        yield app
    finally:
        app.dependency_overrides.clear()


def _client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _assert_problem(response: httpx.Response, status: int, code: str) -> None:
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith("application/problem+json")
    assert set(response.json()) == PROBLEM_FIELDS
    assert response.json()["status"] == status
    assert response.json()["code"] == code
    assert not any(sentinel in response.text for sentinel in SENTINELS)


def test_actual_app_registers_exact_prototype_operation_ids_once() -> None:
    app, prototype = _app_and_route()
    actual: dict[tuple[str, str], str | None] = {}
    for route in prototype.router.routes:
        for method in getattr(route, "methods", set()):
            actual[(method, getattr(route, "path", ""))] = getattr(route, "operation_id", None)
    for route, operation_id in OPERATIONS.items():
        assert actual.get(route) == operation_id
    assert sum(operation_id in actual.values() for operation_id in OPERATIONS.values()) == 7
    assert app is not None


@pytest.mark.asyncio
async def test_six_governed_operations_require_context_and_dashboard_stays_previewable() -> None:
    app, _ = _app_and_route()
    async with _client(app) as client:
        responses = await asyncio.gather(
            client.post("/api/v1/prototype/runs"),
            client.get(f"/api/v1/prototype/runs/{RUN_ID}"),
            client.get(f"/api/v1/prototype/runs/{RUN_ID}/graph"),
            client.get(f"/api/v1/prototype/runs/{RUN_ID}/trace"),
            client.post(f"/api/v1/prototype/runs/{RUN_ID}/approval"),
            client.post(f"/api/v1/prototype/runs/{RUN_ID}/execute"),
        )
    for response in responses:
        _assert_problem(response, 401, "missing_token")
    async with _client(app) as client:
        dashboard = await client.get("/prototype")
    assert dashboard.status_code == 200


@pytest.mark.asyncio
async def test_authenticated_real_app_overrides_forward_trusted_context_and_headers() -> None:
    controller = RecordingController()
    operator = _context("operator")
    approver = _context("approver")
    with _overrides(operator, controller) as app:
        async with _client(app) as client:
            created = await client.post(
                "/api/v1/prototype/runs",
                headers={"Idempotency-Key": "create-contract-v1"},
                json={"scenario_id": "storm-and-checkout-shift-v1"},
            )
            run = await client.get(f"/api/v1/prototype/runs/{RUN_ID}")
            graph = await client.get(f"/api/v1/prototype/runs/{RUN_ID}/graph")
            trace = await client.get(f"/api/v1/prototype/runs/{RUN_ID}/trace")
            dashboard = await client.get("/prototype")
    with _overrides(approver, controller) as app:
        async with _client(app) as client:
            approved = await client.post(
                f"/api/v1/prototype/runs/{RUN_ID}/approval",
                headers={"Idempotency-Key": "approve-contract-v1", "If-Match": f'"{PLAN_HASH}"'},
                json={"plan_hash": PLAN_HASH, "decision": "approve"},
            )
    with _overrides(operator, controller) as app:
        async with _client(app) as client:
            executed = await client.post(
                f"/api/v1/prototype/runs/{RUN_ID}/execute",
                headers={"Idempotency-Key": "execute-contract-v1", "If-Match": f'"{PLAN_HASH}"'},
                json={"plan_hash": PLAN_HASH},
            )

    assert [created.status_code, run.status_code, graph.status_code, trace.status_code] == [
        201,
        200,
        200,
        200,
    ]
    assert approved.status_code == executed.status_code == dashboard.status_code == 200
    assert len(created.json()["audit_events"]) == 8
    assert len(approved.json()["audit_events"]) == 9
    assert len(executed.json()["audit_events"]) == 11
    assert [name for name, _, _ in controller.calls] == [
        "create_run",
        "get_run",
        "get_graph",
        "get_trace",
        "approve",
        "execute",
    ]
    assert [context for _, context, _ in controller.calls[:4]] == [operator] * 4
    assert controller.calls[4][1] == approver
    assert controller.calls[5][1] == operator
    assert controller.calls[0][2][-1] == "create-contract-v1"
    assert controller.calls[4][2][-2:] == ("approve-contract-v1", PLAN_HASH)
    assert controller.calls[5][2][-2:] == ("execute-contract-v1", PLAN_HASH)


@pytest.mark.asyncio
async def test_authenticated_graph_exactly_matches_fixture_and_signal_evidence_allowlist() -> None:
    controller = RecordingController()
    with _overrides(_context("operator"), controller) as app:
        async with _client(app) as client:
            graph = await client.get(f"/api/v1/prototype/runs/{RUN_ID}/graph")
            run = await client.get(f"/api/v1/prototype/runs/{RUN_ID}")
    assert graph.json() == EXPECTED_GRAPH
    allowlist = {node["id"] for node in EXPECTED_GRAPH["nodes"]}
    assert all(set(signal["evidence_node_ids"]) <= allowlist for signal in run.json()["signals"])


@pytest.mark.asyncio
async def test_authenticated_bodies_cannot_supply_authority_and_headers_are_bounded() -> None:
    controller = RecordingController()
    body = {
        "scenario_id": "storm-and-checkout-shift-v1",
        "tenant_id": "018f0000-0000-7000-8000-000000000999",
        "actor_id": "018f0000-0000-7000-8000-000000000999",
        "role": "approver",
        "risk_class": "R3",
        "destination": "https://API-KEY-NEEDLE.example/",
        "policy_facts": {"raw": "POLICY-INPUT-NEEDLE"},
        "evidence_node_ids": ["PROMPT-NEEDLE"],
        "model_output": "MODEL-OUTPUT-NEEDLE",
        "authorization": "BEARER-NEEDLE",
    }
    with _overrides(_context("operator"), controller) as app:
        async with _client(app) as client:
            forbidden = await client.post(
                "/api/v1/prototype/runs", headers={"Idempotency-Key": "create"}, json=body
            )
            oversized = await client.post(
                "/api/v1/prototype/runs",
                headers={"Idempotency-Key": "x" * 256},
                json={"scenario_id": "storm-and-checkout-shift-v1"},
            )
            malformed = await client.post(
                f"/api/v1/prototype/runs/{RUN_ID}/approval",
                headers={"Idempotency-Key": "approve", "If-Match": "not-a-hash"},
                json={"plan_hash": PLAN_HASH, "approved": True},
            )
    _assert_problem(forbidden, 422, "invalid_prototype_request")
    _assert_problem(oversized, 400, "invalid_idempotency_key")
    _assert_problem(malformed, 400, "invalid_if_match")
    assert controller.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception_name,status,code",
    [
        ("PrototypeNotFound", 404, "prototype_not_found"),
        ("PrototypeForbidden", 403, "prototype_forbidden"),
        ("PrototypeConflict", 409, "prototype_conflict"),
        ("PrototypePreconditionFailed", 412, "prototype_precondition_failed"),
        ("PrototypeValidationError", 422, "prototype_validation_failed"),
        ("PrototypeDependencyUnavailable", 503, "prototype_dependency_unavailable"),
    ],
)
async def test_controller_failures_project_stable_nonleaking_rfc9457(
    exception_name: str, status: int, code: str
) -> None:
    service = require_module("nexus_api.prototype.service")
    controller = RecordingController()
    controller.failure = getattr(service, exception_name)()
    with _overrides(_context("operator"), controller) as app:
        async with _client(app) as client:
            response = await client.get(f"/api/v1/prototype/runs/{RUN_ID}")
    _assert_problem(response, status, code)


@pytest.mark.asyncio
async def test_cross_tenant_override_is_nonenumerating_for_every_run_operation() -> None:
    """Read, graph, trace, approval, and execution are indistinguishable from an absent run."""
    service = require_module("nexus_api.prototype.service")
    controller = RecordingController()
    controller.failure = service.PrototypeNotFound()
    other = _context("other")
    with _overrides(other, controller) as app:
        async with _client(app) as client:
            responses = [
                await client.get(f"/api/v1/prototype/runs/{RUN_ID}"),
                await client.get(f"/api/v1/prototype/runs/{RUN_ID}/graph"),
                await client.get(f"/api/v1/prototype/runs/{RUN_ID}/trace"),
                await client.post(
                    f"/api/v1/prototype/runs/{RUN_ID}/approval",
                    headers={"Idempotency-Key": "other-approve", "If-Match": f'"{PLAN_HASH}"'},
                    json={"plan_hash": PLAN_HASH, "decision": "approve"},
                ),
                await client.post(
                    f"/api/v1/prototype/runs/{RUN_ID}/execute",
                    headers={"Idempotency-Key": "other-execute", "If-Match": f'"{PLAN_HASH}"'},
                    json={"plan_hash": PLAN_HASH},
                ),
            ]
    for response in responses:
        _assert_problem(response, 404, "prototype_not_found")
    assert len(controller.calls) == 5
    assert all(context == other for _, context, _ in controller.calls)


def test_run_graph_and_trace_models_are_closed_safe_shapes() -> None:
    """Every serialized surface is extra-forbidding while safe version/digest metadata remains."""
    models = require_module("nexus_api.prototype.models")
    expected = {
        "PrototypeRunView": {
            "schema_version",
            "run_id",
            "scenario_id",
            "seed_digest",
            "status",
            "tenant_id",
            "tenant_name",
            "proposer_id",
            "signals",
            "findings",
            "llm",
            "plan",
            "approval",
            "execution",
            "verification",
            "audit_events",
        },
        "PrototypeGraph": {
            "schema_version",
            "projection_kind",
            "seed_digest",
            "scenario_id",
            "nodes",
            "edges",
        },
        "PrototypeTrace": {"schema_version", "run_id", "events"},
    }
    for name, fields in expected.items():
        model = getattr(models, name)
        assert model.model_config.get("extra") == "forbid"
        assert set(model.model_fields) == fields
    annotation = models.PrototypeRunView.model_fields["llm"].annotation
    candidates = (annotation, *get_args(annotation))
    briefing = next(
        item for item in candidates if isinstance(item, type) and issubclass(item, BaseModel)
    )
    assert briefing.model_config.get("extra") == "forbid"
    assert {"prompt_version", "summary_sha256", "citation_node_ids"} <= set(briefing.model_fields)
    assert not {"prompt", "model_output", "api_key", "authorization", "policy_input"} & set(
        briefing.model_fields
    )


@pytest.mark.asyncio
async def test_authenticated_dashboard_has_accessibility_safety_and_prototype_labels() -> None:
    with _overrides(_context("operator"), RecordingController()) as app:
        async with _client(app) as client:
            response = await client.get("/prototype")
    assert response.status_code == 200
    html = response.text
    for label in (
        "PROTOTYPE",
        "READ-ONLY PROJECTION",
        "SIMULATED ACTION",
        "graph",
        "timeline",
        "audit",
        "prefers-reduced-motion",
    ):
        assert label.lower() in html.lower()
    assert "innerHTML" not in html
