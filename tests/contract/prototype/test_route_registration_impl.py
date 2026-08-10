"""Real-app registration contract for the governed prototype surface."""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest
from nexus_api.contributions import ROUTERS
from nexus_api.main import app
from nexus_api.prototype.models import (
    PrototypeApprovalCommand,
    PrototypeExecutionCommand,
    PrototypeRunView,
)
from nexus_api.prototype.service import PrototypeForbidden
from nexus_api.routes.prototype import get_prototype_controller, router
from nexus_contracts.platform import RequestContext
from nexus_security.dependencies import require_context
from nexus_security.ids import new_id


def test_real_app_registers_all_seven_frozen_prototype_operations() -> None:
    operations = {
        route.operation_id: (next(iter(route.methods)), route.path)
        for route in router.routes
        if getattr(route, "operation_id", None)
        and (route.path == "/prototype" or route.path.startswith("/api/v1/prototype"))
    }
    assert operations == {
        "createPrototypeRun": ("POST", "/api/v1/prototype/runs"),
        "getPrototypeRun": ("GET", "/api/v1/prototype/runs/{run_id}"),
        "getPrototypeGraph": ("GET", "/api/v1/prototype/runs/{run_id}/graph"),
        "getPrototypeTrace": ("GET", "/api/v1/prototype/runs/{run_id}/trace"),
        "approvePrototypeRun": ("POST", "/api/v1/prototype/runs/{run_id}/approval"),
        "executePrototypeRun": ("POST", "/api/v1/prototype/runs/{run_id}/execute"),
        "getPrototypeDashboard": ("GET", "/prototype"),
    }
    assert router in ROUTERS
    assert app is not None
    assert callable(get_prototype_controller)


def test_embedded_preview_is_a_current_model_valid_run() -> None:
    page = (
        Path(__file__).parents[3] / "apps/api/src/nexus_api/static/prototype/index.html"
    ).read_text(encoding="utf-8")
    match = re.search(
        r'<script id="prototype-preview" type="application/json">(.*?)</script>', page
    )
    assert match is not None
    preview = PrototypeRunView.model_validate_json(match.group(1))
    assert preview.seed_digest == (
        "ab6630b92c813392964fad431fe7aba5e2b68f0742e800523d6ceec3196f0e06"
    )
    assert preview.plan.plan_hash == (
        "8814a2fce863a6a334f323da9fa1ce4f5bdb7958be1fea618bef21d230110cca"
    )


def test_api_image_includes_the_declared_llm_workspace_dependency() -> None:
    dockerfile = (
        (Path(__file__).parents[3] / "apps/api/Dockerfile").read_text(encoding="utf-8").splitlines()
    )
    assert "COPY packages/llm/pyproject.toml packages/llm/pyproject.toml" in dockerfile
    assert "COPY packages/llm/src packages/llm/src" in dockerfile


@pytest.mark.asyncio
async def test_route_uses_trusted_context_and_projects_safe_problem() -> None:
    context = RequestContext(
        tenant_id=new_id(),
        actor_id=new_id(),
        correlation_id=new_id(),
        roles=frozenset({"operator"}),
        scopes=frozenset(),
        sensitivity_clearances=frozenset({"internal"}),
    )

    class Controller:
        received = None

        async def create_run(self, trusted, request, idempotency_key):  # type: ignore[no-untyped-def]
            del request, idempotency_key
            self.received = trusted
            raise PrototypeForbidden()

    controller = Controller()
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[get_prototype_controller] = lambda: controller
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/prototype/runs",
                headers={"Idempotency-Key": "route-contract"},
                json={"scenario_id": "storm-and-checkout-shift-v1"},
            )
        assert response.status_code == 403
        assert response.headers["content-type"].startswith("application/problem+json")
        assert response.json()["code"] == "prototype_forbidden"
        assert controller.received == context
        assert "PrototypeForbidden" not in response.text
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_route_maps_missing_mutation_header_to_bounded_400() -> None:
    context = RequestContext(
        tenant_id=new_id(),
        actor_id=new_id(),
        correlation_id=new_id(),
        roles=frozenset({"operator"}),
        scopes=frozenset(),
        sensitivity_clearances=frozenset({"internal"}),
    )
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[get_prototype_controller] = lambda: object()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/prototype/runs",
                json={"scenario_id": "storm-and-checkout-shift-v1"},
            )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_idempotency_key"
        assert "Idempotency-Key" not in response.text
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_route_rejects_multibyte_idempotency_key_over_byte_bound_as_400() -> None:
    context = RequestContext(
        tenant_id=new_id(),
        actor_id=new_id(),
        correlation_id=new_id(),
        roles=frozenset({"operator"}),
        scopes=frozenset(),
        sensitivity_clearances=frozenset({"internal"}),
    )

    class Controller:
        called = False

        async def create_run(self, *args):  # type: ignore[no-untyped-def]
            self.called = True
            raise AssertionError("invalid header reached controller")

    controller = Controller()
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[get_prototype_controller] = lambda: controller
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/prototype/runs",
                headers=[(b"Idempotency-Key", b"\xe9" * 128)],
                json={"scenario_id": "storm-and-checkout-shift-v1"},
            )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_idempotency_key"
        assert controller.called is False
    finally:
        app.dependency_overrides.clear()


def test_rendered_compose_passes_bounded_llm_settings_to_api() -> None:
    root = Path(__file__).parents[3]
    environment = {
        **os.environ,
        "NEXUS_LLM_BASE_URL": "http://proxy.invalid:9997/v1",
        "NEXUS_LLM_MODEL": "deepseek-ai/DeepSeek-V4-Flash-0731",
        "NEXUS_LLM_API_KEY": "contract-only-key",
        "NEXUS_PROTOTYPE_LLM_TIMEOUT_SECONDS": "12",
        "NEXUS_PROTOTYPE_LLM_BASE_URL": "http://prototype-proxy.invalid:9997/v1",
        "NEXUS_PROTOTYPE_LLM_MODEL": "prototype-model",
        "NEXUS_PROTOTYPE_LLM_API_KEY": "prototype-contract-key",
    }
    docker = shutil.which("docker")
    assert docker is not None
    rendered = subprocess.run(  # noqa: S603 -- exact docker path, fixed arguments.
        [
            docker,
            "compose",
            "-f",
            "infrastructure/compose/compose.yml",
            "-f",
            "infrastructure/compose/compose.test.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    api_environment = json.loads(rendered.stdout)["services"]["api"]["environment"]
    assert api_environment["NEXUS_LLM_BASE_URL"] == "http://proxy.invalid:9997/v1"
    assert api_environment["NEXUS_LLM_MODEL"] == "deepseek-ai/DeepSeek-V4-Flash-0731"
    assert api_environment["NEXUS_LLM_API_KEY"] == "contract-only-key"
    assert api_environment["NEXUS_PROTOTYPE_LLM_TIMEOUT_SECONDS"] == "12"
    assert api_environment["NEXUS_PROTOTYPE_LLM_BASE_URL"] == (
        "http://prototype-proxy.invalid:9997/v1"
    )
    assert api_environment["NEXUS_PROTOTYPE_LLM_MODEL"] == "prototype-model"
    assert api_environment["NEXUS_PROTOTYPE_LLM_API_KEY"] == "prototype-contract-key"


@pytest.mark.asyncio
async def test_approval_requires_strong_etag_and_passes_normalized_hash() -> None:
    context = RequestContext(
        tenant_id=new_id(),
        actor_id=new_id(),
        correlation_id=new_id(),
        roles=frozenset({"approver"}),
        scopes=frozenset({"action.approve"}),
        sensitivity_clearances=frozenset({"internal"}),
    )
    plan_hash = "a" * 64
    run_id = new_id()

    class Controller:
        received_if_match = None
        received_execute_if_match = None

        async def approve(self, trusted, target_run, command, idempotency_key, if_match):  # type: ignore[no-untyped-def]
            assert trusted == context
            assert target_run == run_id
            assert command == PrototypeApprovalCommand(plan_hash=plan_hash, decision="approve")
            assert idempotency_key == "etag-contract"
            self.received_if_match = if_match
            raise PrototypeForbidden()

        async def execute(self, trusted, target_run, command, idempotency_key, if_match):  # type: ignore[no-untyped-def]
            assert trusted == context
            assert target_run == run_id
            assert command == PrototypeExecutionCommand(plan_hash=plan_hash)
            assert idempotency_key == "etag-contract-execute"
            self.received_execute_if_match = if_match
            raise PrototypeForbidden()

    controller = Controller()
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[get_prototype_controller] = lambda: controller
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            strong = await client.post(
                f"/api/v1/prototype/runs/{run_id}/approval",
                headers={
                    "Idempotency-Key": "etag-contract",
                    "If-Match": f'"{plan_hash}"',
                },
                json={"plan_hash": plan_hash, "decision": "approve"},
            )
            assert strong.status_code == 403
            assert controller.received_if_match == plan_hash
            strong_execute = await client.post(
                f"/api/v1/prototype/runs/{run_id}/execute",
                headers={
                    "Idempotency-Key": "etag-contract-execute",
                    "If-Match": f'"{plan_hash}"',
                },
                json={"plan_hash": plan_hash},
            )
            assert strong_execute.status_code == 403
            assert controller.received_execute_if_match == plan_hash
            for malformed in (plan_hash, f'W/"{plan_hash}"', '"not-a-hash"'):
                for suffix, body in (
                    ("approval", {"plan_hash": plan_hash, "decision": "approve"}),
                    ("execute", {"plan_hash": plan_hash}),
                ):
                    response = await client.post(
                        f"/api/v1/prototype/runs/{run_id}/{suffix}",
                        headers={
                            "Idempotency-Key": "etag-contract",
                            "If-Match": malformed,
                        },
                        json=body,
                    )
                    assert response.status_code == 400
                    assert response.json()["code"] == "invalid_if_match"
    finally:
        app.dependency_overrides.clear()
