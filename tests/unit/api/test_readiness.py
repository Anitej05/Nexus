"""Required and optional dependency readiness behavior."""

import asyncio
from time import monotonic, sleep

import httpx
import pytest
from nexus_api.contributions import health
from nexus_api.main import app


@pytest.mark.asyncio
async def test_readiness_returns_503_for_missing_required_dependency_and_lists_optionals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Returning 200 for a missing required service makes Compose report a false healthy API."""
    async def tcp_ready(host: str, port: int) -> bool:
        return (host, port) != ("postgres", 5432)

    monkeypatch.setattr(health, "_tcp_ready", tcp_ready)
    monkeypatch.setattr(health, "_http_ready", lambda url: True)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health/ready")

    payload = response.json()
    assert response.status_code == 503
    assert payload["status"] == "not_ready"
    assert payload["dependencies"]["postgres"] is False
    assert set(payload["optional_dependencies"]) >= {"minio", "redis", "neo4j", "mlflow"}


@pytest.mark.asyncio
async def test_readiness_uses_compose_dns_name_for_otel_optional_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The underscore key is not the hyphenated Compose DNS service name."""
    observed_hosts: list[str] = []

    async def tcp_ready(host: str, port: int) -> bool:
        observed_hosts.append(host)
        return True

    monkeypatch.setattr(health, "_tcp_ready", tcp_ready)
    monkeypatch.setattr(health, "_http_ready", lambda url: True)
    await health.ready()

    assert "otel-collector" in observed_hosts


@pytest.mark.asyncio
async def test_readiness_checks_required_and_optional_dependencies_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Serial dependency probes let one unreachable optional exceed the API health deadline."""
    async def slow_tcp_ready(host: str, port: int) -> bool:
        await asyncio.sleep(0.05)
        return True

    def slow_http_ready(url: str) -> bool:
        sleep(0.05)
        return True

    monkeypatch.setattr(health, "_tcp_ready", slow_tcp_ready)
    monkeypatch.setattr(health, "_http_ready", slow_http_ready)

    started = monotonic()
    response = await health.ready()
    elapsed = monotonic() - started

    assert elapsed < 0.15
    assert response.status_code == 200
    assert response.body.find(b'"otel_collector":true') >= 0
