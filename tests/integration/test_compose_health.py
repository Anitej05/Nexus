"""Compose health contracts, enabled only for an explicitly started stack."""

import os
from pathlib import Path

import httpx
import pytest


@pytest.fixture(scope="session")
def compose_urls() -> dict[str, str]:
    if os.environ.get("NEXUS_RUN_COMPOSE_TESTS") != "1":
        pytest.skip("set NEXUS_RUN_COMPOSE_TESTS=1 after starting the Compose stack")
    environment = _development_environment()
    host = environment["NEXUS_COMPOSE_HOST"]
    return {
        "api": f"http://{host}:{environment['NEXUS_API_HOST_PORT']}",
        "opa": f"http://{host}:{environment['NEXUS_OPA_HOST_PORT']}",
        "keycloak": f"http://{host}:{environment['NEXUS_KEYCLOAK_HOST_PORT']}",
    }


def _development_environment() -> dict[str, str]:
    values = {
        name: value
        for line in Path(".env.example").read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.startswith("#")
        for name, value in [line.split("=", maxsplit=1)]
    }
    return {name: os.environ.get(name, value) for name, value in values.items()}


def test_platform_dependencies_report_healthy(compose_urls: dict[str, str]) -> None:
    assert httpx.get(f"{compose_urls['api']}/health/ready", timeout=10).json()["status"] == "ready"
    assert httpx.get(f"{compose_urls['opa']}/health?plugins", timeout=10).status_code == 200
    keycloak = httpx.get(f"{compose_urls['keycloak']}/realms/nexus", timeout=10)
    assert keycloak.json()["realm"] == "nexus"
