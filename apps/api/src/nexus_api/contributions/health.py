"""Task 2 dependency-aware operational health routes."""

from __future__ import annotations

import asyncio
import os
from typing import cast
from urllib.error import URLError
from urllib.request import urlopen

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


async def _tcp_ready(host: str, port: int) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
    except (OSError, TimeoutError):
        return False
    writer.close()
    await writer.wait_closed()
    return True


def _http_ready(url: str) -> bool:
    try:
        with urlopen(url, timeout=2) as response:  # noqa: S310 -- URLs are operator configuration.
            status = cast(int, response.status)
            return 200 <= status < 400
    except URLError:
        return False


@router.get("/health/ready", response_model=None)
async def ready() -> JSONResponse:
    """Report required dependencies individually and fail readiness when any are down."""
    opa_url = os.environ.get("NEXUS_OPA_INTERNAL_URL", "http://opa:8181/health?plugins")
    keycloak_url = os.environ.get(
        "NEXUS_KEYCLOAK_INTERNAL_URL", "http://keycloak:8080/realms/nexus"
    )
    optional_specs = {
        "neo4j": ("NEXUS_NEO4J_HOST", "neo4j", 7687),
        "redpanda": ("NEXUS_REDPANDA_HOST", "redpanda", 9092),
        "minio": ("NEXUS_MINIO_HOST", "minio", 9000),
        "redis": ("NEXUS_REDIS_HOST", "redis", 6379),
        "otel_collector": ("NEXUS_OTEL_COLLECTOR_HOST", "otel-collector", 4317),
        "prometheus": ("NEXUS_PROMETHEUS_HOST", "prometheus", 9090),
        "grafana": ("NEXUS_GRAFANA_HOST", "grafana", 3000),
        "mlflow": ("NEXUS_MLFLOW_HOST", "mlflow", 5000),
    }
    values = await asyncio.gather(
        _tcp_ready(os.environ.get("NEXUS_POSTGRES_HOST", "postgres"), 5432),
        _tcp_ready(os.environ.get("NEXUS_TEMPORAL_HOST", "temporal"), 7233),
        asyncio.to_thread(_http_ready, opa_url),
        asyncio.to_thread(_http_ready, keycloak_url),
        *(
            _tcp_ready(os.environ.get(environment_name, hostname), port)
            for _key, (environment_name, hostname, port) in optional_specs.items()
        ),
    )
    postgres, temporal, opa, keycloak, *optional_values = values
    dependencies = {
        "postgres": postgres,
        "temporal": temporal,
        "opa": opa,
        "keycloak": keycloak,
    }
    payload: dict[str, object] = {
        "status": "ready" if all(dependencies.values()) else "not_ready",
        "dependencies": dependencies,
        "optional_dependencies": dict(zip(optional_specs, optional_values, strict=True)),
    }
    return JSONResponse(payload, status_code=200 if all(dependencies.values()) else 503)
