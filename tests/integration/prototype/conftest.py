"""Guarded local PostgreSQL fixtures for prototype ledger acceptance."""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parents[3]
for source in (
    ROOT / "apps" / "api" / "src",
    ROOT / "packages" / "contracts" / "src",
    ROOT / "packages" / "security" / "src",
):
    sys.path.insert(0, str(source))

from nexus_contracts.platform import RequestContext  # noqa: E402
from nexus_security.ids import new_id  # noqa: E402
from nexus_security.tenancy import TenantSession  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402


def _safe_url(name: str, *, username: str | None = None) -> str:
    if os.getenv("NEXUS_RUN_COMPOSE_TESTS") != "1":
        pytest.skip("set NEXUS_RUN_COMPOSE_TESTS=1 for prototype PostgreSQL tests")
    value = os.getenv(name, "")
    parsed = urlparse(value)
    if (
        parsed.hostname != "127.0.0.1"
        or parsed.port != 15432
        or parsed.path.lstrip("/") != "nexus_test"
        or (username is not None and parsed.username != username)
        or not parsed.password
    ):
        raise RuntimeError(f"refusing unsafe {name} outside guarded local nexus_test")
    return value


@pytest.fixture
def prototype_context() -> RequestContext:
    return RequestContext(
        tenant_id=new_id(),
        actor_id=new_id(),
        correlation_id=new_id(),
        roles=frozenset({"operator"}),
        scopes=frozenset({"action.propose"}),
        sensitivity_clearances=frozenset({"internal"}),
    )


@pytest.fixture
async def prototype_session(prototype_context: RequestContext) -> AsyncIterator[TenantSession]:
    runtime_url = _safe_url("NEXUS_TEST_DATABASE_URL", username="nexus_runtime")
    migration_url = _safe_url("NEXUS_TEST_MIGRATION_DATABASE_URL", username="nexus_migrator")
    recovery_url = _safe_url(
        "NEXUS_TEST_AUDIT_RECOVERY_DATABASE_URL", username="nexus_audit_recovery"
    )
    migration = create_async_engine(migration_url)
    recovery = create_async_engine(recovery_url)
    marker = None
    async with migration.begin() as connection:
        marker_exists = await connection.scalar(
            text("select to_regclass('public.nexus_test_marker') is not null")
        )
        if marker_exists:
            marker = await connection.scalar(text("select marker from nexus_test_marker"))
        if marker != "nexus-security-integration":
            raise RuntimeError("refusing nexus_test database without its safety marker")
        await connection.execute(
            text(
                "insert into tenants(id, slug, display_name, status, version) "
                "values (:id, :slug, 'Prototype integration tenant', 'active', 1)"
            ),
            {
                "id": prototype_context.tenant_id,
                "slug": f"prototype-{prototype_context.tenant_id.hex[:12]}",
            },
        )
    sessions = TenantSession(runtime_url)
    try:
        yield sessions
    finally:
        await sessions.dispose()
        async with recovery.begin() as connection:
            await connection.execute(
                text("delete from audit_events where tenant_id=:tenant"),
                {"tenant": prototype_context.tenant_id},
            )
        async with migration.begin() as connection:
            await connection.execute(
                text("delete from outbox_events where tenant_id=:tenant"),
                {"tenant": prototype_context.tenant_id},
            )
            await connection.execute(
                text("delete from tenants where id=:tenant"),
                {"tenant": prototype_context.tenant_id},
            )
        await recovery.dispose()
        await migration.dispose()
