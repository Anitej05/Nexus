"""PostgreSQL 16 fixtures for tenant-isolation integration tests."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import pytest
from nexus_contracts.platform import RequestContext
from nexus_security.audit_roles import AuditDatabaseRole, validate_audit_database_roles
from nexus_security.ids import new_id
from nexus_security.tenancy import TenantSession
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

_ROOT = Path(__file__).resolve().parents[3]
_LOCAL_TEST_HOST = "127.0.0.1"
_LOCAL_TEST_PORT = 15432


@dataclass(frozen=True)
class TenantContexts:
    alpha: RequestContext
    beta: RequestContext


def _require_safe_compose_urls() -> tuple[str, str, str]:
    """Reject any database target other than the explicit local Compose test DB."""
    if os.environ.get("NEXUS_RUN_COMPOSE_TESTS") != "1":
        pytest.skip("set NEXUS_RUN_COMPOSE_TESTS=1 to run PostgreSQL integration tests")

    runtime_url = os.environ.get("NEXUS_TEST_DATABASE_URL", "")
    migration_url = os.environ.get("NEXUS_TEST_MIGRATION_DATABASE_URL", "")
    admin_url = os.environ.get("NEXUS_TEST_ADMIN_DATABASE_URL", "")
    if not all((runtime_url, migration_url, admin_url)):
        raise RuntimeError("NEXUS_TEST_DATABASE_URL, migration URL, and admin URL are required")
    for label, url, database in (
        ("runtime", runtime_url, "nexus_test"),
        ("migration", migration_url, "nexus_test"),
        ("admin", admin_url, "postgres"),
    ):
        parsed = urlparse(url)
        if parsed.hostname != _LOCAL_TEST_HOST or parsed.port != _LOCAL_TEST_PORT:
            raise RuntimeError(f"refusing {label} database outside local Compose PostgreSQL")
        if parsed.path.lstrip("/") != database:
            raise RuntimeError(f"refusing {label} database other than local {database}")
    return runtime_url, migration_url, admin_url


def _require_safe_recovery_url() -> str:
    recovery_url = os.environ.get("NEXUS_TEST_AUDIT_RECOVERY_DATABASE_URL", "")
    parsed = urlparse(recovery_url)
    if (
        parsed.hostname != _LOCAL_TEST_HOST
        or parsed.port != _LOCAL_TEST_PORT
        or parsed.path.lstrip("/") != "nexus_test"
        or parsed.username != "nexus_audit_recovery"
        or not parsed.password
    ):
        raise RuntimeError("refusing audit recovery database outside guarded local nexus_test")
    return recovery_url


@pytest.fixture(scope="session")
def database_urls() -> tuple[str, str, str]:
    return _require_safe_compose_urls()


@pytest.fixture(scope="session")
def audit_recovery_url() -> str:
    return _require_safe_recovery_url()


@pytest.fixture(scope="session")
def contexts() -> TenantContexts:
    return TenantContexts(
        alpha=RequestContext(
            tenant_id=new_id(),
            actor_id=new_id(),
            correlation_id=new_id(),
            roles=frozenset({"viewer"}),
            scopes=frozenset({"test"}),
            sensitivity_clearances=frozenset({"internal"}),
        ),
        beta=RequestContext(
            tenant_id=new_id(),
            actor_id=new_id(),
            correlation_id=new_id(),
            roles=frozenset({"viewer"}),
            scopes=frozenset({"test"}),
            sensitivity_clearances=frozenset({"internal"}),
        ),
    )


@pytest.fixture(scope="session")
async def bootstrap_test_database(database_urls: tuple[str, str, str]) -> None:
    """Create and mark only the exact dedicated local test database."""
    _, migration_url, admin_url = database_urls
    admin = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
    async with admin.connect() as connection:
        recovery = urlparse(_require_safe_recovery_url())
        password = (recovery.password or "").replace("'", "''")
        role_exists = await connection.scalar(
            text("select exists(select 1 from pg_roles where rolname='nexus_audit_recovery')")
        )
        if not role_exists:
            await connection.execute(  # noqa: S608 -- guarded fixed local test role.
                text(
                    "create role nexus_audit_recovery login nosuperuser nocreatedb "
                    "nocreaterole noinherit nobypassrls password " + f"'{password}'"
                )
            )
        rows = (
            await connection.execute(
                text(
                    "select rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolinherit, rolbypassrls from pg_roles where rolname in "
                    "('nexus_runtime','nexus_migrator','nexus_audit_recovery')"
                )
            )
        ).mappings()
        memberships = (
            await connection.execute(
                text(
                    "select parent.rolname as role_name, child.rolname as member_name "
                    "from pg_auth_members membership "
                    "join pg_roles parent on parent.oid=membership.roleid "
                    "join pg_roles child on child.oid=membership.member "
                    "where parent.rolname in "
                    "('nexus_runtime','nexus_migrator','nexus_audit_recovery') "
                    "or child.rolname in "
                    "('nexus_runtime','nexus_migrator','nexus_audit_recovery')"
                )
            )
        ).mappings()
        validate_audit_database_roles(
            [
                AuditDatabaseRole(
                    row["rolname"],
                    row["rolcanlogin"],
                    row["rolsuper"],
                    row["rolcreatedb"],
                    row["rolcreaterole"],
                    row["rolinherit"],
                    row["rolbypassrls"],
                )
                for row in rows
            ],
            runtime="nexus_runtime",
            migration="nexus_migrator",
            recovery="nexus_audit_recovery",
            memberships=[
                (row["role_name"], row["member_name"]) for row in memberships
            ],
        )
        owner = await connection.scalar(
            text("select pg_get_userbyid(datdba) from pg_database where datname = 'nexus_test'")
        )
        created = owner is None
        if owner is None:
            await connection.execute(text("create database nexus_test owner nexus_migrator"))
        elif owner != "nexus_migrator":
            raise RuntimeError("refusing nexus_test database with an unexpected owner")
        await connection.execute(text("grant connect on database nexus_test to nexus_runtime"))
        await connection.execute(
            text("grant connect on database nexus_test to nexus_audit_recovery")
        )
    await admin.dispose()

    migration = create_async_engine(migration_url)
    async with migration.begin() as connection:
        if created:
            await connection.execute(
                text(
                    "create table public.nexus_test_marker "
                    "(marker text primary key check (marker = 'nexus-security-integration'))"
                )
            )
            await connection.execute(
                text(
                    "insert into public.nexus_test_marker(marker) "
                    "values ('nexus-security-integration')"
                )
            )
        marker = await connection.scalar(
            text("select to_regclass('public.nexus_test_marker') is not null")
        )
        if marker:
            marker = await connection.scalar(text("select marker from public.nexus_test_marker"))
    await migration.dispose()
    if marker != "nexus-security-integration":
        raise RuntimeError("refusing nexus_test database without the integration marker")


@pytest.fixture(scope="session")
async def migrated_schema(
    database_urls: tuple[str, str, str], bootstrap_test_database: None
) -> AsyncIterator[None]:
    """Apply DDL in a separate process because Alembic owns its event loop."""
    _, migration_url, _ = database_urls
    migration_environment = {**os.environ, "NEXUS_MIGRATION_DATABASE_URL": migration_url}
    subprocess.run(  # noqa: ASYNC221, S603
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            str(_ROOT / "apps" / "api" / "alembic.ini"),
            "upgrade",
            "head",
        ],
        check=True,
        cwd=_ROOT,
        env=migration_environment,
    )
    yield


@pytest.fixture(scope="session")
async def migrated_database(
    database_urls: tuple[str, str, str], contexts: TenantContexts, migrated_schema: None
) -> AsyncIterator[None]:
    _, migration_url, _ = database_urls

    engine = create_async_engine(migration_url)
    async with engine.begin() as connection:
        for context in (contexts.alpha, contexts.beta):
            await connection.execute(
                text(
                    "insert into tenants(id, slug, display_name, status, version) "
                    "values (:id, :slug, :name, 'active', 1) on conflict (id) do nothing"
                ),
                {
                    "id": context.tenant_id,
                    "slug": f"test-{context.tenant_id.hex[:12]}",
                    "name": "NEXUS integration test tenant",
                },
            )
        for table in ("tenant_probe", "domain_probe", "audit_probe"):
            await connection.execute(
                text(
                    f"create table if not exists {table} ("
                    "id uuid primary key, tenant_id uuid not null, "
                    "version integer not null default 1 check (version > 0), "
                    "value text, created_at timestamptz not null default now())"
                )
            )
            await connection.execute(text(f"alter table {table} enable row level security"))
            await connection.execute(text(f"alter table {table} force row level security"))
            policy_exists = await connection.scalar(
                text("select exists(select 1 from pg_policies where policyname = :policy)"),
                {"policy": f"{table}_tenant_policy"},
            )
            if not policy_exists:
                await connection.execute(
                    text(
                        f"create policy {table}_tenant_policy on {table} "
                        "using (tenant_id = NULLIF(current_setting("
                        "'nexus.tenant_id', true), '')::uuid) "
                        "with check (tenant_id = NULLIF(current_setting("
                        "'nexus.tenant_id', true), '')::uuid)"
                    )
                )
            await connection.execute(
                text(f"grant select, insert, update, delete on {table} to nexus_runtime")
            )
    await engine.dispose()
    yield
    cleanup = create_async_engine(migration_url)
    async with cleanup.begin() as connection:
        parameters = {
            "alpha_tenant": contexts.alpha.tenant_id,
            "beta_tenant": contexts.beta.tenant_id,
            "alpha_actor": contexts.alpha.actor_id,
            "beta_actor": contexts.beta.actor_id,
        }
        await connection.execute(
            text("delete from consumer_receipts where tenant_id in (:alpha_tenant, :beta_tenant)"),
            parameters,
        )
        await connection.execute(
            text("delete from outbox_events where tenant_id in (:alpha_tenant, :beta_tenant)"),
            parameters,
        )
        await connection.execute(
            text("delete from tenant_memberships where tenant_id in (:alpha_tenant, :beta_tenant)"),
            parameters,
        )
        await connection.execute(
            text("delete from external_principals where actor_id in (:alpha_actor, :beta_actor)"),
            parameters,
        )
        await connection.execute(
            text("delete from tenants where id in (:alpha_tenant, :beta_tenant)"), parameters
        )
        for statement in (
            text("delete from tenant_probe where tenant_id in (:alpha_tenant, :beta_tenant)"),
            text("delete from domain_probe where tenant_id in (:alpha_tenant, :beta_tenant)"),
            text("delete from audit_probe where tenant_id in (:alpha_tenant, :beta_tenant)"),
        ):
            await connection.execute(statement, parameters)
    await cleanup.dispose()


@pytest.fixture
async def tenant_session(
    database_urls: tuple[str, str, str], migrated_database: None
) -> AsyncIterator[TenantSession]:
    runtime_url, _, _ = database_urls
    sessions = TenantSession(runtime_url)
    try:
        yield sessions
    finally:
        await sessions.dispose()


@pytest.fixture(autouse=True)
async def clear_security_test_rows(
    database_urls: tuple[str, str, str],
    audit_recovery_url: str,
    contexts: TenantContexts,
    migrated_database: None,
) -> AsyncIterator[None]:
    """Keep each integration assertion independent without granting runtime cleanup access."""

    async def clear_audit_rows() -> None:
        recovery = create_async_engine(audit_recovery_url)
        async with recovery.begin() as connection:
            await connection.execute(
                text("delete from audit_events where tenant_id in (:alpha_tenant, :beta_tenant)"),
                parameters,
            )
        await recovery.dispose()

    _, migration_url, _ = database_urls
    engine = create_async_engine(migration_url)
    async with engine.begin() as connection:
        parameters = {
            "alpha_tenant": contexts.alpha.tenant_id,
            "beta_tenant": contexts.beta.tenant_id,
            "alpha_actor": contexts.alpha.actor_id,
            "beta_actor": contexts.beta.actor_id,
        }
        for statement in (
            text("delete from consumer_receipts where tenant_id in (:alpha_tenant, :beta_tenant)"),
            text("delete from outbox_events where tenant_id in (:alpha_tenant, :beta_tenant)"),
            text("delete from tenant_memberships where tenant_id in (:alpha_tenant, :beta_tenant)"),
        ):
            await connection.execute(statement, parameters)
        await connection.execute(
            text("delete from external_principals where actor_id in (:alpha_actor, :beta_actor)"),
            parameters,
        )
        for statement in (
            text("delete from tenant_probe where tenant_id in (:alpha_tenant, :beta_tenant)"),
            text("delete from domain_probe where tenant_id in (:alpha_tenant, :beta_tenant)"),
            text("delete from audit_probe where tenant_id in (:alpha_tenant, :beta_tenant)"),
        ):
            await connection.execute(statement, parameters)
    await engine.dispose()
    await clear_audit_rows()
    yield
    await clear_audit_rows()


@pytest.fixture
async def runtime_engine(
    database_urls: tuple[str, str, str], migrated_database: None
) -> AsyncIterator[AsyncEngine]:
    runtime_url, _, _ = database_urls
    engine = create_async_engine(runtime_url)
    try:
        yield engine
    finally:
        await engine.dispose()
