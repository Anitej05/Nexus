"""Tenant RLS behavior must be enforced by PostgreSQL, not application filtering."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from nexus_security.ids import new_id
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine


async def test_database_hides_cross_tenant_rows(tenant_session, contexts) -> None:
    """Removing the SELECT policy would expose another tenant's row."""
    async with tenant_session.begin(contexts.alpha) as session:
        await session.execute(
            text("insert into tenant_probe(id, tenant_id) values (:id, :tenant)"),
            {"id": new_id(), "tenant": contexts.alpha.tenant_id},
        )

    async with tenant_session.begin(contexts.beta) as session:
        count = await session.scalar(text("select count(*) from tenant_probe"))

    assert count == 0


async def test_database_rejects_cross_tenant_insert(tenant_session, contexts) -> None:
    """Removing the WITH CHECK policy would let a tenant write another tenant's row."""
    try:
        async with tenant_session.begin(contexts.alpha) as session:
            await session.execute(
                text("insert into tenant_probe(id, tenant_id) values (:id, :tenant)"),
                {"id": new_id(), "tenant": contexts.beta.tenant_id},
            )
    except DBAPIError:
        return
    raise AssertionError("cross-tenant insert unexpectedly committed")


async def test_database_rejects_cross_tenant_update_and_tenant_move(
    tenant_session, contexts
) -> None:
    """Splitting USING or WITH CHECK policies would expose or move another tenant's row."""
    row_id = new_id()
    async with tenant_session.begin(contexts.alpha) as session:
        await session.execute(
            text("insert into tenant_probe(id, tenant_id, value) values (:id, :tenant, 'alpha')"),
            {"id": row_id, "tenant": contexts.alpha.tenant_id},
        )

    with pytest.raises(DBAPIError):
        async with tenant_session.begin(contexts.alpha) as session:
            await session.execute(
                text("update tenant_probe set tenant_id = :beta where id = :id"),
                {"id": row_id, "beta": contexts.beta.tenant_id},
            )

    async with tenant_session.begin(contexts.alpha) as session:
        assert (
            await session.scalar(
                text("select value from tenant_probe where id = :id"), {"id": row_id}
            )
        ) == "alpha"

    async with tenant_session.begin(contexts.beta) as session:
        result = await session.execute(
            text("update tenant_probe set value = 'beta' where id = :id"), {"id": row_id}
        )

    assert result.rowcount == 0
    async with tenant_session.begin(contexts.alpha) as session:
        assert (
            await session.scalar(
                text("select value from tenant_probe where id = :id"), {"id": row_id}
            )
        ) == "alpha"


async def test_database_denies_unscoped_access(runtime_engine) -> None:
    """Removing RLS or its NULL-safe setting expression would expose unscoped rows."""
    async with runtime_engine.connect() as connection:
        count = await connection.scalar(text("select count(*) from tenant_probe"))

    assert count == 0


async def test_runtime_role_cannot_bypass_or_own_tenant_tables(tenant_session, contexts) -> None:
    """Granting BYPASSRLS or ownership to runtime would defeat forced policies."""
    async with tenant_session.begin(contexts.alpha) as session:
        role = await session.execute(
            text("select rolsuper, rolbypassrls from pg_roles where rolname = current_user")
        )
        owner = await session.scalar(
            text(
                "select tableowner = current_user from pg_tables "
                "where schemaname = 'public' and tablename = 'tenants'"
            )
        )

    assert role.one() == (False, False)
    assert owner is False


async def test_pool_checkout_resets_tenant_and_actor_settings(tenant_session, contexts) -> None:
    """Removing checkout reset could leak a prior tenant or actor over pool reuse."""
    async with tenant_session.engine.connect() as connection:
        await connection.execute(
            text("select set_config('nexus.tenant_id', :tenant, false)"),
            {"tenant": str(contexts.alpha.tenant_id)},
        )
        await connection.execute(
            text("select set_config('nexus.actor_id', :actor, false)"),
            {"actor": str(contexts.alpha.actor_id)},
        )
        await connection.commit()

    async with tenant_session.engine.connect() as connection:
        assert await connection.scalar(text("select current_setting('nexus.tenant_id', true)")) in (
            None,
            "",
        )
        assert await connection.scalar(text("select current_setting('nexus.actor_id', true)")) in (
            None,
            "",
        )


async def test_active_external_principal_resolves_only_active_memberships(
    database_urls, migrated_database, runtime_engine, contexts
) -> None:
    """Removing resolver filters would disclose inactive principal or membership grants."""
    _, migration_url, _ = database_urls
    seed = create_async_engine(migration_url)
    async with seed.begin() as connection:
        await connection.execute(
            text(
                "insert into external_principals(id, issuer, subject, actor_id, status, version) "
                "values (:id, :issuer, :subject, :actor_id, 'active', 1)"
            ),
            {
                "id": new_id(),
                "issuer": "https://issuer.example.test/realms/nexus",
                "subject": "active-subject",
                "actor_id": contexts.alpha.actor_id,
            },
        )
        await connection.execute(
            text(
                "insert into tenant_memberships(tenant_id, actor_id, roles, scopes, "
                "sensitivity_clearances, status) values "
                "(:tenant_id, :actor_id, '{viewer}', '{ontology.read}', '{internal}', 'active'), "
                "(:inactive_tenant, :actor_id, '{operator}', '{ontology.write}', "
                "'{restricted}', 'inactive')"
            ),
            {
                "tenant_id": contexts.alpha.tenant_id,
                "inactive_tenant": contexts.beta.tenant_id,
                "actor_id": contexts.alpha.actor_id,
            },
        )
    await seed.dispose()

    async with runtime_engine.connect() as connection:
        rows = (
            (
                await connection.execute(
                    text("select * from resolve_principal_memberships(:issuer, :subject)"),
                    {
                        "issuer": "https://issuer.example.test/realms/nexus",
                        "subject": "active-subject",
                    },
                )
            )
            .mappings()
            .all()
        )

    assert rows == [
        {
            "actor_id": contexts.alpha.actor_id,
            "tenant_id": contexts.alpha.tenant_id,
            "roles": ["viewer"],
            "scopes": ["ontology.read"],
            "sensitivity_clearances": ["internal"],
        }
    ]


async def test_unknown_or_inactive_external_principal_resolves_nothing(
    database_urls, migrated_database, runtime_engine, contexts
) -> None:
    """Removing principal status filtering would authenticate disabled external identities."""
    _, migration_url, _ = database_urls
    seed = create_async_engine(migration_url)
    async with seed.begin() as connection:
        await connection.execute(
            text(
                "insert into external_principals(id, issuer, subject, actor_id, status, version) "
                "values (:id, :issuer, :subject, :actor_id, 'inactive', 1)"
            ),
            {
                "id": new_id(),
                "issuer": "https://issuer.example.test/realms/nexus",
                "subject": "inactive-subject",
                "actor_id": contexts.beta.actor_id,
            },
        )
    await seed.dispose()

    async with runtime_engine.connect() as connection:
        unknown = await connection.execute(
            text("select * from resolve_principal_memberships(:issuer, :subject)"),
            {"issuer": "https://issuer.example.test/realms/nexus", "subject": "unknown-subject"},
        )
        inactive = await connection.execute(
            text("select * from resolve_principal_memberships(:issuer, :subject)"),
            {"issuer": "https://issuer.example.test/realms/nexus", "subject": "inactive-subject"},
        )

    assert unknown.all() == []
    assert inactive.all() == []


async def test_runtime_cannot_directly_discover_principals_or_unscoped_memberships(
    runtime_engine,
) -> None:
    """Direct mapping access would let an untrusted tenant header drive identity discovery."""
    async with runtime_engine.connect() as connection:
        memberships = await connection.scalar(text("select count(*) from tenant_memberships"))
        with pytest.raises(DBAPIError):
            await connection.execute(text("select count(*) from external_principals"))

    assert memberships == 0


async def test_runtime_acl_is_limited_to_required_operations(tenant_session, contexts) -> None:
    """Broad table grants would permit runtime deletion or immutable payload mutation."""
    async with tenant_session.begin(contexts.alpha) as session:
        table_grants = (
            await session.execute(
                text(
                    "select table_name, privilege_type from information_schema.role_table_grants "
                    "where grantee = current_user and table_schema = 'public' "
                    "and table_name in ('tenants', 'tenant_memberships', 'outbox_events', "
                    "'consumer_receipts') order by table_name, privilege_type"
                )
            )
        ).all()
        update_columns = (
            await session.execute(
                text(
                    "select table_name, column_name from information_schema.column_privileges "
                    "where grantee = current_user and table_schema = 'public' "
                    "and table_name = 'outbox_events' and privilege_type = 'UPDATE' "
                    "order by column_name"
                )
            )
        ).all()

    assert table_grants == [
        ("consumer_receipts", "INSERT"),
        ("consumer_receipts", "SELECT"),
        ("outbox_events", "INSERT"),
        ("outbox_events", "SELECT"),
        ("tenant_memberships", "INSERT"),
        ("tenant_memberships", "SELECT"),
        ("tenant_memberships", "UPDATE"),
        ("tenants", "INSERT"),
        ("tenants", "SELECT"),
        ("tenants", "UPDATE"),
    ]
    assert update_columns == [("outbox_events", "claim_owner"), ("outbox_events", "claimed_at")]


async def test_forward_upgrade_from_existing_0001_applies_persistence_hardening(
    database_urls, migrated_database, runtime_engine
) -> None:
    """A database stamped at 0001 must receive ACL and claim-column corrections from 0002."""
    _, migration_url, _ = database_urls
    environment = {**os.environ, "NEXUS_MIGRATION_DATABASE_URL": migration_url}
    command = [
        sys.executable,
        "-m",
        "alembic",
        "-c",
        str(Path(__file__).parents[3] / "apps/api/alembic.ini"),
    ]
    subprocess.run([*command, "downgrade", "base"], check=True, env=environment)  # noqa: ASYNC221, S603
    subprocess.run([*command, "upgrade", "0001_tenants_and_rls"], check=True, env=environment)  # noqa: ASYNC221, S603

    async with runtime_engine.connect() as connection:
        legacy_delete = await connection.scalar(
            text("select has_table_privilege(current_user, 'outbox_events', 'DELETE')")
        )
        legacy_columns = await connection.scalars(
            text(
                "select column_name from information_schema.columns "
                "where table_schema = 'public' and table_name = 'outbox_events' "
                "and column_name in ('claim_owner', 'claimed_at') order by column_name"
            )
        )

    assert legacy_delete is True
    assert legacy_columns.all() == []
    subprocess.run([*command, "upgrade", "head"], check=True, env=environment)  # noqa: ASYNC221, S603

    async with runtime_engine.connect() as connection:
        hardened_columns = await connection.scalars(
            text(
                "select column_name from information_schema.columns "
                "where table_schema = 'public' and table_name = 'outbox_events' "
                "and column_name in ('claim_owner', 'claimed_at') order by column_name"
            )
        )
        delete_allowed = await connection.scalar(
            text("select has_table_privilege(current_user, 'outbox_events', 'DELETE')")
        )

    assert hardened_columns.all() == ["claim_owner", "claimed_at"]
    assert delete_allowed is False

    # A rollback to the original immutable revision deliberately restores its
    # historical broad grants before removing the forward-only claim columns.
    subprocess.run(  # noqa: ASYNC221, S603
        [*command, "downgrade", "0001_tenants_and_rls"], check=True, env=environment
    )
    async with runtime_engine.connect() as connection:
        restored_delete = await connection.scalar(
            text("select has_table_privilege(current_user, 'outbox_events', 'DELETE')")
        )
        restored_columns = await connection.scalars(
            text(
                "select column_name from information_schema.columns "
                "where table_schema = 'public' and table_name = 'outbox_events' "
                "and column_name in ('claim_owner', 'claimed_at') order by column_name"
            )
        )

    assert restored_delete is True
    assert restored_columns.all() == []
    subprocess.run([*command, "upgrade", "head"], check=True, env=environment)  # noqa: ASYNC221, S603


async def test_fresh_base_to_head_reaches_hardened_persistence_state(
    database_urls, migrated_database, runtime_engine
) -> None:
    """Fresh migration and round-trip migration must converge on the hardened schema."""
    _, migration_url, _ = database_urls
    environment = {**os.environ, "NEXUS_MIGRATION_DATABASE_URL": migration_url}
    command = [
        sys.executable,
        "-m",
        "alembic",
        "-c",
        str(Path(__file__).parents[3] / "apps/api/alembic.ini"),
    ]
    subprocess.run([*command, "downgrade", "base"], check=True, env=environment)  # noqa: ASYNC221, S603
    subprocess.run([*command, "upgrade", "head"], check=True, env=environment)  # noqa: ASYNC221, S603

    migration_engine = create_async_engine(migration_url)
    async with migration_engine.connect() as connection:
        revision = await connection.scalar(text("select version_num from nexus_alembic_version"))
    await migration_engine.dispose()

    async with runtime_engine.connect() as connection:
        claim_columns = await connection.scalar(
            text(
                "select count(*) from information_schema.columns "
                "where table_schema = 'public' and table_name = 'outbox_events' "
                "and column_name in ('claim_owner', 'claimed_at')"
            )
        )

    assert revision == "0002_audit_ledger"
    assert claim_columns == 2
