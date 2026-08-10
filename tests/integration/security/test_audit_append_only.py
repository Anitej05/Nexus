"""Live PostgreSQL append-only ledger, RLS, chain, replay, and outbox tests."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from nexus_api.main import app
from nexus_api.routes.audit import (
    AuditRouteDependencies,
    OpaAuditReadPolicy,
    get_audit_dependencies,
)
from nexus_contracts.platform import EventEnvelope, PolicyDecision, ResourceRef
from nexus_security.audit import (
    AuditCheckpoint,
    AuditIdempotencyConflict,
    AuditPayloadRegistry,
    AuditPayloadSchema,
    AuditWriter,
)
from nexus_security.dependencies import require_context
from nexus_security.ids import new_id
from nexus_security.outbox import OutboxWriter
from nexus_security.policy import AuthorizationEvidence
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine


def _registry() -> AuditPayloadRegistry:
    return AuditPayloadRegistry({"test.event": AuditPayloadSchema(fields={"value": str})})


@pytest.mark.asyncio
async def test_append_replay_chain_and_safe_outbox(tenant_session, contexts) -> None:
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)
    async with tenant_session.begin(context) as session:
        writer = AuditWriter(session, outbox=OutboxWriter(), payload_registry=_registry())
        first = await writer.append(context, "test.event", subject, {"value": "one"}, "key-1")
        replay = await writer.append(context, "test.event", subject, {"value": "one"}, "key-1")
        second = await writer.append(context, "test.event", subject, {"value": "two"}, "key-2")
        verification = await writer.verify_chain(context)
        assert replay.id == first.id
        assert second.sequence == first.sequence + 1
        assert second.previous_hash == first.hash
        assert verification.valid
        outbox = (
            (await session.execute(text("select envelope from outbox_events order by created_at")))
            .scalars()
            .all()
        )
        assert len(outbox) == 2
        assert all(item["event_type"] == "nexus.audit.v1" for item in outbox)
        assert all("idempotency_key" not in str(item) for item in outbox)


@pytest.mark.asyncio
async def test_same_key_different_semantics_is_typed_conflict(tenant_session, contexts) -> None:
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)
    async with tenant_session.begin(context) as session:
        writer = AuditWriter(session, outbox=OutboxWriter(), payload_registry=_registry())
        await writer.append(context, "test.event", subject, {"value": "one"}, "same")
        with pytest.raises(AuditIdempotencyConflict):
            await writer.append(context, "test.event", subject, {"value": "two"}, "same")


@pytest.mark.asyncio
async def test_runtime_cannot_update_delete_or_truncate(tenant_session, contexts) -> None:
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)
    for statement in (
        "update audit_events set event_type='changed' where tenant_id=:tenant",
        "delete from audit_events where tenant_id=:tenant",
        "truncate audit_events",
    ):
        with pytest.raises(DBAPIError):
            async with tenant_session.begin(context) as session:
                writer = AuditWriter(session, outbox=OutboxWriter(), payload_registry=_registry())
                await writer.append(context, "test.event", subject, {"value": "one"}, new_id().hex)
                await session.execute(text(statement), {"tenant": context.tenant_id})


@pytest.mark.asyncio
async def test_32_concurrent_appends_are_contiguous(database_urls, contexts) -> None:
    from nexus_security.tenancy import TenantSession

    runtime_url, _, _ = database_urls
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)

    async def append(index: int) -> int:
        sessions = TenantSession(runtime_url)
        try:
            async with sessions.begin(context) as session:
                event = await AuditWriter(
                    session, outbox=OutboxWriter(), payload_registry=_registry()
                ).append(
                    context, "test.event", subject, {"value": str(index)}, f"concurrent-{index}"
                )
                return event.sequence
        finally:
            await sessions.dispose()

    assert sorted(await asyncio.gather(*(append(i) for i in range(32)))) == list(range(1, 33))


@pytest.mark.asyncio
async def test_audit_and_outbox_rollback_with_caller_transaction(tenant_session, contexts) -> None:
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)
    with pytest.raises(RuntimeError, match="injected"):
        async with tenant_session.begin(context) as session:
            domain_id = new_id()
            await session.execute(
                text("insert into domain_probe(id,tenant_id,value) values (:id,:tenant,'staged')"),
                {"id": domain_id, "tenant": context.tenant_id},
            )
            await OutboxWriter().enqueue(
                session,
                EventEnvelope(
                    event_id=new_id(),
                    event_type="domain.probe.v1",
                    tenant_id=context.tenant_id,
                    source=ResourceRef(
                        tenant_id=context.tenant_id,
                        kind="domain.probe",
                        id=domain_id,
                        version=1,
                    ),
                    subject=f"domain.probe:{domain_id}",
                    occurred_at=datetime.now(UTC),
                    ingested_at=datetime.now(UTC),
                    correlation_id=context.correlation_id,
                    sensitivity=frozenset({"internal"}),
                    payload={"id": str(domain_id)},
                ),
                "domain-probe-business-event",
            )
            await AuditWriter(session, outbox=OutboxWriter(), payload_registry=_registry()).append(
                context, "test.event", subject, {"value": "rollback"}, "rollback-key"
            )
            raise RuntimeError("injected after audit and outbox staging")
    async with tenant_session.begin(context) as session:
        assert await session.scalar(text("select count(*) from audit_events")) == 0
        assert await session.scalar(text("select count(*) from outbox_events")) == 0
        assert await session.scalar(text("select count(*) from domain_probe")) == 0


@pytest.mark.asyncio
async def test_cancellation_rolls_back_audit_and_outbox(tenant_session, contexts) -> None:
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)
    with pytest.raises(asyncio.CancelledError):
        async with tenant_session.begin(context) as session:
            await AuditWriter(session, outbox=OutboxWriter(), payload_registry=_registry()).append(
                context, "test.event", subject, {"value": "cancelled"}, "cancelled"
            )
            raise asyncio.CancelledError
    async with tenant_session.begin(context) as session:
        assert await session.scalar(text("select count(*) from audit_events")) == 0
        assert await session.scalar(text("select count(*) from outbox_events")) == 0


@pytest.mark.asyncio
async def test_concurrent_identical_replay_is_one_row_and_one_outbox(
    database_urls, contexts
) -> None:
    from nexus_security.tenancy import TenantSession

    runtime_url, _, _ = database_urls
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)

    async def replay() -> tuple[object, int]:
        sessions = TenantSession(runtime_url)
        try:
            async with sessions.begin(context) as session:
                event = await AuditWriter(
                    session, outbox=OutboxWriter(), payload_registry=_registry()
                ).append(context, "test.event", subject, {"value": "same"}, "same-replay")
                return event.id, event.sequence
        finally:
            await sessions.dispose()

    results = await asyncio.gather(*(replay() for _ in range(16)))
    assert len(set(results)) == 1
    sessions = TenantSession(runtime_url)
    try:
        async with sessions.begin(context) as session:
            assert await session.scalar(text("select count(*) from audit_events")) == 1
            assert await session.scalar(text("select count(*) from outbox_events")) == 1
    finally:
        await sessions.dispose()


@pytest.mark.asyncio
async def test_recovery_tamper_and_anchored_tail_deletion_are_detected(
    tenant_session, audit_recovery_url, contexts
) -> None:
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)
    async with tenant_session.begin(context) as session:
        writer = AuditWriter(session, outbox=OutboxWriter(), payload_registry=_registry())
        first = await writer.append(context, "test.event", subject, {"value": "one"}, "one")
        second = await writer.append(context, "test.event", subject, {"value": "two"}, "two")
    recovery = create_async_engine(audit_recovery_url)
    async with recovery.begin() as connection:
        await connection.execute(
            text("update audit_events set event_type='test.changed' where id=:id"),
            {"id": first.id},
        )
    async with tenant_session.begin(context) as session:
        verification = await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).verify_chain(context)
        assert not verification.valid
        assert verification.broken_sequence == first.sequence
    async with recovery.begin() as connection:
        await connection.execute(
            text("update audit_events set event_type='test.event' where id=:id"),
            {"id": first.id},
        )
        await connection.execute(text("delete from audit_events where id=:id"), {"id": second.id})
    await recovery.dispose()
    checkpoint = AuditCheckpoint(
        tenant_id=context.tenant_id,
        sequence=second.sequence,
        hash=second.hash,
        captured_at=datetime.now(UTC),
    )
    async with tenant_session.begin(context) as session:
        writer = AuditWriter(session, outbox=OutboxWriter(), payload_registry=_registry())
        assert (await writer.verify_chain(context)).valid  # unanchored suffix loss is undetectable
        anchored = await writer.verify_chain(context, checkpoint=checkpoint)
        assert not anchored.valid
        assert anchored.broken_sequence == second.sequence
        assert anchored.checkpoint_matched is False


@pytest.mark.asyncio
async def test_verifier_detects_domain_version_and_db_legal_payload_corruption(
    tenant_session, audit_recovery_url, contexts
) -> None:
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)
    async with tenant_session.begin(context) as session:
        first = await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).append(context, "test.event", subject, {"value": "one"}, "one")
    recovery = create_async_engine(audit_recovery_url)
    async with recovery.begin() as connection:
        await connection.execute(
            text("update audit_events set hash_domain_version='2' where id=:id"),
            {"id": first.id},
        )
    async with tenant_session.begin(context) as session:
        version_break = await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).verify_chain(context)
    assert not version_break.valid
    assert version_break.broken_sequence == 1
    assert version_break.checked_through_sequence == 0
    async with recovery.begin() as connection:
        await connection.execute(
            text(
                "update audit_events set hash_domain_version='1', "
                "public_payload=cast(:payload as jsonb) where id=:id"
            ),
            {"id": first.id, "payload": '{"n":9007199254740992}'},
        )
    async with tenant_session.begin(context) as session:
        malformed = await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).verify_chain(context)
    assert not malformed.valid
    assert malformed.broken_sequence == 1
    assert malformed.checked_through_sequence == 0
    async with recovery.begin() as connection:
        await connection.execute(
            text(
                "update audit_events set public_payload=cast(:payload as jsonb), "
                "policy_decision='[]'::jsonb, policy_revision='corrupt', "
                "policy_input_sha256=:digest where id=:id"
            ),
            {"id": first.id, "payload": '{"value":"one"}', "digest": "a" * 64},
        )
    async with tenant_session.begin(context) as session:
        malformed_policy = await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).verify_chain(context)
    assert not malformed_policy.valid
    assert malformed_policy.broken_sequence == 1
    assert malformed_policy.checked_through_sequence == 0
    await recovery.dispose()


@pytest.mark.asyncio
async def test_sequence_gap_reports_only_rows_actually_verified(
    tenant_session, audit_recovery_url, contexts
) -> None:
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)
    async with tenant_session.begin(context) as session:
        writer = AuditWriter(session, outbox=OutboxWriter(), payload_registry=_registry())
        first = await writer.append(context, "test.event", subject, {"value": "one"}, "one")
        second = await writer.append(context, "test.event", subject, {"value": "two"}, "two")
    recovery = create_async_engine(audit_recovery_url)
    async with recovery.begin() as connection:
        await connection.execute(text("delete from audit_events where id=:id"), {"id": first.id})
    await recovery.dispose()
    async with tenant_session.begin(context) as session:
        result = await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).verify_chain(context)
    assert not result.valid
    assert result.broken_sequence == second.sequence
    assert result.checked_through_sequence == 0


@pytest.mark.asyncio
async def test_existing_harden_upgrade_and_empty_audit_round_trip(
    database_urls, migrated_database
) -> None:
    _, migration_url, _ = database_urls
    environment = {**os.environ, "NEXUS_MIGRATION_DATABASE_URL": migration_url}
    command = [
        sys.executable,
        "-m",
        "alembic",
        "-c",
        str(Path(__file__).parents[3] / "apps/api/alembic.ini"),
    ]
    engine = create_async_engine(migration_url)
    for _ in range(2):
        subprocess.run(  # noqa: ASYNC221, S603
            [*command, "downgrade", "0002_harden_persistence_acls"],
            check=True,
            env=environment,
        )
        async with engine.connect() as connection:
            assert await connection.scalar(
                text("select version_num from nexus_alembic_version")
            ) == "0002_harden_persistence_acls"
            assert (
                await connection.scalar(text("select to_regclass('public.audit_events')"))
                is None
            )
        subprocess.run(  # noqa: ASYNC221, S603
            [*command, "upgrade", "head"], check=True, env=environment
        )
        async with engine.connect() as connection:
            assert await connection.scalar(
                text("select version_num from nexus_alembic_version")
            ) == "0002_audit_ledger"
            assert await connection.scalar(
                text("select to_regclass('public.audit_events')::text")
            ) == "audit_events"
            assert await connection.scalar(text("select count(*) from audit_events")) == 0
    await engine.dispose()


@pytest.mark.asyncio
async def test_populated_audit_downgrade_refuses_atomically(
    tenant_session, database_urls, contexts
) -> None:
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)
    async with tenant_session.begin(context) as session:
        event = await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).append(context, "test.event", subject, {"value": "preserved"}, "preserved")

    _, migration_url, _ = database_urls
    environment = {**os.environ, "NEXUS_MIGRATION_DATABASE_URL": migration_url}
    result = subprocess.run(  # noqa: ASYNC221, S603
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            str(Path(__file__).parents[3] / "apps/api/alembic.ini"),
            "downgrade",
            "0002_harden_persistence_acls",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode != 0
    assert "refusing to downgrade a populated audit ledger" in result.stderr
    engine = create_async_engine(migration_url)
    async with engine.connect() as connection:
        assert await connection.scalar(
            text("select version_num from nexus_alembic_version")
        ) == "0002_audit_ledger"
        assert await connection.scalar(
            text("select count(*) from audit_events where id=:id"), {"id": event.id}
        ) == 1
    await engine.dispose()


@pytest.mark.asyncio
async def test_migration_rejects_aliased_recovery_role_before_ddl(
    database_urls, migrated_database
) -> None:
    _, migration_url, _ = database_urls
    environment = {**os.environ, "NEXUS_MIGRATION_DATABASE_URL": migration_url}
    command = [
        sys.executable,
        "-m",
        "alembic",
        "-c",
        str(Path(__file__).parents[3] / "apps/api/alembic.ini"),
    ]
    subprocess.run(  # noqa: ASYNC221, S603
        [*command, "downgrade", "0002_harden_persistence_acls"],
        check=True,
        env=environment,
    )
    unsafe_environment = {
        **environment,
        "NEXUS_RUNTIME_DATABASE_USER": "nexus_audit_recovery",
        "NEXUS_AUDIT_RECOVERY_DATABASE_USER": "nexus_audit_recovery",
    }
    refused = subprocess.run(  # noqa: ASYNC221, S603
        [*command, "upgrade", "head"],
        check=False,
        capture_output=True,
        text=True,
        env=unsafe_environment,
    )
    assert refused.returncode != 0
    assert "role names must be distinct" in refused.stderr
    engine = create_async_engine(migration_url)
    async with engine.connect() as connection:
        assert await connection.scalar(text("select to_regclass('public.audit_events')")) is None
        assert await connection.scalar(
            text("select version_num from nexus_alembic_version")
        ) == "0002_harden_persistence_acls"
    await engine.dispose()
    subprocess.run(  # noqa: ASYNC221, S603
        [*command, "upgrade", "head"], check=True, env=environment
    )


@pytest.mark.asyncio
async def test_exact_runtime_and_recovery_role_hardening(
    database_urls, audit_recovery_url, migrated_database
) -> None:
    _, migration_url, _ = database_urls
    engine = create_async_engine(migration_url)
    async with engine.connect() as connection:
        roles = (
            await connection.execute(
                text(
                    "select rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolinherit, rolbypassrls "
                    "from pg_roles where rolname in "
                    "('nexus_runtime','nexus_migrator','nexus_audit_recovery')"
                )
            )
        ).mappings()
        values = {row["rolname"]: row for row in roles}
        assert set(values) == {"nexus_runtime", "nexus_migrator", "nexus_audit_recovery"}
        for name, bypass in (
            ("nexus_runtime", False),
            ("nexus_migrator", True),
            ("nexus_audit_recovery", False),
        ):
            role = values[name]
            assert role["rolcanlogin"]
            assert role["rolbypassrls"] is bypass
            assert not any(
                role[field]
                for field in ("rolsuper", "rolcreatedb", "rolcreaterole", "rolinherit")
            )
        assert await connection.scalar(
            text(
                "select relrowsecurity and relforcerowsecurity "
                "from pg_class where relname='audit_events'"
            )
        )
        for privilege, expected in (
            ("SELECT", True),
            ("INSERT", True),
            ("UPDATE", False),
            ("DELETE", False),
            ("TRUNCATE", False),
            ("TRIGGER", False),
        ):
            assert (
                bool(
                    await connection.scalar(
                        text(
                            "select has_table_privilege('nexus_runtime','audit_events',:privilege)"
                        ),
                        {"privilege": privilege},
                    )
                )
                is expected
            )
        for privilege, expected in (
            ("SELECT", True),
            ("INSERT", False),
            ("UPDATE", True),
            ("DELETE", True),
            ("TRUNCATE", True),
            ("TRIGGER", False),
        ):
            assert bool(
                await connection.scalar(
                    text(
                        "select has_table_privilege("
                        "'nexus_audit_recovery','audit_events',:privilege)"
                    ),
                    {"privilege": privilege},
                )
            ) is expected
        assert await connection.scalar(
            text(
                "select count(*)=0 from pg_auth_members membership "
                "join pg_roles parent on parent.oid=membership.roleid "
                "join pg_roles child on child.oid=membership.member "
                "where parent.rolname in "
                "('nexus_runtime','nexus_migrator','nexus_audit_recovery') "
                "or child.rolname in "
                "('nexus_runtime','nexus_migrator','nexus_audit_recovery')"
            )
        )
        policies = (
            await connection.execute(
                text(
                    "select policy.polname as policyname, policy.polpermissive as permissive, "
                    "array(select case when role_oid=0 then 'PUBLIC' "
                    "else pg_get_userbyid(role_oid) end "
                    "from unnest(policy.polroles) role_oid order by 1) as roles, "
                    "pg_get_expr(policy.polqual,policy.polrelid) as qual, "
                    "pg_get_expr(policy.polwithcheck,policy.polrelid) as with_check "
                    "from pg_policy policy join pg_class relation "
                    "on relation.oid=policy.polrelid join pg_namespace namespace "
                    "on namespace.oid=relation.relnamespace where namespace.nspname='public' "
                    "and relation.relname='audit_events' order by policy.polname"
                )
            )
        ).mappings()
        policy_values = {row["policyname"]: row for row in policies}
        tenant_expression = (
            "(tenant_id = (NULLIF(current_setting('nexus.tenant_id'::text, true), "
            "''::text))::uuid)"
        )
        recovery_expression = "(SESSION_USER = 'nexus_audit_recovery'::name)"
        assert {name: dict(row) for name, row in policy_values.items()} == {
            "audit_events_recovery_policy": {
                "policyname": "audit_events_recovery_policy",
                "permissive": True,
                "roles": ["PUBLIC"],
                "qual": recovery_expression,
                "with_check": recovery_expression,
            },
            "audit_events_tenant_policy": {
                "policyname": "audit_events_tenant_policy",
                "permissive": True,
                "roles": ["PUBLIC"],
                "qual": tenant_expression,
                "with_check": tenant_expression,
            },
        }
        trigger = (
            await connection.execute(
                text(
                    "select pg_get_triggerdef(oid) as definition from pg_trigger "
                    "where tgrelid='audit_events'::regclass and tgname='audit_events_immutable' "
                    "and not tgisinternal"
                )
            )
        ).mappings().one()
        assert " BEFORE " in trigger["definition"]
        assert all(
            operation in trigger["definition"]
            for operation in ("UPDATE", "DELETE", "TRUNCATE")
        )
        function_definition = await connection.scalar(
            text("select pg_get_functiondef('public.guard_audit_ledger_mutation()'::regprocedure)")
        )
        assert "session_user" in function_definition.casefold()
    await engine.dispose()
    recovery_engine = create_async_engine(audit_recovery_url)
    async with recovery_engine.connect() as recovery_connection:
        identity = (
            await recovery_connection.execute(
                text("select current_user as current_identity, session_user as session_identity")
            )
        ).mappings().one()
        assert identity == {
            "current_identity": "nexus_audit_recovery",
            "session_identity": "nexus_audit_recovery",
        }
    await recovery_engine.dispose()


@pytest.mark.asyncio
async def test_runtime_mutation_is_denied_by_trigger_even_with_table_grants(
    tenant_session, database_urls, contexts
) -> None:
    context = contexts.alpha
    subject = ResourceRef(
        tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1
    )
    async with tenant_session.begin(context) as session:
        await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).append(context, "test.event", subject, {"value": "guarded"}, "guarded")

    runtime_url, migration_url, _ = database_urls
    migration = create_async_engine(migration_url)
    runtime = create_async_engine(runtime_url)
    try:
        async with migration.begin() as connection:
            await connection.execute(
                text("grant update, delete, truncate on audit_events to nexus_runtime")
            )
        for statement in (
            "update audit_events set event_type='test.changed'",
            "delete from audit_events",
            "truncate audit_events",
        ):
            with pytest.raises(DBAPIError, match="audit ledger mutation is restricted"):
                async with runtime.begin() as connection:
                    await connection.execute(
                        text("select set_config('nexus.tenant_id',:tenant,true)"),
                        {"tenant": str(context.tenant_id)},
                    )
                    await connection.execute(text(statement))
    finally:
        async with migration.begin() as connection:
            await connection.execute(
                text("revoke update, delete, truncate on audit_events from nexus_runtime")
            )
        await runtime.dispose()
        await migration.dispose()


class _AllowAuditPolicy:
    async def authorize(self, context, attributes):
        return AuthorizationEvidence(
            decision=PolicyDecision(
                decision_id=context.correlation_id,
                allow=True,
                effective_class="R0",
                obligations=("max_rows:1",),
                reason_codes=("explicit_grant",),
            ),
            policy_revision="1.0.0",
            canonical_input_sha256="a" * 64,
        )


@pytest.mark.asyncio
async def test_actual_app_authorized_snapshot_read_is_nonrecursive_and_nonleaking(
    tenant_session, contexts
) -> None:
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)
    async with tenant_session.begin(context) as session:
        writer = AuditWriter(session, outbox=OutboxWriter(), payload_registry=_registry())
        first = await writer.append(context, "test.event", subject, {"value": "first"}, "first")
        second = await writer.append(
            context, "test.event", subject, {"value": "second"}, "second"
        )
    hidden_subject = ResourceRef(
        tenant_id=contexts.beta.tenant_id, kind="test.subject", id=new_id(), version=1
    )
    async with tenant_session.begin(contexts.beta) as session:
        hidden = await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).append(contexts.beta, "test.event", hidden_subject, {"value": "hidden"}, "hidden")
    dependencies = AuditRouteDependencies(tenant_session, _AllowAuditPolicy())
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[get_audit_dependencies] = lambda: dependencies
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/audit/events", params={"limit": 10})
            future_snapshot = await client.get(
                "/api/v1/audit/events", params={"snapshot_sequence": second.sequence + 100}
            )
            async with tenant_session.begin(context) as session:
                late = await AuditWriter(
                    session, outbox=OutboxWriter(), payload_registry=_registry()
                ).append(context, "test.event", subject, {"value": "late"}, "late")
            first_page = response.json()
            second_page = await client.get(
                "/api/v1/audit/events",
                params={
                    "after_sequence": first_page["next_after_sequence"],
                    "snapshot_sequence": first_page["snapshot_sequence"],
                },
            )
            empty_page = await client.get(
                "/api/v1/audit/events",
                params={
                    "after_sequence": second.sequence,
                    "snapshot_sequence": first_page["snapshot_sequence"],
                },
            )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200, response.text
    assert future_snapshot.status_code == 400
    assert future_snapshot.json()["code"] == "invalid_audit_cursor"
    body = response.json()
    assert body["snapshot_sequence"] == second.sequence
    assert [event["id"] for event in body["events"]] == [str(first.id)]
    assert str(hidden.id) not in response.text
    assert second_page.status_code == 200, second_page.text
    assert [event["id"] for event in second_page.json()["events"]] == [str(second.id)]
    assert str(late.id) not in second_page.text
    assert empty_page.status_code == 200, empty_page.text
    assert empty_page.json()["events"] == []
    serialized = response.text.casefold()
    assert "idempotency_key" not in serialized
    assert "request_fingerprint" not in serialized
    assert "protected bytes" not in serialized
    async with tenant_session.begin(context) as session:
        read_rows = await session.scalar(
            text("select count(*) from audit_events where event_type='audit.read'")
        )
        assert read_rows == 3


@pytest.mark.asyncio
async def test_reused_correlation_with_different_filters_has_distinct_read_identity(
    tenant_session, contexts
) -> None:
    context = contexts.alpha
    subject = ResourceRef(tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1)
    async with tenant_session.begin(context) as session:
        source = await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).append(context, "test.event", subject, {"value": "visible"}, "source")
    dependencies = AuditRouteDependencies(tenant_session, _AllowAuditPolicy())
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[get_audit_dependencies] = lambda: dependencies
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            by_type = await client.get(
                "/api/v1/audit/events",
                params={"snapshot_sequence": source.sequence, "event_type": "test.event"},
            )
            by_resource = await client.get(
                "/api/v1/audit/events",
                params={
                    "snapshot_sequence": source.sequence,
                    "resource_kind": "test.subject",
                },
            )
            by_time = await client.get(
                "/api/v1/audit/events",
                params={
                    "snapshot_sequence": source.sequence,
                    "occurred_from": source.occurred_at.isoformat(),
                    "occurred_to": source.occurred_at.isoformat(),
                },
            )
    finally:
        app.dependency_overrides.clear()
    assert by_type.status_code == 200, by_type.text
    assert by_resource.status_code == 200, by_resource.text
    assert by_time.status_code == 200, by_time.text
    async with tenant_session.begin(context) as session:
        rows = (
            await session.execute(
                text(
                    "select public_payload, idempotency_key_sha256 from audit_events "
                    "where event_type='audit.read' order by sequence"
                )
            )
        ).mappings().all()
        assert len(rows) == 3
        assert len({row["idempotency_key_sha256"] for row in rows}) == 3
        assert rows[0]["public_payload"]["event_type"] == "test.event"
        assert rows[0]["public_payload"]["resource_kind"] is None
        assert rows[1]["public_payload"]["event_type"] is None
        assert rows[1]["public_payload"]["resource_kind"] == "test.subject"
        assert rows[2]["public_payload"]["occurred_from"] == (
            source.occurred_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        )
        assert rows[2]["public_payload"]["occurred_to"] == (
            source.occurred_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        )
        assert all(row["public_payload"]["executed_limit"] == 1 for row in rows)
        assert all(
            row["public_payload"]["executed_snapshot_sequence"] == source.sequence
            for row in rows
        )


@pytest.mark.asyncio
async def test_identical_fixed_snapshot_retry_replays_one_read_audit(
    tenant_session, contexts
) -> None:
    context = contexts.alpha
    subject = ResourceRef(
        tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1
    )
    async with tenant_session.begin(context) as session:
        source = await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).append(context, "test.event", subject, {"value": "visible"}, "source")
    dependencies = AuditRouteDependencies(tenant_session, _AllowAuditPolicy())
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[get_audit_dependencies] = lambda: dependencies
    parameters = {
        "snapshot_sequence": source.sequence,
        "event_type": "test.event",
        "resource_kind": "test.subject",
        "resource_id": str(subject.id),
        "actor_id": str(context.actor_id),
        "correlation_id": str(context.correlation_id),
        "occurred_from": source.occurred_at.isoformat(),
        "occurred_to": source.occurred_at.isoformat(),
    }
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            first = await client.get("/api/v1/audit/events", params=parameters)
            second = await client.get("/api/v1/audit/events", params=parameters)
    finally:
        app.dependency_overrides.clear()
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json() == second.json()
    async with tenant_session.begin(context) as session:
        assert await session.scalar(
            text("select count(*) from audit_events where event_type='audit.read'")
        ) == 1


@pytest.mark.skipif(
    os.environ.get("NEXUS_RUN_OPA_TESTS") != "1",
    reason="set NEXUS_RUN_OPA_TESTS=1 when the pinned local OPA service is running",
)
@pytest.mark.asyncio
async def test_live_opa_identical_fixed_snapshot_retry_is_stable(
    tenant_session, contexts
) -> None:
    context = contexts.alpha.model_copy(
        update={"roles": frozenset({"platform_admin"}), "scopes": frozenset({"audit.read"})}
    )
    subject = ResourceRef(
        tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1
    )
    async with tenant_session.begin(context) as session:
        source = await AuditWriter(
            session, outbox=OutboxWriter(), payload_registry=_registry()
        ).append(context, "test.event", subject, {"value": "visible"}, "source")
    dependencies = AuditRouteDependencies(tenant_session, OpaAuditReadPolicy())
    app.dependency_overrides[require_context] = lambda: context
    app.dependency_overrides[get_audit_dependencies] = lambda: dependencies
    parameters = {"snapshot_sequence": source.sequence, "event_type": "test.event"}
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            first = await client.get("/api/v1/audit/events", params=parameters)
            second = await client.get("/api/v1/audit/events", params=parameters)
    finally:
        app.dependency_overrides.clear()
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json() == second.json()
    async with tenant_session.begin(context) as session:
        assert await session.scalar(
            text("select count(*) from audit_events where event_type='audit.read'")
        ) == 1
