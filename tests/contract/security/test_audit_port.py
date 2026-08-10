"""Frozen AuditPort adapter and transaction-ownership contract."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from nexus_contracts.platform import AuditPort, RequestContext, ResourceRef
from nexus_security.audit import (
    GENESIS_HASH,
    AuditActor,
    AuditEvent,
    AuditIdempotencyConflict,
    AuditPayloadRegistry,
    AuditPayloadSchema,
    AuditWriter,
    ProtectedPayloadEvidence,
)
from nexus_security.audit_port import AuditPortAdapter
from nexus_security.ids import new_id
from nexus_security.outbox import OutboxWriter
from sqlalchemy.ext.asyncio import AsyncSession


def _context() -> RequestContext:
    return RequestContext(
        tenant_id=new_id(),
        actor_id=new_id(),
        correlation_id=new_id(),
        roles=frozenset({"auditor"}),
        scopes=frozenset({"audit.read"}),
        sensitivity_clearances=frozenset({"internal"}),
    )


def test_public_audit_port_signature_remains_frozen() -> None:
    assert tuple(inspect.signature(AuditPort.append).parameters) == (
        "self",
        "context",
        "event_type",
        "subject",
        "payload",
        "idempotency_key",
    )
    assert tuple(inspect.signature(AuditPortAdapter.append).parameters) == (
        "self",
        "context",
        "event_type",
        "subject",
        "payload",
        "idempotency_key",
    )


@pytest.mark.asyncio
async def test_adapter_rejects_inactive_session_before_database_io() -> None:
    session = AsyncSession()
    with pytest.raises(RuntimeError, match="active"):
        AuditWriter(
            session,
            outbox=OutboxWriter(),
            payload_registry=AuditPayloadRegistry(
                {"test.event": AuditPayloadSchema(fields={"result": str})}
            ),
        )
    await session.close()


@pytest.mark.asyncio
async def test_adapter_rejects_cross_tenant_subject_before_database_io() -> None:
    session = AsyncSession()
    async with session.begin():
        writer = AuditWriter(
            session,
            outbox=OutboxWriter(),
            payload_registry=AuditPayloadRegistry(
                {"test.event": AuditPayloadSchema(fields={"result": str})}
            ),
        )
        adapter = AuditPortAdapter(writer)
        context = _context()
        subject = ResourceRef(tenant_id=new_id(), kind="test.subject", id=new_id(), version=1)
        with pytest.raises(ValueError, match="tenant"):
            await adapter.append(context, "test.event", subject, {"result": "ok"}, "command-1")
    await session.close()


class _FakeWriter:
    def __init__(self, event: AuditEvent) -> None:
        self.event = event
        self.calls: list[tuple[object, ...]] = []

    async def append(self, *args: object) -> AuditEvent:
        self.calls.append(args)
        return self.event


@pytest.mark.asyncio
async def test_adapter_returns_exact_reference_and_only_delegates_to_supplied_writer() -> None:
    context = _context()
    subject = ResourceRef(
        tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1
    )
    event = AuditEvent(
        id=new_id(),
        tenant_id=context.tenant_id,
        sequence=1,
        occurred_at=datetime.now(UTC),
        actor=AuditActor(actor_id=context.actor_id),
        event_type="test.event",
        resource=subject,
        correlation_id=context.correlation_id,
        public_payload={"result": "ok"},
        previous_hash=GENESIS_HASH,
        hash="a" * 64,
    )
    writer = _FakeWriter(event)
    adapter = AuditPortAdapter(cast(AuditWriter, cast(Any, writer)))
    result = await adapter.append(context, "test.event", subject, {"result": "ok"}, "same")
    assert result == ResourceRef(
        tenant_id=context.tenant_id, kind="audit.event", id=event.id, version=1
    )
    assert writer.calls == [(context, "test.event", subject, {"result": "ok"}, "same")]


@pytest.mark.asyncio
async def test_adapter_preserves_typed_idempotency_conflict() -> None:
    class _ConflictWriter:
        async def append(self, *args: object) -> AuditEvent:
            raise AuditIdempotencyConflict("conflict")

    context = _context()
    subject = ResourceRef(
        tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1
    )
    adapter = AuditPortAdapter(cast(AuditWriter, cast(Any, _ConflictWriter())))
    with pytest.raises(AuditIdempotencyConflict):
        await adapter.append(context, "test.event", subject, {"result": "ok"}, "same")


@pytest.mark.asyncio
async def test_writer_rejects_cross_tenant_protected_ref_before_database_io() -> None:
    session = AsyncSession()
    async with session.begin():
        writer = AuditWriter(
            session,
            outbox=OutboxWriter(),
            payload_registry=AuditPayloadRegistry(
                {"test.event": AuditPayloadSchema(fields={"result": str})}
            ),
        )
        context = _context()
        subject = ResourceRef(
            tenant_id=context.tenant_id, kind="test.subject", id=new_id(), version=1
        )
        protected = ProtectedPayloadEvidence(
            ref=ResourceRef(tenant_id=new_id(), kind="object", id=new_id(), version=1),
            sha256="a" * 64,
        )
        with pytest.raises(ValueError, match="tenant"):
            await writer.append(
                context,
                "test.event",
                subject,
                {"result": "ok"},
                "command-1",
                protected_payload=protected,
            )
    await session.close()
