"""The generic outbox shares the caller's tenant transaction."""

import asyncio
from datetime import UTC, datetime

import pytest
from nexus_contracts.platform import EventEnvelope, ResourceRef
from nexus_security.ids import new_id
from nexus_security.outbox import OutboxWriter
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError


def _envelope(context) -> EventEnvelope:
    now = datetime.now(UTC)
    return EventEnvelope(
        event_id=new_id(),
        event_type="test.domain.changed",
        tenant_id=context.tenant_id,
        source=ResourceRef(tenant_id=context.tenant_id, kind="test.probe", id=new_id(), version=1),
        subject="test:domain",
        occurred_at=now,
        ingested_at=now,
        correlation_id=context.correlation_id,
        sensitivity=frozenset({"internal"}),
        payload={"changed": True},
    )


async def test_domain_audit_and_outbox_roll_back_together(tenant_session, contexts) -> None:
    """Moving outbox insertion to another transaction would leave an event after failure."""
    outbox = OutboxWriter()
    with pytest.raises(RuntimeError, match="abort"):
        async with tenant_session.begin(contexts.alpha) as session:
            await session.execute(
                text(
                    "insert into domain_probe(id, tenant_id, value) values (:id, :tenant, 'domain')"
                ),
                {"id": new_id(), "tenant": contexts.alpha.tenant_id},
            )
            await session.execute(
                text(
                    "insert into audit_probe(id, tenant_id, value) values (:id, :tenant, 'audit')"
                ),
                {"id": new_id(), "tenant": contexts.alpha.tenant_id},
            )
            await outbox.enqueue(session, _envelope(contexts.alpha), "atomic-rollback")
            raise RuntimeError("abort")

    async with tenant_session.begin(contexts.alpha) as session:
        counts = (
            await session.scalar(text("select count(*) from domain_probe")),
            await session.scalar(text("select count(*) from audit_probe")),
            await session.scalar(text("select count(*) from outbox_events")),
        )

    assert counts == (0, 0, 0)


async def test_enqueue_deduplicates_within_tenant(tenant_session, contexts) -> None:
    """Removing the tenant/idempotency uniqueness would duplicate durable delivery."""
    outbox = OutboxWriter()
    async with tenant_session.begin(contexts.alpha) as session:
        first = await outbox.enqueue(session, _envelope(contexts.alpha), "deduplicate")
        second = await outbox.enqueue(session, _envelope(contexts.alpha), "deduplicate")

    assert first == second


async def test_concurrent_enqueue_returns_one_durable_reference(tenant_session, contexts) -> None:
    """A uniqueness race must not leak IntegrityError or create a second event."""
    outbox = OutboxWriter()
    barrier = asyncio.Barrier(2)

    async def writer():
        async with tenant_session.begin(contexts.alpha) as session:
            await barrier.wait()
            return await outbox.enqueue(session, _envelope(contexts.alpha), "concurrent-enqueue")

    first, second = await asyncio.gather(writer(), writer())
    async with tenant_session.begin(contexts.alpha) as session:
        count = await session.scalar(
            text("select count(*) from outbox_events where idempotency_key = 'concurrent-enqueue'")
        )

    assert first == second
    assert count == 1


async def test_crash_before_ack_leaves_event_claimable(tenant_session, contexts) -> None:
    """Persisting a claim outside the caller transaction would lose crashed delivery."""
    outbox = OutboxWriter()
    async with tenant_session.begin(contexts.alpha) as session:
        reference = await outbox.enqueue(session, _envelope(contexts.alpha), "crash-before-ack")

    with pytest.raises(RuntimeError, match="crash"):
        async with tenant_session.begin(contexts.alpha) as session:
            claimed = await outbox.claim(session, "projection", limit=1)
            assert [event.id for event in claimed] == [reference.id]
            raise RuntimeError("crash")

    async with tenant_session.begin(contexts.alpha) as session:
        redelivered = await outbox.claim(session, "projection", limit=1)

    assert [event.id for event in redelivered] == [reference.id]


async def test_skip_locked_claims_do_not_overlap(tenant_session, contexts) -> None:
    """Removing SKIP LOCKED would let concurrent consumers receive the same event."""
    outbox = OutboxWriter()
    async with tenant_session.begin(contexts.alpha) as session:
        reference = await outbox.enqueue(session, _envelope(contexts.alpha), "skip-locked")

    async with tenant_session.begin(contexts.alpha) as first:
        claimed_first = await outbox.claim(first, "projection", limit=1)
        async with tenant_session.begin(contexts.alpha) as second:
            claimed_second = await outbox.claim(second, "projection", limit=1)

    assert [event.id for event in claimed_first] == [reference.id]
    assert claimed_second == ()


async def test_idempotent_acknowledgement_prevents_future_claims(tenant_session, contexts) -> None:
    """Removing the receipt uniqueness would allow duplicate acknowledgement and delivery."""
    outbox = OutboxWriter()
    async with tenant_session.begin(contexts.alpha) as session:
        reference = await outbox.enqueue(session, _envelope(contexts.alpha), "receipt")

    async with tenant_session.begin(contexts.alpha) as session:
        first = await outbox.acknowledge(session, "projection", reference.id)
        second = await outbox.acknowledge(session, "projection", reference.id)

    async with tenant_session.begin(contexts.alpha) as session:
        remaining = await outbox.claim(session, "projection", limit=1)

    assert first == second
    assert remaining == ()


async def test_concurrent_acknowledgement_returns_one_durable_receipt(
    tenant_session, contexts
) -> None:
    """A receipt uniqueness race must not abort either caller transaction."""
    outbox = OutboxWriter()
    async with tenant_session.begin(contexts.alpha) as session:
        reference = await outbox.enqueue(session, _envelope(contexts.alpha), "concurrent-receipt")

    barrier = asyncio.Barrier(2)

    async def acknowledge():
        async with tenant_session.begin(contexts.alpha) as session:
            await barrier.wait()
            return await outbox.acknowledge(session, "projection", reference.id)

    first, second = await asyncio.gather(acknowledge(), acknowledge())
    async with tenant_session.begin(contexts.alpha) as session:
        count = await session.scalar(
            text(
                "select count(*) from consumer_receipts "
                "where consumer_name = 'projection' and event_id = :event_id"
            ),
            {"event_id": reference.id},
        )

    assert first == second
    assert count == 1


async def test_runtime_cannot_delete_or_mutate_immutable_outbox_data(
    tenant_session, contexts
) -> None:
    """Broad DML grants would erase events/receipts or rewrite their durable identity."""
    outbox = OutboxWriter()
    async with tenant_session.begin(contexts.alpha) as session:
        reference = await outbox.enqueue(session, _envelope(contexts.alpha), "immutable-acl")
        await outbox.acknowledge(session, "projection", reference.id)

    operations = (
        ("delete from outbox_events where id = :id", {"id": reference.id}),
        (
            "update outbox_events set idempotency_key = 'rewritten' where id = :id",
            {"id": reference.id},
        ),
        ("update outbox_events set envelope = '{}'::jsonb where id = :id", {"id": reference.id}),
        ("delete from consumer_receipts where event_id = :id", {"id": reference.id}),
        (
            "update consumer_receipts set consumer_name = 'rewritten' where event_id = :id",
            {"id": reference.id},
        ),
    )
    for statement, parameters in operations:
        with pytest.raises(DBAPIError):
            async with tenant_session.begin(contexts.alpha) as session:
                await session.execute(text(statement), parameters)
