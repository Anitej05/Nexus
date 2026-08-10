"""Generic tenant-scoped transactional outbox and delivery receipts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import UUID

from nexus_contracts.platform import EventEnvelope, ResourceRef
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from nexus_security.ids import new_id


@dataclass(frozen=True)
class OutboxRecord:
    """An event locked for one consumer within its caller transaction."""

    id: UUID
    tenant_id: UUID
    envelope: EventEnvelope
    version: int


@dataclass(frozen=True)
class ConsumerReceipt:
    """Idempotent acknowledgement for an event consumer."""

    id: UUID
    tenant_id: UUID
    consumer_name: str
    event_id: UUID
    version: int


class OutboxWriter:
    """Write, claim, and acknowledge canonical envelopes in an existing transaction."""

    @staticmethod
    def _require_transaction(session: AsyncSession) -> None:
        if not session.in_transaction():
            raise RuntimeError("outbox operations require an active TenantSession transaction")

    async def enqueue(
        self, session: AsyncSession, envelope: EventEnvelope, idempotency_key: str
    ) -> ResourceRef:
        """Store one canonical envelope or return the prior idempotent record."""
        self._require_transaction(session)
        event_id = new_id()
        inserted = await session.execute(
            text(
                "insert into outbox_events(id, tenant_id, envelope, idempotency_key) "
                "values (:id, :tenant_id, cast(:envelope as jsonb), :idempotency_key) "
                "on conflict (tenant_id, idempotency_key) do nothing returning id, version"
            ),
            {
                "id": event_id,
                "tenant_id": envelope.tenant_id,
                "envelope": json.dumps(envelope.model_dump(mode="json"), separators=(",", ":")),
                "idempotency_key": idempotency_key,
            },
        )
        row = inserted.one_or_none()
        if row is None:
            existing = await session.execute(
                text(
                    "select id, version from outbox_events "
                    "where tenant_id = :tenant_id and idempotency_key = :idempotency_key"
                ),
                {"tenant_id": envelope.tenant_id, "idempotency_key": idempotency_key},
            )
            row = existing.one()
        return ResourceRef(
            tenant_id=envelope.tenant_id,
            kind="outbox.event",
            id=row.id,
            version=row.version,
        )

    async def claim(
        self, session: AsyncSession, consumer_name: str, limit: int
    ) -> tuple[OutboxRecord, ...]:
        """Lock up to ``limit`` undelivered events without persisting a lease."""
        self._require_transaction(session)
        if limit <= 0:
            raise ValueError("limit must be positive")
        result = await session.execute(
            text(
                "select event.id, event.tenant_id, event.envelope, event.version "
                "from outbox_events as event "
                "where not exists ("
                "  select 1 from consumer_receipts as receipt "
                "  where receipt.tenant_id = event.tenant_id "
                "    and receipt.consumer_name = :consumer_name "
                "    and receipt.event_id = event.id"
                ") order by event.created_at, event.id "
                "for update of event skip locked limit :limit"
            ),
            {"consumer_name": consumer_name, "limit": limit},
        )
        records: list[OutboxRecord] = []
        for row in result:
            envelope_data = (
                json.loads(row.envelope) if isinstance(row.envelope, str) else row.envelope
            )
            records.append(
                OutboxRecord(
                    id=row.id,
                    tenant_id=row.tenant_id,
                    envelope=EventEnvelope.model_validate(envelope_data),
                    version=row.version,
                )
            )
        return tuple(records)

    async def acknowledge(
        self, session: AsyncSession, consumer_name: str, event_id: UUID
    ) -> ConsumerReceipt:
        """Record a consumer receipt once; repeat calls return the original receipt."""
        self._require_transaction(session)
        receipt_id = new_id()
        inserted = await session.execute(
            text(
                "insert into consumer_receipts(id, tenant_id, consumer_name, event_id) "
                "select :id, tenant_id, :consumer_name, id from outbox_events where id = :event_id "
                "on conflict (tenant_id, consumer_name, event_id) do nothing "
                "returning id, tenant_id, consumer_name, event_id, version"
            ),
            {"id": receipt_id, "consumer_name": consumer_name, "event_id": event_id},
        )
        row = inserted.one_or_none()
        if row is None:
            existing = await session.execute(
                text(
                    "select id, tenant_id, consumer_name, event_id, version "
                    "from consumer_receipts where consumer_name = :consumer_name "
                    "and event_id = :event_id"
                ),
                {"consumer_name": consumer_name, "event_id": event_id},
            )
            row = existing.one_or_none()
            if row is None:
                raise LookupError("outbox event is not visible to the active tenant")
        return ConsumerReceipt(
            id=row.id,
            tenant_id=row.tenant_id,
            consumer_name=row.consumer_name,
            event_id=row.event_id,
            version=row.version,
        )
