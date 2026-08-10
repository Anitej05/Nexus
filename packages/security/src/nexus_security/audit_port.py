"""Frozen public AuditPort adapter over the caller-owned ledger writer."""

from __future__ import annotations

from collections.abc import Mapping

from nexus_contracts.platform import JsonValue, RequestContext, ResourceRef

from nexus_security.audit import AuditWriter


class AuditPortAdapter:
    def __init__(self, writer: AuditWriter) -> None:
        self._writer = writer

    async def append(
        self,
        context: RequestContext,
        event_type: str,
        subject: ResourceRef,
        payload: Mapping[str, JsonValue],
        idempotency_key: str,
    ) -> ResourceRef:
        event = await self._writer.append(context, event_type, subject, payload, idempotency_key)
        return ResourceRef(
            tenant_id=event.tenant_id,
            kind="audit.event",
            id=event.id,
            version=1,
        )
