"""Pure deterministic identifiers and resource references for the prototype."""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from nexus_contracts.platform import ResourceRef
from nexus_security.audit import canonical_json_bytes as _canonical_json_bytes
from nexus_security.ids import new_id as _new_id
from pydantic import UUID7, TypeAdapter

_UUID7_ADAPTER = TypeAdapter(UUID7)


def validate_uuid7(value: UUID) -> UUID:
    """Apply the public UUIDv7 validator to an adapter-generated identifier."""
    return _UUID7_ADAPTER.validate_python(value)


def validated_new_id(id_factory: Callable[[], UUID] = _new_id) -> UUID:
    """Obtain an ID through the repository generator boundary and validate its version."""
    return validate_uuid7(id_factory())


def canonical_json_bytes(value: object) -> bytes:
    """Use the repository's bounded RFC 8785 canonical JSON implementation."""
    return _canonical_json_bytes(value)


def event_ref(tenant_id: UUID, event_id: UUID) -> ResourceRef:
    """Address an immutable event as prototype evidence."""
    return ResourceRef(
        tenant_id=tenant_id,
        kind="prototype.event",
        id=validate_uuid7(event_id),
        version=1,
    )


__all__ = ["canonical_json_bytes", "event_ref", "validate_uuid7", "validated_new_id"]
