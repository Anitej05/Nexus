"""Opaque UUIDv7 generation for persistence adapters."""

from uuid import UUID

from uuid6 import uuid7


def new_id() -> UUID:
    """Return a process-call-ordered UUIDv7 identifier."""
    return uuid7()
