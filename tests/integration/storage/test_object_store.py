"""Integration-style adapter tests using a real tenant-aware object-store boundary."""

from hashlib import sha256
from uuid import UUID

import pytest
from nexus_contracts.platform import RequestContext
from nexus_storage.object_store import DigestMismatch, InMemoryMinioClient, MinioObjectStore


def _context(tenant_id: str) -> RequestContext:
    return RequestContext(
        tenant_id=UUID(tenant_id),
        actor_id=UUID("018f0000-0000-7000-8000-000000000002"),
        correlation_id=UUID("018f0000-0000-7000-8000-000000000003"),
        roles=frozenset(),
        scopes=frozenset(),
        sensitivity_clearances=frozenset(),
    )


@pytest.mark.asyncio
async def test_tenants_cannot_address_each_others_prefixed_minio_object() -> None:
    """Removing tenant checks from get_bytes would leak another tenant's object."""
    store = MinioObjectStore(InMemoryMinioClient(), bucket="nexus")
    alpha = _context("018f0000-0000-7000-8000-000000000001")
    beta = _context("018f0000-0000-7000-8000-000000000005")
    body = b"tenant-alpha-only"
    ref = await store.put_bytes(
        alpha, "evidence/report.txt", body, "text/plain", sha256(body).hexdigest(), "put-1"
    )

    with pytest.raises(PermissionError):
        await store.get_bytes(beta, ref)


@pytest.mark.asyncio
async def test_same_idempotency_key_returns_same_resource_ref() -> None:
    """Removing idempotency tracking would create a second resource reference."""
    store = MinioObjectStore(InMemoryMinioClient(), bucket="nexus")
    context = _context("018f0000-0000-7000-8000-000000000001")
    body = b"immutable-evidence"
    digest = sha256(body).hexdigest()

    first = await store.put_bytes(context, "evidence/a.txt", body, "text/plain", digest, "put-1")
    second = await store.put_bytes(context, "evidence/a.txt", body, "text/plain", digest, "put-1")

    assert second == first


@pytest.mark.asyncio
async def test_digest_mismatch_is_rejected_before_object_upload() -> None:
    """Skipping digest verification would persist corrupted caller-supplied evidence."""
    client = InMemoryMinioClient()
    store = MinioObjectStore(client, bucket="nexus")
    context = _context("018f0000-0000-7000-8000-000000000001")

    with pytest.raises(DigestMismatch):
        await store.put_bytes(context, "evidence/a.txt", b"actual", "text/plain", "0" * 64, "put-1")

    assert client.objects == {}


@pytest.mark.asyncio
async def test_recreated_adapter_recovers_reference_from_immutable_minio_metadata() -> None:
    """Process-local reference maps would make persisted evidence unreadable after restart."""
    client = InMemoryMinioClient()
    alpha = _context("018f0000-0000-7000-8000-000000000001")
    body = b"survives-a-replica-restart"
    ref = await MinioObjectStore(client, bucket="nexus").put_bytes(
        alpha, "evidence/restart.txt", body, "text/plain", sha256(body).hexdigest(), "restart-1"
    )

    recreated = MinioObjectStore(client, bucket="nexus")

    assert await recreated.get_bytes(alpha, ref) == body


@pytest.mark.asyncio
async def test_racing_idempotent_writes_create_one_immutable_object() -> None:
    """A non-atomic client write would allow two replicas to overwrite the same key."""
    import asyncio

    client = InMemoryMinioClient()
    alpha = _context("018f0000-0000-7000-8000-000000000001")
    body = b"one-object-only"
    digest = sha256(body).hexdigest()
    first, second = await asyncio.gather(
        MinioObjectStore(client, bucket="nexus").put_bytes(
            alpha, "evidence/race.txt", body, "text/plain", digest, "race-1"
        ),
        MinioObjectStore(client, bucket="nexus").put_bytes(
            alpha, "evidence/race.txt", body, "text/plain", digest, "race-1"
        ),
    )

    assert first == second
    assert len(client.objects) == 1


@pytest.mark.asyncio
async def test_idempotent_winner_ref_is_a_real_uuid7_and_survives_replica_replay() -> None:
    """Digest-shaped UUIDs violate UUIDv7 epoch semantics and cannot be public references."""
    client = InMemoryMinioClient()
    context = _context("018f0000-0000-7000-8000-000000000001")
    body = b"winner-record"
    before_ms = __import__("time").time_ns() // 1_000_000
    first = await MinioObjectStore(client, bucket="nexus").put_bytes(
        context, "evidence/winner.txt", body, "text/plain", sha256(body).hexdigest(), "winner-1"
    )
    after_ms = __import__("time").time_ns() // 1_000_000
    replay = await MinioObjectStore(client, bucket="nexus").put_bytes(
        context, "evidence/winner.txt", body, "text/plain", sha256(body).hexdigest(), "winner-1"
    )

    assert first == replay
    assert first.id.version == 7
    assert before_ms <= (first.id.int >> 80) <= after_ms
