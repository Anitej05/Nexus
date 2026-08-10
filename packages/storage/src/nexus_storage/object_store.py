"""Tenant-isolated, immutable, idempotent object storage adapter."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256 as calculate_sha256
from secrets import randbits
from typing import Protocol
from uuid import UUID

from nexus_contracts.platform import RequestContext, ResourceRef


class DigestMismatch(ValueError):
    """The supplied SHA-256 value did not match the bytes to persist."""


class IdempotencyConflict(ValueError):
    """An idempotency key was replayed with a materially different request."""


class ObjectNotFound(FileNotFoundError):
    """A requested object does not exist in the object store."""


class ObjectStoreClient(Protocol):
    """S3/MinIO boundary requiring conditional creation and metadata retrieval."""

    async def put_object_if_absent(
        self, bucket: str, key: str, body: bytes, content_type: str, metadata: Mapping[str, str]
    ) -> bool: ...

    async def get_object(self, bucket: str, key: str) -> bytes: ...

    async def get_object_metadata(self, bucket: str, key: str) -> Mapping[str, str]: ...

    async def get_or_create_idempotency_record(
        self,
        bucket: str,
        tenant_id: UUID,
        idempotency_key: str,
        candidate_id: UUID,
        metadata: Mapping[str, str],
    ) -> tuple[UUID, Mapping[str, str]]: ...


@dataclass(frozen=True)
class StoredObject:
    body: bytes
    content_type: str
    metadata: Mapping[str, str]


class InMemoryMinioClient:
    """Concurrency-safe S3 contract double used to exercise the real adapter boundary."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], StoredObject] = {}
        self._lock = asyncio.Lock()
        self._idempotency: dict[tuple[str, UUID, str], tuple[UUID, Mapping[str, str]]] = {}

    async def get_or_create_idempotency_record(
        self,
        bucket: str,
        tenant_id: UUID,
        idempotency_key: str,
        candidate_id: UUID,
        metadata: Mapping[str, str],
    ) -> tuple[UUID, Mapping[str, str]]:
        async with self._lock:
            key = (bucket, tenant_id, idempotency_key)
            return self._idempotency.setdefault(key, (candidate_id, dict(metadata)))

    async def put_object_if_absent(
        self, bucket: str, key: str, body: bytes, content_type: str, metadata: Mapping[str, str]
    ) -> bool:
        object_key = (bucket, key)
        async with self._lock:
            if object_key in self.objects:
                return False
            self.objects[object_key] = StoredObject(body, content_type, dict(metadata))
            return True

    async def get_object(self, bucket: str, key: str) -> bytes:
        try:
            return self.objects[(bucket, key)].body
        except KeyError as error:
            raise ObjectNotFound(key) from error

    async def get_object_metadata(self, bucket: str, key: str) -> Mapping[str, str]:
        try:
            return self.objects[(bucket, key)].metadata
        except KeyError as error:
            raise ObjectNotFound(key) from error


class MinioObjectStore:
    """Object store with deterministic tenant prefixing and durable idempotency recovery."""

    def __init__(self, client: ObjectStoreClient, *, bucket: str) -> None:
        self._client = client
        self._bucket = bucket

    async def put_bytes(
        self,
        context: RequestContext,
        key: str,
        body: bytes,
        content_type: str,
        sha256: str,
        idempotency_key: str,
    ) -> ResourceRef:
        """Atomically create the immutable object or verify a compatible replay."""
        actual_digest = calculate_sha256(body).hexdigest()
        if sha256.lower() != actual_digest:
            raise DigestMismatch("supplied SHA-256 does not match object bytes")
        normalized_key = self._normalize_key(key)
        candidate_id = _new_uuid7()
        metadata = {
            "sha256": actual_digest,
            "tenant_id": str(context.tenant_id),
            "idempotency_key": idempotency_key,
            "logical_key": normalized_key,
            "content_type": content_type,
            "immutable": "true",
        }
        resource_id, persisted_record = await self._client.get_or_create_idempotency_record(
            self._bucket, context.tenant_id, idempotency_key, candidate_id, metadata
        )
        self._verify_replay(persisted_record, metadata)
        ref = ResourceRef(tenant_id=context.tenant_id, kind="object", id=resource_id, version=1)
        object_key = self._object_key(context.tenant_id, resource_id)
        created = await self._client.put_object_if_absent(
            self._bucket, object_key, body, content_type, metadata
        )
        if not created:
            persisted = await self._client.get_object_metadata(self._bucket, object_key)
            self._verify_replay(persisted, metadata)
        return ref

    async def get_bytes(self, context: RequestContext, ref: ResourceRef) -> bytes:
        """Recover the tenant-prefixed location without process-local reference maps."""
        if ref.tenant_id != context.tenant_id:
            raise PermissionError("object references are tenant-scoped")
        object_key = self._object_key(context.tenant_id, ref.id)
        metadata = await self._client.get_object_metadata(self._bucket, object_key)
        if (
            metadata.get("tenant_id") != str(context.tenant_id)
            or metadata.get("immutable") != "true"
        ):
            raise PermissionError("object metadata does not authorize this tenant")
        return await self._client.get_object(self._bucket, object_key)

    @staticmethod
    def _verify_replay(persisted: Mapping[str, str], expected: Mapping[str, str]) -> None:
        immutable = {
            "sha256",
            "tenant_id",
            "idempotency_key",
            "logical_key",
            "content_type",
            "immutable",
        }
        if any(persisted.get(name) != expected[name] for name in immutable):
            raise IdempotencyConflict(
                "idempotency key was replayed with different immutable metadata"
            )

    @staticmethod
    def _object_key(tenant_id: UUID, resource_id: UUID) -> str:
        return f"{tenant_id}/{resource_id}"

    @staticmethod
    def _normalize_key(key: str) -> str:
        segments = key.split("/")
        if not key or key.startswith("/") or any(
            segment in {"", ".", ".."} for segment in segments
        ):
            raise ValueError("object key must be a relative, normalized path")
        return "/".join(segments)


def _new_uuid7() -> UUID:
    """Generate a real UUIDv7 whose high 48 bits are Unix epoch milliseconds."""
    value = (time.time_ns() // 1_000_000 & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= randbits(12) << 64
    value |= 0b10 << 62
    value |= randbits(62)
    return UUID(int=value)
