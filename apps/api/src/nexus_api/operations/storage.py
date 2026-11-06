"""Bounded serialized platform store, not an enterprise-scale document database.

PostgreSQL is the deployment backend. SQLite is for local development. All
operations share one locked state row; the complete JSON state is limited to 10 MiB.
"""

import hashlib
import hmac
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

KEYS = ("users", "sessions", "workspaces", "decisions", "receipts")
MAX_BYTES = 10 * 1024 * 1024


class StorageIntegrityError(RuntimeError):
    """Persisted state is malformed, corrupt, or exceeds the supported bound."""


def _encode(state: dict[str, Any]) -> tuple[str, str]:
    if not isinstance(state, dict) or set(state) != set(KEYS):
        raise StorageIntegrityError("Invalid state collections")
    if any(not isinstance(state[key], dict) for key in KEYS):
        raise StorageIntegrityError("Invalid state collection")
    try:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False)
        encoded = payload.encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise StorageIntegrityError("State must be finite JSON") from exc
    if len(encoded) > MAX_BYTES:
        raise StorageIntegrityError("State exceeds 10 MiB limit")
    return payload, hashlib.sha256(encoded).hexdigest()


class OperationsStore:
    def __init__(self, database_url: str):
        if database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        if database_url.startswith("sqlite://"):
            database_url = database_url.replace("sqlite://", "sqlite+aiosqlite://", 1)
        if not database_url.startswith(("postgresql+asyncpg://", "sqlite+aiosqlite://")):
            raise ValueError("Use PostgreSQL asyncpg or development SQLite aiosqlite")
        self.database_url = database_url
        self.sqlite = database_url.startswith("sqlite")
        options = {"connect_args": {"timeout": 30}} if self.sqlite else {}
        self.engine = create_async_engine(database_url, **options)

    async def initialize(self) -> None:
        async with self.engine.begin() as connection:
            # Serialize first-time DDL across independent PostgreSQL processes.
            if not self.sqlite:
                await connection.execute(text("SELECT pg_advisory_xact_lock(734692018)"))
            await connection.execute(
                text(
                    "CREATE TABLE IF NOT EXISTS operations_state "
                    "(id INTEGER PRIMARY KEY, payload TEXT NOT NULL, "
                    "digest VARCHAR(64) NOT NULL)"
                )
            )
            payload, digest = _encode({key: {} for key in KEYS})
            await connection.execute(
                text(
                    "INSERT INTO operations_state (id,payload,digest) "
                    "VALUES (1,:p,:d) ON CONFLICT (id) DO NOTHING"
                ),
                {"p": payload, "d": digest},
            )

    async def close(self) -> None:
        await self.engine.dispose()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[dict[str, Any]]:
        async with self.engine.connect() as connection:
            async with connection.begin():
                if self.sqlite:
                    await connection.execute(text("BEGIN IMMEDIATE"))
                query = "SELECT payload,digest FROM operations_state WHERE id=1"
                if not self.sqlite:
                    query += " FOR UPDATE"
                row = (await connection.execute(text(query))).first()
                if row is None:
                    raise StorageIntegrityError("State row missing")
                try:
                    raw = row.payload.encode("utf-8")
                    if len(raw) > MAX_BYTES or not hmac.compare_digest(
                        hashlib.sha256(raw).hexdigest(), row.digest
                    ):
                        raise StorageIntegrityError("State checksum mismatch")
                    state = json.loads(row.payload)
                    _encode(state)
                except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                    raise StorageIntegrityError("Malformed persisted state") from exc
                yield state
                payload, digest = _encode(state)
                await connection.execute(
                    text("UPDATE operations_state SET payload=:p,digest=:d WHERE id=1"),
                    {"p": payload, "d": digest},
                )
