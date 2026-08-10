"""Transaction-scoped tenant and actor database context."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import cast
from uuid import UUID

import sqlalchemy as sa
from nexus_contracts.platform import Problem, RequestContext
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from nexus_security.db import create_runtime_engine


class TenantSession:
    """Open application sessions that cannot outlive their tenant transaction."""

    def __init__(self, database_url: str) -> None:
        self.engine = create_runtime_engine(database_url)
        self._sessions = async_sessionmaker(self.engine, expire_on_commit=False)

    @asynccontextmanager
    async def begin(self, context: RequestContext) -> AsyncIterator[AsyncSession]:
        """Yield one session with transaction-local tenant and actor GUCs."""
        session = self._sessions()
        try:
            async with session.begin():
                await session.execute(
                    text("select set_config('nexus.tenant_id', :tenant, true)"),
                    {"tenant": str(context.tenant_id)},
                )
                await session.execute(
                    text("select set_config('nexus.actor_id', :actor, true)"),
                    {"actor": str(context.actor_id)},
                )
                yield session
        finally:
            await session.close()

    async def dispose(self) -> None:
        """Release pooled connections, including on Windows event-loop teardown."""
        await self.engine.dispose()


class VersionConflict(Exception):
    """A compare-and-increment precondition failed for a visible resource."""

    def __init__(self, expected_version: int, current_version: int | None) -> None:
        self.expected_version = expected_version
        self.current_version = current_version
        super().__init__(f"expected version {expected_version}, current version {current_version}")


def version_conflict_problem(conflict: VersionConflict, correlation_id: UUID) -> Problem:
    """Adapt a persistence conflict to the canonical framework-neutral problem value."""
    current = "absent" if conflict.current_version is None else str(conflict.current_version)
    return Problem(
        type="https://nexus.local/problems/version-conflict",
        title="Version conflict",
        status=409,
        detail=f"expected version {conflict.expected_version}; current version is {current}",
        code="version_conflict",
        correlation_id=correlation_id,
    )


_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*\Z")


def _validated_identifier(value: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError("table and column names must be lowercase SQL identifiers")
    return value


def _require_transaction(session: AsyncSession) -> None:
    if not session.in_transaction():
        raise RuntimeError("versioned writes require an active TenantSession transaction")


def _versioned_table(table_name: str, columns: tuple[str, ...]) -> sa.TableClause:
    known_columns = tuple(dict.fromkeys(("id", *columns, "version")))
    return sa.table(table_name, *(sa.column(column) for column in known_columns))


async def create_versioned_row(
    session: AsyncSession,
    table: str,
    values: Mapping[str, object],
    *,
    expected_version: int,
) -> int:
    """Create a tenant row at version one only when the caller expects absence."""
    _require_transaction(session)
    if expected_version != 0:
        raise VersionConflict(expected_version, None)
    table_name = _validated_identifier(table)
    columns = tuple(sorted(_validated_identifier(column) for column in values))
    if not columns or "id" not in columns or "version" in columns:
        raise ValueError("new versioned rows require id and may not provide version")
    record = _versioned_table(table_name, columns)
    inserted = await session.execute(
        pg_insert(record)
        .values({**{record.c[column]: values[column] for column in columns}, record.c.version: 1})
        .on_conflict_do_nothing(index_elements=["id"])
        .returning(record.c.version)
    )
    version = inserted.scalar_one_or_none()
    if version is not None:
        return cast(int, version)
    current = await session.scalar(sa.select(record.c.version).where(record.c.id == values["id"]))
    raise VersionConflict(expected_version, cast(int | None, current))


async def update_versioned_row(
    session: AsyncSession,
    table: str,
    row_id: UUID,
    *,
    expected_version: int,
    values: Mapping[str, object],
) -> int:
    """Compare one stored version and increment it exactly once with the update."""
    _require_transaction(session)
    if expected_version < 1:
        raise ValueError("updates require a positive expected version")
    table_name = _validated_identifier(table)
    columns = tuple(sorted(_validated_identifier(column) for column in values))
    if not columns or "id" in columns or "tenant_id" in columns or "version" in columns:
        raise ValueError("updates may only provide mutable non-identity columns")
    record = _versioned_table(table_name, columns)
    updated = await session.execute(
        sa.update(record)
        .where(record.c.id == row_id, record.c.version == expected_version)
        .values(
            {
                **{record.c[column]: values[column] for column in columns},
                "version": record.c.version + 1,
            }
        )
        .returning(record.c.version)
    )
    version = updated.scalar_one_or_none()
    if version is not None:
        return cast(int, version)
    current = await session.scalar(sa.select(record.c.version).where(record.c.id == row_id))
    raise VersionConflict(expected_version, cast(int | None, current))
