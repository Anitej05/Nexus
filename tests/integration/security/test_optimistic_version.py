"""Positive optimistic versions prevent lost tenant-scoped writes."""

import asyncio

from nexus_security.ids import new_id
from nexus_security.tenancy import (
    VersionConflict,
    create_versioned_row,
    update_versioned_row,
    version_conflict_problem,
)
from sqlalchemy import text


async def test_create_expected_version_zero_persists_version_one(tenant_session, contexts) -> None:
    """Allowing a nonzero create precondition would violate create concurrency semantics."""
    row_id = new_id()
    async with tenant_session.begin(contexts.alpha) as session:
        version = await create_versioned_row(
            session,
            "domain_probe",
            {"id": row_id, "tenant_id": contexts.alpha.tenant_id, "value": "initial"},
            expected_version=0,
        )

    assert version == 1


async def test_update_compares_then_increments_version_once(tenant_session, contexts) -> None:
    """Dropping the expected-version predicate or double increment would lose write ordering."""
    row_id = new_id()
    async with tenant_session.begin(contexts.alpha) as session:
        await create_versioned_row(
            session,
            "domain_probe",
            {"id": row_id, "tenant_id": contexts.alpha.tenant_id, "value": "initial"},
            expected_version=0,
        )
    async with tenant_session.begin(contexts.alpha) as session:
        version = await update_versioned_row(
            session,
            "domain_probe",
            row_id,
            expected_version=1,
            values={"value": "updated"},
        )
        stored_version = await session.scalar(
            text("select version from domain_probe where id = :id"), {"id": row_id}
        )

    assert version == 2
    assert stored_version == 2


async def test_concurrent_writers_return_one_version_conflict_problem(
    tenant_session, contexts
) -> None:
    """Removing the compare-and-increment update allows both same-version writers to win."""
    row_id = new_id()
    async with tenant_session.begin(contexts.alpha) as session:
        await create_versioned_row(
            session,
            "domain_probe",
            {"id": row_id, "tenant_id": contexts.alpha.tenant_id, "value": "initial"},
            expected_version=0,
        )

    async def writer(value: str) -> int | VersionConflict:
        try:
            async with tenant_session.begin(contexts.alpha) as session:
                return await update_versioned_row(
                    session,
                    "domain_probe",
                    row_id,
                    expected_version=1,
                    values={"value": value},
                )
        except VersionConflict as error:
            return error

    first, second = await asyncio.gather(writer("first"), writer("second"))
    outcomes = (first, second)
    conflicts = [result for result in outcomes if isinstance(result, VersionConflict)]
    successes = [result for result in outcomes if isinstance(result, int)]

    assert successes == [2]
    assert len(conflicts) == 1
    problem = version_conflict_problem(conflicts[0], contexts.alpha.correlation_id)
    assert problem.status == 409
    assert problem.code == "version_conflict"
