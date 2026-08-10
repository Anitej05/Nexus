"""Fail-closed validation for the three isolated audit database logins."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuditDatabaseRole:
    name: str
    can_login: bool
    superuser: bool
    createdb: bool
    createrole: bool
    inherit: bool
    bypassrls: bool


def validate_audit_database_roles(
    roles: Sequence[AuditDatabaseRole],
    *,
    runtime: str,
    migration: str,
    recovery: str,
    memberships: Iterable[tuple[str, str]],
) -> None:
    """Reject aliases, absent/unsafe logins, and privilege inheritance paths."""

    protected = {runtime, migration, recovery}
    if len(protected) != 3:
        raise RuntimeError("unsafe audit database role configuration: role names must be distinct")
    by_name = {role.name: role for role in roles}
    if len(by_name) != len(roles) or set(by_name) != protected:
        raise RuntimeError("unsafe audit database role configuration: exact roles are required")

    expected = {
        runtime: (True, False, False, False, False, False),
        migration: (True, False, False, False, False, True),
        recovery: (True, False, False, False, False, False),
    }
    for name, required in expected.items():
        role = by_name[name]
        actual = (
            role.can_login,
            role.superuser,
            role.createdb,
            role.createrole,
            role.inherit,
            role.bypassrls,
        )
        if actual != required:
            raise RuntimeError(f"unsafe audit database role configuration: {name} attributes")

    if any(role in protected or member in protected for role, member in memberships):
        raise RuntimeError("unsafe audit database role configuration: memberships are forbidden")
