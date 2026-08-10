"""Fail-closed database-role validation for the audit ledger."""

from __future__ import annotations

import pytest
from nexus_security.audit_roles import AuditDatabaseRole, validate_audit_database_roles


def _safe_roles() -> list[AuditDatabaseRole]:
    return [
        AuditDatabaseRole("nexus_runtime", True, False, False, False, False, False),
        AuditDatabaseRole("nexus_migrator", True, False, False, False, False, True),
        AuditDatabaseRole("nexus_audit_recovery", True, False, False, False, False, False),
    ]


def test_exact_isolated_audit_roles_are_accepted() -> None:
    validate_audit_database_roles(
        _safe_roles(),
        runtime="nexus_runtime",
        migration="nexus_migrator",
        recovery="nexus_audit_recovery",
        memberships=[],
    )


@pytest.mark.parametrize(
    ("roles", "runtime", "migration", "recovery", "memberships"),
    [
        (_safe_roles(), "same", "same", "recovery", []),
        (_safe_roles()[:-1], "nexus_runtime", "nexus_migrator", "nexus_audit_recovery", []),
        (
            [
                *_safe_roles()[:-1],
                AuditDatabaseRole(
                    "nexus_audit_recovery", True, True, False, False, False, False
                ),
            ],
            "nexus_runtime",
            "nexus_migrator",
            "nexus_audit_recovery",
            [],
        ),
        (
            _safe_roles(),
            "nexus_runtime",
            "nexus_migrator",
            "nexus_audit_recovery",
            [("nexus_runtime", "nexus_audit_recovery")],
        ),
    ],
)
def test_alias_missing_unsafe_or_inherited_roles_fail_closed(
    roles: list[AuditDatabaseRole],
    runtime: str,
    migration: str,
    recovery: str,
    memberships: list[tuple[str, str]],
) -> None:
    with pytest.raises(RuntimeError, match="unsafe audit database role configuration"):
        validate_audit_database_roles(
            roles,
            runtime=runtime,
            migration=migration,
            recovery=recovery,
            memberships=memberships,
        )
