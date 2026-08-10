"""Harden persistence ACLs without rewriting the released initial revision.

Revision ID: 0002_harden_persistence_acls
Revises: 0001_tenants_and_rls
Create Date: 2026-08-09
"""

from __future__ import annotations

import os

import sqlalchemy as sa
from alembic import op

revision = "0002_harden_persistence_acls"
down_revision = "0001_tenants_and_rls"
branch_labels = None
depends_on = None

_TENANT_TABLES = ("tenants", "tenant_memberships", "outbox_events", "consumer_receipts")


def _quoted_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _runtime_role() -> str:
    return _quoted_identifier(os.getenv("NEXUS_RUNTIME_DATABASE_USER", "nexus_runtime"))


def _restore_0001_acls(runtime_role: str) -> None:
    for table in _TENANT_TABLES:
        op.execute(f"REVOKE ALL PRIVILEGES ON TABLE {table} FROM {runtime_role}")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {table} TO {runtime_role}")


def upgrade() -> None:
    op.add_column("outbox_events", sa.Column("claim_owner", sa.String(length=255), nullable=True))
    op.add_column(
        "outbox_events", sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True)
    )

    runtime_role = _runtime_role()
    for table in _TENANT_TABLES:
        op.execute(f"REVOKE ALL PRIVILEGES ON TABLE {table} FROM {runtime_role}")
    op.execute(f"REVOKE ALL PRIVILEGES ON TABLE external_principals FROM {runtime_role}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON TABLE tenants TO {runtime_role}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON TABLE tenant_memberships TO {runtime_role}")
    op.execute(f"GRANT SELECT, INSERT ON TABLE outbox_events TO {runtime_role}")
    op.execute(f"GRANT UPDATE (claim_owner, claimed_at) ON TABLE outbox_events TO {runtime_role}")
    op.execute(f"GRANT SELECT, INSERT ON TABLE consumer_receipts TO {runtime_role}")


def downgrade() -> None:
    _restore_0001_acls(_runtime_role())
    op.drop_column("outbox_events", "claimed_at")
    op.drop_column("outbox_events", "claim_owner")
