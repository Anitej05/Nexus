"""Create tenant-isolated transactional persistence tables.

Revision ID: 0001_tenants_and_rls
Revises:
Create Date: 2026-08-09
"""

from __future__ import annotations

import os

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_tenants_and_rls"
down_revision = None
branch_labels = None
depends_on = None

_TENANT_TABLES = ("tenants", "tenant_memberships", "outbox_events", "consumer_receipts")
_TENANT_EXPRESSION = "NULLIF(current_setting('nexus.tenant_id', true), '')::uuid"


def _quoted_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _add_rls(table: str, tenant_column: str) -> None:
    expression = f"{tenant_column} = {_TENANT_EXPRESSION}"
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY {table}_tenant_isolation ON {table} "
        f"USING ({expression}) WITH CHECK ({expression})"
    )


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(length=255), nullable=False, unique=True),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("version > 0", name="tenants_version_positive"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_table(
        "tenant_memberships",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("roles", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("scopes", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column(
            "sensitivity_clearances",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("status", sa.String(length=64), nullable=False, server_default="active"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("version > 0", name="tenant_memberships_version_positive"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("tenant_id", "actor_id"),
    )
    op.create_table(
        "external_principals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False, server_default="active"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("version > 0", name="external_principals_version_positive"),
        sa.UniqueConstraint("issuer", "subject", name="external_principals_issuer_subject"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_table(
        "outbox_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("envelope", postgresql.JSONB(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("version > 0", name="outbox_events_version_positive"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key", name="outbox_events_tenant_idempotency_key"
        ),
    )
    op.create_table(
        "consumer_receipts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("consumer_name", sa.String(length=255), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "acknowledged_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("version > 0", name="consumer_receipts_version_positive"),
        sa.UniqueConstraint(
            "tenant_id", "consumer_name", "event_id", name="consumer_receipts_tenant_consumer_event"
        ),
    )

    _add_rls("tenants", "id")
    for table in ("tenant_memberships", "outbox_events", "consumer_receipts"):
        _add_rls(table, "tenant_id")

    op.execute("ALTER TABLE external_principals ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE external_principals FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY external_principals_no_direct_access ON external_principals "
        "USING (false) WITH CHECK (false)"
    )

    runtime_role = _quoted_identifier(os.getenv("NEXUS_RUNTIME_DATABASE_USER", "nexus_runtime"))
    for table in _TENANT_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {table} TO {runtime_role}")
    op.execute(
        """
        CREATE FUNCTION public.resolve_principal_memberships(p_issuer text, p_subject text)
        RETURNS TABLE (
            actor_id uuid,
            tenant_id uuid,
            roles text[],
            scopes text[],
            sensitivity_clearances text[]
        )
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT principal.actor_id,
                   membership.tenant_id,
                   membership.roles,
                   membership.scopes,
                   membership.sensitivity_clearances
            FROM public.external_principals AS principal
            JOIN public.tenant_memberships AS membership
              ON membership.actor_id = principal.actor_id
            WHERE principal.issuer = p_issuer
              AND principal.subject = p_subject
              AND principal.status = 'active'
              AND membership.status = 'active'
        $$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.resolve_principal_memberships(text, text) FROM PUBLIC"
    )
    resolver = "public.resolve_principal_memberships(text, text)"
    op.execute(f"GRANT EXECUTE ON FUNCTION {resolver} TO {runtime_role}")


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS public.resolve_principal_memberships(text, text)")
    op.execute("DROP TABLE IF EXISTS external_principals")
    for table in reversed(_TENANT_TABLES):
        op.drop_table(table)
