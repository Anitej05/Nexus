"""Create the application-append-only, internally tamper-evident audit ledger.

Revision ID: 0002_audit_ledger
Revises: 0002_harden_persistence_acls
Create Date: 2026-08-10
"""

from __future__ import annotations

import os

import sqlalchemy as sa
from alembic import op
from nexus_security.audit_roles import AuditDatabaseRole, validate_audit_database_roles
from sqlalchemy.dialects import postgresql

revision = "0002_audit_ledger"
down_revision = "0002_harden_persistence_acls"
branch_labels = None
depends_on = None


def _quoted_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _quoted_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _validated_role_names() -> tuple[str, str, str]:
    runtime = os.getenv("NEXUS_RUNTIME_DATABASE_USER", "nexus_runtime")
    migration = os.getenv("NEXUS_MIGRATION_DATABASE_USER", "nexus_migrator")
    recovery = os.getenv("NEXUS_AUDIT_RECOVERY_DATABASE_USER", "nexus_audit_recovery")
    bind = op.get_bind()
    role_rows = bind.execute(
        sa.text(
            "select rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
            "rolinherit, rolbypassrls from pg_roles "
            "where rolname in (:runtime,:migration,:recovery)"
        ),
        {"runtime": runtime, "migration": migration, "recovery": recovery},
    ).mappings()
    roles = [
        AuditDatabaseRole(
            row["rolname"],
            row["rolcanlogin"],
            row["rolsuper"],
            row["rolcreatedb"],
            row["rolcreaterole"],
            row["rolinherit"],
            row["rolbypassrls"],
        )
        for row in role_rows
    ]
    membership_rows = bind.execute(
        sa.text(
            "select parent.rolname as role_name, child.rolname as member_name "
            "from pg_auth_members membership "
            "join pg_roles parent on parent.oid=membership.roleid "
            "join pg_roles child on child.oid=membership.member "
            "where parent.rolname in (:runtime,:migration,:recovery) "
            "or child.rolname in (:runtime,:migration,:recovery)"
        ),
        {"runtime": runtime, "migration": migration, "recovery": recovery},
    ).mappings()
    validate_audit_database_roles(
        roles,
        runtime=runtime,
        migration=migration,
        recovery=recovery,
        memberships=[(row["role_name"], row["member_name"]) for row in membership_rows],
    )
    return runtime, migration, recovery


def upgrade() -> None:
    runtime_name, _, recovery_name = _validated_role_names()
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=255), nullable=False),
        sa.Column("resource_kind", sa.String(length=255), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("resource_version", sa.Integer(), nullable=True),
        sa.Column("policy_decision", postgresql.JSONB(), nullable=True),
        sa.Column("policy_revision", sa.String(length=128), nullable=True),
        sa.Column("policy_input_sha256", sa.String(length=64), nullable=True),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("public_payload", postgresql.JSONB(), nullable=False),
        sa.Column("protected_ref_kind", sa.String(length=64), nullable=True),
        sa.Column("protected_ref_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("protected_ref_version", sa.Integer(), nullable=True),
        sa.Column("protected_payload_sha256", sa.String(length=64), nullable=True),
        sa.Column("idempotency_key_sha256", sa.String(length=64), nullable=False),
        sa.Column("request_fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("hash_domain_version", sa.String(length=16), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.CheckConstraint("sequence > 0", name="audit_events_sequence_positive"),
        sa.CheckConstraint(
            "resource_version is null or resource_version > 0",
            name="audit_events_resource_version_positive",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(public_payload) = 'object'", name="audit_events_public_payload_object"
        ),
        sa.CheckConstraint(
            "(policy_decision is null and policy_revision is null and policy_input_sha256 is null) "
            "or (policy_decision is not null and policy_revision is not null "
            "and policy_input_sha256 is not null)",
            name="audit_events_policy_evidence_paired",
        ),
        sa.CheckConstraint(
            "(protected_ref_kind is null and protected_ref_id is null "
            "and protected_ref_version is null and protected_payload_sha256 is null) "
            "or (protected_ref_kind = 'object' and protected_ref_id is not null "
            "and protected_ref_version = 1 and protected_payload_sha256 is not null)",
            name="audit_events_protected_evidence_paired",
        ),
        sa.CheckConstraint(
            "event_type ~ '^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$'",
            name="audit_events_event_type_format",
        ),
        sa.CheckConstraint(
            "hash_domain_version ~ '^[1-9][0-9]{0,7}$'",
            name="audit_events_hash_domain_version_format",
        ),
        sa.CheckConstraint(
            "idempotency_key_sha256 ~ '^[0-9a-f]{64}$' "
            "and request_fingerprint_sha256 ~ '^[0-9a-f]{64}$' "
            "and previous_hash ~ '^[0-9a-f]{64}$' and hash ~ '^[0-9a-f]{64}$' "
            "and (policy_input_sha256 is null or policy_input_sha256 ~ '^[0-9a-f]{64}$') "
            "and (protected_payload_sha256 is null "
            "or protected_payload_sha256 ~ '^[0-9a-f]{64}$')",
            name="audit_events_sha256_format",
        ),
        sa.UniqueConstraint("tenant_id", "sequence", name="audit_events_tenant_sequence"),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key_sha256", name="audit_events_tenant_idempotency"
        ),
    )
    for name, columns in (
        ("audit_events_tenant_sequence_idx", ("tenant_id", "sequence")),
        ("audit_events_tenant_occurred_idx", ("tenant_id", "occurred_at", "sequence")),
        ("audit_events_tenant_type_idx", ("tenant_id", "event_type", "sequence")),
        (
            "audit_events_tenant_resource_idx",
            ("tenant_id", "resource_kind", "resource_id", "sequence"),
        ),
        ("audit_events_tenant_actor_idx", ("tenant_id", "actor_id", "sequence")),
        (
            "audit_events_tenant_correlation_idx",
            ("tenant_id", "correlation_id", "sequence"),
        ),
    ):
        op.create_index(name, "audit_events", list(columns))

    runtime = _quoted_identifier(runtime_name)
    recovery = _quoted_identifier(recovery_name)
    recovery_literal = _quoted_literal(recovery_name)
    op.execute("ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_events FORCE ROW LEVEL SECURITY")
    tenant_expression = "tenant_id = NULLIF(current_setting('nexus.tenant_id', true), '')::uuid"
    op.execute(
        f"CREATE POLICY audit_events_tenant_policy ON audit_events USING ({tenant_expression}) "
        f"WITH CHECK ({tenant_expression})"
    )
    op.execute(
        "CREATE POLICY audit_events_recovery_policy ON audit_events "
        f"USING (session_user = {recovery_literal}) "
        f"WITH CHECK (session_user = {recovery_literal})"
    )
    op.execute(
        f"""CREATE FUNCTION public.guard_audit_ledger_mutation()
        RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public AS $$
        BEGIN
          IF session_user <> {recovery_literal} THEN
            RAISE EXCEPTION 'audit ledger mutation is restricted to recovery tooling'
              USING ERRCODE = '42501';
          END IF;
          RETURN NULL;
        END $$"""
    )
    op.execute(
        "CREATE TRIGGER audit_events_immutable "
        "BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events "
        "FOR EACH STATEMENT EXECUTE FUNCTION public.guard_audit_ledger_mutation()"
    )
    op.execute(f"REVOKE ALL PRIVILEGES ON TABLE audit_events FROM PUBLIC, {runtime}")
    op.execute(f"GRANT SELECT, INSERT ON TABLE audit_events TO {runtime}")
    op.execute(f"GRANT SELECT, UPDATE, DELETE, TRUNCATE ON TABLE audit_events TO {recovery}")
    op.execute("REVOKE ALL ON FUNCTION public.guard_audit_ledger_mutation() FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION public.guard_audit_ledger_mutation() TO {recovery}")


def downgrade() -> None:
    count = op.get_bind().scalar(sa.text("select count(*) from audit_events"))
    if count:
        raise RuntimeError("refusing to downgrade a populated audit ledger")
    op.execute("DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS public.guard_audit_ledger_mutation()")
    op.drop_table("audit_events")
