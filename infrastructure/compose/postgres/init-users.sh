#!/usr/bin/env sh
set -eu

if [ "$NEXUS_RUNTIME_DATABASE_USER" = "$NEXUS_MIGRATION_DATABASE_USER" ] || \
   [ "$NEXUS_RUNTIME_DATABASE_USER" = "$NEXUS_AUDIT_RECOVERY_DATABASE_USER" ] || \
   [ "$NEXUS_MIGRATION_DATABASE_USER" = "$NEXUS_AUDIT_RECOVERY_DATABASE_USER" ]; then
  echo "unsafe audit database role configuration: role names must be distinct" >&2
  exit 3
fi

# The migration owner, non-owner application role, and isolated audit-recovery
# login are distinct. Passwords are injected through Compose, never migration source.
psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=runtime_user="$NEXUS_RUNTIME_DATABASE_USER" \
  --set=runtime_password="$NEXUS_RUNTIME_DATABASE_PASSWORD" \
  --set=migration_user="$NEXUS_MIGRATION_DATABASE_USER" \
  --set=migration_password="$NEXUS_MIGRATION_DATABASE_PASSWORD" \
  --set=recovery_user="$NEXUS_AUDIT_RECOVERY_DATABASE_USER" \
  --set=recovery_password="$NEXUS_AUDIT_RECOVERY_DATABASE_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS PASSWORD %L', :'migration_user', :'migration_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'migration_user') \gexec
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD %L', :'runtime_user', :'runtime_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'runtime_user') \gexec
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD %L', :'recovery_user', :'recovery_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'recovery_user') \gexec
SELECT (
  (SELECT count(*) <> 3 FROM pg_roles
    WHERE rolname IN (:'runtime_user', :'migration_user', :'recovery_user'))
  OR EXISTS (
    SELECT 1 FROM pg_roles
    WHERE (rolname = :'runtime_user' AND NOT (
      rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
      AND NOT rolinherit AND NOT rolbypassrls))
       OR (rolname = :'migration_user' AND NOT (
      rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
      AND NOT rolinherit AND rolbypassrls))
       OR (rolname = :'recovery_user' AND NOT (
      rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
      AND NOT rolinherit AND NOT rolbypassrls))
  )
  OR EXISTS (
    SELECT 1 FROM pg_auth_members membership
    JOIN pg_roles parent ON parent.oid = membership.roleid
    JOIN pg_roles child ON child.oid = membership.member
    WHERE parent.rolname IN (:'runtime_user', :'migration_user', :'recovery_user')
       OR child.rolname IN (:'runtime_user', :'migration_user', :'recovery_user')
  )
) AS unsafe_roles \gset
\if :unsafe_roles
  \echo 'unsafe audit database role configuration: attributes or memberships' >&2
  \quit 3
\endif
SELECT format('GRANT ALL PRIVILEGES ON DATABASE %I TO %I', current_database(), :'migration_user') \gexec
SELECT format('ALTER DATABASE %I OWNER TO %I', current_database(), :'migration_user') \gexec
SELECT format('ALTER SCHEMA public OWNER TO %I', :'migration_user') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'runtime_user') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'recovery_user') \gexec
SQL
