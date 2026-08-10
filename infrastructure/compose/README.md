# NEXUS local platform stack

This Compose stack is for local development only. PostgreSQL and the Redpanda
event log are authoritative; Neo4j holds a disposable projection that can be
rebuilt from the authoritative records.

All third-party images are pinned to Linux/amd64 digests in `compose.yml`.
The selected Timescale image may include Timescale License components; Neo4j
Community is GPLv3; Redpanda is BSL; MinIO and Grafana are AGPLv3; Redis is
RSALv2/SSPLv1; the remaining selected services are Apache-2.0 or MIT according
to their upstream projects. Review those licenses before redistributing this
development environment. Temporal `auto-setup`, Keycloak `start-dev`, and
MLflow are development conveniences and are not production deployment modes.
`nexus-mlflow:dev` and `nexus-otel-health-probe:dev` are pinned,
infrastructure-only helper images, not NEXUS application images; the three
application-image boundary remains web, API, and worker.

Copy `.env.example` to `.env` and replace all `local-development-*` values
before starting the stack. The application runtime role is non-owner and
`NOBYPASSRLS`; migrations use the separate `BYPASSRLS` owner role. Host access
uses the configured development ports, while service-to-service connections
always use Compose DNS names and canonical container ports.

PostgreSQL only runs files in `docker-entrypoint-initdb.d` when it initializes a
new data directory. After adding or changing the isolated runtime, migration, or
audit-recovery logins on an existing development volume, run the bootstrap
explicitly before migrations:

```sh
docker compose exec postgres /docker-entrypoint-initdb.d/002-application-roles.sh
```

The bootstrap and the audit migration both fail closed if the three configured
names alias one another, a role is missing or over-privileged, or any protected
role participates in role membership. The recovery login must be used directly;
`SET ROLE` cannot satisfy the ledger's `session_user` guard.
