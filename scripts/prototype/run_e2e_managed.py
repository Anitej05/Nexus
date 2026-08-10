# ruff: noqa: E501, S603, S607
"""Guarded owner for the disposable local prototype E2E runtime."""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import os
import secrets
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Protocol
from urllib.parse import quote, unquote, urlparse

import httpx

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = "storm-and-checkout-shift-v1"
MODEL_ID = "deepseek-ai/DeepSeek-V4-Flash-0731"
ACTION_SCOPES = ("action.read", "action.propose", "action.execute", "action.approve")
TEST_DATABASE = "nexus_test"
TEST_MARKER = "nexus-prototype-e2e-v1"
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
INFRA_SERVICES = ("postgres", "keycloak", "opa", "opa-health-probe")
SERVICES = (*INFRA_SERVICES, "api")
ROLE_NAMES = {
    "NEXUS_POSTGRES_USER": "nexus",
    "NEXUS_RUNTIME_DATABASE_USER": "nexus_runtime",
    "NEXUS_MIGRATION_DATABASE_USER": "nexus_migrator",
    "NEXUS_AUDIT_RECOVERY_DATABASE_USER": "nexus_audit_recovery",
}
PLATFORM_ENVIRONMENT = frozenset(
    {
        "PATH",
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATHEXT",
        # Docker Desktop discovers CLI plugins beneath ProgramFiles on Windows.
        # Preserve that location without forwarding credential-bearing variables.
        "ProgramFiles",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOME",
        "VIRTUAL_ENV",
        "UV_CACHE_DIR",
        "UV_LINK_MODE",
        "PYTHONUTF8",
        "PYTHONIOENCODING",
    }
)
RUNNER_SENTINELS = frozenset(
    {
        "NEXUS_PROTOTYPE_E2E_API_KEY_SENTINEL",
        "NEXUS_PROTOTYPE_E2E_PROMPT_SENTINEL",
        "NEXUS_PROTOTYPE_E2E_MODEL_OUTPUT_SENTINEL",
        "NEXUS_PROTOTYPE_E2E_POLICY_INPUT_SENTINEL",
    }
)


def _new_suffix() -> str:
    return secrets.token_hex(6)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _parse_port(name: str) -> int:
    raw = os.getenv(name)
    if raw is None:
        return _free_port()
    try:
        port = int(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be a valid port") from error
    if not 1 <= port <= 65535:
        raise RuntimeError(f"{name} must be a valid port")
    return port


def _assert_port_available(port: int) -> None:
    if not 1 <= port <= 65535:
        raise RuntimeError("managed E2E port is outside 1..65535")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as error:
            raise RuntimeError("managed E2E loopback port is already occupied") from error


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is required for managed prototype E2E")
    return value


def _platform_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    current = os.environ if source is None else source
    return {name: current[name] for name in PLATFORM_ENVIRONMENT if current.get(name)}


def _url(user: str, password: str, host: str, port: int, database: str) -> str:
    encoded_user = quote(user, safe="")
    encoded_password = quote(password, safe="")
    return f"postgresql+asyncpg://{encoded_user}:{encoded_password}@{host}:{port}/{database}"


def _safe_test_url(value: str, *, user: str, password: str, port: int, name: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme != "postgresql+asyncpg"
        or parsed.hostname not in LOOPBACK
        or parsed.port != port
        or parsed.username is None
        or unquote(parsed.username) != user
        or parsed.password is None
        or unquote(parsed.password) != password
        or parsed.path.lstrip("/") != TEST_DATABASE
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(f"{name} must be the exact guarded {user} URL for {TEST_DATABASE}")
    return value


def _uuid7() -> uuid.UUID:
    milliseconds = int(time.time() * 1000) & ((1 << 48) - 1)
    value = milliseconds << 80
    value |= 0x7 << 76
    value |= secrets.randbits(12) << 64
    value |= 0b10 << 62
    value |= secrets.randbits(62)
    return uuid.UUID(int=value)


def _database_disposition(*, exists: bool, owner: str | None, markers: list[str] | None) -> str:
    if not exists:
        if owner is not None or markers is not None:
            raise RuntimeError("refusing inconsistent missing nexus_test state")
        return "create"
    if owner != "nexus_migrator":
        raise RuntimeError("refusing existing nexus_test with unexpected owner")
    if markers != [TEST_MARKER]:
        raise RuntimeError("refusing existing nexus_test without exact managed marker")
    return "reuse"


@dataclass(frozen=True)
class E2ETokens:
    operator: str
    approver: str
    other_tenant: str


@dataclass
class PrincipalSeed:
    label: str
    role: str
    scopes: tuple[str, ...]
    tenant_id: uuid.UUID
    actor_id: uuid.UUID
    username: str
    password: str
    user_id: str | None = None


def _keycloak_user_payload(principal: PrincipalSeed, project: str) -> dict[str, object]:
    """Create a direct-grant-ready transient user without pending profile actions."""
    return {
        "username": principal.username,
        "email": principal.username,
        "firstName": "Nexus",
        "lastName": principal.label.title(),
        "emailVerified": True,
        "enabled": True,
        "requiredActions": [],
        "attributes": {"nexus_prototype_e2e_project": [project]},
        "credentials": [
            {"type": "password", "value": principal.password, "temporary": False}
        ],
    }


@dataclass(frozen=True)
class RuntimePlan:
    project: str
    network: str
    postgres_port: int
    keycloak_port: int
    opa_port: int
    api_port: int
    llm_port: int
    runtime_url: str
    migration_url: str
    recovery_url: str
    admin_url: str
    internal_runtime_url: str
    internal_migration_url: str
    environment: dict[str, str]
    services: tuple[str, ...] = SERVICES

    @property
    def compose_base(self) -> tuple[str, ...]:
        return (
            "docker",
            "compose",
            "-p",
            self.project,
            "-f",
            "infrastructure/compose/compose.yml",
            "-f",
            "infrastructure/compose/compose.prototype-e2e.yml",
        )

    @property
    def compose_infra_up(self) -> tuple[str, ...]:
        return (*self.compose_base, "up", "-d", "--wait", *INFRA_SERVICES)

    @property
    def compose_api_up(self) -> tuple[str, ...]:
        return (*self.compose_base, "up", "-d", "--wait", "--no-deps", "--build", "api")

    @property
    def compose_stop(self) -> tuple[str, ...]:
        return (*self.compose_base, "down", "--remove-orphans")

    @property
    def runner_path(self) -> Path:
        return ROOT / "scripts" / "prototype" / "run_e2e.py"

    @property
    def keycloak_base(self) -> str:
        return f"http://127.0.0.1:{self.keycloak_port}"

    def api_environment(self) -> dict[str, str]:
        return {
            "NEXUS_DATABASE_URL": self.internal_runtime_url,
            "NEXUS_MIGRATION_DATABASE_URL": self.internal_migration_url,
            "NEXUS_OPA_DECISION_URL": "http://opa:8181/v1/data/nexus/authz/decision",
            "NEXUS_OIDC_ISSUER": f"{self.keycloak_base}/realms/nexus",
            "NEXUS_OIDC_JWKS_URL": "http://keycloak:8080/realms/nexus/protocol/openid-connect/certs",
            "NEXUS_OIDC_AUDIENCE": "nexus-api",
            "NEXUS_PROTOTYPE_LLM_BASE_URL": f"http://host.docker.internal:{self.llm_port}/v1",
            "NEXUS_PROTOTYPE_LLM_MODEL": MODEL_ID,
        }


@dataclass(frozen=True)
class RuntimeConfig:
    postgres_password: str
    runtime_password: str
    migration_password: str
    recovery_password: str
    keycloak_admin: str
    keycloak_admin_password: str
    keycloak_test_admin_password: str
    keycloak_test_viewer_password: str
    worker_client_secret: str
    llm_api_key: str
    postgres_port: int
    keycloak_port: int
    opa_port: int
    api_port: int
    llm_port: int
    runtime_url: str
    migration_url: str
    recovery_url: str

    @classmethod
    def from_environment(cls) -> RuntimeConfig:
        if os.getenv("NEXUS_RUN_COMPOSE_TESTS") != "1":
            raise RuntimeError("set NEXUS_RUN_COMPOSE_TESTS=1 for managed prototype E2E")
        if os.getenv("NEXUS_PROTOTYPE_E2E_MANAGED") != "1":
            raise RuntimeError("set NEXUS_PROTOTYPE_E2E_MANAGED=1 to permit managed E2E")
        for name, expected in ROLE_NAMES.items():
            if os.getenv(name, expected) != expected:
                raise RuntimeError(f"{name} violates the fixed managed E2E role contract")
        ports = {
            "postgres": _parse_port("NEXUS_PROTOTYPE_E2E_POSTGRES_PORT"),
            "keycloak": _parse_port("NEXUS_PROTOTYPE_E2E_KEYCLOAK_PORT"),
            "opa": _parse_port("NEXUS_PROTOTYPE_E2E_OPA_PORT"),
            "api": _parse_port("NEXUS_PROTOTYPE_E2E_API_PORT"),
            "llm": _parse_port("NEXUS_PROTOTYPE_E2E_LLM_PORT"),
        }
        if len(set(ports.values())) != len(ports):
            raise RuntimeError("managed E2E ports must be distinct")
        postgres_password = _required("NEXUS_POSTGRES_PASSWORD")
        runtime_password = _required("NEXUS_RUNTIME_DATABASE_PASSWORD")
        migration_password = _required("NEXUS_MIGRATION_DATABASE_PASSWORD")
        recovery_password = _required("NEXUS_AUDIT_RECOVERY_DATABASE_PASSWORD")
        canonical = {
            "runtime": _url(
                "nexus_runtime", runtime_password, "127.0.0.1", ports["postgres"], TEST_DATABASE
            ),
            "migration": _url(
                "nexus_migrator", migration_password, "127.0.0.1", ports["postgres"], TEST_DATABASE
            ),
            "recovery": _url(
                "nexus_audit_recovery",
                recovery_password,
                "127.0.0.1",
                ports["postgres"],
                TEST_DATABASE,
            ),
        }
        runtime_url = os.getenv("NEXUS_TEST_DATABASE_URL", canonical["runtime"])
        migration_url = os.getenv("NEXUS_TEST_MIGRATION_DATABASE_URL", canonical["migration"])
        recovery_url = os.getenv("NEXUS_TEST_AUDIT_RECOVERY_DATABASE_URL", canonical["recovery"])
        _safe_test_url(
            runtime_url,
            user="nexus_runtime",
            password=runtime_password,
            port=ports["postgres"],
            name="NEXUS_TEST_DATABASE_URL",
        )
        _safe_test_url(
            migration_url,
            user="nexus_migrator",
            password=migration_password,
            port=ports["postgres"],
            name="NEXUS_TEST_MIGRATION_DATABASE_URL",
        )
        _safe_test_url(
            recovery_url,
            user="nexus_audit_recovery",
            password=recovery_password,
            port=ports["postgres"],
            name="NEXUS_TEST_AUDIT_RECOVERY_DATABASE_URL",
        )
        return cls(
            postgres_password=postgres_password,
            runtime_password=runtime_password,
            migration_password=migration_password,
            recovery_password=recovery_password,
            keycloak_admin=_required("NEXUS_KEYCLOAK_ADMIN"),
            keycloak_admin_password=_required("NEXUS_KEYCLOAK_ADMIN_PASSWORD"),
            keycloak_test_admin_password=os.getenv(
                "NEXUS_KEYCLOAK_TEST_ADMIN_PASSWORD", secrets.token_urlsafe(32)
            ),
            keycloak_test_viewer_password=os.getenv(
                "NEXUS_KEYCLOAK_TEST_VIEWER_PASSWORD", secrets.token_urlsafe(32)
            ),
            worker_client_secret=os.getenv(
                "NEXUS_OIDC_WORKER_CLIENT_SECRET", secrets.token_urlsafe(32)
            ),
            llm_api_key=os.getenv("NEXUS_PROTOTYPE_LLM_API_KEY", ""),
            postgres_port=ports["postgres"],
            keycloak_port=ports["keycloak"],
            opa_port=ports["opa"],
            api_port=ports["api"],
            llm_port=ports["llm"],
            runtime_url=runtime_url,
            migration_url=migration_url,
            recovery_url=recovery_url,
        )

    def plan(self) -> RuntimePlan:
        suffix = _new_suffix()
        project = f"nexus-prototype-e2e-{suffix}"
        internal_runtime = _url(
            "nexus_runtime", self.runtime_password, "postgres", 5432, TEST_DATABASE
        )
        internal_migration = _url(
            "nexus_migrator", self.migration_password, "postgres", 5432, TEST_DATABASE
        )
        admin_url = _url(
            "nexus", self.postgres_password, "127.0.0.1", self.postgres_port, "postgres"
        )
        environment = {
            "NEXUS_RUN_COMPOSE_TESTS": "1",
            "NEXUS_PROTOTYPE_E2E_MANAGED": "1",
            "NEXUS_PROTOTYPE_E2E_NETWORK": f"{project}-net",
            "NEXUS_PROTOTYPE_E2E_POSTGRES_PORT": str(self.postgres_port),
            "NEXUS_PROTOTYPE_E2E_KEYCLOAK_PORT": str(self.keycloak_port),
            "NEXUS_PROTOTYPE_E2E_OPA_PORT": str(self.opa_port),
            "NEXUS_PROTOTYPE_E2E_API_PORT": str(self.api_port),
            "NEXUS_PROTOTYPE_E2E_LLM_PORT": str(self.llm_port),
            "NEXUS_PROTOTYPE_E2E_DATABASE_INTERNAL_URL": internal_runtime,
            "NEXUS_PROTOTYPE_E2E_MIGRATION_INTERNAL_URL": internal_migration,
            "NEXUS_DATABASE_INTERNAL_URL": internal_runtime,
            "NEXUS_MIGRATION_DATABASE_INTERNAL_URL": internal_migration,
            "NEXUS_POSTGRES_DB": "nexus",
            "NEXUS_POSTGRES_USER": "nexus",
            "NEXUS_POSTGRES_PASSWORD": self.postgres_password,
            "NEXUS_RUNTIME_DATABASE_USER": "nexus_runtime",
            "NEXUS_RUNTIME_DATABASE_PASSWORD": self.runtime_password,
            "NEXUS_MIGRATION_DATABASE_USER": "nexus_migrator",
            "NEXUS_MIGRATION_DATABASE_PASSWORD": self.migration_password,
            "NEXUS_AUDIT_RECOVERY_DATABASE_USER": "nexus_audit_recovery",
            "NEXUS_AUDIT_RECOVERY_DATABASE_PASSWORD": self.recovery_password,
            "NEXUS_KEYCLOAK_ADMIN": self.keycloak_admin,
            "NEXUS_KEYCLOAK_ADMIN_PASSWORD": self.keycloak_admin_password,
            "NEXUS_KEYCLOAK_TEST_ADMIN_PASSWORD": self.keycloak_test_admin_password,
            "NEXUS_KEYCLOAK_TEST_VIEWER_PASSWORD": self.keycloak_test_viewer_password,
            "NEXUS_OIDC_WORKER_CLIENT_SECRET": self.worker_client_secret,
            "NEXUS_COMPOSE_HOST": "127.0.0.1",
            "NEXUS_KEYCLOAK_HOST_PORT": str(self.keycloak_port),
            "NEXUS_OIDC_ISSUER": f"http://127.0.0.1:{self.keycloak_port}/realms/nexus",
            "NEXUS_OIDC_JWKS_URL": "http://keycloak:8080/realms/nexus/protocol/openid-connect/certs",
            "NEXUS_OIDC_AUDIENCE": "nexus-api",
            "NEXUS_OIDC_WORKER_AZP": "nexus-worker",
            "NEXUS_OPA_DECISION_URL": "http://opa:8181/v1/data/nexus/authz/decision",
            "NEXUS_PROTOTYPE_LLM_API_KEY": self.llm_api_key,
            "NEXUS_PROTOTYPE_LLM_TIMEOUT_SECONDS": "30",
        }
        return RuntimePlan(
            project=project,
            network=f"{project}-net",
            postgres_port=self.postgres_port,
            keycloak_port=self.keycloak_port,
            opa_port=self.opa_port,
            api_port=self.api_port,
            llm_port=self.llm_port,
            runtime_url=self.runtime_url,
            migration_url=self.migration_url,
            recovery_url=self.recovery_url,
            admin_url=admin_url,
            internal_runtime_url=internal_runtime,
            internal_migration_url=internal_migration,
            environment=environment,
        )


class Operations(Protocol):
    def start_stub(self, plan: RuntimePlan) -> None: ...
    def start_infra(self, plan: RuntimePlan) -> None: ...
    def bootstrap_database(self, plan: RuntimePlan) -> None: ...
    def provision_identities(self, plan: RuntimePlan) -> E2ETokens: ...
    def start_api(self, plan: RuntimePlan) -> None: ...
    def run_runner(self, plan: RuntimePlan, tokens: E2ETokens) -> None: ...
    def cleanup_identities(self, plan: RuntimePlan) -> None: ...
    def stop_stub(self, plan: RuntimePlan) -> None: ...
    def stop_compose(self, plan: RuntimePlan) -> None: ...


def execute(plan: RuntimePlan, operations: Operations) -> None:
    _preflight_browser(ROOT)
    stub_owned = compose_owned = identities_owned = False
    try:
        operations.start_stub(plan)
        stub_owned = True
        compose_owned = True
        operations.start_infra(plan)
        operations.bootstrap_database(plan)
        identities_owned = True
        tokens = operations.provision_identities(plan)
        operations.start_api(plan)
        operations.run_runner(plan, tokens)
    finally:
        try:
            if identities_owned:
                operations.cleanup_identities(plan)
        finally:
            try:
                if stub_owned:
                    operations.stop_stub(plan)
            finally:
                if compose_owned:
                    operations.stop_compose(plan)


def _load_runner(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("nexus_prototype_acceptance", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load integrated run_e2e.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _preflight_browser(root: Path) -> None:
    path = root / "scripts" / "prototype" / "run_e2e.py"
    if not path.is_file():
        raise RuntimeError("run_e2e.py is required from the integrated test harness")
    runner = _load_runner(path)
    preflight = getattr(runner, "preflight_browser", None)
    if not callable(preflight):
        raise RuntimeError("integrated run_e2e.py is missing preflight_browser")
    preflight(root)


def _acceptance_child(scenario: str) -> int:
    path = ROOT / "scripts" / "prototype" / "run_e2e.py"
    if not path.is_file():
        raise RuntimeError("run_e2e.py is required from the integrated test harness")
    runner = _load_runner(path)
    runner.run(scenario)
    return 0


@dataclass
class ManagedOperations:
    config: RuntimeConfig
    _stub: subprocess.Popen[bytes] | None = None
    _client_uuid: str | None = None
    _client_scope_ids: list[str] = field(default_factory=list)
    _user_ids: list[str] = field(default_factory=list)
    _owned_tenant_ids: tuple[uuid.UUID, ...] = ()
    _owned_actor_ids: tuple[uuid.UUID, ...] = ()
    _database_seed_committed: bool = False

    def _compose_environment(self, plan: RuntimePlan) -> dict[str, str]:
        return {**_platform_environment(), **plan.environment}

    def _stub_environment(self) -> dict[str, str]:
        return {
            **_platform_environment(),
            "NEXUS_RUN_COMPOSE_TESTS": "1",
            "NEXUS_PROTOTYPE_E2E_MANAGED": "1",
        }

    def _runner_environment(self, plan: RuntimePlan, tokens: E2ETokens) -> dict[str, str]:
        result = {
            **_platform_environment(),
            "NEXUS_RUN_COMPOSE_TESTS": "1",
            "NEXUS_PROTOTYPE_E2E_MANAGED": "1",
            "NEXUS_PROTOTYPE_E2E_MANAGE_COMPOSE": "0",
            "NEXUS_PROTOTYPE_E2E_BASE_URL": f"http://127.0.0.1:{plan.api_port}",
            "NEXUS_PROTOTYPE_E2E_LLM_CONTROL_URL": f"http://127.0.0.1:{plan.llm_port}/control",
            "NEXUS_PROTOTYPE_E2E_OPERATOR_TOKEN": tokens.operator,
            "NEXUS_PROTOTYPE_E2E_APPROVER_TOKEN": tokens.approver,
            "NEXUS_PROTOTYPE_E2E_OTHER_TENANT_TOKEN": tokens.other_tenant,
        }
        for name in RUNNER_SENTINELS:
            if value := os.getenv(name):
                result[name] = value
        return result

    def _command(self, command: tuple[str, ...], plan: RuntimePlan) -> None:
        subprocess.run(
            command,
            cwd=ROOT,
            env=self._compose_environment(plan),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )

    def start_stub(self, plan: RuntimePlan) -> None:
        _assert_port_available(plan.llm_port)
        command = (
            sys.executable,
            str(ROOT / "scripts" / "prototype" / "llm_control_stub.py"),
            "--port",
            str(plan.llm_port),
            "--upstream",
            "http://127.0.0.1:9997/v1",
        )
        self._stub = subprocess.Popen(
            command,
            cwd=ROOT,
            env=self._stub_environment(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(40):
            try:
                response = httpx.get(f"http://127.0.0.1:{plan.llm_port}/control", timeout=0.25)
                if response.status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
        self.stop_stub(plan)
        raise RuntimeError("managed LLM control stub did not become ready")

    def start_infra(self, plan: RuntimePlan) -> None:
        # Compose exposes no stable typed port-bind error across engines/platforms.
        # Fail closed after exact-project cleanup; a fresh command invocation creates
        # a new project and fresh auto-ports (or the caller changes explicit ports)
        # without risking an unrelated-failure retry.
        for port in (plan.postgres_port, plan.keycloak_port, plan.opa_port, plan.api_port):
            _assert_port_available(port)
        self._command(plan.compose_infra_up, plan)

    def start_api(self, plan: RuntimePlan) -> None:
        _assert_port_available(plan.api_port)
        self._command(plan.compose_api_up, plan)

    def bootstrap_database(self, plan: RuntimePlan) -> None:
        disposition = asyncio.run(self._inspect_database(plan))
        self._command(
            (
                *plan.compose_base,
                "exec",
                "-T",
                "postgres",
                "/docker-entrypoint-initdb.d/002-application-roles.sh",
            ),
            plan,
        )
        asyncio.run(self._prepare_database(plan, disposition))
        migration_environment = {
            **_platform_environment(),
            "NEXUS_MIGRATION_DATABASE_URL": plan.migration_url,
            "NEXUS_RUNTIME_DATABASE_USER": "nexus_runtime",
            "NEXUS_MIGRATION_DATABASE_USER": "nexus_migrator",
            "NEXUS_AUDIT_RECOVERY_DATABASE_USER": "nexus_audit_recovery",
        }
        subprocess.run(
            (sys.executable, "-m", "alembic", "-c", "apps/api/alembic.ini", "upgrade", "head"),
            cwd=ROOT,
            env=migration_environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )

    async def _inspect_database(self, plan: RuntimePlan) -> str:
        import asyncpg

        admin_dsn = plan.admin_url.replace("postgresql+asyncpg://", "postgresql://")
        admin = await asyncpg.connect(admin_dsn)
        try:
            owner = await admin.fetchval(
                "select pg_get_userbyid(datdba) from pg_database where datname=$1", TEST_DATABASE
            )
        finally:
            await admin.close()
        if owner is None:
            return _database_disposition(exists=False, owner=None, markers=None)
        test_admin = await asyncpg.connect(admin_dsn.rsplit("/", 1)[0] + f"/{TEST_DATABASE}")
        try:
            marker_exists = await test_admin.fetchval(
                "select to_regclass('public.nexus_test_marker') is not null"
            )
            markers = (
                [
                    row["marker"]
                    for row in await test_admin.fetch(
                        "select marker from public.nexus_test_marker order by marker"
                    )
                ]
                if marker_exists
                else None
            )
        finally:
            await test_admin.close()
        return _database_disposition(exists=True, owner=owner, markers=markers)

    async def _prepare_database(self, plan: RuntimePlan, disposition: str) -> None:
        import asyncpg

        admin_dsn = plan.admin_url.replace("postgresql+asyncpg://", "postgresql://")
        admin = await asyncpg.connect(admin_dsn)
        try:
            if disposition == "create":
                await admin.execute(f"create database {TEST_DATABASE} owner nexus_migrator")
        finally:
            await admin.close()
        if disposition == "create":
            migration = await asyncpg.connect(
                plan.migration_url.replace("postgresql+asyncpg://", "postgresql://")
            )
            try:
                await migration.execute(
                    "create table public.nexus_test_marker "
                    "(marker text primary key check (marker = 'nexus-prototype-e2e-v1'))"
                )
                await migration.execute(
                    "insert into public.nexus_test_marker(marker) values($1)", TEST_MARKER
                )
            finally:
                await migration.close()
        admin = await asyncpg.connect(admin_dsn)
        try:
            await admin.execute(f"grant connect on database {TEST_DATABASE} to nexus_runtime")
            await admin.execute(
                f"grant connect on database {TEST_DATABASE} to nexus_audit_recovery"
            )
        finally:
            await admin.close()

    def _admin_token(self, plan: RuntimePlan) -> str:
        response = httpx.post(
            f"{plan.keycloak_base}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.config.keycloak_admin,
                "password": self.config.keycloak_admin_password,
            },
            timeout=10.0,
        )
        response.raise_for_status()
        bearer = response.json().get("access_token")
        if not isinstance(bearer, str) or not bearer:
            raise RuntimeError("Keycloak did not return an admin token")
        return bearer

    def _admin_request(
        self, method: str, path: str, token: str, **kwargs: object
    ) -> httpx.Response:
        response = httpx.request(
            method,
            path,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
            **kwargs,
        )
        response.raise_for_status()
        return response

    def _new_principals(self, plan: RuntimePlan) -> list[PrincipalSeed]:
        suffix = plan.project.rsplit("-", 1)[-1]
        primary_tenant = _uuid7()
        other_tenant = _uuid7()
        return [
            PrincipalSeed(
                "operator",
                "operator",
                ("action.read", "action.propose", "action.execute"),
                primary_tenant,
                _uuid7(),
                f"prototype-e2e-operator-{suffix}@test.invalid",
                secrets.token_urlsafe(32),
            ),
            PrincipalSeed(
                "approver",
                "approver",
                ("action.read", "action.approve"),
                primary_tenant,
                _uuid7(),
                f"prototype-e2e-approver-{suffix}@test.invalid",
                secrets.token_urlsafe(32),
            ),
            PrincipalSeed(
                "other",
                "operator",
                ("action.read", "action.propose", "action.execute"),
                other_tenant,
                _uuid7(),
                f"prototype-e2e-other-{suffix}@test.invalid",
                secrets.token_urlsafe(32),
            ),
        ]

    def provision_identities(self, plan: RuntimePlan) -> E2ETokens:
        admin_token = self._admin_token(plan)
        suffix = plan.project.rsplit("-", 1)[-1]
        external_client_id = f"nexus-prototype-e2e-{suffix}"
        base = f"{plan.keycloak_base}/admin/realms/nexus"
        client_scopes = self._admin_request("GET", f"{base}/client-scopes", admin_token).json()
        scopes_by_name = {
            item["name"]: item
            for item in client_scopes
            if isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and isinstance(item.get("id"), str)
        }
        for scope_name in ACTION_SCOPES:
            if scope_name in scopes_by_name:
                continue
            created_scope = self._admin_request(
                "POST",
                f"{base}/client-scopes",
                admin_token,
                json={
                    "name": scope_name,
                    "protocol": "openid-connect",
                    "attributes": {
                        "display.on.consent.screen": "false",
                        "include.in.token.scope": "true",
                    },
                },
            )
            scope_id = created_scope.headers.get("location", "").rstrip("/").rsplit("/", 1)[-1]
            if not scope_id:
                raise RuntimeError("Keycloak did not identify temporary client scope")
            self._client_scope_ids.append(scope_id)
        existing = self._admin_request(
            "GET", f"{base}/clients", admin_token, params={"clientId": external_client_id}
        ).json()
        if existing:
            raise RuntimeError("refusing pre-existing managed E2E Keycloak client")
        client = {
            "clientId": external_client_id,
            "enabled": True,
            "publicClient": True,
            "directAccessGrantsEnabled": True,
            "standardFlowEnabled": False,
            "protocol": "openid-connect",
            "defaultClientScopes": ["basic", "roles"],
            "optionalClientScopes": [*ACTION_SCOPES],
            "attributes": {"nexus.prototype.e2e.project": plan.project},
            "protocolMappers": [
                {
                    "name": "nexus-api-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "consentRequired": False,
                    "config": {
                        "included.client.audience": "nexus-api",
                        "access.token.claim": "true",
                        "id.token.claim": "false",
                        "introspection.token.claim": "true",
                    },
                },
            ],
        }
        response = self._admin_request("POST", f"{base}/clients", admin_token, json=client)
        self._client_uuid = response.headers.get("location", "").rstrip("/").rsplit("/", 1)[-1]
        if not self._client_uuid:
            raise RuntimeError("Keycloak did not identify temporary client")
        roles = self._admin_request("GET", f"{base}/roles", admin_token).json()
        by_name = {
            role["name"]: role
            for role in roles
            if isinstance(role, dict) and isinstance(role.get("name"), str)
        }
        if not {"operator", "approver"}.issubset(by_name):
            raise RuntimeError("Keycloak realm is missing required test roles")
        principals = self._new_principals(plan)
        for principal in principals:
            prior = self._admin_request(
                "GET",
                f"{base}/users",
                admin_token,
                params={"username": principal.username, "exact": "true"},
            ).json()
            if prior:
                raise RuntimeError("refusing pre-existing managed E2E Keycloak user")
            payload = _keycloak_user_payload(principal, plan.project)
            created = self._admin_request("POST", f"{base}/users", admin_token, json=payload)
            principal.user_id = created.headers.get("location", "").rstrip("/").rsplit("/", 1)[-1]
            if not principal.user_id:
                raise RuntimeError("Keycloak did not identify temporary user")
            self._user_ids.append(principal.user_id)
            self._admin_request(
                "POST",
                f"{base}/users/{principal.user_id}/role-mappings/realm",
                admin_token,
                json=[by_name[principal.role]],
            )
        asyncio.run(self._seed_principals(plan, principals))
        tokens: list[str] = []
        for principal in principals:
            issued = httpx.post(
                f"{plan.keycloak_base}/realms/nexus/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": external_client_id,
                    "username": principal.username,
                    "password": principal.password,
                    "scope": " ".join(principal.scopes),
                },
                timeout=10.0,
            )
            issued.raise_for_status()
            bearer = issued.json().get("access_token")
            if not isinstance(bearer, str) or not bearer:
                raise RuntimeError("Keycloak did not return a temporary access token")
            tokens.append(bearer)
        return E2ETokens(*tokens)

    async def _seed_principals(self, plan: RuntimePlan, principals: list[PrincipalSeed]) -> None:
        import asyncpg

        if any(principal.user_id is None for principal in principals):
            raise RuntimeError("refusing database seed without complete Keycloak subjects")
        connection = await asyncpg.connect(
            plan.migration_url.replace("postgresql+asyncpg://", "postgresql://")
        )
        try:
            async with connection.transaction():
                tenants = {principal.tenant_id: principal.label for principal in principals}
                for tenant_id, label in tenants.items():
                    await connection.execute(
                        "insert into tenants(id, slug, display_name, status, version) values($1,$2,$3,'active',1)",
                        tenant_id,
                        f"prototype-e2e-{label}-{str(tenant_id)[-8:]}",
                        f"Prototype E2E {label} tenant",
                    )
                issuer = f"{plan.keycloak_base}/realms/nexus"
                for principal in principals:
                    await connection.execute(
                        "insert into external_principals(id, issuer, subject, actor_id, status, version) values($1,$2,$3,$4,'active',1)",
                        _uuid7(),
                        issuer,
                        principal.user_id,
                        principal.actor_id,
                    )
                    await connection.execute(
                        "insert into tenant_memberships(tenant_id, actor_id, roles, scopes, sensitivity_clearances, status) values($1,$2,$3,$4,$5,'active')",
                        principal.tenant_id,
                        principal.actor_id,
                        [principal.role],
                        list(principal.scopes),
                        ["internal"],
                    )
            self._owned_tenant_ids = tuple({principal.tenant_id for principal in principals})
            self._owned_actor_ids = tuple(principal.actor_id for principal in principals)
            self._database_seed_committed = True
        finally:
            await connection.close()

    def run_runner(self, plan: RuntimePlan, tokens: E2ETokens) -> None:
        if not plan.runner_path.is_file():
            raise RuntimeError("run_e2e.py is required from the integrated test harness")
        subprocess.run(
            (
                sys.executable,
                str(Path(__file__).resolve()),
                "--acceptance-child",
                "--scenario",
                SCENARIO,
            ),
            cwd=ROOT,
            env=self._runner_environment(plan, tokens),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )

    def cleanup_identities(self, plan: RuntimePlan) -> None:
        failures: list[str] = []
        if self._database_seed_committed:
            try:
                asyncio.run(self._cleanup_database(plan))
            except Exception as error:  # noqa: BLE001 - aggregate type-only cleanup evidence.
                failures.append(type(error).__name__)
        admin_token: str | None = None
        try:
            admin_token = self._admin_token(plan)
        except Exception as error:  # noqa: BLE001
            failures.append(type(error).__name__)
        if admin_token is not None:
            base = f"{plan.keycloak_base}/admin/realms/nexus"
            for user_id in reversed(self._user_ids):
                try:
                    self._admin_request("DELETE", f"{base}/users/{user_id}", admin_token)
                except Exception as error:  # noqa: BLE001
                    failures.append(type(error).__name__)
            if self._client_uuid is not None:
                try:
                    self._admin_request(
                        "DELETE", f"{base}/clients/{self._client_uuid}", admin_token
                    )
                except Exception as error:  # noqa: BLE001
                    failures.append(type(error).__name__)
            for scope_id in reversed(self._client_scope_ids):
                try:
                    self._admin_request(
                        "DELETE", f"{base}/client-scopes/{scope_id}", admin_token
                    )
                except Exception as error:  # noqa: BLE001
                    failures.append(type(error).__name__)
        self._user_ids.clear()
        self._client_uuid = None
        self._client_scope_ids.clear()
        if failures:
            raise RuntimeError(f"temporary identity cleanup failed in {len(failures)} operation(s)")

    async def _cleanup_database(self, plan: RuntimePlan) -> None:
        import asyncpg

        tenants = list(self._owned_tenant_ids)
        actors = list(self._owned_actor_ids)
        recovery = await asyncpg.connect(
            plan.recovery_url.replace("postgresql+asyncpg://", "postgresql://")
        )
        try:
            await recovery.execute(
                "delete from audit_events where tenant_id = any($1::uuid[])", tenants
            )
        finally:
            await recovery.close()
        migration = await asyncpg.connect(
            plan.migration_url.replace("postgresql+asyncpg://", "postgresql://")
        )
        try:
            async with migration.transaction():
                await migration.execute(
                    "delete from outbox_events where tenant_id = any($1::uuid[])", tenants
                )
                await migration.execute(
                    "delete from tenant_memberships where tenant_id = any($1::uuid[])", tenants
                )
                await migration.execute(
                    "delete from external_principals where actor_id = any($1::uuid[])", actors
                )
                await migration.execute("delete from tenants where id = any($1::uuid[])", tenants)
            self._database_seed_committed = False
            self._owned_tenant_ids = ()
            self._owned_actor_ids = ()
        finally:
            await migration.close()

    def stop_stub(self, _plan: RuntimePlan) -> None:
        if self._stub is not None:
            self._stub.terminate()
            try:
                self._stub.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._stub.kill()
                self._stub.wait(timeout=5)
            self._stub = None

    def stop_compose(self, plan: RuntimePlan) -> None:
        self._command(plan.compose_stop, plan)


def _dry_run(plan: RuntimePlan) -> None:
    print(f"would create isolated project {plan.project} on network {plan.network}")
    print("would start postgres, keycloak, opa, and opa-health-probe before API")
    print(
        "would bootstrap marked nexus_test, migrate it, and use separate runtime/migrator/recovery roles"
    )
    print("would provision three temporary principals, then start API, then invoke run_e2e.py")
    print(
        "would delete only owned identities/memberships and the owned project/network; volumes remain"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--acceptance-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--scenario", default=SCENARIO)
    arguments = parser.parse_args(argv)
    if arguments.acceptance_child:
        return _acceptance_child(arguments.scenario)
    config = RuntimeConfig.from_environment()
    plan = config.plan()
    if arguments.dry_run:
        _dry_run(plan)
        return 0
    execute(plan, ManagedOperations(config))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError, httpx.HTTPError) as error:
        print(f"managed prototype E2E failed: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(1) from None
