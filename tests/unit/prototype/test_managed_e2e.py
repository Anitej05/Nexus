# ruff: noqa: E501, S105, S603
"""Behavioral guard tests for the managed, disposable prototype E2E runtime."""

from __future__ import annotations

import importlib.util
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType, SimpleNamespace

import httpx
import pytest

SCRIPT = Path("scripts/prototype/run_e2e_managed.py").resolve()
STUB = Path("scripts/prototype/llm_control_stub.py").resolve()
COMPOSE_OVERRIDE = Path("infrastructure/compose/compose.prototype-e2e.yml").resolve()


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("prototype_managed_e2e", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "NEXUS_RUN_COMPOSE_TESTS": "1",
        "NEXUS_PROTOTYPE_E2E_MANAGED": "1",
        "NEXUS_POSTGRES_PASSWORD": "postgres-secret",
        "NEXUS_RUNTIME_DATABASE_PASSWORD": "runtime-secret",
        "NEXUS_MIGRATION_DATABASE_PASSWORD": "migration-secret",
        "NEXUS_AUDIT_RECOVERY_DATABASE_PASSWORD": "recovery-secret",
        "NEXUS_KEYCLOAK_ADMIN": "admin",
        "NEXUS_KEYCLOAK_ADMIN_PASSWORD": "keycloak-secret",
        "NEXUS_PROTOTYPE_LLM_API_KEY": "llm-secret",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_platform_environment_keeps_windows_plugin_root_without_secrets() -> None:
    runtime = _module()
    source = {
        "PATH": r"C:\Windows\System32",
        "ProgramFiles": r"C:\Program Files",
        "NEXUS_POSTGRES_PASSWORD": "DATABASE-SECRET",
    }

    environment = runtime._platform_environment(source)

    assert environment == {
        "PATH": r"C:\Windows\System32",
        "ProgramFiles": r"C:\Program Files",
    }


def test_transient_keycloak_user_has_no_incomplete_profile_actions() -> None:
    runtime = _module()
    principal = runtime.PrincipalSeed(
        label="operator",
        role="operator",
        scopes=("action.read",),
        tenant_id=runtime._uuid7(),
        actor_id=runtime._uuid7(),
        username="prototype-operator@test.invalid",
        password=os.urandom(16).hex(),
    )

    payload = runtime._keycloak_user_payload(principal, "nexus-prototype-e2e-test")

    assert payload["email"] == principal.username
    assert payload["emailVerified"] is True
    assert payload["firstName"] == "Nexus"
    assert payload["lastName"] == "Operator"
    assert payload["requiredActions"] == []


def test_managed_identity_uses_real_oidc_action_scopes() -> None:
    runtime = _module()

    assert runtime.ACTION_SCOPES == (
        "action.read",
        "action.propose",
        "action.execute",
        "action.approve",
    )
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"defaultClientScopes": ["basic", "roles"]' in source
    assert '"optionalClientScopes": [*ACTION_SCOPES]' in source
    assert '"scope": " ".join(principal.scopes)' in source
    assert "oidc-hardcoded-claim-mapper" not in source


def test_llm_stub_bounds_raw_identity_responses_before_json_parsing() -> None:
    source = STUB.read_text(encoding="utf-8")

    assert '"accept-encoding": "identity"' in source
    assert "response.iter_raw()" in source
    assert "len(bounded) > MAX_BODY_BYTES" in source
    assert "response.content" not in source


def test_requires_explicit_managed_opt_in_before_planning(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _module()
    monkeypatch.setenv("NEXUS_RUN_COMPOSE_TESTS", "1")
    monkeypatch.delenv("NEXUS_PROTOTYPE_E2E_MANAGED", raising=False)

    with pytest.raises(RuntimeError, match="NEXUS_PROTOTYPE_E2E_MANAGED=1"):
        runtime.RuntimeConfig.from_environment()


def test_plan_uses_unique_network_and_only_required_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setattr(runtime, "_new_suffix", lambda: "a1b2c3d4e5f6")

    plan = runtime.RuntimeConfig.from_environment().plan()

    assert plan.project == "nexus-prototype-e2e-a1b2c3d4e5f6"
    assert plan.network == "nexus-prototype-e2e-a1b2c3d4e5f6-net"
    assert plan.services == ("postgres", "keycloak", "opa", "opa-health-probe", "api")
    assert plan.compose_infra_up[-4:] == ("postgres", "keycloak", "opa", "opa-health-probe")
    assert plan.compose_api_up[-1:] == ("api",)
    assert "--build" in plan.compose_api_up
    assert "temporal" not in (*plan.compose_infra_up, *plan.compose_api_up)
    assert plan.environment["NEXUS_PROTOTYPE_LLM_TIMEOUT_SECONDS"] == "30"
    assert plan.compose_stop[-2:] == ("down", "--remove-orphans")
    assert "volume" not in " ".join(plan.compose_stop).lower()


def test_compose_override_replaces_ports_and_dependencies_instead_of_resetting_them() -> None:
    override = COMPOSE_OVERRIDE.read_text(encoding="utf-8")

    assert "!reset" not in override
    assert override.count("ports: !override") == 4
    assert "depends_on: !override" in override


def test_test_database_urls_are_exact_and_recovery_stays_out_of_api_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setattr(runtime, "_new_suffix", lambda: "a1b2c3d4e5f6")

    environment = runtime.RuntimeConfig.from_environment().plan().api_environment()

    assert environment["NEXUS_DATABASE_URL"].endswith("@postgres:5432/nexus_test")
    assert environment["NEXUS_MIGRATION_DATABASE_URL"].endswith("@postgres:5432/nexus_test")
    assert "NEXUS_TEST_AUDIT_RECOVERY_DATABASE_URL" not in environment
    assert "recovery-secret" not in "\n".join(environment.values())


def test_dry_run_explains_steps_without_secret_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setattr(runtime, "_new_suffix", lambda: "a1b2c3d4e5f6")

    assert runtime.main(["--dry-run"]) == 0

    output = capsys.readouterr().out
    assert "would create isolated project nexus-prototype-e2e-a1b2c3d4e5f6" in output
    assert "would bootstrap marked nexus_test" in output
    assert "would provision three temporary principals" in output
    for secret in (
        "postgres-secret",
        "runtime-secret",
        "migration-secret",
        "recovery-secret",
        "keycloak-secret",
        "llm-secret",
    ):
        assert secret not in output


def test_browser_preflight_failure_calls_no_runtime_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    calls: list[str] = []
    preflight_calls: list[Path] = []

    class Operations:
        def __getattr__(self, name):
            def forbidden(*_args, **_kwargs):
                calls.append(name)
                raise AssertionError(f"{name} must not run after failed browser preflight")

            return forbidden

    def failed_preflight(root: Path) -> None:
        preflight_calls.append(root)
        raise RuntimeError("browser unavailable")

    monkeypatch.setattr(runtime, "_preflight_browser", failed_preflight)

    with pytest.raises(RuntimeError, match="browser unavailable"):
        runtime.execute(runtime.RuntimeConfig.from_environment().plan(), Operations())

    assert preflight_calls == [runtime.ROOT]
    assert calls == []


def test_browser_preflight_calls_integrated_runner_helper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    runner_path = tmp_path / "scripts" / "prototype" / "run_e2e.py"
    runner_path.parent.mkdir(parents=True)
    runner_path.write_text("# integrated test harness placeholder\n", encoding="utf-8")
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    called: list[Path] = []
    runner = SimpleNamespace(preflight_browser=called.append)
    monkeypatch.setattr(runtime, "_load_runner", lambda path: runner)
    runtime._preflight_browser(tmp_path)

    assert called == [tmp_path]


def test_runner_failure_still_cleans_only_owned_stub_and_compose_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setattr(runtime, "_new_suffix", lambda: "a1b2c3d4e5f6")
    monkeypatch.setattr(runtime, "_preflight_browser", lambda _root: None)
    calls: list[tuple[str, tuple[str, ...]]] = []

    class FakeOperations:
        def start_stub(self, _plan):
            calls.append(("start_stub", ()))

        def start_infra(self, plan):
            calls.append(("start_infra", plan.services[:-1]))

        def bootstrap_database(self, _plan):
            calls.append(("bootstrap_database", ()))

        def provision_identities(self, _plan):
            calls.append(("provision_identities", ()))
            return runtime.E2ETokens("operator-secret", "approver-secret", "other-secret")

        def start_api(self, _plan):
            calls.append(("start_api", ()))

        def run_runner(self, _plan, _tokens):
            calls.append(("run_runner", ()))
            raise RuntimeError("runner failed")

        def cleanup_identities(self, _plan):
            calls.append(("cleanup_identities", ()))

        def stop_stub(self, _plan):
            calls.append(("stop_stub", ()))

        def stop_compose(self, plan):
            calls.append(("stop_compose", plan.compose_stop))

    with pytest.raises(RuntimeError, match="runner failed"):
        runtime.execute(runtime.RuntimeConfig.from_environment().plan(), FakeOperations())

    assert [name for name, _ in calls] == [
        "start_stub",
        "start_infra",
        "bootstrap_database",
        "provision_identities",
        "start_api",
        "run_runner",
        "cleanup_identities",
        "stop_stub",
        "stop_compose",
    ]
    rendered = repr(calls)
    assert "operator-secret" not in rendered
    assert "approver-secret" not in rendered
    assert "other-secret" not in rendered


def test_rejects_non_test_database_url_before_running_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setenv(
        "NEXUS_TEST_DATABASE_URL",
        "postgresql+asyncpg://nexus_runtime:runtime-secret@127.0.0.1:15432/nexus",
    )

    with pytest.raises(RuntimeError, match="nexus_test"):
        runtime.RuntimeConfig.from_environment()


def test_uses_only_the_validated_guarded_database_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setenv("NEXUS_PROTOTYPE_E2E_POSTGRES_PORT", "25432")
    runtime_url = "postgresql+asyncpg://nexus_runtime:runtime-secret@127.0.0.1:25432/nexus_test"
    migration_url = (
        "postgresql+asyncpg://nexus_migrator:migration-secret@127.0.0.1:25432/nexus_test"
    )
    recovery_url = (
        "postgresql+asyncpg://nexus_audit_recovery:recovery-secret@127.0.0.1:25432/nexus_test"
    )
    monkeypatch.setenv("NEXUS_TEST_DATABASE_URL", runtime_url)
    monkeypatch.setenv("NEXUS_TEST_MIGRATION_DATABASE_URL", migration_url)
    monkeypatch.setenv("NEXUS_TEST_AUDIT_RECOVERY_DATABASE_URL", recovery_url)

    plan = runtime.RuntimeConfig.from_environment().plan()

    assert plan.runtime_url == runtime_url
    assert plan.migration_url == migration_url
    assert plan.recovery_url == recovery_url


def test_partial_identity_provision_is_cleaned_up_when_bootstrap_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setattr(runtime, "_preflight_browser", lambda _root: None)
    events: list[str] = []

    class FakeOperations:
        def start_stub(self, _plan):
            events.append("stub")

        def start_infra(self, _plan):
            events.append("compose")

        def bootstrap_database(self, _plan):
            events.append("database")

        def provision_identities(self, _plan):
            events.append("identities")
            raise RuntimeError("identity bootstrap failed")

        def start_api(self, _plan):
            pytest.fail("API must not start")

        def run_runner(self, _plan, _tokens):
            pytest.fail("runner must not execute")

        def cleanup_identities(self, _plan):
            events.append("cleanup-identities")

        def stop_stub(self, _plan):
            events.append("cleanup-stub")

        def stop_compose(self, _plan):
            events.append("cleanup-compose")

    with pytest.raises(RuntimeError, match="identity bootstrap failed"):
        runtime.execute(runtime.RuntimeConfig.from_environment().plan(), FakeOperations())

    assert events[-3:] == ["cleanup-identities", "cleanup-stub", "cleanup-compose"]


def test_child_environments_are_strictly_allowlisted(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setenv("NEXUS_PROTOTYPE_E2E_PROMPT_SENTINEL", "sentinel-canary")
    monkeypatch.setenv("UNRELATED_CANARY", "unrelated-canary")
    config = runtime.RuntimeConfig.from_environment()
    plan = config.plan()
    operations = runtime.ManagedOperations(config)
    tokens = runtime.E2ETokens("operator-canary", "approver-canary", "other-canary")

    stub = operations._stub_environment()
    runner = operations._runner_environment(plan, tokens)

    assert stub["NEXUS_RUN_COMPOSE_TESTS"] == "1"
    assert stub["NEXUS_PROTOTYPE_E2E_MANAGED"] == "1"
    assert not any("secret" in value for value in stub.values())
    assert runner["NEXUS_PROTOTYPE_E2E_OPERATOR_TOKEN"] == "operator-canary"
    assert runner["NEXUS_PROTOTYPE_E2E_PROMPT_SENTINEL"] == "sentinel-canary"
    for child in (stub, runner):
        assert "UNRELATED_CANARY" not in child
        assert "NEXUS_POSTGRES_PASSWORD" not in child
        assert "NEXUS_AUDIT_RECOVERY_DATABASE_PASSWORD" not in child
        assert "NEXUS_KEYCLOAK_ADMIN_PASSWORD" not in child
        assert "NEXUS_PROTOTYPE_LLM_API_KEY" not in child


def test_acceptance_child_preserves_runner_two_argument_screenshot_seam(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = _module()
    runner_path = tmp_path / "scripts" / "prototype" / "run_e2e.py"
    runner_path.parent.mkdir(parents=True)
    runner_path.write_text("# integrated runner\n", encoding="utf-8")
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    calls: list[tuple[str, object]] = []
    browser_runtime = object()

    def capture(populated_html: str, supplied_runtime: object) -> None:
        calls.append((populated_html, supplied_runtime))

    def run(scenario: str) -> None:
        assert scenario == runtime.SCENARIO
        runner._capture_screenshot("<html>safe</html>", browser_runtime)

    runner = SimpleNamespace(_capture_screenshot=capture, run=run)
    monkeypatch.setattr(runtime, "_load_runner", lambda path: runner)

    assert runtime._acceptance_child(runtime.SCENARIO) == 0
    assert calls == [("<html>safe</html>", browser_runtime)]


def test_managed_runtime_has_no_duplicate_or_npx_screenshot_path() -> None:
    runtime = _module()
    source = SCRIPT.read_text(encoding="utf-8")

    assert not hasattr(runtime, "_capture_screenshot")
    assert '"npx"' not in source


@pytest.mark.parametrize("port", ["0", "-1", "65536", "not-a-port"])
def test_explicit_ports_must_be_valid(monkeypatch: pytest.MonkeyPatch, port: str) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setenv("NEXUS_PROTOTYPE_E2E_API_PORT", port)

    with pytest.raises(RuntimeError, match="port"):
        runtime.RuntimeConfig.from_environment()


def test_explicit_ports_must_be_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setenv("NEXUS_PROTOTYPE_E2E_API_PORT", "25432")
    monkeypatch.setenv("NEXUS_PROTOTYPE_E2E_POSTGRES_PORT", "25432")

    with pytest.raises(RuntimeError, match="distinct"):
        runtime.RuntimeConfig.from_environment()


def test_occupied_loopback_port_is_refused() -> None:
    runtime = _module()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))

        with pytest.raises(RuntimeError, match="occupied"):
            runtime._assert_port_available(listener.getsockname()[1])


@pytest.mark.parametrize(
    ("exists", "owner", "markers"),
    [
        (True, "nexus_migrator", None),
        (True, "nexus_migrator", []),
        (True, "nexus_migrator", ["wrong"]),
        (True, "nexus_migrator", ["nexus-prototype-e2e-v1", "nexus-prototype-e2e-v1"]),
        (True, "other_owner", ["nexus-prototype-e2e-v1"]),
    ],
)
def test_existing_database_requires_exact_marker_before_mutation(
    exists: bool, owner: str, markers: list[str] | None
) -> None:
    runtime = _module()

    with pytest.raises(RuntimeError, match="refusing"):
        runtime._database_disposition(exists=exists, owner=owner, markers=markers)


def test_only_new_database_can_receive_marker() -> None:
    runtime = _module()

    assert runtime._database_disposition(exists=False, owner=None, markers=None) == "create"
    assert (
        runtime._database_disposition(
            exists=True, owner="nexus_migrator", markers=["nexus-prototype-e2e-v1"]
        )
        == "reuse"
    )


def test_role_names_are_fixed_and_cannot_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setenv("NEXUS_RUNTIME_DATABASE_USER", "nexus_migrator")

    with pytest.raises(RuntimeError, match="role"):
        runtime.RuntimeConfig.from_environment()


def test_reserved_url_credentials_are_encoded_and_retained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    password = "migrate@:/?#% secret"
    monkeypatch.setenv("NEXUS_MIGRATION_DATABASE_PASSWORD", password)

    plan = runtime.RuntimeConfig.from_environment().plan()

    assert "migrate%40%3A%2F%3F%23%25%20secret" in plan.migration_url
    assert password not in plan.migration_url


def test_api_port_is_rechecked_immediately_before_api_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    config = runtime.RuntimeConfig.from_environment()
    plan = config.plan()
    checked: list[int] = []
    commands: list[tuple[str, ...]] = []
    monkeypatch.setattr(runtime, "_assert_port_available", checked.append)
    operations = runtime.ManagedOperations(config)
    monkeypatch.setattr(operations, "_command", lambda command, _plan: commands.append(command))

    operations.start_api(plan)

    assert checked == [plan.api_port]
    assert commands == [plan.compose_api_up]


@pytest.mark.parametrize("failure_insert", range(1, 9))
def test_database_identity_seed_rolls_back_after_every_insert(
    monkeypatch: pytest.MonkeyPatch, failure_insert: int
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    config = runtime.RuntimeConfig.from_environment()
    plan = config.plan()
    operations = runtime.ManagedOperations(config)
    rolled_back = False

    class Transaction:
        async def __aenter__(self):
            return self

        async def __aexit__(self, error_type, _error, _traceback):
            nonlocal rolled_back
            rolled_back = error_type is not None
            return False

    class Connection:
        def __init__(self):
            self.inserts = 0

        def transaction(self):
            return Transaction()

        async def execute(self, *_args):
            self.inserts += 1
            if self.inserts == failure_insert:
                raise RuntimeError("injected insert failure")

        async def close(self):
            return None

    connection = Connection()

    async def connect(_dsn):
        return connection

    monkeypatch.setitem(sys.modules, "asyncpg", SimpleNamespace(connect=connect))
    principals = operations._new_principals(plan)
    for index, principal in enumerate(principals):
        principal.user_id = f"keycloak-user-{index}"

    with pytest.raises(RuntimeError, match="injected insert failure"):
        import asyncio

        asyncio.run(operations._seed_principals(plan, principals))

    assert rolled_back
    assert operations._owned_tenant_ids == ()
    assert operations._owned_actor_ids == ()
    assert not operations._database_seed_committed


def test_keycloak_cleanup_attempts_every_owned_resource_after_delete_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    operations = runtime.ManagedOperations(runtime.RuntimeConfig.from_environment())
    plan = operations.config.plan()
    operations._user_ids[:] = ["user-a", "user-b", "user-c"]
    operations._client_uuid = "client-internal-uuid"
    attempted: list[str] = []
    monkeypatch.setattr(operations, "_admin_token", lambda _plan: "admin-token")

    def request(method, path, _token, **_kwargs):
        assert method == "DELETE"
        attempted.append(path.rsplit("/", 1)[-1])
        if path.endswith("/user-c"):
            raise RuntimeError("first deletion failed")

    monkeypatch.setattr(operations, "_admin_request", request)

    with pytest.raises(RuntimeError, match="1 operation"):
        operations.cleanup_identities(plan)

    assert attempted == ["user-c", "user-b", "user-a", "client-internal-uuid"]


@pytest.mark.parametrize(
    ("failure_stage", "expected_cleanup"),
    [
        ("start_stub", []),
        ("start_infra", ["stop_stub", "stop_compose"]),
        ("bootstrap_database", ["stop_stub", "stop_compose"]),
        (
            "provision_identities",
            ["cleanup_identities", "stop_stub", "stop_compose"],
        ),
        ("start_api", ["cleanup_identities", "stop_stub", "stop_compose"]),
        ("run_runner", ["cleanup_identities", "stop_stub", "stop_compose"]),
    ],
)
def test_every_startup_boundary_has_exact_reverse_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
    expected_cleanup: list[str],
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    monkeypatch.setattr(runtime, "_preflight_browser", lambda _root: None)
    events: list[str] = []

    class Operations:
        def _stage(self, name):
            events.append(name)
            if name == failure_stage:
                raise RuntimeError("injected boundary failure")

        def start_stub(self, _plan):
            self._stage("start_stub")

        def start_infra(self, _plan):
            self._stage("start_infra")

        def bootstrap_database(self, _plan):
            self._stage("bootstrap_database")

        def provision_identities(self, _plan):
            self._stage("provision_identities")
            return runtime.E2ETokens("one", "two", "three")

        def start_api(self, _plan):
            self._stage("start_api")

        def run_runner(self, _plan, _tokens):
            self._stage("run_runner")

        def cleanup_identities(self, _plan):
            events.append("cleanup_identities")

        def stop_stub(self, _plan):
            events.append("stop_stub")

        def stop_compose(self, _plan):
            events.append("stop_compose")

    with pytest.raises(RuntimeError, match="injected boundary failure"):
        runtime.execute(runtime.RuntimeConfig.from_environment().plan(), Operations())

    assert (
        events[-len(expected_cleanup) :] == expected_cleanup
        if expected_cleanup
        else events == [failure_stage]
    )


def test_failed_stub_readiness_terminates_the_owned_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _module()
    _environment(monkeypatch)
    plan = runtime.RuntimeConfig.from_environment().plan()
    terminated: list[bool] = []

    class Child:
        def terminate(self):
            terminated.append(True)

        def wait(self, timeout):
            del timeout

    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *args, **kwargs: Child())
    monkeypatch.setattr(
        runtime.httpx,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(runtime.httpx.ConnectError("offline")),
    )
    monkeypatch.setattr(runtime.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="did not become ready"):
        runtime.ManagedOperations(runtime.RuntimeConfig.from_environment()).start_stub(plan)

    assert terminated == [True]


def test_llm_control_stub_requires_both_live_guards() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.run(
        [sys.executable, str(STUB), "--port", str(port), "--upstream", "http://127.0.0.1:1/v1"],
        env={"SystemRoot": os.environ.get("SystemRoot", ""), "PATH": os.environ.get("PATH", "")},
        capture_output=True,
        timeout=5,
        check=False,
    )

    assert process.returncode != 0
    assert b"NEXUS_RUN_COMPOSE_TESTS" not in process.stderr


def test_llm_control_stub_returns_typed_unavailable_without_contacting_upstream() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen(
        [sys.executable, str(STUB), "--port", str(port), "--upstream", "http://127.0.0.1:1/v1"],
        env={
            **os.environ,
            "NEXUS_RUN_COMPOSE_TESTS": "1",
            "NEXUS_PROTOTYPE_E2E_MANAGED": "1",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        control = f"http://127.0.0.1:{port}/control"
        for _ in range(30):
            try:
                if httpx.get(control, timeout=0.1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.05)
        else:
            pytest.fail("LLM stub did not start")
        models = httpx.get(f"http://127.0.0.1:{port}/v1/models", timeout=1)
        assert models.status_code == 200
        assert models.json()["data"] == [
            {
                "id": "deepseek-ai/DeepSeek-V4-Flash-0731",
                "object": "model",
                "owned_by": "managed-e2e",
            }
        ]
        assert httpx.post(control, json={"mode": "unavailable"}, timeout=1).status_code == 200
        response = httpx.post(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            json={"model": "deepseek-ai/DeepSeek-V4-Flash-0731"},
            timeout=1,
        )
        assert response.status_code == 503
        assert response.json() == {
            "error": {"code": "provider_unavailable", "message": "unavailable"}
        }
    finally:
        process.terminate()
        process.wait(timeout=5)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/chat/completions"),
        ("POST", "/v1/files"),
        ("POST", "/v1//chat/completions"),
        ("POST", "/v1/%2Fchat/completions"),
        ("POST", "/v1/chat/completions?mode=other"),
        ("PUT", "/control"),
        ("GET", "/control/"),
    ],
)
def test_llm_stub_rejects_every_non_allowlisted_method_and_path(method: str, path: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen(
        [sys.executable, str(STUB), "--port", str(port), "--upstream", "http://127.0.0.1:1/v1"],
        env={
            **os.environ,
            "NEXUS_RUN_COMPOSE_TESTS": "1",
            "NEXUS_PROTOTYPE_E2E_MANAGED": "1",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        control = f"http://127.0.0.1:{port}/control"
        for _ in range(30):
            try:
                if httpx.get(control, timeout=0.1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.05)
        response = httpx.request(method, f"http://127.0.0.1:{port}{path}", timeout=1)
        assert response.status_code in {404, 405}
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_llm_stub_forwards_only_exact_chat_body_and_required_headers() -> None:
    received: dict[str, object] = {}

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return None

        def do_POST(self):  # noqa: N802
            length = int(self.headers["content-length"])
            received.update(
                path=self.path,
                authorization=self.headers.get("authorization"),
                content_type=self.headers.get("content-type"),
                proxy_authorization=self.headers.get("proxy-authorization"),
                unrelated=self.headers.get("x-unrelated-secret"),
                body=self.rfile.read(length),
            )
            body = b'{"id":"allowed-output","choices":[]}'
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        stub_port = listener.getsockname()[1]
    process = subprocess.Popen(
        [
            sys.executable,
            str(STUB),
            "--port",
            str(stub_port),
            "--upstream",
            f"http://127.0.0.1:{upstream.server_port}/v1",
        ],
        env={
            **os.environ,
            "NEXUS_RUN_COMPOSE_TESTS": "1",
            "NEXUS_PROTOTYPE_E2E_MANAGED": "1",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        control = f"http://127.0.0.1:{stub_port}/control"
        for _ in range(30):
            try:
                if httpx.get(control, timeout=0.1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.05)
        request = {
            "model": "deepseek-ai/DeepSeek-V4-Flash-0731",
            "messages": [{"role": "user", "content": "prompt-canary"}],
        }
        response = httpx.post(
            f"http://127.0.0.1:{stub_port}/v1/chat/completions",
            json=request,
            headers={
                "authorization": "Bearer provider-canary",
                "proxy-authorization": "Basic proxy-canary",
                "x-unrelated-secret": "header-canary",
            },
            timeout=2,
        )

        assert response.status_code == 200
        assert response.json() == {"id": "allowed-output", "choices": []}
        assert received["path"] == "/v1/chat/completions"
        assert received["authorization"] == "Bearer provider-canary"
        assert received["content_type"] == "application/json"
        assert received["proxy_authorization"] is None
        assert received["unrelated"] is None
        assert b"prompt-canary" in received["body"]
    finally:
        process.terminate()
        process.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=5)
