"""Safety tests for the guarded black-box runner itself."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import httpx
import pytest

SCRIPT = Path("scripts/prototype/run_e2e.py").resolve()
FIXTURES = Path("tests/contract/prototype/_fake_controller.py").resolve()


def _runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("prototype_e2e_runner", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _fixtures() -> ModuleType:
    spec = importlib.util.spec_from_file_location("prototype_e2e_fixtures", FIXTURES)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_guard_refuses_live_work_before_network_or_compose(monkeypatch) -> None:
    runner = _runner()
    monkeypatch.delenv("NEXUS_RUN_COMPOSE_TESTS", raising=False)
    monkeypatch.setattr(runner, "_compose_start", lambda: pytest.fail("compose was called"))
    with pytest.raises(RuntimeError, match="NEXUS_RUN_COMPOSE_TESTS"):
        runner.run(runner.SCENARIO)


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.test",
        "http://user:password@127.0.0.1:8000",
        "file:///tmp/prototype",
    ],
)
def test_token_destination_is_restricted_to_credential_free_loopback(monkeypatch, url: str) -> None:
    runner = _runner()
    monkeypatch.setenv("NEXUS_PROTOTYPE_E2E_BASE_URL", url)
    with pytest.raises(RuntimeError, match="loopback"):
        runner._base_url()


def test_compose_is_untouched_without_manage_opt_in(monkeypatch) -> None:
    runner = _runner()
    monkeypatch.delenv("NEXUS_PROTOTYPE_E2E_MANAGE_COMPOSE", raising=False)
    calls: list[object] = []
    monkeypatch.setattr(runner.subprocess, "run", lambda *args, **kwargs: calls.append(args))
    assert runner._compose_start() is None
    runner._compose_stop(None)
    assert calls == []


def test_managed_compose_uses_unique_project_and_never_tears_down_volumes(monkeypatch) -> None:
    runner = _runner()
    monkeypatch.setenv("NEXUS_PROTOTYPE_E2E_MANAGE_COMPOSE", "1")
    calls: list[list[str]] = []

    def record(command, **kwargs):
        calls.append(command)

    monkeypatch.setattr(runner.subprocess, "run", record)
    project = runner._compose_start()
    runner._compose_stop(project)

    assert project.startswith("nexus-prototype-")
    assert calls[0][0:4] == ["docker", "compose", "-p", project]
    assert calls[1][0:4] == ["docker", "compose", "-p", project]
    assert calls[1][-1] == "stop"
    rendered = " ".join(part for call in calls for part in call).lower()
    assert "down" not in rendered and "volume" not in rendered and "-v" not in rendered


def test_failed_managed_start_stops_only_the_generated_project(monkeypatch) -> None:
    runner = _runner()
    monkeypatch.setenv("NEXUS_PROTOTYPE_E2E_MANAGE_COMPOSE", "1")
    calls: list[list[str]] = []

    def fail_then_record(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(runner.subprocess, "run", fail_then_record)
    with pytest.raises(subprocess.CalledProcessError):
        runner._compose_start()
    project = calls[0][calls[0].index("-p") + 1]
    assert calls[1][calls[1].index("-p") + 1] == project
    assert calls[1][-1] == "stop"


def test_artifact_redaction_matches_secret_values_and_preserves_safe_metadata(monkeypatch) -> None:
    runner = _runner()
    sentinels = {
        "NEXUS_PROTOTYPE_E2E_OPERATOR_TOKEN": "BEARER-NEEDLE",
        "NEXUS_PROTOTYPE_E2E_API_KEY_SENTINEL": "API-KEY-NEEDLE",
        "NEXUS_PROTOTYPE_E2E_PROMPT_SENTINEL": "PROMPT-NEEDLE",
        "NEXUS_PROTOTYPE_E2E_MODEL_OUTPUT_SENTINEL": "MODEL-OUTPUT-NEEDLE",
        "NEXUS_PROTOTYPE_E2E_POLICY_INPUT_SENTINEL": "POLICY-INPUT-NEEDLE",
    }
    for name, value in sentinels.items():
        monkeypatch.setenv(name, value)
    artifact = {
        "prompt_version": "prototype-briefing.v1",
        "summary_sha256": "a" * 64,
        "nested": list(sentinels.values()),
    }
    sanitized = runner._sanitized(artifact)
    runner._assert_no_sensitive_text(sanitized)
    assert sanitized["prompt_version"] == "prototype-briefing.v1"
    assert sanitized["summary_sha256"] == "a" * 64
    assert sanitized["nested"] == ["[redacted]"] * len(sentinels)


def test_live_leak_gate_rejects_credentials_and_preserves_model_identifiers(monkeypatch) -> None:
    runner = _runner()
    api_key = "-".join(("sk", "proj")) + "-A9fK2qM7vR4cT8nP3dL6wZ1x"
    reviewed_probe = "sk-12345678"
    model_id = "demo.incident-risk.v1"
    payload = {"model_id": model_id, "provider_detail": api_key}

    assert runner._sanitized(payload) == {
        "model_id": model_id,
        "provider_detail": "[redacted]",
    }
    runner._assert_no_sensitive_text({"model_id": model_id})
    with pytest.raises(AssertionError):
        runner._assert_no_sensitive_text(payload)
    assert runner._sanitized(reviewed_probe) == "[redacted]"
    with pytest.raises(AssertionError):
        runner._assert_no_sensitive_text(reviewed_probe)

    non_openai_key = "provider-secret-without-openai-prefix"
    monkeypatch.setenv("NEXUS_PROTOTYPE_LLM_API_KEY", non_openai_key)
    assert runner._sanitized({"provider_detail": non_openai_key}) == {
        "provider_detail": "[redacted]"
    }
    with pytest.raises(AssertionError):
        runner._assert_no_sensitive_text({"provider_detail": non_openai_key})


def test_populated_snapshot_contains_visible_accepted_state_and_escapes_markup(
    monkeypatch,
) -> None:
    runner = _runner()
    fixtures = _fixtures()
    monkeypatch.setenv("NEXUS_PROTOTYPE_E2E_PROMPT_SENTINEL", "PROMPT-NEEDLE")
    run_view = fixtures.run_payload(status="verified")
    run_view["llm"] = {**run_view["llm"], "provider_status": "available"}
    run_view["verification"]["observed_delay_hours"] = 14.0
    degraded_view = fixtures.run_payload()
    graph = fixtures.graph_payload()
    graph["nodes"][1]["label"] = "<script>PROMPT-NEEDLE</script>"
    trace = fixtures.trace_payload()

    snapshot = runner._populated_snapshot_html(
        "<html>authenticated dashboard shell</html>",
        run_view,
        degraded_view,
        graph,
        trace,
    )
    runner._assert_populated_snapshot(snapshot, run_view, degraded_view, graph, trace)

    assert "<script>" not in snapshot
    assert "&lt;script&gt;[redacted]&lt;/script&gt;" in snapshot
    assert "score 0.91" in snapshot and "score 0.94" in snapshot
    assert "Correlated operational priority, not a proven causal link" in snapshot
    assert "Live provider state: available" in snapshot
    assert "Degraded provider state: unavailable" in snapshot
    assert "risk R3" in snapshot and "hash " + "a" * 64 in snapshot
    assert "Approval: approved" in snapshot
    assert "Execution: simulated" in snapshot and "sim-receipt-001" in snapshot
    assert "Status: verified" in snapshot and "delay_reduced" in snapshot
    assert "Audit events: 11" in snapshot


def test_response_adapter_accepts_only_the_current_closed_run_view() -> None:
    runner = _runner()
    fixtures = _fixtures()
    current = fixtures.run_payload(status="verified")

    assert runner._validated_run_view(current)["llm"]["prompt_version"] == ("prototype-briefing.v1")
    obsolete = {**current, "briefing": {**current["llm"], "secret": "RESPONSE-NEEDLE"}}
    obsolete.pop("llm")
    with pytest.raises(RuntimeError, match="invalid prototype run response") as failure:
        runner._validated_run_view(obsolete)
    assert "RESPONSE-NEEDLE" not in str(failure.value)
    assert runner._validated_graph(fixtures.graph_payload())["projection_kind"] == (
        "seeded_read_only_prototype"
    )
    assert runner._validated_trace(fixtures.trace_payload())["run_id"] == current["run_id"]


def test_response_body_never_reaches_failure_or_cli_stderr(monkeypatch, tmp_path, capsys) -> None:
    runner = _runner()
    needle = "RESPONSE-NEEDLE"
    response = httpx.Response(
        503,
        text=f'{{"detail":"{needle}"}}',
        headers={"content-type": "application/problem+json"},
    )

    with pytest.raises(RuntimeError) as failure:
        runner._problem(response, 422, "invalid_prototype_request")
    assert needle not in str(failure.value)

    monkeypatch.setattr(runner, "ARTIFACT", tmp_path / "evidence.json")
    monkeypatch.setattr(
        runner,
        "run",
        lambda scenario: runner._problem(response, 422, "invalid_prototype_request"),
    )
    assert runner.cli(["--scenario", runner.SCENARIO]) == 1
    captured = capsys.readouterr()
    assert needle not in captured.out + captured.err
    assert not runner.ARTIFACT.exists() or needle not in runner.ARTIFACT.read_text(encoding="utf-8")


def test_browser_preflight_and_capture_use_only_pinned_local_runtime(monkeypatch, tmp_path) -> None:
    runner = _runner()
    secret_environment = {
        "NEXUS_PROTOTYPE_E2E_OPERATOR_TOKEN": "bearer-child-secret",
        "NEXUS_DATABASE_URL": "postgresql://database-child-secret",
        "NEXUS_POSTGRES_PASSWORD": "database-password-child-secret",
        "NEXUS_KEYCLOAK_ADMIN_PASSWORD": "keycloak-child-secret",
    }
    for name, value in secret_environment.items():
        monkeypatch.setenv(name, value)
    root = tmp_path.resolve()
    node = root / ("node.exe" if os.name == "nt" else "node")
    node.write_bytes(b"synthetic node")
    cli = root / "node_modules" / "playwright" / "cli.js"
    cli.parent.mkdir(parents=True)
    cli.write_text("// synthetic CLI", encoding="utf-8")
    chromium = root / ("chromium.exe" if os.name == "nt" else "chromium")
    chromium.write_bytes(b"synthetic chromium")
    if os.name != "nt":
        node.chmod(0o755)
        chromium.chmod(0o755)

    discovery_calls: list[tuple[list[str], dict[str, object]]] = []

    def discover(command, **kwargs):
        discovery_calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, str(chromium), "RESPONSE-NEEDLE")

    monkeypatch.setattr(runner.shutil, "which", lambda executable: str(node))
    monkeypatch.setattr(runner.subprocess, "run", discover)
    runtime = runner.preflight_browser(root)

    assert runtime == runner.BrowserRuntime(
        node_executable=node,
        playwright_cli=cli,
        chromium_executable=chromium,
    )
    assert discovery_calls[0][0][0] == str(node)
    assert discovery_calls[0][1]["shell"] is False
    discovery_environment = discovery_calls[0][1]["env"]
    assert isinstance(discovery_environment, dict)
    assert not secret_environment.keys() & discovery_environment.keys()
    assert not any(
        secret in discovery_environment.values() for secret in secret_environment.values()
    )

    screenshot = root / "artifact.png"
    monkeypatch.setattr(runner, "ROOT", root)
    monkeypatch.setattr(runner, "SCREENSHOT", screenshot)
    capture_calls: list[tuple[list[str], dict[str, object]]] = []

    def capture(command, **kwargs):
        capture_calls.append((command, kwargs))
        screenshot.write_bytes(b"png")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(runner.subprocess, "run", capture)
    runner._capture_screenshot("<html>safe</html>", runtime)

    command, options = capture_calls[0]
    assert command[:2] == [str(node), str(cli)]
    assert "npx" not in command
    assert options["shell"] is False
    assert options["stdout"] is subprocess.DEVNULL
    assert options["stderr"] is subprocess.DEVNULL
    child_environment = options["env"]
    assert isinstance(child_environment, dict)
    assert not secret_environment.keys() & child_environment.keys()
    assert not any(secret in child_environment.values() for secret in secret_environment.values())


def test_browser_preflight_fails_closed_before_discovery_without_local_cli(
    monkeypatch, tmp_path
) -> None:
    runner = _runner()
    node = tmp_path / ("node.exe" if os.name == "nt" else "node")
    node.write_bytes(b"synthetic node")
    if os.name != "nt":
        node.chmod(0o755)
    monkeypatch.setattr(runner.shutil, "which", lambda executable: str(node))
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("browser discovery was called"),
    )

    with pytest.raises(RuntimeError, match="browser runtime unavailable"):
        runner.preflight_browser(tmp_path)


def test_request_adapter_quotes_etag_and_builds_strict_approval_command() -> None:
    runner = _runner()
    fixtures = _fixtures()
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=fixtures.run_payload(status="approved"))

    with httpx.Client(
        base_url="http://127.0.0.1:8000", transport=httpx.MockTransport(handler)
    ) as client:
        response = runner._approval_request(
            client,
            runner.Principal("test-only-token"),
            fixtures.run_payload()["run_id"],
            key="approval-contract",
            plan_hash="a" * 64,
            decision="approve",
        )

    assert response.status_code == 200
    assert captured["body"] == {"plan_hash": "a" * 64, "decision": "approve"}
    assert captured["headers"]["if-match"] == f'"{"a" * 64}"'


def test_runner_restores_external_llm_mode_and_stops_compose_after_failure(monkeypatch) -> None:
    runner = _runner()
    environment = {
        "NEXUS_RUN_COMPOSE_TESTS": "1",
        "NEXUS_PROTOTYPE_E2E_BASE_URL": "http://127.0.0.1:8000",
        "NEXUS_PROTOTYPE_E2E_OPERATOR_TOKEN": "operator-test-token",
        "NEXUS_PROTOTYPE_E2E_APPROVER_TOKEN": "approver-test-token",
        "NEXUS_PROTOTYPE_E2E_OTHER_TENANT_TOKEN": "other-test-token",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    modes: list[str] = []
    stopped: list[str | None] = []
    startup_order: list[str] = []
    browser_runtime = object()
    monkeypatch.setattr(
        runner,
        "preflight_browser",
        lambda root: startup_order.append("browser") or browser_runtime,
    )
    monkeypatch.setattr(
        runner,
        "_compose_start",
        lambda: startup_order.append("compose") or "nexus-prototype-owned",
    )
    monkeypatch.setattr(runner, "_compose_stop", stopped.append)
    monkeypatch.setattr(runner, "_get_llm_mode", lambda: "original-mode")
    monkeypatch.setattr(runner, "_set_llm_mode", modes.append)

    def fail_create(*args, **kwargs):
        del args, kwargs
        raise RuntimeError("injected live failure")

    monkeypatch.setattr(runner, "_concurrent_create", fail_create)

    with pytest.raises(RuntimeError, match="injected live failure"):
        runner.run(runner.SCENARIO)

    assert modes == ["valid-alias", "original-mode"]
    assert stopped == ["nexus-prototype-owned"]
    assert startup_order == ["browser", "compose"]
