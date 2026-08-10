# ruff: noqa: S101, S607
"""Guarded HTTP acceptance runner for the disposable prototype demonstration.

This script starts only a uniquely named Compose project when explicitly permitted. It
never invokes ``down --volumes``, removes volumes, resets a database, or touches an
existing Compose project. Tokens are supplied only through test-only environment variables
and are never included in the evidence artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

import httpx
from nexus_api.prototype.models import (  # type: ignore[import-untyped]
    PrototypeGraph,
    PrototypeRunView,
    PrototypeTrace,
)
from pydantic import ValidationError

SCENARIO = "storm-and-checkout-shift-v1"
ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "artifacts" / "prototype" / f"{SCENARIO}.json"
SCREENSHOT = ROOT / "artifacts" / "prototype" / f"{SCENARIO}.png"
SENSITIVE_KEYS = frozenset(
    {"authorization", "api_key", "secret", "token", "prompt", "model_output"}
)
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
API_KEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b", re.IGNORECASE)
BROWSER_ENVIRONMENT = frozenset(
    {
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOME",
        "LOCALAPPDATA",
        "XDG_CACHE_HOME",
        "PLAYWRIGHT_BROWSERS_PATH",
        "LANG",
        "LC_ALL",
    }
)


@dataclass(frozen=True)
class Principal:
    """A supplied test-only bearer token; it is deliberately excluded from evidence."""

    token: str

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


@dataclass(frozen=True)
class BrowserRuntime:
    """Absolute, preflighted browser tooling used by the evidence capture step."""

    node_executable: Path
    playwright_cli: Path
    chromium_executable: Path


def _browser_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    current = os.environ if source is None else source
    return {name: current[name] for name in BROWSER_ENVIRONMENT if current.get(name)}


def preflight_browser(root: Path) -> BrowserRuntime:
    """Fail closed unless pinned local Playwright and its Chromium are executable."""
    try:
        resolved_root = root.resolve(strict=True)
    except OSError:
        raise RuntimeError("prototype browser runtime unavailable") from None

    node_raw = shutil.which("node")
    if node_raw is None:
        raise RuntimeError("prototype browser runtime unavailable")
    try:
        node = Path(node_raw).resolve(strict=True)
    except OSError:
        raise RuntimeError("prototype browser runtime unavailable") from None
    if not node.is_file() or not os.access(node, os.X_OK):
        raise RuntimeError("prototype browser runtime unavailable")

    cli_candidate = resolved_root / "node_modules" / "playwright" / "cli.js"
    try:
        cli = cli_candidate.resolve(strict=True)
    except OSError:
        raise RuntimeError("prototype browser runtime unavailable") from None
    if not cli.is_file() or not cli.is_relative_to(resolved_root):
        raise RuntimeError("prototype browser runtime unavailable")

    discovery_script = (
        "const {chromium}=require(process.argv[1]);process.stdout.write(chromium.executablePath());"
    )
    try:
        discovered = subprocess.run(  # noqa: S603 -- absolute preflighted node executable.
            [str(node), "-e", discovery_script, str(cli.parent)],
            check=False,
            cwd=resolved_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            shell=False,
            env=_browser_environment(),
        )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("prototype browser runtime unavailable") from None
    chromium_raw = discovered.stdout.strip()
    if discovered.returncode != 0 or not chromium_raw or len(chromium_raw) > 4096:
        raise RuntimeError("prototype browser runtime unavailable")
    chromium_candidate = Path(chromium_raw)
    if not chromium_candidate.is_absolute():
        raise RuntimeError("prototype browser runtime unavailable")
    try:
        chromium = chromium_candidate.resolve(strict=True)
    except OSError:
        raise RuntimeError("prototype browser runtime unavailable") from None
    if not chromium.is_file() or not os.access(chromium, os.X_OK):
        raise RuntimeError("prototype browser runtime unavailable")
    return BrowserRuntime(
        node_executable=node,
        playwright_cli=cli,
        chromium_executable=chromium,
    )


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is required for guarded prototype E2E")
    return value


def _base_url() -> str:
    raw = _required("NEXUS_PROTOTYPE_E2E_BASE_URL").rstrip("/")
    parsed = urlparse(raw)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.hostname not in LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise RuntimeError("NEXUS_PROTOTYPE_E2E_BASE_URL must be an absolute loopback URL")
    return raw


def _sensitive_values() -> tuple[str, ...]:
    names = (
        "NEXUS_PROTOTYPE_E2E_OPERATOR_TOKEN",
        "NEXUS_PROTOTYPE_E2E_APPROVER_TOKEN",
        "NEXUS_PROTOTYPE_E2E_OTHER_TENANT_TOKEN",
        "NEXUS_PROTOTYPE_LLM_API_KEY",
        "NEXUS_PROTOTYPE_E2E_API_KEY_SENTINEL",
        "NEXUS_PROTOTYPE_E2E_PROMPT_SENTINEL",
        "NEXUS_PROTOTYPE_E2E_MODEL_OUTPUT_SENTINEL",
        "NEXUS_PROTOTYPE_E2E_POLICY_INPUT_SENTINEL",
    )
    return tuple(value for name in names if (value := os.getenv(name)))


def _contains_credential(value: str) -> bool:
    return "bearer " in value.lower() or API_KEY_PATTERN.search(value) is not None


def _sanitized(value: Any, *, sensitive_values: tuple[str, ...] | None = None) -> Any:
    needles = _sensitive_values() if sensitive_values is None else sensitive_values
    if isinstance(value, dict):
        return {
            str(key): (
                "[redacted]"
                if str(key).lower() in SENSITIVE_KEYS
                else _sanitized(item, sensitive_values=needles)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitized(item, sensitive_values=needles) for item in value]
    if isinstance(value, str):
        sanitized = value
        for needle in needles:
            sanitized = sanitized.replace(needle, "[redacted]")
        if _contains_credential(sanitized):
            return "[redacted]"
        return sanitized
    return value


def _assert_no_sensitive_text(value: Any) -> None:
    rendered = json.dumps(value, sort_keys=True)
    for needle in _sensitive_values():
        assert needle not in rendered
    assert not _contains_credential(rendered)


def _validated_run_view(value: Any) -> dict[str, Any]:
    try:
        validated = PrototypeRunView.model_validate(value)
    except ValidationError:
        raise RuntimeError("invalid prototype run response") from None
    return cast(dict[str, Any], validated.model_dump(mode="json"))


def _validated_graph(value: Any) -> dict[str, Any]:
    try:
        validated = PrototypeGraph.model_validate(value)
    except ValidationError:
        raise RuntimeError("invalid prototype graph response") from None
    return cast(dict[str, Any], validated.model_dump(mode="json"))


def _validated_trace(value: Any) -> dict[str, Any]:
    try:
        validated = PrototypeTrace.model_validate(value)
    except ValidationError:
        raise RuntimeError("invalid prototype trace response") from None
    return cast(dict[str, Any], validated.model_dump(mode="json"))


def _compose_start() -> str | None:
    """Optionally create a unique project; stop only that project on exit, never remove volumes."""
    if os.getenv("NEXUS_PROTOTYPE_E2E_MANAGE_COMPOSE") != "1":
        return None
    project = f"nexus-prototype-{uuid.uuid4().hex[:12]}"
    try:
        subprocess.run(  # noqa: S603 -- fixed Compose invocation in the repository.
            [
                "docker",
                "compose",
                "-p",
                project,
                "-f",
                "infrastructure/compose/compose.yml",
                "-f",
                "infrastructure/compose/compose.test.yml",
                "up",
                "-d",
                "--wait",
            ],
            check=True,
            cwd=ROOT,
        )
    except subprocess.CalledProcessError:
        _compose_stop(project)
        raise
    return project


def _compose_stop(project: str | None) -> None:
    if project is None:
        return
    subprocess.run(  # noqa: S603 -- project was generated in _compose_start.
        [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            "infrastructure/compose/compose.yml",
            "-f",
            "infrastructure/compose/compose.test.yml",
            "stop",
        ],
        check=False,
        cwd=ROOT,
    )


def _populated_snapshot_html(
    authenticated_html: str,
    run_view: dict[str, Any],
    degraded_view: dict[str, Any],
    graph: dict[str, Any],
    trace: dict[str, Any],
) -> str:
    """Render a sanitized, self-contained acceptance snapshot from authenticated responses."""
    safe = _sanitized({"run": run_view, "degraded": degraded_view, "graph": graph, "trace": trace})
    _assert_no_sensitive_text(safe)
    safe_run = safe["run"]
    safe_degraded = safe["degraded"]
    safe_graph = safe["graph"]
    safe_trace = safe["trace"]

    def escaped(value: object) -> str:
        return html.escape(str(value), quote=True)

    nodes = "".join(
        f"<li><strong>{escaped(node['id'])}</strong> — "
        f"{escaped(node['type'])}: {escaped(node['label'])}</li>"
        for node in safe_graph["nodes"]
    )
    edges = "".join(
        f"<li>{escaped(edge['source'])} → {escaped(edge['type'])} → {escaped(edge['target'])}</li>"
        for edge in safe_graph["edges"]
    )
    events = "".join(
        f"<li>#{escaped(event['sequence'])} {escaped(event['event_type'])}</li>"
        for event in safe_trace["events"]
    )
    signals = "".join(
        f"<li>{escaped(signal['domain'])}: score {escaped(signal['score'])}; "
        f"threshold {escaped(signal['threshold'])}; target {escaped(signal['target_id'])}; "
        f"model {escaped(signal['model_version'])}; evidence "
        f"{escaped(', '.join(signal['evidence_node_ids']))}</li>"
        for signal in safe_run["signals"]
    )
    specialists = "".join(
        f"<li>{escaped(finding['agent_role'])}: {escaped(finding['status'])}; "
        f"finding {escaped(finding['finding_code'])}; evidence "
        f"{escaped(', '.join(finding['evidence_node_ids']))}</li>"
        for finding in safe_run["findings"]
        if finding["agent_role"] != "decision_critic"
    )
    critic = next(
        finding for finding in safe_run["findings"] if finding["agent_role"] == "decision_critic"
    )
    briefing = safe_run["llm"]
    degraded_briefing = safe_degraded["llm"]
    plan = safe_run["plan"]
    approval = safe_run["approval"]
    execution = safe_run["execution"]
    verification = safe_run["verification"]
    audit_event_count = len(safe_run["audit_events"])
    source_digest = hashlib.sha256(authenticated_html.encode("utf-8")).hexdigest()
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>NEXUS populated prototype acceptance snapshot</title>
<style>
body {{ font: 16px/1.5 system-ui; margin: 2rem; max-width: 90rem; }}
main {{ display: grid; gap: 1rem; }} section {{ border: 1px solid #888; padding: 1rem; }}
@media (prefers-reduced-motion: reduce) {{
  *, *::before, *::after {{ animation: none !important; }}
}}
</style></head><body><main>
<h1>PROTOTYPE — AUTHENTICATED POPULATED SNAPSHOT</h1>
<p>READ-ONLY PROJECTION · SIMULATED ACTION · run {escaped(safe_run["run_id"])}</p>
<section id="graph"><h2>Graph</h2><h3>Nodes</h3><ul>{nodes}</ul>
<h3>Edges</h3><ul>{edges}</ul></section>
<section id="signals"><h2>Signals</h2><ul>{signals}</ul></section>
<section id="agents"><h2>Specialists</h2><ul>{specialists}</ul>
<h3>Decision critic</h3><p>{escaped(critic["agent_role"])}: {escaped(critic["status"])};
finding {escaped(critic["finding_code"])}; evidence
{escaped(", ".join(critic["evidence_node_ids"]))}</p>
<p>Uncertainty: {escaped(critic["uncertainty_code"])}</p></section>
<section id="llm"><h2>Advisory LLM</h2>
<p>Live provider state: {escaped(briefing["provider_status"])};
model {escaped(briefing["model_id"])};
prompt {escaped(briefing["prompt_version"])}; digest {escaped(briefing["summary_sha256"])};
citations {escaped(", ".join(briefing["citation_node_ids"]))}</p>
<p>Degraded provider state: {escaped(degraded_briefing["provider_status"])}; digest
{escaped(degraded_briefing["summary_sha256"])}; citations
{escaped(", ".join(degraded_briefing["citation_node_ids"]))}</p></section>
<section id="plan"><h2>R3 plan</h2><p>{escaped(plan["action_kind"])};
target {escaped(plan["target_id"])}; destination {escaped(plan["destination"])};
risk {escaped(plan["risk_class"])}; expected effect {escaped(plan["expected_effect"])};
hash {escaped(plan["plan_hash"])}; status {escaped(plan["status"])}</p></section>
<section id="governance"><h2>Approval and simulated execution</h2>
<p>Approval: {escaped(approval["status"])}; approver {escaped(approval["approver_id"])};
plan hash {escaped(approval["plan_hash"])}</p>
<p>Execution: {escaped(execution["status"])}; connector
{escaped(execution["connector_kind"])}; receipt {escaped(execution["receipt_id"])}</p></section>
<section id="timeline"><h2>Timeline</h2><ol>{events}</ol></section>
<section id="verification"><h2>Verification</h2><p>Status: {escaped(verification["status"])}</p>
<p>Effect: {escaped(verification["verified_effect"])}</p>
<p>Observed delay improvement: {escaped(verification["observed_delay_hours"])} hours</p></section>
<section id="audit"><h2>Audit</h2><p><a href="#timeline">Audit timeline</a></p>
<p>Audit events: {escaped(audit_event_count)}</p></section>
<footer>Authenticated dashboard source SHA-256: {source_digest}</footer>
</main></body></html>"""


def _assert_populated_snapshot(
    snapshot: str,
    run_view: dict[str, Any],
    degraded_view: dict[str, Any],
    graph: dict[str, Any],
    trace: dict[str, Any],
) -> None:
    """Prove the screenshot source visibly contains the accepted populated state."""
    for value in (
        "AUTHENTICATED POPULATED SNAPSHOT",
        "Graph",
        "Timeline",
        "Signals",
        "Specialists",
        "Decision critic",
        "Advisory LLM",
        "R3 plan",
        "Approval and simulated execution",
        "Verification",
        "Audit",
        run_view["run_id"],
        run_view["verification"]["status"],
        run_view["verification"]["verified_effect"],
        f"Observed delay improvement: {run_view['verification']['observed_delay_hours']} hours",
        f"Audit events: {len(run_view['audit_events'])}",
        *(node["id"] for node in graph["nodes"]),
        *(f"{edge['source']} → {edge['type']} → {edge['target']}" for edge in graph["edges"]),
        *(event["event_type"] for event in trace["events"]),
        *(
            value
            for signal in run_view["signals"]
            for value in (
                signal["domain"],
                signal["score"],
                signal["threshold"],
                signal["target_id"],
                signal["model_version"],
                *signal["evidence_node_ids"],
            )
        ),
        *(
            value
            for finding in run_view["findings"]
            for value in (
                finding["agent_role"],
                finding["status"],
                finding["finding_code"],
                *finding["evidence_node_ids"],
            )
        ),
        run_view["llm"]["provider_status"],
        run_view["llm"]["model_id"],
        run_view["llm"]["prompt_version"],
        run_view["llm"]["summary_sha256"],
        *run_view["llm"]["citation_node_ids"],
        degraded_view["llm"]["provider_status"],
        degraded_view["llm"]["summary_sha256"],
        *degraded_view["llm"]["citation_node_ids"],
        run_view["plan"]["action_kind"],
        run_view["plan"]["target_id"],
        run_view["plan"]["destination"],
        run_view["plan"]["risk_class"],
        run_view["plan"]["expected_effect"],
        run_view["plan"]["plan_hash"],
        run_view["plan"]["status"],
        run_view["approval"]["status"],
        run_view["approval"]["approver_id"],
        run_view["approval"]["plan_hash"],
        run_view["execution"]["status"],
        run_view["execution"]["connector_kind"],
        run_view["execution"]["receipt_id"],
    ):
        assert html.escape(str(value), quote=True) in snapshot, (
            "populated prototype snapshot is incomplete"
        )
    assert "innerHTML" not in snapshot
    _assert_no_sensitive_text(snapshot)


def _capture_screenshot(populated_html: str, runtime: BrowserRuntime) -> None:
    """Capture populated authenticated evidence without passing a bearer token to a browser."""
    SCREENSHOT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nexus-prototype-dashboard-") as directory:
        page = Path(directory) / "index.html"
        page.write_text(populated_html, encoding="utf-8")
        subprocess.run(  # noqa: S603 -- fixed tool and owned local HTML/screenshot paths.
            [
                str(runtime.node_executable),
                str(runtime.playwright_cli),
                "screenshot",
                "--full-page",
                page.resolve().as_uri(),
                str(SCREENSHOT),
            ],
            check=True,
            cwd=ROOT,
            timeout=60,
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_browser_environment(),
        )
    if not SCREENSHOT.is_file() or SCREENSHOT.stat().st_size == 0:
        raise RuntimeError("dashboard screenshot was not created")


def _problem(response: httpx.Response, status: int, code: str | None = None) -> None:
    _expect_status(response, {status}, "problem response")
    if not response.headers.get("content-type", "").startswith("application/problem+json"):
        raise RuntimeError("prototype E2E problem response had an invalid content type")
    if code is not None:
        payload = _response_json(response, "problem response")
        if payload.get("code") != code:
            raise RuntimeError("prototype E2E problem response had an unexpected code")


def _expect_status(response: httpx.Response, expected: set[int], check_name: str) -> None:
    if response.status_code not in expected:
        raise RuntimeError(
            f"prototype E2E {check_name} returned unexpected HTTP status {response.status_code}"
        )


def _response_json(response: httpx.Response, check_name: str) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        raise RuntimeError(f"prototype E2E {check_name} returned invalid JSON") from None
    if not isinstance(payload, dict):
        raise RuntimeError(f"prototype E2E {check_name} returned an invalid JSON object")
    return cast(dict[str, Any], payload)


def _llm_control_url() -> str:
    raw = _required("NEXUS_PROTOTYPE_E2E_LLM_CONTROL_URL")
    parsed = urlparse(raw)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise RuntimeError("LLM control URL must be an absolute loopback URL")
    return raw


def _get_llm_mode() -> str:
    response = httpx.get(_llm_control_url(), timeout=5.0)
    _expect_status(response, {200}, "LLM control read")
    mode = _response_json(response, "LLM control read").get("mode")
    if not isinstance(mode, str) or not 1 <= len(mode) <= 64:
        raise RuntimeError("LLM control endpoint returned an invalid mode")
    return mode


def _set_llm_mode(mode: str) -> None:
    if not isinstance(mode, str) or not 1 <= len(mode) <= 64:
        raise RuntimeError("LLM control mode must be a bounded string")
    raw = _llm_control_url()
    response = httpx.post(raw, json={"mode": mode}, timeout=5.0)
    _expect_status(response, {200}, "LLM control update")


def _request(
    client: httpx.Client,
    principal: Principal,
    method: str,
    path: str,
    *,
    key: str | None = None,
    json_body: dict[str, Any] | None = None,
    if_match: str | None = None,
) -> httpx.Response:
    headers = principal.headers()
    if key is not None:
        headers["Idempotency-Key"] = key
    if if_match is not None:
        if re.fullmatch(r"[0-9a-f]{64}", if_match) is None:
            raise RuntimeError("If-Match plan hash must be exactly 64 lowercase hex characters")
        headers["If-Match"] = f'"{if_match}"'
    return client.request(method, path, headers=headers, json=json_body)


def _approval_request(
    client: httpx.Client,
    principal: Principal,
    run_id: str,
    *,
    key: str,
    plan_hash: str,
    decision: str,
) -> httpx.Response:
    if decision not in {"approve", "reject"}:
        raise RuntimeError("approval decision must be approve or reject")
    return _request(
        client,
        principal,
        "POST",
        f"/api/v1/prototype/runs/{run_id}/approval",
        key=key,
        json_body={"plan_hash": plan_hash, "decision": decision},
        if_match=plan_hash,
    )


def _concurrent_create(
    base_url: str, principal: Principal, key: str, scenario: str
) -> httpx.Response:
    with httpx.Client(base_url=base_url, timeout=30.0) as client:
        return _request(
            client,
            principal,
            "POST",
            "/api/v1/prototype/runs",
            key=key,
            json_body={"scenario_id": scenario},
        )


def run(scenario: str) -> dict[str, Any]:
    if os.getenv("NEXUS_RUN_COMPOSE_TESTS") != "1":
        raise RuntimeError("refusing live run: set NEXUS_RUN_COMPOSE_TESTS=1")
    if scenario != SCENARIO:
        raise RuntimeError(f"only {SCENARIO!r} is supported")
    browser_runtime = preflight_browser(ROOT)
    operator = Principal(_required("NEXUS_PROTOTYPE_E2E_OPERATOR_TOKEN"))
    approver = Principal(_required("NEXUS_PROTOTYPE_E2E_APPROVER_TOKEN"))
    other_tenant = Principal(_required("NEXUS_PROTOTYPE_E2E_OTHER_TENANT_TOKEN"))
    project = _compose_start()
    previous_llm_mode: str | None = None
    evidence: dict[str, Any] = {"scenario_id": scenario, "checks": {}}
    try:
        base_url = _base_url()
        previous_llm_mode = _get_llm_mode()
        _set_llm_mode("valid-alias")
        with ThreadPoolExecutor(max_workers=2) as pool:
            same_key = tuple(
                pool.map(
                    lambda _: _concurrent_create(
                        base_url, operator, "prototype-e2e-concurrent-same", scenario
                    ),
                    range(2),
                )
            )
        for response in same_key:
            _expect_status(response, {200, 201}, "concurrent create")
        same_views = tuple(
            _validated_run_view(_response_json(response, "concurrent create"))
            for response in same_key
        )
        assert len({view["run_id"] for view in same_views}) == 1
        run_view = same_views[0]
        assert run_view["llm"]["provider_status"] == "available"
        with ThreadPoolExecutor(max_workers=2) as pool:
            different_keys = tuple(
                pool.submit(
                    _concurrent_create,
                    base_url,
                    operator,
                    f"prototype-e2e-distinct-{side}",
                    scenario,
                )
                for side in ("left", "right")
            )
            distinct_responses = tuple(future.result() for future in different_keys)
        for response in distinct_responses:
            _expect_status(response, {200, 201}, "distinct create")
        distinct_views = tuple(
            _validated_run_view(_response_json(response, "distinct create"))
            for response in distinct_responses
        )
        assert len({view["run_id"] for view in distinct_views}) == 2

        with httpx.Client(base_url=base_url, timeout=30.0) as client:
            run_id = run_view["run_id"]
            plan_hash = run_view["plan"]["plan_hash"]
            assert run_view["status"] == "awaiting_approval"
            assert {(item["score"], item["threshold"]) for item in run_view["signals"]} == {
                (0.91, 0.80),
                (0.94, 0.80),
            }
            critic = next(
                finding
                for finding in run_view["findings"]
                if finding["agent_role"] == "decision_critic"
            )
            assert critic["uncertainty_code"] == (
                "Correlated operational priority, not a proven causal link"
            )
            assert not run_view.get("execution")
            conflict = _request(
                client,
                operator,
                "POST",
                "/api/v1/prototype/runs",
                key="prototype-e2e-concurrent-same",
                json_body={"scenario_id": "wrong"},
            )
            _problem(conflict, 422, "invalid_prototype_request")
            _set_llm_mode("unavailable")
            degraded = _request(
                client,
                operator,
                "POST",
                "/api/v1/prototype/runs",
                key="prototype-e2e-degraded",
                json_body={"scenario_id": scenario},
            )
            _expect_status(degraded, {200, 201}, "degraded create")
            degraded_view = _validated_run_view(_response_json(degraded, "degraded create"))
            assert degraded_view["status"] == "awaiting_approval"
            assert degraded_view["llm"]["provider_status"] == "unavailable"
            graph = _request(client, operator, "GET", f"/api/v1/prototype/runs/{run_id}/graph")
            expected_graph = json.loads(
                (ROOT / "tests/fixtures/prototype/storm-and-checkout-shift-v1.json").read_text(
                    encoding="utf-8"
                )
            )
            graph_view = _validated_graph(_response_json(graph, "graph read"))
            assert graph.status_code == 200 and graph_view == expected_graph
            for path in ("", "/graph", "/trace"):
                _problem(
                    _request(
                        client,
                        other_tenant,
                        "GET",
                        f"/api/v1/prototype/runs/{run_id}{path}",
                    ),
                    404,
                    "prototype_not_found",
                )
            _problem(
                _approval_request(
                    client,
                    other_tenant,
                    run_id,
                    key="cross-tenant-approval",
                    plan_hash=plan_hash,
                    decision="approve",
                ),
                404,
                "prototype_not_found",
            )
            _problem(
                _request(
                    client,
                    other_tenant,
                    "POST",
                    f"/api/v1/prototype/runs/{run_id}/execute",
                    key="cross-tenant-execute",
                    json_body={"plan_hash": plan_hash},
                    if_match=plan_hash,
                ),
                404,
                "prototype_not_found",
            )
            _problem(
                _approval_request(
                    client,
                    operator,
                    run_id,
                    key="self-approval",
                    plan_hash=plan_hash,
                    decision="approve",
                ),
                403,
                "prototype_forbidden",
            )
            _problem(
                _request(
                    client,
                    operator,
                    "POST",
                    f"/api/v1/prototype/runs/{run_id}/execute",
                    key="before-approval",
                    json_body={"plan_hash": plan_hash},
                    if_match=plan_hash,
                ),
                409,
                "prototype_conflict",
            )
            _problem(
                _approval_request(
                    client,
                    approver,
                    run_id,
                    key="stale-approval",
                    plan_hash="0" * 64,
                    decision="approve",
                ),
                412,
                "prototype_precondition_failed",
            )
            unchanged = _request(client, operator, "GET", f"/api/v1/prototype/runs/{run_id}")
            unchanged_view = _validated_run_view(_response_json(unchanged, "run read"))
            assert len(unchanged_view["audit_events"]) == 8
            approved = _approval_request(
                client,
                approver,
                run_id,
                key="approve-v1",
                plan_hash=plan_hash,
                decision="approve",
            )
            _expect_status(approved, {200}, "approval")
            approved_view = _validated_run_view(_response_json(approved, "approval"))
            approval_replay = _approval_request(
                client,
                approver,
                run_id,
                key="approve-v1",
                plan_hash=plan_hash,
                decision="approve",
            )
            assert approval_replay.status_code == 200
            approval_replay_view = _validated_run_view(
                _response_json(approval_replay, "approval replay")
            )
            assert approval_replay_view["approval"] == approved_view["approval"]
            _problem(
                _approval_request(
                    client,
                    approver,
                    run_id,
                    key="approve-v1",
                    plan_hash=plan_hash,
                    decision="reject",
                ),
                409,
                "prototype_conflict",
            )
            _problem(
                _request(
                    client,
                    approver,
                    "POST",
                    f"/api/v1/prototype/runs/{run_id}/execute",
                    key="approver-execute",
                    json_body={"plan_hash": plan_hash},
                    if_match=plan_hash,
                ),
                403,
                "prototype_forbidden",
            )
            executed = _request(
                client,
                operator,
                "POST",
                f"/api/v1/prototype/runs/{run_id}/execute",
                key="execute-v1",
                json_body={"plan_hash": plan_hash},
                if_match=plan_hash,
            )
            _expect_status(executed, {200}, "execution")
            executed_view = _validated_run_view(_response_json(executed, "execution"))
            duplicate = _request(
                client,
                operator,
                "POST",
                f"/api/v1/prototype/runs/{run_id}/execute",
                key="execute-v1",
                json_body={"plan_hash": plan_hash},
                if_match=plan_hash,
            )
            assert (
                duplicate.status_code == 200
                and _validated_run_view(_response_json(duplicate, "execution replay"))["execution"]
                == executed_view["execution"]
            )
            _problem(
                _request(
                    client,
                    operator,
                    "POST",
                    f"/api/v1/prototype/runs/{run_id}/execute",
                    key="execute-v1",
                    json_body={"plan_hash": "0" * 64},
                    if_match="0" * 64,
                ),
                412,
                "prototype_precondition_failed",
            )
            rejected_seed = _request(
                client,
                operator,
                "POST",
                "/api/v1/prototype/runs",
                key="prototype-e2e-rejected",
                json_body={"scenario_id": scenario},
            )
            rejected_run = _validated_run_view(_response_json(rejected_seed, "rejected run create"))
            rejected = _approval_request(
                client,
                approver,
                rejected_run["run_id"],
                key="reject-v1",
                plan_hash=rejected_run["plan"]["plan_hash"],
                decision="reject",
            )
            rejected_view = _validated_run_view(_response_json(rejected, "rejection"))
            assert rejected.status_code == 200 and rejected_view["status"] == "rejected"
            rejected_replay = _approval_request(
                client,
                approver,
                rejected_run["run_id"],
                key="reject-v1",
                plan_hash=rejected_run["plan"]["plan_hash"],
                decision="reject",
            )
            assert rejected_replay.status_code == 200
            _problem(
                _approval_request(
                    client,
                    approver,
                    rejected_run["run_id"],
                    key="reject-v1",
                    plan_hash=rejected_run["plan"]["plan_hash"],
                    decision="approve",
                ),
                409,
                "prototype_conflict",
            )
            _problem(
                _request(
                    client,
                    operator,
                    "POST",
                    f"/api/v1/prototype/runs/{rejected_run['run_id']}/execute",
                    key="execute-rejected",
                    json_body={"plan_hash": rejected_run["plan"]["plan_hash"]},
                    if_match=rejected_run["plan"]["plan_hash"],
                ),
                409,
                "prototype_conflict",
            )
            final = _request(client, operator, "GET", f"/api/v1/prototype/runs/{run_id}")
            final_view = _validated_run_view(_response_json(final, "final run read"))
            assert final.status_code == 200 and final_view["verification"]["status"] == "verified"
            assert final_view["verification"]["observed_delay_hours"] == 14.0
            trace = _request(client, operator, "GET", f"/api/v1/prototype/runs/{run_id}/trace")
            trace_view = _validated_trace(_response_json(trace, "trace read"))
            assert trace.status_code == 200 and trace_view["run_id"] == run_id
            event_types = [item["event_type"] for item in trace_view["events"]]
            assert event_types.count("prototype.action.executed") == 1
            assert event_types.count("prototype.verification.completed") == 1
            assert len(event_types) == 11
            assert len(final_view["audit_events"]) == 11
            dashboard = client.get("/prototype", headers=operator.headers())
            assert dashboard.status_code == 200
            for label in (
                "PROTOTYPE",
                "READ-ONLY PROJECTION",
                "SIMULATED ACTION",
                "prefers-reduced-motion",
                "graph",
                "timeline",
                "audit",
            ):
                assert label.lower() in dashboard.text.lower()
            assert "innerHTML" not in dashboard.text
            populated_snapshot = _populated_snapshot_html(
                dashboard.text,
                final_view,
                degraded_view,
                graph_view,
                trace_view,
            )
            _assert_populated_snapshot(
                populated_snapshot,
                final_view,
                degraded_view,
                graph_view,
                trace_view,
            )
            _capture_screenshot(populated_snapshot, browser_runtime)
            _assert_no_sensitive_text({"run": final_view, "trace": trace_view})
            evidence["checks"] = {
                "run_id": run_id,
                "event_types": event_types,
                "live_provider_status": run_view["llm"]["provider_status"],
                "degraded_provider_status": degraded_view["llm"]["provider_status"],
                "concurrent_same_key": True,
                "concurrent_distinct_keys": True,
                "audit_event_count": len(final_view["audit_events"]),
                "verification": final_view["verification"],
            }
    finally:
        try:
            if previous_llm_mode is not None:
                _set_llm_mode(previous_llm_mode)
        finally:
            _compose_stop(project)
    sanitized = _sanitized(evidence)
    _assert_no_sensitive_text(sanitized)
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(sanitized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return cast(dict[str, Any], sanitized)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    arguments = parser.parse_args(argv)
    run(arguments.scenario)
    return 0


def cli(argv: Sequence[str] | None = None) -> int:
    """Run the guarded CLI without projecting arbitrary exception details."""
    try:
        return main(argv)
    except (AssertionError, RuntimeError, httpx.HTTPError, subprocess.SubprocessError):
        print("prototype E2E failed: guarded acceptance check failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
