# ruff: noqa: S101, S603, S607
"""Exercise real HTTP ingestion, automatic learning, governed writeback and optional NVIDIA."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from nexus_api.operations.learning import predict_models
from nexus_api.operations.synthetic import generate_cases, generate_history


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-llm", action="store_true")
    parser.add_argument("--output", default="artifacts/operations-learning-evaluation.json")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="nexus-learning-evaluation-") as temporary:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        command = [
            sys.executable,
            str(root / "scripts/run_operations.py"),
            "--port",
            str(port),
            "--database",
            str(Path(temporary) / "evaluation.sqlite"),
        ]
        with (Path(temporary) / "server.log").open("w", encoding="utf-8") as log:
            server = subprocess.Popen(
                command, cwd=root, stdout=log, stderr=log, start_new_session=os.name != "nt"
            )  # noqa: S603
            try:
                origin = f"http://127.0.0.1:{port}"
                with httpx.Client(base_url=origin, timeout=110) as client:
                    for _ in range(100):
                        try:
                            if client.get("/health/live", timeout=0.5).is_success:
                                break
                        except httpx.HTTPError:
                            pass
                        if server.poll() is not None:
                            raise RuntimeError("Owned evaluation server exited")
                        time.sleep(0.1)
                    else:
                        raise RuntimeError("Owned evaluation server did not become healthy")

                    def call(method: str, path: str, body: Any = None, expected: int = 200) -> Any:
                        response = client.request(
                            method,
                            "/api/v1/operations" + path,
                            json=body,
                            headers={"Idempotency-Key": uuid.uuid4().hex},
                        )
                        assert response.status_code == expected, (
                            path,
                            response.status_code,
                            response.text,
                        )
                        return response.json()

                    password = secrets.token_urlsafe(24)
                    session = call(
                        "POST", "/setup", {"username": "evaluation-owner", "password": password}
                    )
                    client.headers["X-Nexus-CSRF"] = session["csrf_token"]
                    call(
                        "POST",
                        "/users",
                        {
                            "username": "evaluation-approver",
                            "password": password,
                            "role": "approver",
                        },
                    )
                    report: dict[str, Any] = {
                        "kind": "synthetic_evaluation",
                        "seed": 42,
                        "live_llm_requested": args.live_llm,
                        "domains": [],
                        "passed": False,
                    }
                    for domain in ("construction", "manufacturing"):
                        workspace = call(
                            "POST", "/workspaces", {"name": "Synthetic " + domain, "domain": domain}
                        )
                        path = "/workspaces/" + workspace["id"]
                        revision = 0
                        cases = []
                        generated = generate_cases(domain, seed=42)
                        for case in generated:
                            call(
                                "PUT",
                                path + "/dataset",
                                {
                                    "payload": case["payload"],
                                    "expected_revision": revision,
                                    "provenance": {"kind": "synthetic", "name": case["name"]},
                                },
                            )
                            revision += 1
                            analysis = call("POST", path + "/analyze", {"seed": 42, "samples": 50})
                            feasible = not bool(analysis["infeasible"])
                            assert feasible == case["expected_feasible"], case["name"]
                            cases.append(
                                {
                                    "name": case["name"],
                                    "feasible": feasible,
                                    "forecast": analysis["forecast"],
                                }
                            )
                        history = generate_history(domain, projects=80, seed=42)
                        early = {**history, "rows": history["rows"][:80]}
                        state = call(
                            "POST",
                            path + "/learning/history",
                            {"history": early, "mode": "append", "expected_history_revision": 0},
                        )
                        assert state["active_model"] is None and not state["runs"]
                        state = call(
                            "POST",
                            path + "/learning/history",
                            {"history": history, "mode": "append", "expected_history_revision": 1},
                        )
                        assert state["active_model"] and state["runs"][-1]["status"] == "promoted"
                        extra = generate_history(domain, projects=24, seed=43)
                        state = call(
                            "POST",
                            path + "/learning/history",
                            {"history": extra, "mode": "append", "expected_history_revision": 2},
                        )
                        assert (
                            len(state["runs"]) == 2 and state["runs"][-1]["trigger"] == "automatic"
                        )
                        model_id = state["active_model"]["id"]
                        artifact = call("GET", path + "/learning/models/" + model_id)
                        groups = [set(v) for v in artifact["split"]["project_ids"].values()]
                        assert all(not a & b for i, a in enumerate(groups) for b in groups[i + 1 :])
                        # JSON reload returns an actual fitted prediction.
                        reloaded = json.loads(json.dumps(artifact))
                        prediction = predict_models(reloaded, history["rows"][0]["features"])
                        assert prediction["duration_working_days"] > 0
                        shifted = generate_history(domain, projects=80, seed=900, shifted=True)
                        external = call(
                            "POST",
                            path + "/learning/evaluate",
                            {"history": shifted, "model_id": model_id},
                        )
                        assert call("GET", path + "/learning")["history_revision"] == 3
                        nominal = next(c for c in generated if c["expected_feasible"])
                        call(
                            "PUT",
                            path + "/dataset",
                            {
                                "payload": nominal["payload"],
                                "expected_revision": revision,
                                "provenance": {
                                    "kind": "synthetic",
                                    "name": "ML operational evaluation",
                                },
                            },
                        )
                        revision += 1
                        branch = call(
                            "POST",
                            path + "/learning/scenarios",
                            {
                                "name": "Trained duration branch",
                                "model_id": model_id,
                                "expected_revision": revision,
                            },
                        )
                        assert not branch["analysis"]["infeasible"]
                        decision = call(
                            "POST",
                            path + "/decisions",
                            {"scenario_id": branch["id"], "expected_revision": revision},
                        )
                        approval = {"plan_hash": decision["plan_hash"], "decision": "approve"}
                        call(
                            "POST",
                            "/decisions/" + decision["id"] + "/approve",
                            approval,
                            expected=403,
                        )

                        def login(username: str) -> None:
                            call("POST", "/logout", {})
                            session = call(
                                "POST", "/login", {"username": username, "password": password}
                            )
                            client.headers["X-Nexus-CSRF"] = session["csrf_token"]

                        login("evaluation-approver")
                        call("POST", "/decisions/" + decision["id"] + "/approve", approval)
                        login("evaluation-owner")
                        call("POST", "/decisions/" + decision["id"] + "/apply", approval)
                        applied = call("GET", path)
                        assert applied["revision"] == revision + 1
                        assert applied["analysis"]["learning"]["id"] == model_id
                        advisory = None
                        if args.live_llm:
                            advisory = call(
                                "POST",
                                path + "/integrations/advice",
                                {
                                    "question": (
                                        "Explain validation/test errors versus planned duration. "
                                        "State synthetic-data limits. Cite the exact @model/ ID. "
                                        "Do not claim to train yourself."
                                    )
                                },
                            )
                            assert advisory["model"] == "nvidia/nemotron-3-ultra-550b-a55b"
                            assert "@model/" + model_id in advisory["evidence_ids"]
                        report["domains"].append(
                            {
                                "domain": domain,
                                "operational_cases": cases,
                                "rows": state["row_count"],
                                "automatic_runs": state["runs"],
                                "active_model": state["active_model"],
                                "ood_evaluation": external,
                                "inference": prediction,
                                "applied_revision": applied["revision"],
                                "scenario_forecast": applied["analysis"]["forecast"],
                                "advisory": advisory,
                            }
                        )
                    report["passed"] = True
                    output = Path(args.output)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(
                        json.dumps(report, indent=2, allow_nan=False), encoding="utf-8"
                    )
                    print(
                        json.dumps(
                            {
                                "passed": True,
                                "operational_cases": 14,
                                "domains": 2,
                                "automatic_runs": 4,
                                "live_nemotron": args.live_llm,
                                "report": str(output),
                            }
                        )
                    )
            finally:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(server.pid), "/T", "/F"],
                        capture_output=True,
                        check=False,
                    )  # noqa: S603,S607
                else:
                    os.killpg(server.pid, signal.SIGTERM)
                server.wait(timeout=15)


if __name__ == "__main__":
    main()
