"""End-to-end academic workflow tests against real calculations and SQLite."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from pathlib import Path

import httpx
import pytest
from nexus_api.academic_demo import create_demo_app


def client_for(path: Path) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_demo_app(path), client=("127.0.0.1", 12345)),
        base_url="http://127.0.0.1:8080",
    )


def headers(role: str = "proposer", key: str = "create-1") -> dict[str, str]:
    return {"Authorization": f"Bearer academic-{role}", "Idempotency-Key": key}


@pytest.mark.asyncio
async def test_real_scenario_approval_execution_and_restart(tmp_path: Path) -> None:
    database = tmp_path / "demo.sqlite3"
    async with client_for(database) as client:
        session = (await client.get("/api/v1/prototype/demo-session")).json()
        assert session["mode"] == "academic_local"
        assert {item["role"] for item in session["identities"]} == {
            "proposer",
            "approver",
            "viewer",
        }
        catalog = (await client.get("/api/v1/prototype/scenarios", headers=headers())).json()
        assert len(catalog["scenarios"]) >= 4
        created = await client.post(
            "/api/v1/prototype/runs",
            json={"scenario_id": "supply-heavy-v1"},
            headers=headers(),
        )
        assert created.status_code == 201, created.text
        run = created.json()
        assert run["llm"]["summary"]
        run_id = run["run_id"]
        plan_hash = run["plan"]["plan_hash"]
        body = {"plan_hash": plan_hash, "decision": "approve"}
        approval_headers = {**headers("approver", "approve-1"), "If-Match": f'"{plan_hash}"'}
        approved = await client.post(
            f"/api/v1/prototype/runs/{run_id}/approval", json=body, headers=approval_headers
        )
        assert approved.status_code == 200, approved.text
        execution_headers = {**headers(key="execute-1"), "If-Match": f'"{plan_hash}"'}
        executed = await client.post(
            f"/api/v1/prototype/runs/{run_id}/execute",
            json={"plan_hash": plan_hash},
            headers=execution_headers,
        )
        assert executed.status_code == 200, executed.text
        final = executed.json()
        assert final["status"] == "verified"
        verification = final["verification"]
        assert verification["baseline_delay_hours"] == pytest.approx(
            verification["observed_delay_hours"] + verification["delay_reduction_hours"]
        )
        trace = (
            await client.get(f"/api/v1/prototype/runs/{run_id}/trace", headers=headers("viewer"))
        ).json()
        assert len(trace["events"]) >= 10
        assert len({event["hash"] for event in trace["events"]}) == len(trace["events"])
        replay = await client.post(
            f"/api/v1/prototype/runs/{run_id}/execute",
            json={"plan_hash": plan_hash},
            headers=execution_headers,
        )
        assert replay.status_code == 200
        assert replay.json()["audit_events"] == final["audit_events"]
    async with client_for(database) as restarted:
        loaded = await restarted.get(f"/api/v1/prototype/runs/{run_id}", headers=headers("viewer"))
        assert loaded.status_code == 200
        assert loaded.json() == final


@pytest.mark.asyncio
async def test_roles_plan_preconditions_and_terminal_rejection(tmp_path: Path) -> None:
    async with client_for(tmp_path / "roles.sqlite3") as client:
        endpoint = "/api/v1/prototype/runs"
        payload = {"scenario_id": "it-heavy-v1"}
        assert (await client.post(endpoint, json=payload)).status_code == 401
        assert (
            await client.post(endpoint, json=payload, headers=headers("viewer"))
        ).status_code == 403
        run = (await client.post(endpoint, json=payload, headers=headers())).json()
        run_id, digest = run["run_id"], run["plan"]["plan_hash"]
        approval = {"plan_hash": digest, "decision": "approve"}
        matched = {**headers(), "If-Match": f'"{digest}"'}
        assert (
            await client.post(f"{endpoint}/{run_id}/approval", json=approval, headers=matched)
        ).status_code == 403
        assert (
            await client.post(
                f"{endpoint}/{run_id}/execute", json={"plan_hash": digest}, headers=matched
            )
        ).status_code == 409
        wrong = {**headers("approver"), "If-Match": '"' + "0" * 64 + '"'}
        assert (
            await client.post(f"{endpoint}/{run_id}/approval", json=approval, headers=wrong)
        ).status_code == 412
        rejected = await client.post(
            f"{endpoint}/{run_id}/approval",
            json={"plan_hash": digest, "decision": "reject", "reason": "review"},
            headers={**headers("approver", "reject"), "If-Match": f'"{digest}"'},
        )
        assert rejected.status_code == 200
        assert rejected.json()["status"] == "rejected"
        assert (
            await client.post(
                f"{endpoint}/{run_id}/execute", json={"plan_hash": digest}, headers=matched
            )
        ).status_code == 409


@pytest.mark.asyncio
async def test_idempotency_conflict_and_changed_inputs(tmp_path: Path) -> None:
    async with client_for(tmp_path / "inputs.sqlite3") as client:
        endpoint = "/api/v1/prototype/runs"
        stable = await client.post(
            endpoint, json={"scenario_id": "supply-stable-v1"}, headers=headers()
        )
        repeated = await client.post(
            endpoint, json={"scenario_id": "supply-stable-v1"}, headers=headers()
        )
        assert stable.status_code == repeated.status_code == 201
        assert stable.json() == repeated.json()
        conflict = await client.post(
            endpoint, json={"scenario_id": "supply-heavy-v1"}, headers=headers()
        )
        assert conflict.status_code == 409
        heavy = await client.post(
            endpoint, json={"scenario_id": "supply-heavy-v1"}, headers=headers(key="heavy")
        )
        assert stable.json()["signals"] != heavy.json()["signals"]
        assert stable.json()["plan"]["plan_hash"] != heavy.json()["plan"]["plan_hash"]


@pytest.mark.asyncio
async def test_trace_tampering_locks_reads(tmp_path: Path) -> None:
    path = tmp_path / "tamper.sqlite3"
    async with client_for(path) as client:
        run = (
            await client.post(
                "/api/v1/prototype/runs", json={"scenario_id": "it-heavy-v1"}, headers=headers()
            )
        ).json()
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE events SET hash = ?", ("0" * 64,))
        response = await client.get(
            f"/api/v1/prototype/runs/{run['run_id']}", headers=headers("viewer")
        )
        assert response.status_code == 503


@pytest.mark.asyncio
async def test_snapshot_cannot_forge_approval_even_with_recomputed_hash(tmp_path: Path) -> None:
    path = tmp_path / "snapshot.sqlite3"
    async with client_for(path) as client:
        run = (
            await client.post(
                "/api/v1/prototype/runs", json={"scenario_id": "it-heavy-v1"}, headers=headers()
            )
        ).json()
        with sqlite3.connect(path) as connection:
            state = json.loads(connection.execute("SELECT state FROM runs").fetchone()[0])
            state["status"] = "approved"
            state["approval"] = {
                "plan_hash": state["plan"]["plan_hash"],
                "approver_id": "018f0000-0000-7000-8000-000000000a03",
                "status": "approved",
                "reason_sha256": None,
            }
            body = json.dumps(state, sort_keys=True, separators=(",", ":"))
            connection.execute(
                "UPDATE runs SET state=?, state_hash=?",
                (body, hashlib.sha256(body.encode()).hexdigest()),
            )
        response = await client.post(
            f"/api/v1/prototype/runs/{run['run_id']}/execute",
            json={"plan_hash": run["plan"]["plan_hash"]},
            headers={**headers(key="execute"), "If-Match": '"' + run["plan"]["plan_hash"] + '"'},
        )
        assert response.status_code == 503


@pytest.mark.asyncio
async def test_cross_origin_and_nonlocal_hosts_are_rejected(tmp_path: Path) -> None:
    async with client_for(tmp_path / "origin.sqlite3") as client:
        response = await client.post(
            "/api/v1/prototype/runs",
            json={"scenario_id": "it-heavy-v1"},
            headers={**headers(), "Origin": "https://untrusted.example"},
        )
        assert response.status_code == 403
        response = await client.get(
            "/api/v1/prototype/demo-session", headers={"Host": "untrusted.example"}
        )
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_simultaneous_repeated_creations_record_only_one_run(tmp_path: Path) -> None:
    async with client_for(tmp_path / "concurrent.sqlite3") as client:
        responses = await asyncio.gather(
            *(
                client.post(
                    "/api/v1/prototype/runs", json={"scenario_id": "it-heavy-v1"}, headers=headers()
                )
                for _ in range(3)
            )
        )
        assert all(response.status_code == 201 for response in responses)
        assert len({response.json()["run_id"] for response in responses}) == 1
        assert all(len(response.json()["audit_events"]) == 8 for response in responses)


@pytest.mark.asyncio
async def test_malformed_snapshot_returns_safe_unavailable_response(tmp_path: Path) -> None:
    database = tmp_path / "malformed.sqlite3"
    async with client_for(database) as client:
        run = (
            await client.post(
                "/api/v1/prototype/runs", json={"scenario_id": "it-heavy-v1"}, headers=headers()
            )
        ).json()
        with sqlite3.connect(database) as connection:
            connection.execute("UPDATE runs SET state='not json'")
        response = await client.get(f"/api/v1/prototype/runs/{run['run_id']}", headers=headers())
        assert response.status_code == 503
        assert "not json" not in response.text
