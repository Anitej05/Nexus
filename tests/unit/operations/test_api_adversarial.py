import asyncio

import httpx
import pytest
from nexus_api.operations.api import COOKIE, PREFIX, create_operations_app


@pytest.fixture
async def client(tmp_path):
    app = create_operations_app(f"sqlite+aiosqlite:///{tmp_path}/api.db")
    await app.state.store.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        yield client, app
    await app.state.store.close()


async def test_bootstrap_rejects_remote_and_cross_origin(client):
    c, app = client
    body = {"username": "owner", "password": "a lengthy owner password"}
    assert (
        await c.post(PREFIX + "/setup", json=body, headers={"Origin": "https://evil.example"})
    ).status_code == 403
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("192.0.2.1", 123)),
        base_url="http://localhost",
    ) as remote:
        assert (await remote.post(PREFIX + "/setup", json=body)).status_code == 403
    results = await asyncio.gather(*(c.post(PREFIX + "/setup", json=body) for _ in range(2)))
    assert sorted(r.status_code for r in results) == [200, 409]


async def test_csrf_viewer_payload_bound_and_login_throttle(client):
    c, _ = client
    result = await c.post(
        PREFIX + "/setup", json={"username": "owner", "password": "a lengthy owner password"}
    )
    csrf = {"X-Nexus-CSRF": result.json()["csrf_token"]}
    assert c.cookies.get(COOKIE)
    assert (await c.post(PREFIX + "/workspaces", json={})).status_code == 403
    assert (
        await c.post(
            PREFIX + "/workspaces", json={}, headers={**csrf, "Origin": "https://evil.example"}
        )
    ).status_code == 403
    assert (
        await c.post(
            PREFIX + "/users",
            headers=csrf,
            json={"username": "viewer", "password": "a lengthy viewer password", "role": "viewer"},
        )
    ).status_code == 200
    await c.post(PREFIX + "/logout", headers=csrf, json={})
    result = await c.post(
        PREFIX + "/login", json={"username": "viewer", "password": "a lengthy viewer password"}
    )
    csrf = {"X-Nexus-CSRF": result.json()["csrf_token"]}
    assert (
        await c.post(
            PREFIX + "/workspaces", headers=csrf, json={"name": "x", "domain": "construction"}
        )
    ).status_code == 403
    assert (await c.post(PREFIX + "/login", content=b"x" * (1024 * 1024 + 1))).status_code == 413
    statuses = [
        (
            await c.post(
                PREFIX + "/login",
                json={"username": "missing", "password": "a lengthy wrong password"},
            )
        ).status_code
        for _ in range(11)
    ]
    assert statuses[-1] == 429


async def test_network_wait_does_not_hold_store_lock(client, monkeypatch):
    c, app = client
    response = await c.post(
        PREFIX + "/setup", json={"username": "owner", "password": "a lengthy owner password"}
    )
    headers = {"X-Nexus-CSRF": response.json()["csrf_token"]}
    ws = (
        await c.post(
            PREFIX + "/workspaces", headers=headers, json={"name": "test", "domain": "construction"}
        )
    ).json()
    entered, release = asyncio.Event(), asyncio.Event()

    async def slow_weather(latitude, longitude):
        entered.set()
        await release.wait()
        return {"source": "test weather", "daily": {}}

    monkeypatch.setattr("nexus_api.operations.integrations.fetch_weather", slow_weather)
    task = asyncio.create_task(
        c.post(
            PREFIX + f"/workspaces/{ws['id']}/integrations/weather",
            headers=headers,
            json={"latitude": 1, "longitude": 2},
        )
    )
    await asyncio.wait_for(entered.wait(), 2)
    try:
        response = await asyncio.wait_for(c.get(PREFIX + "/workspaces"), 2)
        assert response.status_code == 200
    finally:
        release.set()
        assert (await task).status_code == 200


async def test_idempotency_stale_branches_and_approval_content_binding(client):
    c, app = client
    result = await c.post(
        PREFIX + "/setup", json={"username": "owner", "password": "a lengthy owner password"}
    )
    headers = {"X-Nexus-CSRF": result.json()["csrf_token"], "Idempotency-Key": "create-once"}
    body = {"name": "test", "domain": "manufacturing"}
    ws = (await c.post(PREFIX + "/workspaces", headers=headers, json=body)).json()
    assert (await c.post(PREFIX + "/workspaces", headers=headers, json=body)).json()["id"] == ws[
        "id"
    ]
    assert (
        await c.post(PREFIX + "/workspaces", headers=headers, json={**body, "name": "different"})
    ).status_code == 409
    headers.pop("Idempotency-Key")
    path = PREFIX + f"/workspaces/{ws['id']}"
    payload = (await c.get(PREFIX + "/domains/manufacturing/sample")).json()
    upload = {
        "payload": payload,
        "expected_revision": 0,
        "provenance": {"kind": "synthetic", "name": "test"},
    }
    assert (await c.put(path + "/dataset", headers=headers, json=upload)).status_code == 200
    branch_response = await c.post(
        path + "/scenarios",
        headers=headers,
        json={
            "name": "branch",
            "changes": [{"path": "/resources/machine/capacity", "value": 2}],
            "expected_revision": 1,
        },
    )
    assert branch_response.status_code == 200, branch_response.text
    branch = branch_response.json()
    decision = (
        await c.post(
            path + "/decisions",
            headers=headers,
            json={"scenario_id": branch["id"], "expected_revision": 1},
        )
    ).json()
    approval = PREFIX + f"/decisions/{decision['id']}/approve"
    assert (
        await c.post(approval, headers=headers, json={"plan_hash": "wrong", "decision": "approve"})
    ).status_code == 409
    async with app.state.store.transaction() as state:
        state["decisions"][decision["id"]]["payload"]["budget"] = 0
    assert (
        await c.post(
            approval,
            headers=headers,
            json={"plan_hash": decision["plan_hash"], "decision": "approve"},
        )
    ).status_code == 503
    upload["expected_revision"] = 1
    assert (await c.put(path + "/dataset", headers=headers, json=upload)).status_code == 200
    assert (
        await c.post(
            path + "/decisions",
            headers=headers,
            json={"scenario_id": branch["id"], "expected_revision": 2},
        )
    ).status_code == 409
    async with app.state.store.transaction() as state:
        state["workspaces"][ws["id"]]["events"][0]["details"]["domain"] = "tampered"
    assert (await c.get(path)).status_code == 503
