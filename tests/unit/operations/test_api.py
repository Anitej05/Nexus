import httpx
import pytest
from nexus_api.operations.api import create_operations_app


@pytest.mark.asyncio
async def test_real_approval_writeback_and_restart(tmp_path):
    url = "sqlite+aiosqlite:///" + str(tmp_path / "workflow.sqlite")
    app = create_operations_app(url)
    await app.state.store.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as c:

        async def post(path, body):
            return await c.post("/api/v1/operations" + path, json=body, headers=headers)

        headers = {}
        r = await post("/setup", {"username": "owner", "password": "StrongOwner!123"})
        assert r.status_code == 200
        headers = {"X-Nexus-CSRF": r.json()["csrf_token"]}
        assert (
            await post(
                "/users",
                {"username": "reviewer", "password": "StrongReview!123", "role": "approver"},
            )
        ).status_code == 200
        w = (await post("/workspaces", {"name": "Test", "domain": "construction"})).json()
        wid = w["id"]
        payload = (await c.get("/api/v1/operations/domains/construction/sample")).json()
        r = await c.put(
            f"/api/v1/operations/workspaces/{wid}/dataset",
            headers=headers,
            json={
                "payload": payload,
                "expected_revision": 0,
                "provenance": {"kind": "synthetic", "name": "test"},
            },
        )
        assert r.status_code == 200
        s = (
            await post(
                f"/workspaces/{wid}/scenarios",
                {
                    "name": "Capacity",
                    "expected_revision": 1,
                    "changes": [{"path": "/resources/crew/capacity", "value": 2}],
                },
            )
        ).json()
        d = (
            await post(
                f"/workspaces/{wid}/decisions", {"scenario_id": s["id"], "expected_revision": 1}
            )
        ).json()
        body = {"plan_hash": d["plan_hash"], "decision": "approve"}
        assert (await post(f"/decisions/{d['id']}/approve", body)).status_code == 403
        await post("/logout", {})
        r = await post("/login", {"username": "reviewer", "password": "StrongReview!123"})
        headers = {"X-Nexus-CSRF": r.json()["csrf_token"]}
        assert (await post(f"/decisions/{d['id']}/approve", body)).status_code == 200
        assert (await post(f"/decisions/{d['id']}/apply", body)).status_code == 403
        await post("/logout", {})
        r = await post("/login", {"username": "owner", "password": "StrongOwner!123"})
        headers = {"X-Nexus-CSRF": r.json()["csrf_token"]}
        assert (await post(f"/decisions/{d['id']}/apply", body)).status_code == 200
        assert (await post(f"/decisions/{d['id']}/apply", body)).status_code == 409
    await app.state.store.close()
    app = create_operations_app(url)
    await app.state.store.initialize()
    async with app.state.store.transaction() as state:
        assert state["workspaces"][wid]["revision"] == 2
        assert state["workspaces"][wid]["dataset"]["resources"][0]["capacity"] == 2
        assert state["workspaces"][wid]["provenance"]["origin"]["kind"] == "synthetic"
    await app.state.store.close()
