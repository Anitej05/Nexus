import httpx
from nexus_api.operations.api import create_operations_app


async def test_history_automatically_trains_and_restores_model(tmp_path):
    app = create_operations_app("sqlite+aiosqlite:///" + str(tmp_path / "learning.db"))
    await app.state.store.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        result = await client.post(
            "/api/v1/operations/setup", json={"username": "owner", "password": "RealLearning!123"}
        )
        headers = {"X-Nexus-CSRF": result.json()["csrf_token"]}
        base = "/api/v1/operations"
        workspace = (
            await client.post(
                base + "/workspaces",
                headers=headers,
                json={"name": "Learning", "domain": "construction"},
            )
        ).json()
        path = base + "/workspaces/" + workspace["id"]
        history = (await client.get(base + "/domains/construction/history-sample")).json()
        result = await client.post(
            path + "/learning/history",
            headers=headers,
            json={"history": history, "mode": "append", "expected_history_revision": 0},
        )
        assert result.status_code == 200, result.text
        status = (await client.get(path + "/learning")).json()
        assert status["active_model"]["kind"] == "trained"
        assert status["runs"][-1]["trigger"] == "automatic"
        assert status["runs"][-1]["status"] == "promoted"
        model_id = status["active_model"]["id"]
        assert status["row_count"] == 640
        dataset = (await client.get(base + "/domains/construction/sample")).json()
        assert (
            await client.put(
                path + "/dataset",
                headers=headers,
                json={
                    "payload": dataset,
                    "expected_revision": 0,
                    "provenance": {"kind": "synthetic", "name": "test"},
                },
            )
        ).status_code == 200
        result = await client.post(
            path + "/learning/scenarios",
            headers=headers,
            json={"name": "Learned duration", "model_id": model_id, "expected_revision": 1},
        )
        assert result.status_code == 200, result.text
        assert result.json()["analysis"]["learning"]["id"] == model_id
        assert (await client.get(path)).json()["revision"] == 1
        # Repeated identical rows do not cause spurious retraining.
        result = await client.post(
            path + "/learning/history",
            headers=headers,
            json={"history": history, "mode": "append", "expected_history_revision": 1},
        )
        assert result.status_code == 200
        assert len((await client.get(path + "/learning")).json()["runs"]) == 1
    await app.state.store.close()
