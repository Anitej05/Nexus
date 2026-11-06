import asyncio
import copy
import threading

import httpx
import pytest
from nexus_api.operations import learning_control as control
from nexus_api.operations.api import PREFIX, create_operations_app
from nexus_api.operations.synthetic import generate_history


def ingest(ws, history, mode="append"):
    result = control.prepare_learning(
        ws,
        "learning/history",
        {
            "history": history,
            "expected_history_revision": ws.get("learning", control.initial())["history_revision"],
            "mode": mode,
        },
    )
    ws["learning"] = result["state"]
    return result


def test_partial_labels_wait_first_valid_history_promotes_and_new_groups_retrain():
    ws = {"domain": "construction"}
    first = ingest(ws, generate_history("construction", projects=10))
    assert first["training"] == "waiting_for_labels"
    assert not ws["learning"]["runs"]
    result = ingest(ws, generate_history("construction"))
    assert result["training"] == "promoted"
    active = ws["learning"]["active_id"]
    assert len(ws["learning"]["runs"]) == 1
    duplicate = ingest(ws, generate_history("construction"))
    assert duplicate["training"] == "unchanged"
    assert len(ws["learning"]["runs"]) == 1
    below_threshold = ingest(ws, generate_history("construction", projects=6, seed=43))
    assert below_threshold["training"] == "waiting_for_labels"
    assert len(ws["learning"]["runs"]) == 1
    result = ingest(ws, generate_history("construction", projects=10, seed=43))
    assert result["training"] in ("promoted", "rejected")
    assert len(ws["learning"]["runs"]) == 2
    assert ws["learning"]["last_training_rows"] == 720
    assert active in ws["learning"]["models"]


def test_mixed_synthetic_and_observed_provenance_requires_explicit_replace():
    ws = {"domain": "construction"}
    ingest(ws, generate_history("construction", projects=5))
    observed = generate_history("construction", projects=5, seed=43)
    observed["kind"] = "user_upload"
    before = copy.deepcopy(ws)
    with pytest.raises(ValueError, match="provenance"):
        ingest(ws, observed)
    assert ws == before
    result = ingest(ws, observed, mode="replace")
    assert result["state"]["history"]["kind"] == "user_upload"


def test_validation_gate_rejects_degraded_candidates_and_retains_three_artifacts(monkeypatch):
    ws = {"domain": "construction"}
    assert ingest(ws, generate_history("construction"))["training"] == "promoted"
    active = ws["learning"]["active_id"]
    template = copy.deepcopy(ws["learning"]["models"][active])
    count = 0

    def degraded(*args, **kwargs):
        nonlocal count
        count += 1
        artifact = copy.deepcopy(template)
        artifact["id"] = f"degraded-{count}"
        artifact["metrics"]["validation"]["duration"]["mae"] = 1000
        artifact["metrics"]["test"]["duration"]["mae"] = 0
        return artifact

    monkeypatch.setattr(control, "train_models", degraded)
    for _ in range(4):
        result = control.prepare_learning(
            ws, "learning/train", {"expected_history_revision": ws["learning"]["history_revision"]}
        )
        ws["learning"] = result["state"]
        assert result["training"] == "rejected"
        assert ws["learning"]["active_id"] == active
    assert len(ws["learning"]["models"]) == 3
    assert active in ws["learning"]["models"]
    assert "degraded-4" in ws["learning"]["models"]


def test_model_must_beat_planned_duration_baseline(monkeypatch):
    ws = {"domain": "construction"}
    assert ingest(ws, generate_history("construction"))["training"] == "promoted"
    active = ws["learning"]["active_id"]
    candidate = copy.deepcopy(ws["learning"]["models"][active])
    candidate["id"] = "worse-than-planned"
    val = candidate["metrics"]["validation"]
    val["baseline"]["duration"]["mae"] = 100
    val["duration"]["mae"] *= 0.5
    val["planned_baseline"]["duration"]["mae"] = val["duration"]["mae"] * 0.5
    monkeypatch.setattr(control, "train_models", lambda *args, **kwargs: candidate)
    result = control.prepare_learning(
        ws, "learning/train", {"expected_history_revision": ws["learning"]["history_revision"]}
    )
    assert result["training"] == "rejected"
    assert result["state"]["active_id"] == active
    assert not result["state"]["runs"][-1]["comparison"]["planned_baseline_ok"]


def test_rejects_other_domain_history_including_manual_training():
    ws = {"domain": "construction"}
    with pytest.raises(ValueError, match="domain"):
        ingest(ws, generate_history("manufacturing"))
    state = control.initial()
    state["history"] = generate_history("manufacturing")
    ws["learning"] = state
    with pytest.raises(ValueError, match="domain"):
        control.prepare_learning(ws, "learning/train", {"expected_history_revision": 0})


async def test_unlabelled_operational_import_never_trains_and_stale_history_does_not_commit(
    tmp_path, monkeypatch
):
    app = create_operations_app(f"sqlite+aiosqlite:///{tmp_path}/learning.db")
    await app.state.store.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        response = await client.post(
            PREFIX + "/setup", json={"username": "owner", "password": "a lengthy owner password"}
        )
        headers = {"X-Nexus-CSRF": response.json()["csrf_token"]}
        ws = (
            await client.post(
                PREFIX + "/workspaces",
                headers=headers,
                json={"domain": "construction", "name": "Training"},
            )
        ).json()
        path = PREFIX + f"/workspaces/{ws['id']}"
        sample = (await client.get(PREFIX + "/domains/construction/sample")).json()

        def unexpected(*args, **kwargs):
            raise AssertionError("Operational data is not labelled training history")

        original = control.train_models
        monkeypatch.setattr(control, "train_models", unexpected)
        response = await client.put(
            path + "/dataset",
            headers=headers,
            json={
                "payload": sample,
                "expected_revision": 0,
                "provenance": {"kind": "synthetic", "name": "sample"},
            },
        )
        assert response.status_code == 200
        assert (await client.get(path + "/learning")).json()["row_count"] == 0
        entered, release = threading.Event(), threading.Event()

        def delayed(*args, **kwargs):
            entered.set()
            assert release.wait(10)
            return original(*args, **kwargs)

        monkeypatch.setattr(control, "train_models", delayed)
        pending = asyncio.create_task(
            client.post(
                path + "/learning/history",
                headers=headers,
                json={"history": generate_history("construction"), "expected_history_revision": 0},
            )
        )
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            async with app.state.store.transaction() as state:
                learning = control.initial()
                learning["history_revision"] = 1
                state["workspaces"][ws["id"]]["learning"] = learning
        finally:
            release.set()
        assert (await pending).status_code == 409
        current = (await client.get(path + "/learning")).json()
        assert current["history_revision"] == 1
        assert current["row_count"] == 0
        assert current["active_model"] is None
    await app.state.store.close()
