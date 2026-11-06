"""Automatic, bounded candidate training and validation-only promotion policy."""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from .learning import apply_predictions, evaluate_models, train_models, validate_history
from .registry import analyze_domain


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def initial() -> dict[str, Any]:
    return {
        "history_revision": 0,
        "history": None,
        "runs": [],
        "models": {},
        "active_id": None,
        "last_training_rows": 0,
        "last_training_projects": [],
    }


def summary(ws: dict[str, Any]) -> dict[str, Any]:
    state = ws.get("learning", initial())
    rows = (state["history"] or {}).get("rows", [])
    active = state["models"].get(state["active_id"])
    return {
        "history_revision": state["history_revision"],
        "row_count": len(rows),
        "project_count": len({r["project_id"] for r in rows}),
        "auto_train": True,
        "min_rows": 120,
        "retrain_rows": 50,
        "retrain_projects": 3,
        "runs": state["runs"],
        "active_model": public_model(active) if active else None,
        "last_training_rows": state["last_training_rows"],
        "last_training_projects": state["last_training_projects"],
    }


def public_model(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        key: artifact[key]
        for key in (
            "id",
            "kind",
            "metrics",
            "split",
            "training_digest",
            "trained_at",
            "history_kind",
            "integrity_digest",
            "sklearn_version",
            "limitations",
            "recipe_version",
            "recipe_params",
        )
    }


def prepare_learning(ws: dict[str, Any], action: str, body: dict[str, Any]) -> dict[str, Any]:
    state = copy.deepcopy(ws.get("learning", initial()))
    expected = body.get("expected_history_revision")
    if type(expected) is not int or expected != state["history_revision"]:
        raise ValueError("Historical outcomes changed; refresh before training/import")
    revision = state["history_revision"]
    if action == "learning/history":
        history = body.get("history")
        if not isinstance(history, dict):
            raise ValueError("Historical outcomes must be an object")
        incoming = validate_history(history)
        if any(row["domain"] != ws["domain"] for row in incoming["rows"]):
            raise ValueError("Historical outcomes must match the workspace domain")
        mode = body.get("mode", "append")
        if mode not in ("append", "replace"):
            raise ValueError("History mode must be append or replace")
        if mode == "replace":
            state = initial()
            state["history_revision"] = revision
        previous = state["history"]
        if previous is not None and previous["kind"] != incoming["kind"]:
            raise ValueError("History provenance cannot be mixed; explicitly replace history")
        old = {row["id"]: row for row in (previous or {}).get("rows", [])}
        added = 0
        for row in incoming["rows"]:
            if row["id"] in old and old[row["id"]] != row:
                raise ValueError("Existing outcome IDs are immutable; replace history explicitly")
            if row["id"] not in old:
                added += 1
                old[row["id"]] = row
        if added == 0 and mode == "append":
            return {"learning_revision": revision, "state": state, "training": "unchanged"}
        kind = incoming["kind"]
        state["history"] = validate_history(
            {"schema_version": 1, "kind": kind, "rows": list(old.values())}
        )
        state["history_revision"] = revision + 1
    elif action != "learning/train":
        raise ValueError("Unknown learning operation")
    rows = (state["history"] or {}).get("rows", [])
    if any(row["domain"] != ws["domain"] for row in rows):
        raise ValueError("Historical outcomes must match the workspace domain")
    projects = {row["project_id"] for row in rows}
    new_projects = projects - set(state["last_training_projects"])
    first = state["last_training_rows"] == 0
    due = (
        len(rows) >= 120
        and len(projects) >= 12
        and (first or (len(rows) - state["last_training_rows"] >= 50 and len(new_projects) >= 3))
    )
    if action == "learning/train":
        due = len(rows) >= 120 and len(projects) >= 12
    outcome = "waiting_for_labels"
    if due:
        run: dict[str, Any] = {
            "id": uuid.uuid4().hex,
            "trigger": "automatic" if action == "learning/history" else "manual",
            "history_revision": state["history_revision"],
            "at": datetime.now(UTC).isoformat(),
            "row_count": len(rows),
        }
        try:
            artifact = train_models(state["history"], seed=42)
            val = artifact["metrics"]["validation"]
            incumbent = state["models"].get(state["active_id"])
            active_metrics = (
                evaluate_models(incumbent, state["history"], "validation") if incumbent else None
            )
            baseline_ok = (
                val["duration"]["mae"] < val["baseline"]["duration"]["mae"] * 0.95
                and val["delay"]["brier"] <= val["baseline"]["delay"]["brier"]
            )
            planned_baseline_ok = (
                val["duration"]["mae"] < val["planned_baseline"]["duration"]["mae"] * 0.95
            )
            champion_ok = not active_metrics or (
                val["duration"]["mae"] < active_metrics["duration"]["mae"]
                and val["delay"]["brier"] <= active_metrics["delay"]["brier"] + 0.005
            )
            promoted = bool(baseline_ok and planned_baseline_ok and champion_ok)
            run.update(
                {
                    "model_id": artifact["id"],
                    "status": "promoted" if promoted else "rejected",
                    "metrics": artifact["metrics"],
                    "artifact_digest": artifact["integrity_digest"],
                    "comparison": {
                        "baseline_ok": baseline_ok,
                        "champion_ok": champion_ok,
                        "planned_baseline_ok": planned_baseline_ok,
                        "active_validation": active_metrics,
                    },
                    "reason": "Validation quality gate; test metrics are reporting only",
                }
            )
            if promoted:
                state["active_id"] = artifact["id"]
            # Retain bounded candidate evidence as well as the active model. A rejected
            # candidate must never evict the champion, even after repeated attempts.
            state["models"].pop(artifact["id"], None)
            state["models"][artifact["id"]] = artifact
            while len(state["models"]) > 3:
                oldest = next(key for key in state["models"] if key != state["active_id"])
                del state["models"][oldest]
            state["last_training_rows"] = len(rows)
            state["last_training_projects"] = sorted(projects)
        except ValueError as exc:
            run.update({"status": "waiting_for_labels", "reason": str(exc)[:250]})
        state["runs"] = (state["runs"] + [run])[-20:]
        outcome = run["status"]
    return {"learning_revision": revision, "state": state, "training": outcome}


def prepare_model_scenario(ws: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    state = ws.get("learning", initial())
    artifact = state["models"].get(body.get("model_id"))
    if not artifact or artifact["id"] != state["active_id"]:
        raise ValueError("Select the current active trained model")
    if not ws["dataset"]:
        raise ValueError("Import an operational dataset first")
    predicted = apply_predictions(ws["domain"], ws["dataset"], artifact)
    baseline = analyze_domain(ws["domain"], ws["dataset"], seed=42, samples=100)
    analysis = analyze_domain(ws["domain"], predicted["payload"], seed=42, samples=100)
    metadata = {**public_model(artifact), "predictions": predicted["predictions"]}
    analysis["learning"] = metadata
    return {
        "revision": ws["revision"],
        "learning_revision": state["history_revision"],
        "model_id": artifact["id"],
        "payload": predicted["payload"],
        "baseline": baseline,
        "analysis": analysis,
        "model_metadata": metadata,
        "changes": [{"path": "/trained_model", "value": artifact["id"]}],
        "fingerprint": _hash(predicted),
    }
