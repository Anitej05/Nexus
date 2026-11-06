"""Bounded, project-grouped supervised learning with portable JSON trees."""

from __future__ import annotations

import copy
import hashlib
import json
import math
from datetime import UTC, datetime
from typing import Any

import numpy as np
import sklearn  # type: ignore[import-untyped]
from sklearn.dummy import DummyClassifier, DummyRegressor  # type: ignore[import-untyped]
from sklearn.ensemble import (  # type: ignore[import-untyped]
    ExtraTreesClassifier,
    ExtraTreesRegressor,
)
from sklearn.metrics import (  # type: ignore[import-untyped]
    accuracy_score,
    brier_score_loss,
    mean_absolute_error,
    mean_squared_error,
    roc_auc_score,
)

FEATURES = [
    "planned_duration",
    "quantity",
    "productivity",
    "resource_capacity",
    "material_coverage",
    "supplier_delay_days",
    "weather_risk",
    "complexity",
]


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _features(values: Any) -> list[float]:
    if not isinstance(values, dict) or set(values) != set(FEATURES):
        raise ValueError("features must contain exactly the eight protocol fields")
    out = []
    for name in FEATURES:
        value = values[name]
        if (
            isinstance(value, bool)
            or not isinstance(value, (float, int))
            or value < 0
            or value > 1e9
            or not math.isfinite(value)
        ):
            raise ValueError(f"invalid feature {name}")
        out.append(float(value))
    return out


def _partition(project: str, seed: int) -> str:
    bucket = int(hashlib.sha256(f"{seed}:{project}".encode()).hexdigest()[:8], 16) % 100
    return "train" if bucket < 60 else "validation" if bucket < 80 else "test"


def _history(history: Any, seed: int, *, partial: bool = False) -> dict[str, list[dict[str, Any]]]:
    if (
        not isinstance(history, dict)
        or history.get("schema_version") != 1
        or history.get("kind") not in ("synthetic", "user_upload")
    ):
        raise ValueError("invalid history schema or provenance")
    rows = history.get("rows")
    if not isinstance(rows, list) or not (1 if partial else 100) <= len(rows) <= 2000:
        raise ValueError(
            "history must contain 1 to 2000 rows"
            if partial
            else "history must contain 100 to 2000 rows"
        )
    splits: dict[str, list[dict[str, Any]]] = {"train": [], "validation": [], "test": []}
    ids: set[str] = set()
    groups: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid row")
        rid, project = row.get("id"), row.get("project_id")
        if (
            not isinstance(rid, str)
            or not rid
            or rid in ids
            or not isinstance(project, str)
            or not project
        ):
            raise ValueError("unique row and project IDs required")
        ids.add(rid)
        groups.add(project)
        _features(row.get("features"))
        target = row.get("actual_duration")
        if (
            isinstance(target, bool)
            or not isinstance(target, (int, float))
            or target <= 0
            or target > 1e9
            or not math.isfinite(target)
            or type(row.get("delayed")) is not bool
        ):
            raise ValueError("invalid outcome")
        if not isinstance(row.get("domain"), str) or not row["domain"]:
            raise ValueError("domain required")
        splits[_partition(project, seed)].append(row)
    if not partial and (len(groups) < 12 or any(len(splits[k]) < 6 for k in splits)):
        raise ValueError("at least 12 projects and six rows in each stable partition required")
    if not partial and len({r["delayed"] for r in splits["train"]}) != 2:
        raise ValueError("training partition requires both delay classes")
    return splits


def validate_history(history: dict[str, Any]) -> dict[str, Any]:
    _history(history, 42, partial=True)
    return copy.deepcopy(history)


def _matrix(rows: list[dict[str, Any]]) -> list[list[float]]:
    return [_features(row["features"]) for row in rows]


def _metrics(
    rows: list[dict[str, Any]],
    duration: Any,
    delay: Any,
    baseline_duration: Any,
    baseline_delay: Any,
) -> dict[str, Any]:
    x = _matrix(rows)
    y = [r["actual_duration"] for r in rows]
    binary = [int(r["delayed"]) for r in rows]
    predicted = duration.predict(x)
    probs = delay.predict_proba(x)[:, 1]
    baseline_probs = baseline_delay.predict_proba(x)[:, 1]

    def classification(p: Any) -> dict[str, Any]:
        return {
            "brier": float(brier_score_loss(binary, p)),
            "accuracy": float(accuracy_score(binary, np.asarray(p) >= 0.5)),
            "auc": float(roc_auc_score(binary, p)) if len(set(binary)) == 2 else None,
        }

    def regression(pred: Any) -> dict[str, float]:
        return {
            "mae": float(mean_absolute_error(y, pred)),
            "rmse": float(math.sqrt(mean_squared_error(y, pred))),
        }

    return {
        "duration": regression(predicted),
        "delay": classification(probs),
        "planned_baseline": {
            "duration": regression([row["features"]["planned_duration"] for row in rows])
        },
        "baseline": {
            "duration": regression(baseline_duration.predict(x)),
            "delay": classification(baseline_probs),
        },
    }


def _tree(estimator: Any, classifier: bool) -> dict[str, Any]:
    tree = estimator.tree_
    value = tree.value[:, 0, 1] if classifier else tree.value[:, 0, 0]
    return {
        "left": tree.children_left.tolist(),
        "right": tree.children_right.tolist(),
        "feature": tree.feature.tolist(),
        "threshold": tree.threshold.tolist(),
        "value": value.tolist(),
    }


def train_models(history: dict[str, Any], seed: int = 42) -> dict[str, Any]:
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed must be a 32-bit nonnegative integer")
    splits = _history(history, seed)
    rows = splits["train"]
    x = _matrix(rows)
    y = [r["actual_duration"] for r in rows]
    labels = [int(r["delayed"]) for r in rows]
    duration = ExtraTreesRegressor(
        n_estimators=24, max_depth=5, min_samples_leaf=3, n_jobs=1, random_state=seed
    ).fit(x, y)
    delay = ExtraTreesClassifier(
        n_estimators=24, max_depth=5, min_samples_leaf=3, n_jobs=1, random_state=seed
    ).fit(x, labels)
    base_duration = DummyRegressor(strategy="mean").fit(x, y)
    base_delay = DummyClassifier(strategy="prior").fit(x, labels)
    split_ids = {key: sorted({r["project_id"] for r in group}) for key, group in splits.items()}
    train_bounds = {
        name: [min(v[i] for v in x), max(v[i] for v in x)] for i, name in enumerate(FEATURES)
    }
    recipe_version = "extra_trees_v1"
    recipe_params = {"n_estimators": 24, "max_depth": 5, "min_samples_leaf": 3, "n_jobs": 1}
    result: dict[str, Any] = {
        "id": _digest([history, seed, recipe_version, sklearn.__version__, recipe_params])[:24],
        "recipe_version": recipe_version,
        "recipe_params": recipe_params,
        "kind": "trained",
        "schema_version": 1,
        "features": FEATURES.copy(),
        "seed": seed,
        "history_kind": history["kind"],
        "models": {
            "duration": {"trees": [_tree(t, False) for t in duration.estimators_]},
            "delay": {"trees": [_tree(t, True) for t in delay.estimators_]},
        },
        "metrics": {
            k: _metrics(splits[k], duration, delay, base_duration, base_delay)
            for k in ("validation", "test")
        },
        "baseline": {"duration_mean": float(np.mean(y)), "delay_rate": float(np.mean(labels))},
        "split": {"project_ids": split_ids, "row_counts": {k: len(v) for k, v in splits.items()}},
        "training_bounds": train_bounds,
        "training_digest": _digest(history),
        "trained_at": datetime.now(UTC).isoformat(),
        "limitations": [
            "Activity-level predictions; not calibrated project deadline probabilities.",
            "Validation selects candidates; test is held out from selection.",
            "Training data provenance and distribution limit applicability.",
        ],
        "sklearn_version": sklearn.__version__,
    }
    result["integrity_digest"] = _digest(result)
    return result


def _check(artifact: Any) -> None:
    if (
        not isinstance(artifact, dict)
        or artifact.get("kind") != "trained"
        or artifact.get("schema_version") != 1
        or artifact.get("features") != FEATURES
    ):
        raise ValueError("invalid model artifact")
    expected = artifact.get("integrity_digest")
    if not isinstance(expected, str) or expected != _digest(
        {k: v for k, v in artifact.items() if k != "integrity_digest"}
    ):
        raise ValueError("model artifact integrity mismatch")
    for kind in ("duration", "delay"):
        trees = artifact["models"][kind]["trees"]
        if not isinstance(trees, list) or len(trees) != 24:
            raise ValueError("invalid model tree count")
        for t in trees:
            n = len(t["left"])
            if not 1 <= n <= 63 or any(
                len(t[k]) != n for k in ("right", "feature", "threshold", "value")
            ):
                raise ValueError("invalid tree arrays")
            visited: set[int] = set()
            stack = [(0, 0)]
            while stack:
                i, depth = stack.pop()
                if i in visited or depth > 5:
                    raise ValueError("invalid tree structure or depth")
                visited.add(i)
                left, right, feature = t["left"][i], t["right"][i], t["feature"][i]
                threshold, value = t["threshold"][i], t["value"][i]
                if (
                    isinstance(threshold, bool)
                    or not isinstance(threshold, (int, float))
                    or not math.isfinite(threshold)
                    or isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not math.isfinite(value)
                    or (kind == "delay" and not 0 <= value <= 1)
                    or (kind == "duration" and not 0 < value <= 1e9)
                ):
                    raise ValueError("invalid tree numeric value")
                if left == right == -1:
                    continue
                if (
                    type(left) is not int
                    or type(right) is not int
                    or type(feature) is not int
                    or not (i < left < n and i < right < n and 0 <= feature < len(FEATURES))
                ):
                    raise ValueError("invalid tree structure")
                stack.extend([(left, depth + 1), (right, depth + 1)])
            if len(visited) != n:
                raise ValueError("invalid tree unreachable node")


def _predict_unchecked(artifact: dict[str, Any], features: list[float]) -> tuple[float, float]:
    results = []
    for kind in ("duration", "delay"):
        values = []
        for tree in artifact["models"][kind]["trees"]:
            node = 0
            while tree["left"][node] != -1:
                node = (
                    tree["left"][node]
                    if features[tree["feature"][node]] <= tree["threshold"][node]
                    else tree["right"][node]
                )
            values.append(tree["value"][node])
        results.append(sum(values) / len(values))
    return float(results[0]), float(results[1])


def predict_models(artifact: dict[str, Any], features: dict[str, Any]) -> dict[str, Any]:
    _check(artifact)
    x = _features(features)
    duration, probability = _predict_unchecked(artifact, x)
    outside = [
        name
        for name, value in zip(FEATURES, x, strict=True)
        if not artifact["training_bounds"][name][0] <= value <= artifact["training_bounds"][name][1]
    ]
    return {
        "duration_working_days": duration,
        "delay_probability": probability,
        "model_id": artifact["id"],
        "warning": "Outside training range: " + ", ".join(outside) if outside else None,
    }


def evaluate_models(
    artifact: dict[str, Any], history: dict[str, Any], partition: str = "validation"
) -> dict[str, Any]:
    _check(artifact)
    if partition not in ("validation", "test"):
        raise ValueError("partition must be validation or test")
    valid = validate_history(history)
    rows = [
        row for row in valid["rows"] if _partition(row["project_id"], artifact["seed"]) == partition
    ]
    if not rows:
        raise ValueError("No rows in selected evaluation partition")
    predictions = [_predict_unchecked(artifact, _features(r["features"])) for r in rows]
    actual = [r["actual_duration"] for r in rows]
    labels = [int(r["delayed"]) for r in rows]
    durations = [p[0] for p in predictions]
    probabilities = [p[1] for p in predictions]

    def regression(pred: list[float]) -> dict[str, float]:
        return {
            "mae": float(mean_absolute_error(actual, pred)),
            "rmse": float(math.sqrt(mean_squared_error(actual, pred))),
        }

    def classification(pred: list[float]) -> dict[str, Any]:
        return {
            "brier": float(brier_score_loss(labels, pred)),
            "accuracy": float(accuracy_score(labels, np.asarray(pred) >= 0.5)),
            "auc": float(roc_auc_score(labels, pred)) if len(set(labels)) == 2 else None,
        }

    return {
        "duration": regression(durations),
        "delay": classification(probabilities),
        "planned_baseline": {
            "duration": regression([row["features"]["planned_duration"] for row in rows])
        },
        "baseline": {
            "duration": regression([artifact["baseline"]["duration_mean"]] * len(rows)),
            "delay": classification([artifact["baseline"]["delay_rate"]] * len(rows)),
        },
    }


def workspace_features(payload: dict[str, Any]) -> list[dict[str, Any]]:
    resources = {r["id"]: r for r in payload["resources"]}
    materials = {m["id"]: m for m in payload["materials"]}
    result = []
    for task in payload["tasks"]:
        remaining = task.get("remaining_quantity", task["quantity"])
        if remaining <= 0:
            continue
        demand = task.get("materials", {})
        coverage = min(
            (
                min(1.0, materials[mid].get("stock", 0) / amount)
                for mid, amount in demand.items()
                if amount > 0
            ),
            default=1.0,
        )
        capacity = min(
            (
                resources[rid]["capacity"] / amount
                for rid, amount in task.get("resources", {}).items()
                if amount > 0
            ),
            default=1.0,
        )
        lead = max((materials[mid].get("supplier_lead_days", 0) for mid in demand), default=0)
        features = {
            "planned_duration": max(
                task.get("minimum_duration", 0), remaining / task["productivity"]
            ),
            "quantity": remaining,
            "productivity": task["productivity"],
            "resource_capacity": capacity,
            "material_coverage": coverage,
            "supplier_delay_days": lead,
            "weather_risk": min(
                1.0,
                len(payload.get("weather_delays", [])) / max(1, payload.get("horizon_days", 365)),
            ),
            "complexity": float(
                len(task.get("dependencies", [])) + len(task.get("resources", {})) + len(demand)
            ),
        }
        result.append({"task_id": task["id"], "features": features})
    return result


def apply_predictions(
    domain: str, payload: dict[str, Any], artifact: dict[str, Any]
) -> dict[str, Any]:
    from .registry import validate_domain

    updated = validate_domain(domain, payload)
    predictions = []
    for item in workspace_features(updated):
        pred = predict_models(artifact, item["features"])
        task = next(t for t in updated["tasks"] if t["id"] == item["task_id"])
        duration = max(float(task.get("minimum_duration", 0)), pred["duration_working_days"])
        task["duration_estimate"] = duration
        task["estimate_quantity"] = task.get("remaining_quantity", task["quantity"])
        predictions.append({"task_id": task["id"], **pred})
    return {"payload": validate_domain(domain, updated), "predictions": predictions}
