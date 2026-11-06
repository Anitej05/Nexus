import copy
import json

import pytest
from nexus_api.operations.learning import (
    apply_predictions,
    predict_models,
    train_models,
    workspace_features,
)
from nexus_api.operations.registry import sample_payload


def history():
    rows = []
    for i in range(144):
        f = {
            "planned_duration": 2 + i % 9,
            "quantity": 10 + i % 5,
            "productivity": 2,
            "resource_capacity": 1 + i % 3,
            "material_coverage": 0.5 + (i % 3) / 4,
            "supplier_delay_days": i % 4,
            "weather_risk": (i % 4) / 4,
            "complexity": 1 + i % 4,
        }
        rows.append(
            {
                "id": str(i),
                "project_id": f"p{i // 8}",
                "domain": "construction",
                "features": f,
                "actual_duration": f["planned_duration"] + f["supplier_delay_days"] * 0.5,
                "delayed": i % 4 > 1,
            }
        )
    return {"schema_version": 1, "kind": "synthetic", "rows": rows}


def test_train_predict_json_roundtrip_and_project_split():
    artifact = train_models(history())
    split = artifact["split"]["project_ids"]
    assert not set(split["train"]) & set(split["test"])
    assert not set(split["validation"]) & set(split["test"])
    result = predict_models(json.loads(json.dumps(artifact)), history()["rows"][0]["features"])
    assert result["duration_working_days"] > 0
    assert 0 <= result["delay_probability"] <= 1
    assert "mae" in artifact["metrics"]["test"]["duration"]


def test_tampering_and_leakage_rejected():
    artifact = train_models(history())
    artifact["models"]["duration"]["trees"][0]["threshold"][0] += 1
    with pytest.raises(ValueError):
        predict_models(artifact, history()["rows"][0]["features"])
    bad = history()
    bad["rows"][0]["features"]["actual_duration"] = 4
    with pytest.raises(ValueError):
        train_models(bad)


def test_apply_returns_valid_separate_scenario():
    payload = sample_payload("construction")
    before = copy.deepcopy(payload)
    artifact = train_models(history())
    result = apply_predictions("construction", payload, artifact)
    assert payload == before
    assert len(result["predictions"]) == len(workspace_features(payload))
    assert result["payload"] != payload


def test_appended_projects_preserve_split_and_evaluate_validation():
    from nexus_api.operations.learning import evaluate_models

    base = history()
    artifact = train_models(base)
    later = copy.deepcopy(base)
    new_rows = copy.deepcopy(base["rows"][:24])
    for row in new_rows:
        row["id"] = "new-" + row["id"]
        row["project_id"] = "new-" + row["project_id"]
    later["rows"].extend(new_rows)
    candidate = train_models(later)
    for name in ("train", "validation", "test"):
        assert set(artifact["split"]["project_ids"][name]) <= set(
            candidate["split"]["project_ids"][name]
        )
    assert "duration" in evaluate_models(artifact, later, partition="validation")


def test_portable_tree_predictions_match_sklearn():
    from nexus_api.operations.learning import FEATURES, _partition
    from sklearn.ensemble import ExtraTreesRegressor

    data = history()
    artifact = train_models(data)
    training = [r for r in data["rows"] if _partition(r["project_id"], 42) == "train"]
    x = [[r["features"][f] for f in FEATURES] for r in training]
    model = ExtraTreesRegressor(
        n_estimators=24, max_depth=5, min_samples_leaf=3, n_jobs=1, random_state=42
    ).fit(x, [r["actual_duration"] for r in training])
    features = data["rows"][0]["features"]
    predicted = predict_models(artifact, features)["duration_working_days"]
    assert predicted == pytest.approx(model.predict([[features[f] for f in FEATURES]])[0])


def test_partial_history_can_be_validated_but_not_trained():
    from nexus_api.operations.learning import validate_history

    partial = history()
    partial["rows"] = partial["rows"][:1]
    assert len(validate_history(partial)["rows"]) == 1
    with pytest.raises(ValueError, match="100"):
        train_models(partial)


def test_portable_delay_probability_matches_sklearn():
    from nexus_api.operations.learning import FEATURES, _partition
    from sklearn.ensemble import ExtraTreesClassifier

    data = history()
    artifact = train_models(data)
    training = [r for r in data["rows"] if _partition(r["project_id"], 42) == "train"]
    x = [[r["features"][f] for f in FEATURES] for r in training]
    model = ExtraTreesClassifier(
        n_estimators=24, max_depth=5, min_samples_leaf=3, n_jobs=1, random_state=42
    ).fit(x, [int(r["delayed"]) for r in training])
    features = data["rows"][0]["features"]
    predicted = predict_models(artifact, features)["delay_probability"]
    assert predicted == pytest.approx(model.predict_proba([[features[f] for f in FEATURES]])[0, 1])


def test_resealed_malformed_tree_is_rejected():
    from nexus_api.operations.learning import _digest

    artifact = train_models(history())
    tree = artifact["models"]["duration"]["trees"][0]
    tree["left"][0] = 0
    artifact["integrity_digest"] = _digest(
        {k: v for k, v in artifact.items() if k != "integrity_digest"}
    )
    with pytest.raises(ValueError, match="tree"):
        predict_models(artifact, history()["rows"][0]["features"])


def test_planned_duration_baseline_on_heldout_and_evaluation():
    from nexus_api.operations.learning import evaluate_models

    data = history()
    artifact = train_models(data)
    for partition in ("validation", "test"):
        expected = artifact["metrics"][partition]["planned_baseline"]["duration"]
        assert expected["mae"] >= 0
        assert evaluate_models(artifact, data, partition=partition)["planned_baseline"][
            "duration"
        ] == pytest.approx(expected)


def test_resealed_tree_with_invalid_probability_is_rejected():
    from nexus_api.operations.learning import _digest

    artifact = train_models(history())
    tree = artifact["models"]["delay"]["trees"][0]
    leaf = tree["left"].index(-1)
    tree["value"][leaf] = 1.5
    artifact["integrity_digest"] = _digest(
        {k: v for k, v in artifact.items() if k != "integrity_digest"}
    )
    with pytest.raises(ValueError, match="tree"):
        predict_models(artifact, history()["rows"][0]["features"])


def test_history_rejects_huge_numeric_values():
    from nexus_api.operations.learning import validate_history

    data = history()
    data["rows"][0]["features"]["quantity"] = 10**1000
    with pytest.raises(ValueError):
        validate_history(data)


def test_model_id_binds_training_recipe_and_library_version():
    import sklearn
    from nexus_api.operations.learning import _digest

    data = history()
    artifact = train_models(data)
    params = {"n_estimators": 24, "max_depth": 5, "min_samples_leaf": 3, "n_jobs": 1}
    assert artifact["recipe_version"] == "extra_trees_v1"
    assert artifact["recipe_params"] == params
    assert artifact["id"] == _digest([data, 42, "extra_trees_v1", sklearn.__version__, params])[:24]


def test_evaluate_small_single_class_external_test_cohort():
    from nexus_api.operations.learning import _partition, evaluate_models

    artifact = train_models(history())
    project = next(f"external-{i}" for i in range(100) if _partition(f"external-{i}", 42) == "test")
    external = history()
    external["rows"] = external["rows"][:3]
    for i, row in enumerate(external["rows"]):
        row["id"] = f"external-{i}"
        row["project_id"] = project
        row["delayed"] = True
    metrics = evaluate_models(artifact, external, "test")
    assert metrics["delay"]["auc"] is None
    assert metrics["delay"]["brier"] >= 0
    assert metrics["duration"]["mae"] >= 0


def test_model_proposals_preserve_productivity_and_do_not_compound():
    payload = sample_payload("construction")
    artifact = train_models(history())
    first = apply_predictions("construction", payload, artifact)["payload"]
    second = apply_predictions("construction", first, artifact)["payload"]
    for original, once, twice in zip(
        payload["tasks"], first["tasks"], second["tasks"], strict=True
    ):
        assert once["productivity"] == original["productivity"]
        assert twice.get("duration_estimate") == pytest.approx(once.get("duration_estimate"))
