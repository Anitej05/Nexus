import csv
import hashlib
import json
import math
import subprocess
import sys
from pathlib import Path

import pytest
from nexus_api.operations.imports import parse_csv_bundle
from nexus_api.operations.registry import analyze_domain, validate_domain
from nexus_api.operations.synthetic import generate_cases, generate_history


@pytest.mark.parametrize("domain", ["construction", "manufacturing"])
def test_reproducible_grouped_history_has_independent_labels(domain):
    history = generate_history(domain)
    assert history == generate_history(domain)
    assert history["kind"] == "synthetic"
    assert len(history["rows"]) == 640
    assert len({row["project_id"] for row in history["rows"]}) == 80
    assert len({row["id"] for row in history["rows"]}) == 640
    labels = set()
    for row in history["rows"]:
        features = row["features"]
        assert set(features) == {
            "planned_duration",
            "quantity",
            "productivity",
            "resource_capacity",
            "material_coverage",
            "supplier_delay_days",
            "weather_risk",
            "complexity",
        }
        assert all(math.isfinite(value) and value >= 0 for value in features.values())
        assert features["planned_duration"] == pytest.approx(
            features["quantity"] / features["productivity"]
        )
        assert row["actual_duration"] > 0
        assert row["delayed"] == (row["actual_duration"] > features["planned_duration"] * 1.15)
        labels.add(row["delayed"])
    assert labels == {True, False}
    shifted = generate_history(domain, shifted=True)
    other = generate_history(domain, seed=43)
    original_ids = {row["project_id"] for row in history["rows"]}
    assert not original_ids & {row["project_id"] for row in shifted["rows"]}
    assert not original_ids & {row["project_id"] for row in other["rows"]}
    assert shifted["rows"] != history["rows"]


@pytest.mark.parametrize("domain", ["construction", "manufacturing"])
def test_cases_exercise_actual_engine_constraints(domain):
    cases = generate_cases(domain)
    assert cases == generate_cases(domain)
    assert {case["name"] for case in cases} == {
        "nominal",
        "shortage",
        "zero_capacity",
        "budget_overrun",
        "rain_calendar",
        "shared_resources",
        "complete_progress",
    }
    for case in cases:
        payload = validate_domain(domain, case["payload"])
        assert case["kind"] == "synthetic"
        assert len(payload["projects"]) == 3
        assert len(payload["tasks"]) == 24
        assert all(task["id"].startswith(domain + "-") for task in payload["tasks"])
        result = analyze_domain(domain, payload, samples=2)
        assert (not result["infeasible"]) == case["expected_feasible"], case["name"]


@pytest.mark.parametrize("projects", [0, -1, 10001, True])
def test_rejects_invalid_history_size(projects):
    with pytest.raises(ValueError):
        generate_history("construction", projects=projects)


def test_rejects_unknown_domains():
    with pytest.raises(ValueError):
        generate_history("unknown")
    with pytest.raises(ValueError):
        generate_cases("unknown")


def test_export_script_manifest_and_csv_bundles(tmp_path):
    script = Path(__file__).parents[3] / "scripts/generate_operations_data.py"
    subprocess.run(  # noqa: S603 - fixed local script and pytest-generated output directory
        [sys.executable, str(script), "--output", str(tmp_path), "--projects", "4", "--seed", "17"],
        check=True,
        capture_output=True,
    )
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["kind"] == "synthetic"
    assert manifest["seed"] == 17
    assert len(manifest["files"]) == 94
    for relative, record in manifest["files"].items():
        data = (tmp_path / relative).read_bytes()
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        assert len(data) == record["bytes"]
    with (tmp_path / "construction/history.csv").open(newline="") as source:
        rows = list(csv.DictReader(source))
    assert len(rows) == 32
    assert set(row["delayed"] for row in rows) <= {"0", "1"}
    folder = tmp_path / "manufacturing/cases/rain_calendar"
    bundle = {
        file.name: file.read_text() for file in folder.iterdir() if file.name != "dataset.json"
    }
    parsed = validate_domain("manufacturing", parse_csv_bundle(bundle))
    original = validate_domain("manufacturing", json.loads((folder / "dataset.json").read_text()))
    assert parsed == original
    assert all("actual_duration" not in task and "delayed" not in task for task in parsed["tasks"])
