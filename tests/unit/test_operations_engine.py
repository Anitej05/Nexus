import copy

import pytest
from nexus_api.operations.registry import analyze_domain, apply_domain_changes, sample_payload


def test_shared_capacity_and_seeded_forecast():
    payload = sample_payload("construction")
    result = analyze_domain("construction", payload, seed=9, samples=20)
    assert not result["infeasible"]
    assert result == analyze_domain("construction", payload, seed=9, samples=20)
    tasks = result["activities"]
    assert len(tasks) >= 4
    assert result["forecast"]["p50_date"] <= result["forecast"]["p80_date"]


def test_invalid_cycle_and_impossible_capacity():
    payload = sample_payload("construction")
    payload["tasks"][0]["dependencies"] = [payload["tasks"][1]["id"]]
    with pytest.raises(ValueError, match="cycle"):
        analyze_domain("construction", payload)
    payload = sample_payload("construction")
    payload["resources"][0]["capacity"] = 0
    result = analyze_domain("construction", payload, samples=2)
    assert result["infeasible"]
    assert result["forecast"]["p50_date"] is None


def test_branch_changes_and_manufacturing():
    payload = sample_payload("manufacturing")
    original = copy.deepcopy(payload)
    changed = apply_domain_changes(
        "manufacturing", payload, [{"path": "/resources/machine/capacity", "value": 2}]
    )
    assert payload == original
    assert changed["resources"][0]["capacity"] == 2
    assert not analyze_domain("manufacturing", changed, samples=2)["infeasible"]


def test_material_shortage_and_budget_are_infeasible():
    payload = sample_payload("construction")
    payload["materials"][0]["stock"] = 0
    payload["materials"][0]["deliveries"] = []
    result = analyze_domain("construction", payload, samples=2)
    assert result["infeasible"] and result["metrics"]["finish_date"] is None
    payload = sample_payload("construction")
    payload["budget"] = 1
    assert "budget" in analyze_domain("construction", payload, samples=2)["infeasible"][0]


def test_rejects_nonfinite_and_unknown_dependencies():
    payload = sample_payload("construction")
    payload["tasks"][0]["productivity"] = float("nan")
    with pytest.raises(ValueError):
        analyze_domain("construction", payload)
    payload = sample_payload("construction")
    payload["tasks"][0]["dependencies"] = ["missing"]
    with pytest.raises(ValueError):
        analyze_domain("construction", payload)


def test_critical_impact_and_alternative_are_calculated():
    result = analyze_domain("construction", sample_payload("construction"), samples=2)
    assert any(a["dependency_impact_days"] > 0 for a in result["activities"])
    assert result["alternatives"]
    assert all("finish_date" in alternative for alternative in result["alternatives"])


def test_completed_task_uses_no_resources_or_materials():
    payload = sample_payload("manufacturing")
    payload["tasks"][0]["remaining_quantity"] = 0
    payload["resources"][0]["capacity"] = 0
    payload["tasks"][1]["resources"] = {}
    payload["materials"][0]["stock"] = 0
    result = analyze_domain("manufacturing", payload, samples=4)
    assert result["infeasible"] == []
    assert result["activities"][0]["duration_working_days"] == 0


def test_uncertainty_preserves_minimum_duration():
    payload = sample_payload("manufacturing")
    payload["tasks"] = [payload["tasks"][0]]
    payload["tasks"][0]["minimum_duration"] = 10
    payload["tasks"][0]["uncertainty"] = 1
    import random

    from nexus_api.operations.models import _schedule

    for seed in range(30):
        result, errors = _schedule(payload, random.Random(seed))  # noqa: S311
        assert not errors
        assert result[0]["duration_working_days"] >= 10


def test_rejects_invalid_calendar_and_boolean_days():
    payload = sample_payload("manufacturing")
    payload["working_days"] = [True]
    with pytest.raises(ValueError):
        analyze_domain("manufacturing", payload)
    payload = sample_payload("manufacturing")
    payload["start_date"] = "9999-12-31"
    with pytest.raises(ValueError):
        analyze_domain("manufacturing", payload)


def test_construction_sample_has_two_realistic_project_chains():
    payload = sample_payload("construction")
    assert len(payload["tasks"]) >= 12
    assert len({t["project_id"] for t in payload["tasks"]}) == 2
    assert any("procure" in t["id"] for t in payload["tasks"])
    assert not analyze_domain("construction", payload, samples=3)["infeasible"]


def test_rejects_derived_overflow_and_noncanonical_dates():
    payload = sample_payload("manufacturing")
    payload["tasks"][0]["quantity"] = 1e308
    payload["tasks"][0]["remaining_quantity"] = 1e308
    payload["tasks"][0]["productivity"] = 1e-308
    with pytest.raises(ValueError):
        analyze_domain("manufacturing", payload)
    payload = sample_payload("manufacturing")
    payload["start_date"] = "20260105"
    with pytest.raises(ValueError):
        analyze_domain("manufacturing", payload)


def test_rejects_duplicate_ids_across_entities_and_overflow_supply():
    from nexus_api.operations.registry import validate_domain

    payload = sample_payload("manufacturing")
    payload["resources"][0]["id"] = payload["tasks"][0]["id"]
    with pytest.raises(ValueError, match="unique"):
        validate_domain("manufacturing", payload)
    payload = sample_payload("manufacturing")
    payload["materials"][0]["stock"] = 1e308
    payload["materials"][0]["deliveries"] = [{"id": "d", "quantity": 1e308, "expected_day": 1}]
    with pytest.raises(ValueError, match="supply"):
        validate_domain("manufacturing", payload)


def test_rejects_empty_or_oversized_changes():
    payload = sample_payload("manufacturing")
    with pytest.raises(ValueError):
        apply_domain_changes("manufacturing", payload, [])
    with pytest.raises(ValueError):
        apply_domain_changes("manufacturing", payload, [{"path": "/budget", "value": 1}] * 101)


def test_rejects_huge_integer_cleanly():
    from nexus_api.operations.registry import validate_domain

    payload = sample_payload("manufacturing")
    payload["tasks"][0]["quantity"] = 10**1000
    with pytest.raises(ValueError):
        validate_domain("manufacturing", payload)


def test_graph_connects_shared_resources_across_projects():
    result = analyze_domain("construction", sample_payload("construction"), samples=2)
    graph = result["graph"]
    nodes = {node["id"]: node for node in graph["nodes"]}
    assert nodes["crew"]["type"] == "resource"
    assert nodes["steel"]["type"] == "material"
    crew_tasks = [
        edge["source"]
        for edge in graph["edges"]
        if edge["type"] == "requires_resource" and edge["target"] == "crew"
    ]
    assert len({nodes[task]["project_id"] for task in crew_tasks}) == 2
    assert all(edge["source"] in nodes and edge["target"] in nodes for edge in graph["edges"])


def test_graph_includes_supply_and_capacity_evidence():
    result = analyze_domain("construction", sample_payload("construction"), samples=2)
    nodes = {node["id"]: node for node in result["graph"]["nodes"]}
    assert nodes["steel"]["stock"] == 3
    assert nodes["crew"]["capacity"] == 1
    assert nodes["@delivery/steel/steel-1"]["expected_day"] == 8
