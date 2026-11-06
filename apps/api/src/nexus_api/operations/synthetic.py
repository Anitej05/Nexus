"""Reproducible synthetic evidence for exercising pipelines, not empirical validation.

Historical outcomes use an independent latent project-effect model; they are never
obtained by running the planning scheduler. Features describe pre-outcome inputs.
"""

import copy
import random
from datetime import date, timedelta
from typing import Any

FEATURE_NAMES = (
    "planned_duration",
    "quantity",
    "productivity",
    "resource_capacity",
    "material_coverage",
    "supplier_delay_days",
    "weather_risk",
    "complexity",
)
OUTCOME_FORMULA = (
    "actual=max(0.1, planned*(0.65+0.10*complexity+0.40*weather_risk"
    "+0.35*max(0,1-material_coverage)+0.18/resource_capacity"
    "+project_effect+activity_noise)"
    "+0.5*supplier_delay_days*max(0,1-material_coverage)); "
    "project_effect~Normal(0,0.14), activity_noise~Normal(0,0.12); "
    "actual rounded to 4 decimals; delayed=actual>planned*1.15"
)


def _validate(domain: str, seed: int) -> None:
    if domain not in ("construction", "manufacturing"):
        raise ValueError("Unknown synthetic domain")
    if type(seed) is not int:
        raise ValueError("Seed must be an integer")


def generate_history(
    domain: str, projects: int = 80, seed: int = 42, shifted: bool = False
) -> dict[str, Any]:
    _validate(domain, seed)
    if type(projects) is not int or not 1 <= projects <= 10000:
        raise ValueError("Projects must be between 1 and 10000")
    if type(shifted) is not bool:
        raise ValueError("Shifted must be a boolean")
    namespace = f"{domain}-s{seed}-" + ("ood" if shifted else "history")
    rng = random.Random(f"{namespace}-v1")  # noqa: S311 - reproducible synthetic data
    rows = []
    for project_index in range(projects):
        project_id = f"{namespace}-p{project_index:05d}"
        project_effect = rng.gauss(0, 0.14)
        weather_base = rng.uniform(0.3, 0.85) if shifted else rng.uniform(0, 0.55)
        for activity_index in range(8):
            productivity = round(
                rng.uniform(2, 9) if domain == "construction" else rng.uniform(8, 35), 4
            )
            quantity = round(productivity * rng.uniform(1, 12 if shifted else 8), 4)
            planned = quantity / productivity
            capacity = rng.randint(1, 3 if shifted else 4)
            coverage = round(rng.uniform(0.35, 1.15) if shifted else rng.uniform(0.6, 1.5), 4)
            supplier_delay = rng.randint(4, 24) if shifted else rng.randint(0, 12)
            weather = round(min(0.95, max(0, weather_base + rng.uniform(-0.1, 0.1))), 4)
            complexity = rng.randint(3, 7) if shifted else rng.randint(1, 5)
            noise = rng.gauss(0, 0.12)
            shortage = max(0, 1 - coverage)
            actual = round(
                max(
                    0.1,
                    planned
                    * (
                        0.65
                        + 0.10 * complexity
                        + 0.40 * weather
                        + 0.35 * shortage
                        + 0.18 / capacity
                        + project_effect
                        + noise
                    )
                    + 0.5 * supplier_delay * shortage,
                ),
                4,
            )
            features = dict(
                zip(
                    FEATURE_NAMES,
                    (
                        planned,
                        quantity,
                        productivity,
                        capacity,
                        coverage,
                        supplier_delay,
                        weather,
                        complexity,
                    ),
                    strict=True,
                )
            )
            rows.append(
                {
                    "id": f"{project_id}-a{activity_index:02d}",
                    "project_id": project_id,
                    "domain": domain,
                    "features": features,
                    "actual_duration": actual,
                    "delayed": actual > planned * 1.15,
                }
            )
    return {
        "schema_version": 1,
        "kind": "synthetic",
        "domain": domain,
        "seed": seed,
        "shifted": shifted,
        "outcome_formula": OUTCOME_FORMULA,
        "assumptions": [
            "Eight labelled completed activities per independent synthetic project.",
            "Within-project outcomes correlate through a latent project effect.",
            "Features precede outcomes; planned duration equals quantity/productivity.",
            "OOD projects have disjoint IDs and shifted feature distributions.",
            "Synthetic model performance does not establish real-world predictive validity.",
        ],
        "rows": rows,
    }


def generate_cases(domain: str, seed: int = 42) -> list[dict[str, Any]]:
    _validate(domain, seed)
    rng = random.Random(f"{domain}-{seed}-cases-v1")  # noqa: S311
    prefix = f"{domain}-s{seed}"
    resource_ids = [f"{prefix}-shared", f"{prefix}-equipment"]
    material_ids = [f"{prefix}-bulk", f"{prefix}-finish"]
    stages = (
        ["survey", "excavate", "foundation", "frame", "services", "enclose", "finish", "inspect"]
        if domain == "construction"
        else ["receive", "prepare", "cut", "form", "assemble", "coat", "test", "pack"]
    )
    payload: dict[str, Any] = {
        "name": f"Synthetic {domain} constraint evaluation",
        "start_date": "2026-01-05",
        "horizon_days": 180,
        "working_days": [0, 1, 2, 3, 4],
        "weather_delays": [],
        "projects": [],
        "resources": [
            {
                "id": resource_ids[0],
                "name": "Shared crew" if domain == "construction" else "Shared production machine",
                "capacity": 2,
                "unit": "capacity_unit",
            },
            {
                "id": resource_ids[1],
                "name": "Specialist equipment",
                "capacity": 1,
                "unit": "equipment_unit",
            },
        ],
        "materials": [
            {
                "id": mid,
                "name": "Bulk input" if i == 0 else "Finishing input",
                "unit": "unit",
                "stock": 3,
                "supplier_lead_days": 7 + i,
                "deliveries": [
                    {"id": f"{prefix}-delivery{i}", "quantity": 20, "expected_day": 7 + i * 3}
                ],
            }
            for i, mid in enumerate(material_ids)
        ],
        "tasks": [],
    }
    for project_index in range(3):
        pid = f"{prefix}-project{project_index}"
        payload["projects"].append(
            {"id": pid, "name": f"Synthetic project {project_index + 1}", "deadline": "2026-05-01"}
        )
        previous = None
        for stage_index, stage in enumerate(stages):
            tid = f"{prefix}-task{project_index}-{stage}"
            productivity = round(rng.uniform(2, 6), 3)
            quantity = round(productivity * rng.uniform(1, 3), 3)
            remaining = 0 if stage_index == 0 else round(quantity * rng.uniform(0.5, 1), 3)
            demands = {resource_ids[0]: 1}
            if stage_index % 3 == 1:
                demands[resource_ids[1]] = 1
            payload["tasks"].append(
                {
                    "id": tid,
                    "project_id": pid,
                    "name": f"Project {project_index + 1} {stage}",
                    "dependencies": [previous] if previous else [],
                    "quantity": quantity,
                    "remaining_quantity": remaining,
                    "unit": "work_unit",
                    "productivity": productivity,
                    "minimum_duration": 1,
                    "resources": demands,
                    "materials": {material_ids[stage_index % 2]: 1},
                    "cost": rng.randint(500, 4000),
                    "uncertainty": round(rng.uniform(0.05, 0.3), 3),
                }
            )
            previous = tid
    payload["budget"] = sum(task["cost"] for task in payload["tasks"]) * 1.2
    cases = []
    for case_name in (
        "nominal",
        "shortage",
        "zero_capacity",
        "budget_overrun",
        "rain_calendar",
        "shared_resources",
        "complete_progress",
    ):
        case = copy.deepcopy(payload)
        feasible = case_name not in ("shortage", "zero_capacity", "budget_overrun")
        if case_name == "shortage":
            for material in case["materials"]:
                material["stock"], material["deliveries"] = 0, []
        elif case_name == "zero_capacity":
            case["resources"][0]["capacity"] = 0
        elif case_name == "budget_overrun":
            case["budget"] = 1
        elif case_name == "rain_calendar":
            start = date.fromisoformat(case["start_date"])
            case["weather_delays"] = [
                (start + timedelta(days=d)).isoformat() for d in (1, 2, 7, 8, 9, 15, 16)
            ]
        elif case_name == "shared_resources":
            case["resources"][0]["capacity"] = 1
        elif case_name == "complete_progress":
            for task in case["tasks"]:
                task["remaining_quantity"] = 0
            for material in case["materials"]:
                material["stock"], material["deliveries"] = 0, []
        cases.append(
            {"name": case_name, "kind": "synthetic", "payload": case, "expected_feasible": feasible}
        )
    return cases
