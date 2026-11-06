from typing import Any

NAME = "Construction"
DESCRIPTION = "Shared crews, equipment and materials across construction projects."


def _base_payload() -> dict[str, Any]:
    return {
        "name": "Synthetic two-project example",
        "start_date": "2026-01-05",
        "horizon_days": 120,
        "working_days": [0, 1, 2, 3, 4],
        "weather_delays": ["2026-01-12"],
        "budget": 90000,
        "projects": [
            {"id": "north", "name": "North site", "deadline": "2026-03-01"},
            {"id": "south", "name": "South site", "deadline": "2026-03-15"},
        ],
        "resources": [
            {"id": "crew", "name": "Shared crew", "capacity": 1, "unit": "crew"},
            {"id": "crane", "name": "Crane", "capacity": 1, "unit": "crane"},
        ],
        "materials": [
            {
                "id": "steel",
                "name": "Steel",
                "unit": "tonne",
                "stock": 3,
                "supplier_lead_days": 5,
                "deliveries": [{"id": "steel-1", "quantity": 5, "expected_day": 8}],
            }
        ],
        "tasks": [
            {
                "id": "n-foundation",
                "project_id": "north",
                "name": "North foundation",
                "dependencies": [],
                "quantity": 10,
                "remaining_quantity": 8,
                "unit": "m3",
                "productivity": 2,
                "minimum_duration": 1,
                "resources": {"crew": 1},
                "materials": {"steel": 2},
                "cost": 20000,
                "uncertainty": 0.2,
            },
            {
                "id": "n-frame",
                "project_id": "north",
                "name": "North frame",
                "dependencies": ["n-foundation"],
                "quantity": 6,
                "remaining_quantity": 6,
                "unit": "tonne",
                "productivity": 2,
                "minimum_duration": 1,
                "resources": {"crew": 1, "crane": 1},
                "materials": {"steel": 2},
                "cost": 25000,
                "uncertainty": 0.2,
            },
            {
                "id": "s-foundation",
                "project_id": "south",
                "name": "South foundation",
                "dependencies": [],
                "quantity": 8,
                "remaining_quantity": 8,
                "unit": "m3",
                "productivity": 2,
                "minimum_duration": 1,
                "resources": {"crew": 1},
                "materials": {"steel": 1},
                "cost": 18000,
                "uncertainty": 0.2,
            },
            {
                "id": "s-frame",
                "project_id": "south",
                "name": "South frame",
                "dependencies": ["s-foundation"],
                "quantity": 6,
                "remaining_quantity": 6,
                "unit": "tonne",
                "productivity": 2,
                "minimum_duration": 1,
                "resources": {"crew": 1, "crane": 1},
                "materials": {"steel": 3},
                "cost": 22000,
                "uncertainty": 0.2,
            },
        ],
    }


def sample_payload() -> dict[str, Any]:
    payload = _base_payload()
    payload["budget"] = 160000
    payload["horizon_days"] = 180
    payload["weather_delays"] += ["2026-01-26", "2026-02-09"]
    for prefix, project in (("n", "north"), ("s", "south")):
        procurement = {
            "id": f"{prefix}-procure",
            "project_id": project,
            "name": f"{project.title()} procurement approval",
            "dependencies": [],
            "quantity": 1,
            "remaining_quantity": 1,
            "unit": "approval",
            "productivity": 1,
            "minimum_duration": 2,
            "resources": {},
            "materials": {},
            "cost": 1000,
            "uncertainty": 0.1,
        }
        frame = next(t for t in payload["tasks"] if t["id"] == f"{prefix}-frame")
        frame["dependencies"].append(procurement["id"])
        payload["tasks"].append(procurement)
        previous = frame["id"]
        for stage, label, days, cost in (
            ("envelope", "Building envelope", 4, 8000),
            ("services", "Building services", 4, 7000),
            ("finish", "Interior finish", 3, 6000),
        ):
            task = {
                "id": f"{prefix}-{stage}",
                "project_id": project,
                "name": f"{project.title()} {label.lower()}",
                "dependencies": [previous],
                "quantity": days,
                "remaining_quantity": days,
                "unit": "workday",
                "productivity": 1,
                "minimum_duration": 1,
                "resources": {"crew": 1},
                "materials": {},
                "cost": cost,
                "uncertainty": 0.2,
            }
            payload["tasks"].append(task)
            previous = task["id"]
    return payload
