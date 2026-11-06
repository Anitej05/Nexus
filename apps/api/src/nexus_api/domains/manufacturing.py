from typing import Any

NAME = "Manufacturing"
DESCRIPTION = "Work orders sharing machine capacity and component inventory."


def sample_payload() -> dict[str, Any]:
    return {
        "name": "Synthetic production example",
        "start_date": "2026-01-05",
        "horizon_days": 90,
        "working_days": [0, 1, 2, 3, 4],
        "weather_delays": [],
        "budget": 10000,
        "projects": [{"id": "batch", "name": "Batch A"}],
        "resources": [{"id": "machine", "name": "Machine", "capacity": 1, "unit": "machine"}],
        "materials": [
            {
                "id": "parts",
                "name": "Parts",
                "unit": "piece",
                "stock": 20,
                "supplier_lead_days": 3,
                "deliveries": [],
            }
        ],
        "tasks": [
            {
                "id": "cut",
                "project_id": "batch",
                "name": "Cut",
                "dependencies": [],
                "quantity": 10,
                "remaining_quantity": 10,
                "unit": "piece",
                "productivity": 5,
                "minimum_duration": 1,
                "resources": {"machine": 1},
                "materials": {"parts": 10},
                "cost": 1000,
                "uncertainty": 0.1,
            },
            {
                "id": "finish",
                "project_id": "batch",
                "name": "Finish",
                "dependencies": ["cut"],
                "quantity": 10,
                "remaining_quantity": 10,
                "unit": "piece",
                "productivity": 5,
                "minimum_duration": 1,
                "resources": {"machine": 1},
                "materials": {},
                "cost": 1000,
                "uncertainty": 0.1,
            },
        ],
    }
