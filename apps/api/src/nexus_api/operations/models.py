"""Generic operational scheduling engine."""

from __future__ import annotations

import copy
import math
import random
from datetime import date, timedelta
from typing import Any


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    p = copy.deepcopy(payload)
    if not isinstance(p, dict):
        raise ValueError("payload must be an object")
    try:

        def iso_date(value: Any) -> date:
            parsed = date.fromisoformat(value)
            if value != parsed.isoformat():
                raise ValueError("dates must use YYYY-MM-DD")
            return parsed

        start_date = iso_date(p["start_date"])
        horizon = p.get("horizon_days", 365)
        if isinstance(horizon, bool) or not isinstance(horizon, int) or not 1 <= horizon <= 730:
            raise ValueError("horizon_days must be between 1 and 730")
        p["horizon_days"] = horizon
        if (date.max - start_date).days < horizon:
            raise ValueError("horizon extends beyond supported dates")
        days = p.get("working_days", [0, 1, 2, 3, 4])
        if not days or any(
            isinstance(x, bool) or not isinstance(x, int) or x not in range(7) for x in days
        ):
            raise ValueError("working_days must contain weekdays 0 through 6")
        p["working_days"] = days
        for d in p.get("weather_delays", []):
            iso_date(d)

        def number(value: Any, label: str, positive: bool = False) -> float:
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
                or (positive and value == 0)
            ):
                raise ValueError(
                    f"{label} must be a finite {'positive' if positive else 'nonnegative'} number"
                )
            return float(value)

        if p.get("budget") is not None:
            number(p["budget"], "budget")
        tables = {}
        for key in ("projects", "resources", "materials", "tasks"):
            entries = p.get(key, [])
            if not isinstance(entries, list) or (key == "tasks" and not 1 <= len(entries) <= 200):
                raise ValueError(f"invalid {key} list")
            ids = [x["id"] for x in entries]
            if any(not isinstance(x, str) or not x or "/" in x for x in ids) or len(
                set(ids)
            ) != len(ids):
                raise ValueError(f"{key} IDs must be unique nonempty strings without slashes")
            tables[key] = {x["id"]: x for x in entries}
        all_ids = [item_id for table in tables.values() for item_id in table]
        if len(all_ids) != len(set(all_ids)):
            raise ValueError("entity IDs must be unique across all tables")
        for project in p["projects"]:
            if project.get("deadline"):
                iso_date(project["deadline"])
        for resource in p["resources"]:
            number(resource["capacity"], "capacity")
            if not resource.get("unit"):
                raise ValueError("resource unit required")
        for material in p["materials"]:
            if not material.get("unit"):
                raise ValueError("material unit required")
            number(material.get("stock", 0), "stock")
            number(material.get("supplier_lead_days", 0), "supplier_lead_days")
            delivery_ids: set[str] = set()
            supply = number(material.get("stock", 0), "stock")
            for delivery in material.get("deliveries", []):
                if not delivery.get("id") or delivery["id"] in delivery_ids:
                    raise ValueError("delivery IDs must be unique")
                delivery_ids.add(delivery["id"])
                supply += number(delivery["quantity"], "delivery quantity")
                if not math.isfinite(supply):
                    raise ValueError("material supply exceeds numeric bounds")
                if (
                    isinstance(delivery["expected_day"], bool)
                    or not isinstance(delivery["expected_day"], int)
                    or delivery["expected_day"] < 0
                ):
                    raise ValueError("expected_day must be a nonnegative integer")
        for task in p["tasks"]:
            if task["project_id"] not in tables["projects"]:
                raise ValueError("unknown project")
            if not task.get("unit"):
                raise ValueError("task unit required")
            quantity = number(task["quantity"], "quantity")
            remaining = number(task.get("remaining_quantity", quantity), "remaining_quantity")
            if remaining > quantity:
                raise ValueError("remaining_quantity exceeds quantity")
            productivity = number(task["productivity"], "productivity", True)
            if not math.isfinite(remaining / productivity) or remaining / productivity > 1e9:
                raise ValueError("derived task duration exceeds numeric bounds")
            number(task.get("minimum_duration", 0), "minimum_duration")
            number(task.get("cost", 0), "cost")
            uncertainty = number(task.get("uncertainty", 0), "uncertainty")
            if uncertainty > 1:
                raise ValueError("uncertainty must be at most 1")
            for dep in task.get("dependencies", []):
                if dep not in tables["tasks"]:
                    raise ValueError(f"unknown dependency {dep}")
            for kind in ("resources", "materials"):
                for ref, demand in task.get(kind, {}).items():
                    if ref not in tables[kind]:
                        raise ValueError(f"unknown {kind} ID {ref}")
                    number(demand, f"{kind} demand")
        if not math.isfinite(sum(t.get("cost", 0) for t in p["tasks"])):
            raise ValueError("total cost exceeds numeric bounds")
        seen, visiting = set(), set()

        def visit(tid: str) -> None:
            if tid in visiting:
                raise ValueError("dependency cycle")
            if tid in seen:
                return
            visiting.add(tid)
            for dep in tables["tasks"][tid].get("dependencies", []):
                visit(dep)
            visiting.remove(tid)
            seen.add(tid)

        for tid in tables["tasks"]:
            visit(tid)
    except (KeyError, TypeError, AttributeError, OverflowError) as exc:
        raise ValueError(f"invalid payload: {exc}") from exc
    return p


def _schedule(
    p: dict[str, Any], rng: random.Random | None = None
) -> tuple[list[dict[str, Any]], list[str]]:
    start = date.fromisoformat(p["start_date"])
    resources = {r["id"]: r["capacity"] for r in p["resources"]}
    stock = {m["id"]: m.get("stock", 0) for m in p["materials"]}
    tasks = {t["id"]: t for t in p["tasks"]}
    errors = []
    for t in p["tasks"]:
        if t.get("remaining_quantity", t["quantity"]) == 0:
            continue
        for rid, demand in t.get("resources", {}).items():
            if demand > resources[rid]:
                errors.append(
                    f"Task {t['id']} requires {demand} {rid}; capacity is {resources[rid]}"
                )
    cost = sum(t.get("cost", 0) for t in p["tasks"])
    if p.get("budget") is not None and cost > p["budget"]:
        errors.append(f"Planned cost {cost:g} exceeds budget {p['budget']:g}")
    if errors:
        return [], errors
    done: dict[str, int] = {}
    active: dict[str, int] = {}
    records: dict[str, dict[str, Any]] = {}
    delays = set(p.get("weather_delays", []))
    delivered = set()
    for day in range(p["horizon_days"]):
        current = start + timedelta(days=day)
        for m in p["materials"]:
            for d in m.get("deliveries", []):
                key = (m["id"], d["id"])
                if key not in delivered and day >= d["expected_day"]:
                    stock[m["id"]] += d["quantity"]
                    delivered.add(key)
        if current.weekday() not in p["working_days"] or current.isoformat() in delays:
            continue
        available = dict(resources)
        for tid in active:
            for rid, amount in tasks[tid].get("resources", {}).items():
                available[rid] -= amount
        for tid, t in tasks.items():
            if (
                tid in done
                or tid in active
                or any(dep not in done for dep in t.get("dependencies", []))
            ):
                continue
            remaining = t.get("remaining_quantity", t["quantity"])
            if remaining and any(
                demand > available[rid] for rid, demand in t.get("resources", {}).items()
            ):
                continue
            if remaining and any(
                demand > stock[mid] for mid, demand in t.get("materials", {}).items()
            ):
                continue
            if remaining:
                for rid, amount in t.get("resources", {}).items():
                    available[rid] -= amount
                for mid, amount in t.get("materials", {}).items():
                    stock[mid] -= amount
            duration = (
                max(t.get("minimum_duration", 0), remaining / t["productivity"]) if remaining else 0
            )
            if rng and duration:
                duration = max(
                    t.get("minimum_duration", 0),
                    duration
                    * rng.uniform(1 - t.get("uncertainty", 0), 1 + t.get("uncertainty", 0)),
                )
            duration = max(1, math.ceil(duration)) if remaining else 0
            records[tid] = {
                "id": tid,
                "project_id": t["project_id"],
                "name": t.get("name", tid),
                "start_date": current.isoformat(),
                "duration_working_days": duration,
                "dependencies": t.get("dependencies", []),
            }
            if duration == 0:
                done[tid] = day
                records[tid]["finish_date"] = current.isoformat()
            else:
                active[tid] = duration
        for tid in list(active):
            active[tid] -= 1
            if active[tid] == 0:
                done[tid] = day
                records[tid]["finish_date"] = current.isoformat()
                del active[tid]
        if len(done) == len(tasks):
            return list(records.values()), []
    unfinished = [tid for tid in tasks if tid not in done]
    return list(records.values()), [
        f"Horizon exhausted; unfinished tasks: {', '.join(unfinished)}. "
        "Check dependencies, resources and material stock/deliveries."
    ]


def analyze(p: dict[str, Any], seed: int, samples: int, domain: str) -> dict[str, Any]:
    if isinstance(samples, bool) or not isinstance(samples, int) or not 1 <= samples <= 500:
        raise ValueError("samples must be between 1 and 500")
    p = validate(p)
    activities, errors = _schedule(p)
    finish = (
        max((x["finish_date"] for x in activities if "finish_date" in x), default=None)
        if not errors
        else None
    )
    rng = random.Random(seed)  # noqa: S311 - reproducible simulation, not cryptography
    forecasts = []
    failed_samples = 0
    if not errors:
        for _ in range(samples):
            run, issues = _schedule(p, rng)
            if issues:
                failed_samples += 1
            else:
                forecasts.append(max(x["finish_date"] for x in run))
    forecasts.sort()

    def percentile(q: float) -> str | None:
        # Failed samples are beyond the horizon, not silently dropped.
        index = math.ceil(q * samples) - 1
        return forecasts[index] if index < len(forecasts) else None

    projects = []
    for project in p["projects"]:
        dates = [
            a["finish_date"]
            for a in activities
            if a["project_id"] == project["id"] and a.get("finish_date")
        ]
        project_tasks = [t for t in p["tasks"] if t["project_id"] == project["id"]]
        project_finish = max(dates) if len(dates) == len(project_tasks) and dates else None
        projects.append(
            {
                "id": project["id"],
                "name": project.get("name", project["id"]),
                "finish_date": project_finish,
                "deadline": project.get("deadline"),
                "late": bool(
                    project_finish
                    and project.get("deadline")
                    and project_finish > project["deadline"]
                ),
            }
        )
    # Measure the effect of one additional working day on the overall finish.
    if finish:
        for activity in activities:
            altered = copy.deepcopy(p)
            task = next(t for t in altered["tasks"] if t["id"] == activity["id"])
            task["minimum_duration"] = activity["duration_working_days"] + 1
            trial, trial_errors = _schedule(altered)
            trial_finish = max(
                (a["finish_date"] for a in trial if "finish_date" in a), default=None
            )
            if trial_errors or not trial_finish:
                activity["dependency_impact_days"] = None
                activity["critical"] = True
                activity["impact_status"] = "beyond_horizon"
            else:
                activity["dependency_impact_days"] = (
                    date.fromisoformat(trial_finish) - date.fromisoformat(finish)
                ).days
                activity["critical"] = activity["dependency_impact_days"] > 0
                activity["impact_status"] = "measured"
    alternatives = []
    if finish:
        for resource in p["resources"]:
            altered = copy.deepcopy(p)
            next(r for r in altered["resources"] if r["id"] == resource["id"])["capacity"] += 1
            trial, trial_errors = _schedule(altered)
            if not trial_errors:
                trial_finish = max(a["finish_date"] for a in trial)
                alternatives.append(
                    {
                        "description": f"Add one unit of {resource['id']} capacity",
                        "resource_id": resource["id"],
                        "finish_date": trial_finish,
                        "days_saved": (
                            date.fromisoformat(finish) - date.fromisoformat(trial_finish)
                        ).days,
                        "cost_note": "Additional capacity cost is not included; "
                        "evaluate before adoption.",
                    }
                )
    nodes = [
        {
            "id": t["id"],
            "type": "activity",
            "label": t.get("name", t["id"]),
            "project_id": t["project_id"],
            "quantity": t["quantity"],
            "remaining_quantity": t.get("remaining_quantity", t["quantity"]),
            "productivity": t["productivity"],
            "unit": t["unit"],
        }
        for t in p["tasks"]
    ]
    edges = [
        {"source": dep, "target": t["id"], "type": "depends_on"}
        for t in p["tasks"]
        for dep in t.get("dependencies", [])
    ]
    for kind, table in (
        ("project", "projects"),
        ("resource", "resources"),
        ("material", "materials"),
    ):
        for item in p[table]:
            nodes.append(
                {
                    "id": item["id"],
                    "type": kind,
                    "label": item.get("name", item["id"]),
                    **{
                        key: item[key]
                        for key in ("unit", "stock", "capacity", "deadline", "supplier_lead_days")
                        if key in item
                    },
                }
            )
    for task in p["tasks"]:
        edges.append({"source": task["id"], "target": task["project_id"], "type": "belongs_to"})
        for rid, quantity in task.get("resources", {}).items():
            unit = next(r["unit"] for r in p["resources"] if r["id"] == rid)
            edges.append(
                {
                    "source": task["id"],
                    "target": rid,
                    "type": "requires_resource",
                    "quantity": quantity,
                    "unit": unit,
                }
            )
        for mid, quantity in task.get("materials", {}).items():
            unit = next(m["unit"] for m in p["materials"] if m["id"] == mid)
            edges.append(
                {
                    "source": task["id"],
                    "target": mid,
                    "type": "consumes_material",
                    "quantity": quantity,
                    "unit": unit,
                }
            )
    for material in p["materials"]:
        for delivery in material.get("deliveries", []):
            delivery_id = f"@delivery/{material['id']}/{delivery['id']}"
            nodes.append(
                {
                    "id": delivery_id,
                    "type": "delivery",
                    "label": delivery["id"],
                    "expected_day": delivery["expected_day"],
                    "quantity": delivery["quantity"],
                    "unit": material["unit"],
                }
            )
            edges.append(
                {
                    "source": delivery_id,
                    "target": material["id"],
                    "type": "supplies",
                    "quantity": delivery["quantity"],
                    "unit": material["unit"],
                }
            )
    cost = sum(t.get("cost", 0) for t in p["tasks"])
    risks = [{"type": "infeasible", "message": e} for e in errors]
    risks += [
        {"type": "deadline", "message": f"Project {x['id']} finishes after its deadline"}
        for x in projects
        if x["late"]
    ]
    return {
        "domain": domain,
        "graph": {"nodes": nodes, "edges": edges},
        "metrics": {
            "finish_date": finish,
            "task_count": len(p["tasks"]),
            "project_count": len(p["projects"]),
        },
        "projects": projects,
        "activities": activities,
        "schedule": activities,
        "risks": risks,
        "assumptions": [
            "Daily non-preemptive resource allocation in input order; "
            "materials consumed at task start.",
            "Uncertainty uses independent uniform duration multipliers; "
            "percentiles are modelled, not calibrated predictions.",
            "Supplier lead time is informational; expected delivery days drive the schedule.",
        ],
        "infeasible": errors,
        "forecast": {
            "p50_date": percentile(0.5),
            "p80_date": percentile(0.8),
            "samples": samples,
            "seed": seed,
            "failed_samples": failed_samples,
        },
        "cost": {"planned": cost, "budget": p.get("budget")},
        "alternatives": alternatives,
    }
