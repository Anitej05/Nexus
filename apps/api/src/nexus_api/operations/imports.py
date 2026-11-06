"""Strict, bounded CSV bundle decoding; domain validation remains the next step."""

import csv
import io
import json
import math
from typing import Any

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_ROWS = 200
SCHEMAS = {
    "projects": ({"id"}, {"id", "name", "deadline"}),
    "resources": ({"id", "capacity", "unit"}, {"id", "name", "capacity", "unit"}),
    "materials": (
        {"id", "unit"},
        {"id", "name", "unit", "stock", "supplier_lead_days", "deliveries"},
    ),
    "tasks": (
        {"id", "project_id", "quantity", "unit", "productivity"},
        {
            "id",
            "project_id",
            "name",
            "dependencies",
            "quantity",
            "remaining_quantity",
            "unit",
            "productivity",
            "minimum_duration",
            "resources",
            "materials",
            "cost",
            "uncertainty",
        },
    ),
}
NUMBERS = {
    "capacity",
    "stock",
    "supplier_lead_days",
    "quantity",
    "remaining_quantity",
    "productivity",
    "minimum_duration",
    "cost",
    "uncertainty",
}
NESTED = {"deliveries": list, "dependencies": list, "resources": dict, "materials": dict}
SETTINGS = {"name", "start_date", "horizon_days", "working_days", "weather_delays", "budget"}


def _reject_constant(value: str) -> Any:
    raise ValueError(f"Nonfinite JSON number: {value}")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _json(value: str) -> Any:
    try:
        parsed = json.loads(value, parse_constant=_reject_constant, object_pairs_hook=_object)
        # Overflow exponents (1e999) also need rejection, including nested cells.
        json.dumps(parsed, allow_nan=False)
        return parsed
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Malformed or nonfinite JSON") from exc


def parse_csv_bundle(files: dict[str, str]) -> dict[str, Any]:
    expected = {"settings.json", *(f"{table}.csv" for table in SCHEMAS)}
    if not isinstance(files, dict) or set(files) != expected:
        raise ValueError("Bundle requires settings.json and projects/resources/materials/tasks.csv")
    total = 0
    for name, content in files.items():
        if not isinstance(content, str):
            raise ValueError(f"{name} must be UTF-8 text")
        try:
            size = len(content.encode("utf-8"))
        except UnicodeError as exc:
            raise ValueError(f"{name} must be valid UTF-8") from exc
        total += size
        if size > MAX_FILE_BYTES or total > MAX_BUNDLE_BYTES:
            raise ValueError("CSV bundle exceeds supported size")
    settings = _json(files["settings.json"])
    if not isinstance(settings, dict) or set(settings) - SETTINGS or "start_date" not in settings:
        raise ValueError("Invalid settings fields")
    result = dict(settings)
    for table, (required, allowed) in SCHEMAS.items():
        try:
            reader = csv.reader(io.StringIO(files[f"{table}.csv"].lstrip("\ufeff")), strict=True)
            headers = next(reader, [])
            if (
                len(set(headers)) != len(headers)
                or set(headers) - allowed
                or not required <= set(headers)
            ):
                raise ValueError(f"Invalid or duplicate {table} columns")
            rows: list[dict[str, Any]] = []
            for cells in reader:
                if len(rows) >= MAX_ROWS:
                    raise ValueError(f"{table} exceeds {MAX_ROWS} rows")
                if len(cells) != len(headers):
                    raise ValueError(f"{table} row has incorrect column count")
                row: dict[str, Any] = {}
                for key, cell in zip(headers, cells, strict=True):
                    cell = cell.strip()
                    if not cell:
                        if key in required:
                            raise ValueError(f"{table}.{key} is required")
                        continue
                    if key in NUMBERS:
                        value = float(cell)
                        if not math.isfinite(value):
                            raise ValueError(f"{table}.{key} must be finite")
                        row[key] = value
                    elif key in NESTED:
                        parsed = _json(cell)
                        if not isinstance(parsed, NESTED[key]):
                            raise ValueError(f"Invalid {table}.{key} JSON type")
                        row[key] = parsed
                    else:
                        row[key] = cell
                rows.append(row)
            result[table] = rows
        except (csv.Error, OverflowError) as exc:
            raise ValueError(f"Malformed {table} CSV") from exc
    return result
