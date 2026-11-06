"""Export explicitly synthetic labelled history and unlabelled planning cases."""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
from typing import Any

from nexus_api.operations.synthetic import (
    FEATURE_NAMES,
    OUTCOME_FORMULA,
    generate_cases,
    generate_history,
)


def _json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _csv(rows: list[dict[str, Any]], fields: list[str]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                key: json.dumps(value, separators=(",", ":"), allow_nan=False)
                if isinstance(value, (dict, list))
                else value
                for key, value in row.items()
            }
        )
    return stream.getvalue().encode("utf-8")


def export_data(output: Path, projects: int = 80, seed: int = 42) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    files: dict[str, dict[str, Any]] = {}

    def write(relative: str, data: bytes, purpose: str) -> None:
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files[relative] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "kind": "synthetic",
            "purpose": purpose,
        }

    for domain in ("construction", "manufacturing"):
        for shifted in (False, True):
            history = generate_history(domain, projects=projects, seed=seed, shifted=shifted)
            label = "history_ood" if shifted else "history"
            write(f"{domain}/{label}.json", _json(history), "labelled completed history")
            rows = [
                {
                    **{key: row[key] for key in ("id", "project_id", "domain")},
                    **row["features"],
                    "actual_duration": row["actual_duration"],
                    "delayed": int(row["delayed"]),
                }
                for row in history["rows"]
            ]
            fields = ["id", "project_id", "domain", *FEATURE_NAMES, "actual_duration", "delayed"]
            write(f"{domain}/{label}.csv", _csv(rows, fields), "labelled completed history")
        cases = generate_cases(domain, seed=seed)
        write(f"{domain}/cases.json", _json(cases), "unlabelled future planning cases")
        for case in cases:
            prefix = f"{domain}/cases/{case['name']}"
            payload = case["payload"]
            write(f"{prefix}/dataset.json", _json(payload), "unlabelled future planning case")
            settings = {
                key: value
                for key, value in payload.items()
                if key not in ("projects", "resources", "materials", "tasks")
            }
            write(f"{prefix}/settings.json", _json(settings), "CSV planning bundle settings")
            for table in ("projects", "resources", "materials", "tasks"):
                rows = payload[table]
                fields = list(dict.fromkeys(key for row in rows for key in row))
                write(f"{prefix}/{table}.csv", _csv(rows, fields), "CSV planning bundle table")
    manifest = {
        "schema_version": 1,
        "kind": "synthetic",
        "seed": seed,
        "projects_per_domain_per_distribution": projects,
        "activities_per_project": 8,
        "features": list(FEATURE_NAMES),
        "outcome_formula": OUTCOME_FORMULA,
        "assumptions": [
            "Generated evidence only; no real project or credential data is used.",
            "Completed history labels come from a latent model independent of the scheduler.",
            "Correlated activities must be split by project_id, never randomly by activity row.",
            "Use a deterministic project_id hash for train/validation/test partitions.",
            "OOD history has new project IDs and shifted input distributions.",
            "Planning cases contain no outcome labels; expected_feasible is a test oracle.",
            "Performance on generated outcomes is not evidence of real-world forecast accuracy.",
        ],
        "files": files,
    }
    (output / "manifest.json").write_bytes(_json(manifest))
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/operations/synthetic"))
    parser.add_argument("--projects", type=int, default=80)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    manifest = export_data(args.output, projects=args.projects, seed=args.seed)
    print(
        json.dumps(
            {
                "kind": "synthetic",
                "files": len(manifest["files"]),
                "output": str(args.output.resolve()),
                "seed": args.seed,
            }
        )
    )


if __name__ == "__main__":
    main()
