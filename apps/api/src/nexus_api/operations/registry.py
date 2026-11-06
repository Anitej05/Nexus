"""Domain pack registry."""

from __future__ import annotations

import copy
from typing import Any

from nexus_api.domains import construction, manufacturing
from nexus_api.operations import models

PACKS = {"construction": construction, "manufacturing": manufacturing}


def _pack(domain: str) -> Any:
    if domain not in PACKS:
        raise ValueError(f"unknown domain: {domain}")
    return PACKS[domain]


def domain_catalog() -> list[dict[str, str]]:
    return [
        {"id": key, "name": pack.NAME, "description": pack.DESCRIPTION}
        for key, pack in PACKS.items()
    ]


def sample_payload(domain: str) -> dict[str, Any]:
    return copy.deepcopy(_pack(domain).sample_payload())


def validate_domain(domain: str, payload: dict[str, Any]) -> dict[str, Any]:
    _pack(domain)
    return models.validate(payload)


def analyze_domain(
    domain: str, payload: dict[str, Any], seed: int = 42, samples: int = 100
) -> dict[str, Any]:
    _pack(domain)
    return models.analyze(payload, seed, samples, domain)


def apply_domain_changes(
    domain: str, payload: dict[str, Any], changes: list[dict[str, Any]]
) -> dict[str, Any]:
    if not isinstance(changes, list) or not 1 <= len(changes) <= 100:
        raise ValueError("changes must contain 1 to 100 entries")
    result = validate_domain(domain, payload)
    for change in changes:
        path = change.get("path", "")
        if not isinstance(path, str) or not path.startswith("/") or not path[1:]:
            raise ValueError("invalid change path")
        parts = path[1:].split("/")
        target: Any = result
        for part in parts[:-1]:
            if isinstance(target, list):
                target = next(
                    (x for x in target if isinstance(x, dict) and x.get("id") == part), None
                )
                if target is None:
                    raise ValueError(f"unknown path ID {part}")
            elif isinstance(target, dict) and part in target:
                target = target[part]
            else:
                raise ValueError(f"unknown path {part}")
        if not isinstance(target, dict) or parts[-1] not in target or parts[-1] == "id":
            raise ValueError("change must target an existing non-ID field")
        target[parts[-1]] = copy.deepcopy(change["value"])
    return validate_domain(domain, result)
