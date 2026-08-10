"""Small helpers that make a missing route implementation an intentional RED failure."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

import pytest


def require_module(name: str) -> ModuleType:
    try:
        return import_module(name)
    except ModuleNotFoundError as exc:
        pytest.fail(f"prototype contract is not implemented: missing {name} ({exc.name})")
