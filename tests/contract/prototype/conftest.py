"""Prototype contract-test source-path bootstrap without package edits."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
for source in (
    ROOT / "apps" / "api" / "src",
    ROOT / "packages" / "contracts" / "src",
    ROOT / "packages" / "security" / "src",
    ROOT / "packages" / "prototype" / "src",
    ROOT / "packages" / "llm" / "src",
):
    sys.path.insert(0, str(source))
