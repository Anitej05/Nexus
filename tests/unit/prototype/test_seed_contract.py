"""Production projection acceptance against the committed seed fixture."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from _contract import require_module

FIXTURE = Path("tests/fixtures/prototype/storm-and-checkout-shift-v1.json")


def test_production_projection_canonically_equals_the_committed_fixture() -> None:
    """Implementation output cannot drift in nodes, edges, labels, types, or sensitivity."""
    seed = require_module("nexus_api.prototype.seed")
    expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
    projection = seed.build_projection("storm-and-checkout-shift-v1")
    actual = projection.model_dump(mode="json")

    assert actual == expected
    digest_material = {key: value for key, value in actual.items() if key != "seed_digest"}
    assert seed.seed_digest(projection) == expected["seed_digest"]
    assert (
        hashlib.sha256(seed.canonical_seed_bytes(digest_material)).hexdigest()
        == (expected["seed_digest"])
    )
