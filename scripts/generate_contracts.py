"""Generate the deterministic platform contract schema bundle."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from nexus_contracts.actions import ActionRequest
from nexus_contracts.agents import ArtifactEnvelope, DelegatedTask, TaskResult
from nexus_contracts.platform import (
    EntityDecisionReceipt,
    EventEnvelope,
    MalwareScanResult,
    OntologyObservation,
    OntologySnapshotRef,
    PolicyDecision,
    Problem,
    ResourceRef,
)
from nexus_contracts.prototype import (
    ApprovalCommand,
    EvidenceBundle,
    EvidenceFact,
    PortClosureRiskInput,
    Recommendation,
    RiskSignal,
    SpecialistFinding,
)
from pydantic.json_schema import models_json_schema

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "packages" / "contracts" / "generated" / "platform-1.0.0.json"
MODELS = (
    ActionRequest,
    ApprovalCommand,
    ArtifactEnvelope,
    DelegatedTask,
    EvidenceBundle,
    EvidenceFact,
    EntityDecisionReceipt,
    EventEnvelope,
    MalwareScanResult,
    OntologyObservation,
    OntologySnapshotRef,
    PolicyDecision,
    PortClosureRiskInput,
    Problem,
    Recommendation,
    ResourceRef,
    RiskSignal,
    SpecialistFinding,
    TaskResult,
)


def schema_bytes() -> bytes:
    _, generated = models_json_schema([(model, "validation") for model in MODELS])
    document: dict[str, Any] = dict(generated)
    document["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    document["schema_version"] = "1.0.0"
    document["models"] = {model.__name__: {"$ref": f"#/$defs/{model.__name__}"} for model in MODELS}
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def independently_generated_bytes() -> bytes:
    """Prove two isolated generations are byte-for-byte deterministic."""
    with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
        first_path = Path(first_dir) / OUTPUT.name
        second_path = Path(second_dir) / OUTPUT.name
        first_path.write_bytes(schema_bytes())
        second_path.write_bytes(schema_bytes())
        first = first_path.read_bytes()
        second = second_path.read_bytes()
    if first != second:
        raise RuntimeError("contract schema generation is not deterministic")
    return first


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    generated = independently_generated_bytes()
    if arguments.check:
        if not OUTPUT.exists() or OUTPUT.read_bytes() != generated:
            raise SystemExit("platform schema is stale; run scripts/generate_contracts.py")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
