"""Canonical immutable contracts for governed external actions."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, Self

from pydantic import UUID7, model_validator

from nexus_contracts.platform import (
    FrozenContract,
    JsonValue,
    OntologySnapshotRef,
    ResourceRef,
    validate_tenant_references,
)


class ActionRequest(FrozenContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    action_request_id: UUID7
    tenant_id: UUID7
    action_type: ResourceRef
    target_refs: tuple[ResourceRef, ...]
    parameters: Mapping[str, JsonValue]
    ontology_snapshot_ref: OntologySnapshotRef
    expected_effects: tuple[Mapping[str, JsonValue], ...]
    external_destination: str | None
    idempotency_key: str
    evidence_artifact_refs: tuple[ResourceRef, ...]

    @model_validator(mode="after")
    def _references_match_tenant(self) -> Self:
        validate_tenant_references(
            self.tenant_id,
            self.action_type,
            *self.target_refs,
            self.ontology_snapshot_ref,
            *self.evidence_artifact_refs,
        )
        return self
