"""Canonical immutable contracts used by agent orchestration."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import UUID7, Field, model_validator

from nexus_contracts.platform import (
    FrozenContract,
    JsonValue,
    OntologySnapshotRef,
    ResourceRef,
    validate_tenant_references,
)


class AutonomyClass(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


class CapabilityScope(FrozenContract):
    tools: frozenset[str]
    object_types: frozenset[str]
    properties: frozenset[str]
    actions: frozenset[str]
    external_destinations: frozenset[str]


class ExecutionBudget(FrozenContract):
    max_tokens: int = Field(ge=0)
    max_cost_micros: int = Field(ge=0)
    max_tool_calls: int = Field(ge=0)
    deadline: datetime


class ExecutionUsage(FrozenContract):
    tokens: int = Field(ge=0)
    cost_micros: int = Field(ge=0)
    tool_calls: int = Field(ge=0)


class DelegatedTask(FrozenContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    task_id: UUID7
    tenant_id: UUID7
    objective_id: UUID7
    situation_id: UUID7 | None
    parent_task_id: UUID7 | None
    priority: int = Field(ge=0, le=100)
    budget: ExecutionBudget
    input_artifact_refs: tuple[ResourceRef, ...]
    ontology_snapshot_ref: OntologySnapshotRef
    capability_scope: CapabilityScope
    output_schema_uri: str
    evidence_requirements: tuple[str, ...]
    autonomy_class: AutonomyClass
    escalation_policy_id: UUID7
    agent_version_id: UUID7
    prompt_version_id: UUID7
    tool_version_ids: tuple[UUID7, ...]
    workflow_version_id: UUID7
    model_id: str

    @model_validator(mode="after")
    def _references_match_tenant(self) -> Self:
        validate_tenant_references(
            self.tenant_id,
            *self.input_artifact_refs,
            self.ontology_snapshot_ref,
        )
        return self


class TaskResult(FrozenContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    task_id: UUID7
    status: str
    output_artifact_refs: tuple[ResourceRef, ...]
    child_task_ids: tuple[UUID7, ...]
    usage: ExecutionUsage
    escalation_reason: str | None = None
    error_code: str | None = None


class ArtifactProvenance(FrozenContract):
    creator: ResourceRef
    input_artifact_refs: tuple[ResourceRef, ...]
    ontology_snapshot_ref: OntologySnapshotRef
    version_ids: Mapping[str, UUID7]
    tool_call_ids: tuple[UUID7, ...]
    correlation_id: UUID7
    random_seed: int | None = None


class ArtifactEnvelope(FrozenContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    artifact_id: UUID7
    tenant_id: UUID7
    objective_id: UUID7 | None
    situation_id: UUID7 | None
    task_id: UUID7 | None
    artifact_type: str
    schema_uri: str
    payload: Mapping[str, JsonValue]
    provenance: ArtifactProvenance
    sensitivity: frozenset[str]
    evidence_refs: tuple[ResourceRef, ...]
    revises_id: UUID7 | None = None
    conflicts_with: tuple[UUID7, ...] = ()
    created_at: datetime

    @model_validator(mode="after")
    def _references_match_tenant(self) -> Self:
        validate_tenant_references(
            self.tenant_id,
            self.provenance.creator,
            *self.provenance.input_artifact_refs,
            self.provenance.ontology_snapshot_ref,
            *self.evidence_refs,
        )
        return self
