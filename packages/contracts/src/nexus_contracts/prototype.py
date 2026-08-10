"""Frozen boundaries for the deterministic port-closure prototype."""

from __future__ import annotations

import math
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from pydantic import UUID7, Field, field_validator, model_validator

from nexus_contracts.actions import ActionRequest
from nexus_contracts.platform import (
    EventEnvelope,
    FrozenContract,
    JsonValue,
    OntologySnapshotRef,
    ResourceRef,
    validate_tenant_references,
)


class PortClosureRiskInput(FrozenContract):
    """One port-closure event evaluated against a fixed ontology snapshot."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    event: EventEnvelope
    snapshot: OntologySnapshotRef
    idempotency_key: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def _event_and_snapshot_share_a_tenant(self) -> PortClosureRiskInput:
        if self.event.tenant_id != self.snapshot.tenant_id:
            raise ValueError("event and snapshot must belong to the same tenant")
        return self


class EvidenceFact(FrozenContract):
    """A single cited, untrusted observation used by a prototype signal."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    ref: ResourceRef
    occurred_at: datetime
    predicate: str = Field(min_length=1, max_length=128)
    value: JsonValue

    @field_validator("value")
    @classmethod
    def _value_is_ijson(cls, value: JsonValue) -> JsonValue:
        _validate_ijson(value)
        return value


class RiskSignal(FrozenContract):
    """An immutable, explainable port-closure risk result."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    signal_id: UUID7
    tenant_id: UUID7
    subject: ResourceRef
    signal_type: Literal["supply.port_closure_risk"]
    severity: Literal["high"]
    score: float = Field(ge=0, le=1)
    rule_version: str = Field(min_length=1, max_length=128)
    feature_values: Mapping[str, float]
    evidence_refs: tuple[ResourceRef, ...]
    snapshot: OntologySnapshotRef
    model_version: ResourceRef
    created_at: datetime

    @field_validator("feature_values")
    @classmethod
    def _finite_feature_values(cls, value: Mapping[str, float]) -> Mapping[str, float]:
        if not value or any(not math.isfinite(item) for item in value.values()):
            raise ValueError("feature values must be finite and non-empty")
        return value

    @model_validator(mode="after")
    def _references_match_tenant(self) -> RiskSignal:
        validate_tenant_references(
            self.tenant_id,
            self.subject,
            *self.evidence_refs,
            self.snapshot,
            self.model_version,
        )
        return self


class EvidenceBundle(FrozenContract):
    """A content-addressed, bounded evidence set for one signal."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    bundle_id: UUID7
    tenant_id: UUID7
    signal_ref: ResourceRef
    snapshot: OntologySnapshotRef
    events: tuple[ResourceRef, ...]
    facts: tuple[EvidenceFact, ...]
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sensitivity: frozenset[str]

    @model_validator(mode="after")
    def _references_match_tenant(self) -> EvidenceBundle:
        validate_tenant_references(
            self.tenant_id,
            self.signal_ref,
            self.snapshot,
            *self.events,
            *(fact.ref for fact in self.facts),
        )
        return self


class SpecialistFinding(FrozenContract):
    """Typed LLM output consumed by a later supervisor slice."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    specialist: Literal["causal_investigator", "impact_analyst", "decision_critic"]
    conclusion: str = Field(min_length=1, max_length=2_000)
    confidence: float = Field(ge=0, le=1)
    cited_evidence: tuple[ResourceRef, ...]
    unresolved_questions: tuple[str, ...]
    abstain: bool


class Recommendation(FrozenContract):
    """An approval-gated recommendation; execution remains out of this slice."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    recommendation_id: UUID7
    tenant_id: UUID7
    signal_ref: ResourceRef
    root_cause: str = Field(min_length=1, max_length=2_000)
    scenario: Literal["reroute_simulated_shipment"]
    confidence: float = Field(ge=0, le=1)
    findings: tuple[SpecialistFinding, ...]
    evidence_refs: tuple[ResourceRef, ...]
    action_request: ActionRequest
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["awaiting_approval", "rejected", "approved", "recorded"]
    created_at: datetime

    @model_validator(mode="after")
    def _references_match_tenant(self) -> Recommendation:
        validate_tenant_references(
            self.tenant_id,
            self.signal_ref,
            *self.evidence_refs,
            self.action_request.action_type,
            *self.action_request.target_refs,
            self.action_request.ontology_snapshot_ref,
            *self.action_request.evidence_artifact_refs,
            *(ref for finding in self.findings for ref in finding.cited_evidence),
        )
        if self.action_request.tenant_id != self.tenant_id:
            raise ValueError("action request must belong to the recommendation tenant")
        return self


class ApprovalCommand(FrozenContract):
    """An exact-plan human approval input for the future workflow slice."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved: bool
    comment: str | None = Field(default=None, max_length=2_000)


class PrototypeEvidencePort(Protocol):
    async def append_event(
        self, context_tenant_id: UUID, event: EventEnvelope, idempotency_key: str
    ) -> ResourceRef: ...

    async def snapshot_for_signal(
        self, context_tenant_id: UUID, event_refs: Sequence[ResourceRef]
    ) -> OntologySnapshotRef: ...

    async def build_bundle(self, context_tenant_id: UUID, signal: RiskSignal) -> EvidenceBundle: ...


class RiskScorer(Protocol):
    def score(self, input_value: PortClosureRiskInput) -> RiskSignal: ...


class RecommendationStore(Protocol):
    async def create_or_get(
        self, recommendation: Recommendation, idempotency_key: str
    ) -> Recommendation: ...

    async def record_approval(
        self, recommendation_id: UUID, command: ApprovalCommand, expected_version: int
    ) -> Recommendation: ...


def _validate_ijson(value: object) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        return
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            raise ValueError("integer is outside the interoperable JSON range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        if value == 0 and math.copysign(1.0, value) < 0:
            raise ValueError("negative zero is ambiguous")
        return
    if isinstance(value, Mapping):
        normalized: set[str] = set()
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            _validate_ijson(key)
            canonical_key = unicodedata.normalize("NFC", key)
            if canonical_key in normalized:
                raise ValueError("duplicate normalized JSON object key")
            normalized.add(canonical_key)
            _validate_ijson(item)
        return
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for item in value:
            _validate_ijson(item)
        return
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


__all__ = [
    "ApprovalCommand",
    "EvidenceBundle",
    "EvidenceFact",
    "PortClosureRiskInput",
    "PrototypeEvidencePort",
    "Recommendation",
    "RecommendationStore",
    "RiskScorer",
    "RiskSignal",
    "SpecialistFinding",
]
