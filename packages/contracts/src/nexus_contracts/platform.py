"""Canonical, immutable platform contracts and boundary protocols."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, Self, TypeVar
from uuid import UUID

from pydantic import UUID7, BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import TypeAliasType

JsonValue = TypeAliasType(
    "JsonValue",
    "str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]",
)
ModelT = TypeVar("ModelT", bound=BaseModel)


class FrozenContract(BaseModel):
    """Shared Pydantic policy for public platform values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("*", mode="after")
    @classmethod
    def _datetimes_are_aware(cls, value: object) -> object:
        if isinstance(value, datetime) and value.utcoffset() != timedelta(0):
            raise ValueError("datetimes must be timezone-aware UTC values")
        return value


class RequestContext(FrozenContract):
    tenant_id: UUID7
    actor_id: UUID7
    correlation_id: UUID7
    roles: frozenset[str]
    scopes: frozenset[str]
    sensitivity_clearances: frozenset[str]
    agent_id: UUID7 | None = None


class ResourceRef(FrozenContract):
    tenant_id: UUID7
    kind: str
    id: UUID7
    version: int | None = Field(default=None, gt=0)


class EventEnvelope(FrozenContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    event_id: UUID7
    event_type: str
    tenant_id: UUID7
    source: ResourceRef
    subject: str
    occurred_at: datetime
    ingested_at: datetime
    correlation_id: UUID7
    causation_id: UUID7 | None = None
    traceparent: str | None = None
    sensitivity: frozenset[str]
    payload: JsonValue

    @model_validator(mode="after")
    def _source_matches_tenant(self) -> Self:
        validate_tenant_references(self.tenant_id, self.source)
        return self


class OntologyObservation(FrozenContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    observation_id: UUID7
    tenant_id: UUID7
    subject: ResourceRef
    source_record: ResourceRef
    transformation_ref: ResourceRef | None = None
    properties: Mapping[str, JsonValue]
    observed_at: datetime
    ingested_at: datetime
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)

    @model_validator(mode="after")
    def _references_match_tenant(self) -> Self:
        validate_tenant_references(
            self.tenant_id,
            self.subject,
            self.source_record,
            self.transformation_ref,
        )
        return self


class OntologySnapshotRef(FrozenContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    snapshot_id: UUID7
    tenant_id: UUID7
    schema_version_id: UUID7
    branch_id: UUID7 | None = None
    transaction_time: datetime
    valid_time: datetime
    event_watermark: int = Field(ge=0)
    content_hash: str


def validate_tenant_references(
    tenant_id: UUID, *references: ResourceRef | OntologySnapshotRef | None
) -> None:
    """Reject references that could join data from a different tenant."""
    if any(reference is not None and reference.tenant_id != tenant_id for reference in references):
        raise ValueError("nested references must belong to the contract tenant")


class PolicyDecision(FrozenContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    decision_id: UUID7
    allow: bool
    effective_class: str | None = None
    obligations: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()


class Problem(FrozenContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    type: str
    title: str
    status: int = Field(ge=100, le=599)
    detail: str | None = None
    instance: str | None = None
    code: str
    correlation_id: UUID7


class EntityDecisionReceipt(FrozenContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    receipt_id: UUID7
    tenant_id: UUID7
    decision_ref: ResourceRef
    applied_ref: ResourceRef
    inverse_payload: Mapping[str, JsonValue]

    @model_validator(mode="after")
    def _references_match_tenant(self) -> Self:
        validate_tenant_references(self.tenant_id, self.decision_ref, self.applied_ref)
        return self


class MalwareScanResult(FrozenContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    clean: bool
    scanner: str
    scanned_at: datetime
    detections: tuple[str, ...] = ()


class OntologyWritePort(Protocol):
    async def apply_observations(
        self,
        context: RequestContext,
        observations: Sequence[OntologyObservation],
        idempotency_key: str,
    ) -> tuple[ResourceRef, ...]: ...


class OntologyReadPort(Protocol):
    async def snapshot(
        self,
        context: RequestContext,
        object_refs: Sequence[ResourceRef],
        valid_time: datetime,
        branch_id: UUID | None = None,
    ) -> OntologySnapshotRef: ...

    def read_objects(
        self,
        context: RequestContext,
        snapshot: OntologySnapshotRef,
        query: Mapping[str, JsonValue],
    ) -> AsyncIterator[dict[str, JsonValue]]: ...


class GraphProjectionPort(Protocol):
    async def read_subgraph(
        self,
        context: RequestContext,
        snapshot: OntologySnapshotRef,
        query: Mapping[str, JsonValue],
    ) -> dict[str, JsonValue]: ...


class BranchPort(Protocol):
    async def put(
        self,
        context: RequestContext,
        branch_id: UUID,
        resource_kind: str,
        resource_key: str,
        content: Mapping[str, JsonValue],
        expected_version: int,
        idempotency_key: str,
    ) -> ResourceRef: ...

    async def diff(self, context: RequestContext, branch_id: UUID) -> Mapping[str, JsonValue]: ...


class PolicyPort(Protocol):
    async def authorize(
        self,
        context: RequestContext,
        operation: str,
        resources: Sequence[ResourceRef],
        attributes: Mapping[str, JsonValue],
    ) -> PolicyDecision: ...


class SecretPort(Protocol):
    async def resolve(
        self, context: RequestContext, secret_ref: ResourceRef
    ) -> Mapping[str, str]: ...


class ObjectStorePort(Protocol):
    async def put_bytes(
        self,
        context: RequestContext,
        key: str,
        body: bytes,
        content_type: str,
        sha256: str,
        idempotency_key: str,
    ) -> ResourceRef: ...

    async def get_bytes(self, context: RequestContext, ref: ResourceRef) -> bytes: ...


class AuditPort(Protocol):
    async def append(
        self,
        context: RequestContext,
        event_type: str,
        subject: ResourceRef,
        payload: Mapping[str, JsonValue],
        idempotency_key: str,
    ) -> ResourceRef: ...


class ArtifactPort(Protocol):
    async def publish(
        self,
        context: RequestContext,
        artifact_type: str,
        schema_uri: str,
        payload: Mapping[str, JsonValue],
        evidence: Sequence[ResourceRef],
        idempotency_key: str,
        *,
        objective_id: UUID | None = None,
        situation_id: UUID | None = None,
        task_id: UUID | None = None,
        sensitivity: frozenset[str] = frozenset(),
    ) -> ResourceRef: ...


class SignalPort(Protocol):
    async def publish_signal(
        self,
        context: RequestContext,
        signal_type: str,
        severity: str,
        body: Mapping[str, JsonValue],
        evidence: Sequence[ResourceRef],
        idempotency_key: str,
    ) -> ResourceRef: ...


class EmbeddingPort(Protocol):
    async def embed(
        self,
        context: RequestContext,
        texts: Sequence[str],
        model_id: str,
    ) -> tuple[tuple[float, ...], ...]: ...


class MalwareScanPort(Protocol):
    async def scan(
        self,
        context: RequestContext,
        content: bytes,
        content_type: str,
    ) -> MalwareScanResult: ...


class StructuredOutputPort(Protocol):
    async def generate_object(
        self,
        context: RequestContext,
        prompt: str,
        output_type: type[ModelT],
        idempotency_key: str,
    ) -> ModelT: ...


class EntityDecisionPort(Protocol):
    async def apply(
        self,
        context: RequestContext,
        decision: Mapping[str, JsonValue],
        expected_version: int,
        idempotency_key: str,
    ) -> EntityDecisionReceipt: ...


def utc_now() -> datetime:
    """Provide a canonical UTC value for adapters that need a timestamp."""
    return datetime.now(UTC)
