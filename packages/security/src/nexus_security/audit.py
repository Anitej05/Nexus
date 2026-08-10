"""Application-append-only, internally tamper-evident tenant audit ledger."""

from __future__ import annotations

import asyncio
import hashlib
import math
import unicodedata
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Self, cast

import rfc8785
from nexus_contracts.platform import (
    EventEnvelope,
    JsonValue,
    PolicyDecision,
    RequestContext,
    ResourceRef,
)
from pydantic import (
    UUID7,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from sqlalchemy import text
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncSession

from nexus_security.ids import new_id
from nexus_security.outbox import OutboxWriter
from nexus_security.policy import AuthorizationEvidence

AUDIT_HASH_DOMAIN_VERSION = "1"
AUDIT_HASH_DOMAINS = {AUDIT_HASH_DOMAIN_VERSION: "nexus.audit.event.v1"}
GENESIS_HASH = "0" * 64
MAX_SAFE_INTEGER = 2**53 - 1
MAX_JSON_DEPTH = 16
MAX_CANONICAL_BYTES = 65_536
MAX_IDEMPOTENCY_BYTES = 255
_HEX64 = r"^[0-9a-f]{64}$"
_EVENT_TYPE = r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"


class FrozenAuditModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("*", mode="after")
    @classmethod
    def _datetimes_are_utc(cls, value: object) -> object:
        if isinstance(value, datetime) and value.utcoffset() != timedelta(0):
            raise ValueError("datetimes must be timezone-aware UTC values")
        return value


class AuditActor(FrozenAuditModel):
    actor_id: UUID7
    agent_id: UUID7 | None = None


class AuditPolicyEvidence(FrozenAuditModel):
    decision: PolicyDecision
    policy_revision: str = Field(min_length=1, max_length=128)
    canonical_input_sha256: str = Field(pattern=_HEX64)
    operation: str | None = Field(default=None, min_length=1, max_length=128, pattern=_EVENT_TYPE)

    @classmethod
    def from_authorization(cls, evidence: AuthorizationEvidence) -> Self:
        if evidence.policy_revision is None or evidence.canonical_input_sha256 is None:
            raise ValueError("successful policy transport evidence is required")
        return cls(
            decision=evidence.decision,
            policy_revision=evidence.policy_revision,
            canonical_input_sha256=evidence.canonical_input_sha256,
            operation=evidence.operation,
        )


class ProtectedPayloadEvidence(FrozenAuditModel):
    ref: ResourceRef
    sha256: str = Field(pattern=_HEX64)

    @model_validator(mode="after")
    def _immutable_object(self) -> Self:
        if self.ref.kind != "object" or self.ref.version != 1:
            raise ValueError("protected payload must reference immutable object version 1")
        return self


class AuditEvent(FrozenAuditModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    id: UUID7
    tenant_id: UUID7
    sequence: int = Field(gt=0)
    occurred_at: datetime
    actor: AuditActor
    event_type: str = Field(min_length=1, max_length=255, pattern=_EVENT_TYPE)
    resource: ResourceRef
    policy_evidence: AuditPolicyEvidence | None = None
    correlation_id: UUID7
    public_payload: Mapping[str, JsonValue]
    protected_payload: ProtectedPayloadEvidence | None = None
    hash_domain_version: str = Field(
        default=AUDIT_HASH_DOMAIN_VERSION, pattern=r"^[1-9][0-9]{0,7}$"
    )
    previous_hash: str = Field(pattern=_HEX64)
    hash: str = Field(pattern=_HEX64)

    @model_validator(mode="after")
    def _tenant_references(self) -> Self:
        if self.resource.tenant_id != self.tenant_id:
            raise ValueError("resource must belong to the event tenant")
        if (
            self.protected_payload is not None
            and self.protected_payload.ref.tenant_id != self.tenant_id
        ):
            raise ValueError("protected payload must belong to the event tenant")
        return self


class AuditCheckpoint(FrozenAuditModel):
    tenant_id: UUID7
    sequence: int = Field(gt=0)
    hash: str = Field(pattern=_HEX64)
    captured_at: datetime


class AuditVerification(FrozenAuditModel):
    valid: bool
    checked_through_sequence: int = Field(ge=0)
    broken_sequence: int | None = Field(default=None, gt=0)
    expected_hash: str | None = Field(default=None, pattern=_HEX64)
    actual_hash: str | None = Field(default=None, pattern=_HEX64)
    checkpoint_matched: bool | None = None


class AuditIdempotencyConflict(RuntimeError):
    """The same tenant command key was reused for different audit semantics."""


class AuditPayloadSchema:
    """Public-field allowlist for one event type."""

    def __init__(
        self,
        *,
        fields: Mapping[str, type[Any] | tuple[type[Any], ...]],
        policy_evidence_required: bool = False,
        max_string_length: int = 2048,
    ) -> None:
        if not fields or max_string_length <= 0:
            raise ValueError("audit payload schemas require fields and a positive string bound")
        self.fields = dict(fields)
        self.policy_evidence_required = policy_evidence_required
        self.max_string_length = max_string_length


class AuditPayloadRegistry:
    """Fail-closed registry separating auditor-safe public data from protected data."""

    def __init__(
        self,
        schemas: Mapping[str, AuditPayloadSchema],
        *,
        redactor: Callable[[Mapping[str, JsonValue]], Mapping[str, JsonValue]] | None = None,
    ) -> None:
        self._schemas = dict(schemas)
        self._redactor = redactor or (lambda value: value)

    def sanitize(
        self,
        event_type: str,
        payload: Mapping[str, JsonValue],
        policy_evidence: object | None,
    ) -> dict[str, JsonValue]:
        try:
            schema = self._schemas[event_type]
        except KeyError as error:
            raise ValueError("audit event type is not registered") from error
        if schema.policy_evidence_required and policy_evidence is None:
            raise ValueError("audit event requires policy evidence")
        unknown = set(payload) - set(schema.fields)
        if unknown:
            raise ValueError("public audit field is not registered")
        result = dict(self._redactor(payload))
        if set(result) != set(payload):
            raise ValueError("redaction must preserve the registered payload shape")
        for name, value in result.items():
            allowed = schema.fields[name]
            allowed_types = allowed if isinstance(allowed, tuple) else (allowed,)
            if type(value) not in allowed_types:
                raise ValueError(f"public audit field {name} has the wrong type")
            if isinstance(value, str) and len(value) > schema.max_string_length:
                raise ValueError(f"public audit field {name} exceeds its size bound")
        canonical_json_bytes(result)
        return {name: result[name] for name in sorted(result)}


def _validate_json(value: object, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON exceeds maximum depth")
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            value.encode("utf-8", "strict")
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("integer exceeds interoperable IEEE-754 range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite number")
        if value == 0 and math.copysign(1.0, value) < 0:
            raise ValueError("negative zero is ambiguous")
        return
    if isinstance(value, list | tuple):
        for item in value:
            _validate_json(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        normalized: set[str] = set()
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            key.encode("utf-8", "strict")
            canonical_key = unicodedata.normalize("NFC", key)
            if canonical_key in normalized:
                raise ValueError("duplicate normalized JSON object key")
            normalized.add(canonical_key)
            _validate_json(item, depth=depth + 1)
        return
    raise TypeError("unsupported JSON value")


def canonical_json_bytes(value: object) -> bytes:
    """Return bounded RFC 8785 bytes after NEXUS I-JSON rejection checks."""
    _validate_json(value)
    result = rfc8785.dumps(cast(Any, value))
    if len(result) > MAX_CANONICAL_BYTES:
        raise ValueError("canonical JSON exceeds maximum size")
    return result


def _canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("audit timestamps must be timezone-aware UTC")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _resource_json(resource: ResourceRef) -> dict[str, JsonValue]:
    return {
        "tenant_id": str(resource.tenant_id),
        "kind": resource.kind,
        "id": str(resource.id),
        "version": resource.version,
    }


def _actor_json(actor: AuditActor) -> dict[str, JsonValue]:
    return {
        "actor_id": str(actor.actor_id),
        "agent_id": str(actor.agent_id) if actor.agent_id else None,
    }


def _evidence_json(value: BaseModel | None) -> JsonValue:
    return (
        None
        if value is None
        else cast(JsonValue, value.model_dump(mode="json", exclude_none=True))
    )


def compute_request_fingerprint(
    *,
    actor: AuditActor,
    event_type: str,
    resource: ResourceRef,
    public_payload: Mapping[str, JsonValue],
    protected_payload: ProtectedPayloadEvidence | None,
    policy_evidence: AuditPolicyEvidence | None,
) -> str:
    material: dict[str, JsonValue] = {
        "actor": _actor_json(actor),
        "event_type": event_type,
        "resource": _resource_json(resource),
        "public_payload": dict(public_payload),
        "protected_payload": _evidence_json(protected_payload),
        "policy_evidence": _evidence_json(policy_evidence),
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def compute_event_hash(
    event: AuditEvent, idempotency_key_sha256: str, request_fingerprint_sha256: str
) -> str:
    for value in (idempotency_key_sha256, request_fingerprint_sha256):
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("audit storage digests must be lowercase SHA-256")
    try:
        domain = AUDIT_HASH_DOMAINS[event.hash_domain_version]
    except KeyError as error:
        raise ValueError("unsupported audit hash domain version") from error
    material: dict[str, JsonValue] = {
        "domain": domain,
        "hash_domain_version": event.hash_domain_version,
        "schema_version": event.schema_version,
        "id": str(event.id),
        "tenant_id": str(event.tenant_id),
        "sequence": event.sequence,
        "occurred_at": _canonical_timestamp(event.occurred_at),
        "actor": _actor_json(event.actor),
        "event_type": event.event_type,
        "resource": _resource_json(event.resource),
        "policy_evidence": _evidence_json(event.policy_evidence),
        "correlation_id": str(event.correlation_id),
        "public_payload": dict(event.public_payload),
        "protected_payload": _evidence_json(event.protected_payload),
        "idempotency_key_sha256": idempotency_key_sha256,
        "request_fingerprint_sha256": request_fingerprint_sha256,
        "previous_hash": event.previous_hash,
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _idempotency_digest(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("idempotency key must be non-empty")
    encoded = value.encode("utf-8", "strict")
    if len(encoded) > MAX_IDEMPOTENCY_BYTES:
        raise ValueError("idempotency key exceeds maximum size")
    return hashlib.sha256(encoded).hexdigest()


def audit_event_from_mapping(row: Mapping[str, Any] | RowMapping) -> AuditEvent:
    policy = row["policy_decision"]
    policy_evidence = None
    if policy is not None:
        stored_policy = dict(policy)
        operation = stored_policy.pop("operation", None)
        policy_evidence = AuditPolicyEvidence(
            decision=PolicyDecision.model_validate(stored_policy),
            policy_revision=row["policy_revision"],
            canonical_input_sha256=row["policy_input_sha256"],
            operation=operation,
        )
    protected = None
    if row["protected_ref_id"] is not None:
        protected = ProtectedPayloadEvidence(
            ref=ResourceRef(
                tenant_id=row["tenant_id"],
                kind=row["protected_ref_kind"],
                id=row["protected_ref_id"],
                version=row["protected_ref_version"],
            ),
            sha256=row["protected_payload_sha256"],
        )
    return AuditEvent(
        id=row["id"],
        tenant_id=row["tenant_id"],
        sequence=row["sequence"],
        occurred_at=row["occurred_at"],
        actor=AuditActor(actor_id=row["actor_id"], agent_id=row["agent_id"]),
        event_type=row["event_type"],
        resource=ResourceRef(
            tenant_id=row["tenant_id"],
            kind=row["resource_kind"],
            id=row["resource_id"],
            version=row["resource_version"],
        ),
        policy_evidence=policy_evidence,
        correlation_id=row["correlation_id"],
        public_payload=row["public_payload"],
        protected_payload=protected,
        hash_domain_version=row["hash_domain_version"],
        previous_hash=row["previous_hash"],
        hash=row["hash"],
    )


AUDIT_SELECT_COLUMNS = """id, tenant_id, sequence, occurred_at, actor_id, agent_id, event_type,
resource_kind, resource_id, resource_version, policy_decision, policy_revision,
policy_input_sha256, correlation_id, public_payload, protected_ref_kind, protected_ref_id,
protected_ref_version, protected_payload_sha256, idempotency_key_sha256,
request_fingerprint_sha256, hash_domain_version, previous_hash, hash"""


class AuditWriter:
    """Append and verify audit rows inside one caller-owned tenant transaction."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        outbox: OutboxWriter,
        payload_registry: AuditPayloadRegistry,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.session = session
        self.outbox = outbox
        self.payload_registry = payload_registry
        self.clock = clock
        self._require_transaction()

    def _require_transaction(self) -> None:
        if not self.session.in_transaction():
            raise RuntimeError("audit operations require an active caller transaction")

    async def append(
        self,
        context: RequestContext,
        event_type: str,
        resource: ResourceRef,
        public_payload: Mapping[str, JsonValue],
        idempotency_key: str,
        protected_payload: ProtectedPayloadEvidence | None = None,
        policy_evidence: AuditPolicyEvidence | None = None,
        operation: str | None = None,
    ) -> AuditEvent:
        if resource.tenant_id != context.tenant_id:
            raise ValueError("audit resource must belong to the context tenant")
        if protected_payload is not None and protected_payload.ref.tenant_id != context.tenant_id:
            raise ValueError("protected payload must belong to the context tenant")
        if operation is not None:
            if policy_evidence is None or policy_evidence.operation != operation:
                raise ValueError("policy evidence operation does not match the trusted operation")
        payload = self.payload_registry.sanitize(event_type, public_payload, policy_evidence)
        idempotency_digest = _idempotency_digest(idempotency_key)
        actor = AuditActor(actor_id=context.actor_id, agent_id=context.agent_id)
        request_digest = compute_request_fingerprint(
            actor=actor,
            event_type=event_type,
            resource=resource,
            public_payload=payload,
            protected_payload=protected_payload,
            policy_evidence=policy_evidence,
        )
        self._require_transaction()
        await self.session.execute(
            text("select pg_advisory_xact_lock(hashtextextended(:tenant, 0))"),
            {"tenant": str(context.tenant_id)},
        )
        existing = (
            (
                await self.session.execute(
                    text(
                        f"select {AUDIT_SELECT_COLUMNS} from audit_events "  # noqa: S608
                        "where tenant_id=:tenant and idempotency_key_sha256=:digest"
                    ),
                    {"tenant": context.tenant_id, "digest": idempotency_digest},
                )
            )
            .mappings()
            .one_or_none()
        )
        if existing is not None:
            if existing["request_fingerprint_sha256"] != request_digest:
                raise AuditIdempotencyConflict("audit command key conflicts with prior semantics")
            return audit_event_from_mapping(existing)
        tail = (
            (
                await self.session.execute(
                    text(
                        "select sequence, hash from audit_events where tenant_id=:tenant "
                        "order by sequence desc limit 1"
                    ),
                    {"tenant": context.tenant_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        sequence = 1 if tail is None else cast(int, tail["sequence"]) + 1
        previous_hash = GENESIS_HASH if tail is None else cast(str, tail["hash"])
        occurred_at = self.clock()
        _canonical_timestamp(occurred_at)
        draft = AuditEvent(
            id=new_id(),
            tenant_id=context.tenant_id,
            sequence=sequence,
            occurred_at=occurred_at,
            actor=actor,
            event_type=event_type,
            resource=resource,
            policy_evidence=policy_evidence,
            correlation_id=context.correlation_id,
            public_payload=payload,
            protected_payload=protected_payload,
            previous_hash=previous_hash,
            hash=GENESIS_HASH,
        )
        event = draft.model_copy(
            update={"hash": compute_event_hash(draft, idempotency_digest, request_digest)}
        )
        await self.session.execute(
            text(
                """insert into audit_events(
                id, tenant_id, sequence, occurred_at, actor_id, agent_id, event_type,
                resource_kind, resource_id, resource_version, policy_decision, policy_revision,
                policy_input_sha256, correlation_id, public_payload, protected_ref_kind,
                protected_ref_id, protected_ref_version, protected_payload_sha256,
                idempotency_key_sha256, request_fingerprint_sha256, hash_domain_version,
                previous_hash, hash) values (
                :id, :tenant, :sequence, :occurred_at, :actor_id, :agent_id, :event_type,
                :resource_kind, :resource_id, :resource_version, cast(:policy_decision as jsonb),
                :policy_revision, :policy_input_sha256, :correlation_id,
                cast(:public_payload as jsonb), :protected_ref_kind, :protected_ref_id,
                :protected_ref_version, :protected_payload_sha256, :idempotency_digest,
                :request_digest, :hash_domain_version, :previous_hash, :hash)
                """
            ),
            {
                "id": event.id,
                "tenant": event.tenant_id,
                "sequence": event.sequence,
                "occurred_at": event.occurred_at,
                "actor_id": event.actor.actor_id,
                "agent_id": event.actor.agent_id,
                "event_type": event.event_type,
                "resource_kind": event.resource.kind,
                "resource_id": event.resource.id,
                "resource_version": event.resource.version,
                "policy_decision": (
                    None
                    if event.policy_evidence is None
                    else canonical_json_bytes(
                        {
                            **event.policy_evidence.decision.model_dump(mode="json"),
                            **(
                                {"operation": event.policy_evidence.operation}
                                if event.policy_evidence.operation is not None
                                else {}
                            ),
                        }
                    ).decode()
                ),
                "policy_revision": (
                    None if event.policy_evidence is None else event.policy_evidence.policy_revision
                ),
                "policy_input_sha256": (
                    None
                    if event.policy_evidence is None
                    else event.policy_evidence.canonical_input_sha256
                ),
                "correlation_id": event.correlation_id,
                "public_payload": canonical_json_bytes(dict(event.public_payload)).decode(),
                "protected_ref_kind": (
                    None if event.protected_payload is None else event.protected_payload.ref.kind
                ),
                "protected_ref_id": (
                    None if event.protected_payload is None else event.protected_payload.ref.id
                ),
                "protected_ref_version": (
                    None if event.protected_payload is None else event.protected_payload.ref.version
                ),
                "protected_payload_sha256": (
                    None if event.protected_payload is None else event.protected_payload.sha256
                ),
                "idempotency_digest": idempotency_digest,
                "request_digest": request_digest,
                "hash_domain_version": event.hash_domain_version,
                "previous_hash": event.previous_hash,
                "hash": event.hash,
            },
        )
        audit_ref = ResourceRef(
            tenant_id=event.tenant_id, kind="audit.event", id=event.id, version=1
        )
        await self.outbox.enqueue(
            self.session,
            EventEnvelope(
                event_id=new_id(),
                event_type="nexus.audit.v1",
                tenant_id=event.tenant_id,
                source=audit_ref,
                subject=f"{event.resource.kind}:{event.resource.id}",
                occurred_at=event.occurred_at,
                ingested_at=event.occurred_at,
                correlation_id=event.correlation_id,
                sensitivity=frozenset({"internal"}),
                payload={
                    "event_id": str(event.id),
                    "sequence": event.sequence,
                    "event_type": event.event_type,
                    "resource": _resource_json(event.resource),
                    "hash": event.hash,
                },
            ),
            f"audit:{event.id}",
        )
        return event

    async def verify_chain(
        self, context: RequestContext, *, checkpoint: AuditCheckpoint | None = None
    ) -> AuditVerification:
        if checkpoint is not None and checkpoint.tenant_id != context.tenant_id:
            raise ValueError("audit checkpoint must belong to the context tenant")
        self._require_transaction()
        stream = await self.session.stream(
            text(  # noqa: S608
                f"select {AUDIT_SELECT_COLUMNS} from audit_events "  # noqa: S608
                "where tenant_id=:tenant order by sequence"
            ),
            {"tenant": context.tenant_id},
        )
        expected_previous = GENESIS_HASH
        last_valid_sequence = 0
        checkpoint_matched: bool | None = None if checkpoint is None else False
        async for row in stream.mappings():
            sequence = cast(int, row["sequence"])
            actual_hash = cast(str, row["hash"])
            if sequence != last_valid_sequence + 1:
                return AuditVerification(
                    valid=False,
                    checked_through_sequence=last_valid_sequence,
                    broken_sequence=sequence,
                    actual_hash=actual_hash,
                    checkpoint_matched=False if checkpoint is not None else None,
                )
            try:
                event = audit_event_from_mapping(row)
                expected = compute_event_hash(
                    event,
                    cast(str, row["idempotency_key_sha256"]),
                    cast(str, row["request_fingerprint_sha256"]),
                )
            except (TypeError, UnicodeError, ValueError, ValidationError):
                return AuditVerification(
                    valid=False,
                    checked_through_sequence=last_valid_sequence,
                    broken_sequence=sequence,
                    actual_hash=actual_hash,
                    checkpoint_matched=False if checkpoint is not None else None,
                )
            if event.previous_hash != expected_previous or event.hash != expected:
                return AuditVerification(
                    valid=False,
                    checked_through_sequence=last_valid_sequence,
                    broken_sequence=event.sequence,
                    expected_hash=expected,
                    actual_hash=event.hash,
                    checkpoint_matched=False if checkpoint is not None else None,
                )
            expected_previous = event.hash
            last_valid_sequence = event.sequence
            if checkpoint is not None and event.sequence == checkpoint.sequence:
                checkpoint_matched = event.hash == checkpoint.hash
                if not checkpoint_matched:
                    return AuditVerification(
                        valid=False,
                        checked_through_sequence=event.sequence,
                        broken_sequence=event.sequence,
                        expected_hash=checkpoint.hash,
                        actual_hash=event.hash,
                        checkpoint_matched=False,
                    )
        if checkpoint is not None and checkpoint.sequence > last_valid_sequence:
            return AuditVerification(
                valid=False,
                checked_through_sequence=last_valid_sequence,
                broken_sequence=checkpoint.sequence,
                expected_hash=checkpoint.hash,
                actual_hash=None,
                checkpoint_matched=False,
            )
        return AuditVerification(
            valid=True,
            checked_through_sequence=last_valid_sequence,
            checkpoint_matched=checkpoint_matched,
        )


async def cancellation_checkpoint() -> None:
    """Keep cancellation propagation explicit at higher-level test injection boundaries."""
    await asyncio.sleep(0)
