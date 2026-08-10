"""Deterministic, fail-closed OPA authorization boundary."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import Literal, Protocol, Self
from uuid import UUID

import httpx
import rfc8785
from nexus_contracts.platform import JsonValue, PolicyDecision, RequestContext, ResourceRef
from pydantic import (
    UUID7,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from nexus_security.ids import new_id

DEFAULT_DECISION_URL = "http://opa:8181/v1/data/nexus/authz/decision"
SENSITIVITY_LABELS = frozenset({"public", "internal", "confidential", "restricted"})
RISK_CLASSES = ("R0", "R1", "R2", "R3", "R4")
SECURITY_ATTRIBUTE_KEYS = frozenset(
    {
        "actor",
        "actor_id",
        "agent_id",
        "roles",
        "scopes",
        "sensitivity_clearances",
        "delegation_chain",
        "trusted_facts",
        "configured_base_risk",
        "contextual_risk",
        "approval",
        "capabilities",
    }
)


class FrozenPolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ActorIdentity(FrozenPolicyModel):
    actor_id: UUID7
    roles: frozenset[str]
    scopes: frozenset[str]
    sensitivity_clearances: frozenset[str]
    agent_id: UUID7 | None = None

    @field_validator("sensitivity_clearances")
    @classmethod
    def _known_clearances(cls, value: frozenset[str]) -> frozenset[str]:
        if not value <= SENSITIVITY_LABELS:
            raise ValueError("unknown sensitivity clearance")
        return value


class CapabilitySet(FrozenPolicyModel):
    tools: frozenset[str] = frozenset()
    object_types: frozenset[str] = frozenset()
    properties: frozenset[str] = frozenset()
    actions: frozenset[str] = frozenset()
    external_destinations: frozenset[str] = frozenset()

    @field_validator("*")
    @classmethod
    def _valid_capability_names(cls, value: frozenset[str]) -> frozenset[str]:
        if any(not item for item in value):
            raise ValueError("capability names must be non-empty")
        return value


class DelegationLink(FrozenPolicyModel):
    tenant_id: UUID7
    delegator_id: UUID7
    delegate_id: UUID7
    capabilities: CapabilitySet


class ApprovalFacts(FrozenPolicyModel):
    tenant_id: UUID7
    action_id: UUID7
    action_version: int = Field(gt=0)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approver_id: UUID7
    requester_id: UUID7
    proposer_id: UUID7
    executor_id: UUID7
    approved: bool = True
    consumed: bool = False


class TrustedPolicyFacts(FrozenPolicyModel):
    resource_sensitivity: frozenset[str]
    configured_base_risk: Literal["R0", "R1", "R2", "R3", "R4"]
    contextual_risk: Literal["R0", "R1", "R2", "R3", "R4"]
    delegator_capabilities: CapabilitySet | None = None
    requested_capabilities: CapabilitySet | None = None
    used_tools: frozenset[str] = frozenset()
    used_properties: frozenset[str] = frozenset()
    used_actions: frozenset[str] = frozenset()
    used_external_destinations: frozenset[str] = frozenset()
    delegation_chain: tuple[DelegationLink, ...] = ()
    approval: ApprovalFacts | None = None
    action_id: UUID7 | None = None
    action_version: int | None = Field(default=None, gt=0)
    plan_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    consumer_enforced_obligations: frozenset[str] = frozenset()
    obligations: tuple[str, ...] = ()

    @field_validator("resource_sensitivity")
    @classmethod
    def _known_sensitivity(cls, value: frozenset[str]) -> frozenset[str]:
        if not value or not value <= SENSITIVITY_LABELS:
            raise ValueError("unknown sensitivity label")
        return value

    @field_validator("obligations", "consumer_enforced_obligations")
    @classmethod
    def _valid_obligations(cls, value: Sequence[str]) -> Sequence[str]:
        for obligation in value:
            if not _valid_obligation(obligation):
                raise ValueError("unknown or malformed policy obligation")
        return value

    @model_validator(mode="after")
    def _bounded_delegation(self) -> Self:
        if len(self.delegation_chain) > 8:
            raise ValueError("delegation depth exceeds eight")
        return self


class AuthorizationInput(FrozenPolicyModel):
    decision_id: UUID7
    actor: ActorIdentity
    tenant_id: UUID7
    resources: tuple[ResourceRef, ...]
    operation: str
    attributes: Mapping[str, JsonValue]
    delegation_chain: tuple[DelegationLink, ...] = ()
    trusted_facts: TrustedPolicyFacts

    @model_validator(mode="after")
    def _local_invariants(self) -> Self:
        if SECURITY_ATTRIBUTE_KEYS.intersection(self.attributes):
            raise ValueError("caller attributes contain trusted security fields")
        identities = {
            (resource.tenant_id, resource.kind, resource.id, resource.version)
            for resource in self.resources
        }
        if len(identities) != len(self.resources):
            raise ValueError("duplicate resources")
        if any(resource.tenant_id != self.tenant_id for resource in self.resources):
            raise ValueError("cross-tenant resource")
        if self.delegation_chain != self.trusted_facts.delegation_chain:
            raise ValueError("delegation provenance mismatch")
        _validate_ijson(self.attributes)
        requested = self.trusted_facts.requested_capabilities
        if self.actor.agent_id is not None:
            if requested is None or requested != self._derived_capabilities():
                raise ValueError("agent requested capabilities must match actual resource use")
        if self.operation == "action.execute" and (
            self.trusted_facts.action_id is None
            or self.trusted_facts.action_version is None
            or self.trusted_facts.plan_hash is None
        ):
            raise ValueError("action execution requires immutable action provenance")
        return self

    def _derived_capabilities(self) -> CapabilitySet:
        return CapabilitySet(
            tools=self.trusted_facts.used_tools,
            object_types=frozenset(resource.kind for resource in self.resources),
            properties=self.trusted_facts.used_properties,
            actions=self.trusted_facts.used_actions | {self.operation},
            external_destinations=self.trusted_facts.used_external_destinations,
        )

    def to_opa_input(self) -> dict[str, JsonValue]:
        actor: dict[str, JsonValue] = {
            "actor_id": str(self.actor.actor_id),
            "roles": [_jsonable(value) for value in sorted(self.actor.roles)],
            "scopes": [_jsonable(value) for value in sorted(self.actor.scopes)],
            "sensitivity_clearances": [
                _jsonable(value) for value in sorted(self.actor.sensitivity_clearances)
            ],
            "agent_id": str(self.actor.agent_id) if self.actor.agent_id else None,
        }
        resources: list[JsonValue] = []
        for resource in sorted(
            self.resources, key=lambda item: (item.kind, str(item.id), item.version or 0)
        ):
            resources.append(
                {
                    "tenant_id": str(resource.tenant_id),
                    "kind": resource.kind,
                    "id": str(resource.id),
                    "version": resource.version,
                }
            )
        facts = _jsonable(self.trusted_facts.model_dump(exclude={"delegation_chain"}))
        return {
            "decision_id": str(self.decision_id),
            "actor": actor,
            "tenant_id": str(self.tenant_id),
            "resources": resources,
            "operation": self.operation,
            "attributes": _jsonable(dict(self.attributes)),
            "delegation_chain": _jsonable(
                [link.model_dump(mode="python") for link in self.delegation_chain]
            ),
            "trusted_facts": facts,
        }


class AuthorizationEvidence(FrozenPolicyModel):
    decision: PolicyDecision
    policy_revision: Literal["1.0.0"] | None
    canonical_input_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    operation: str | None = None


class _OPAResult(FrozenPolicyModel):
    decision_id: UUID7
    allow: bool
    effective_class: Literal["R0", "R1", "R2", "R3", "R4"] | None
    obligations: tuple[str, ...]
    reason_codes: tuple[str, ...]
    policy_revision: Literal["1.0.0"]

    @field_validator("obligations", "reason_codes")
    @classmethod
    def _canonical_arrays(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("policy arrays must be sorted and deduplicated")
        return value

    @field_validator("obligations")
    @classmethod
    def _known_obligations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _valid_obligation(item) for item in value):
            raise ValueError("unknown obligation")
        return value


class _OPAEnvelope(FrozenPolicyModel):
    result: _OPAResult


class TrustedPolicyFactsProvider(Protocol):
    async def get_facts(
        self,
        context: RequestContext,
        operation: str,
        resources: Sequence[ResourceRef],
        attributes: Mapping[str, JsonValue],
    ) -> TrustedPolicyFacts: ...


class PolicyClient:
    """Small HTTP adapter that never converts an OPA failure into permission."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        decision_url: str = DEFAULT_DECISION_URL,
        *,
        timeout_seconds: float = 2.0,
        max_response_bytes: int = 65_536,
    ) -> None:
        self._http = http
        self._decision_url = decision_url
        self._timeout_seconds = timeout_seconds
        self._timeout = httpx.Timeout(timeout_seconds)
        self._max_response_bytes = max_response_bytes

    async def authorize(self, request: AuthorizationInput) -> PolicyDecision:
        return (await self.authorize_with_evidence(request)).decision

    async def authorize_with_evidence(self, request: AuthorizationInput) -> AuthorizationEvidence:
        try:
            opa_input = request.to_opa_input()
            _validate_ijson(opa_input)
            canonical = rfc8785.dumps(opa_input)
            wire_body = rfc8785.dumps({"input": opa_input})
            digest = hashlib.sha256(canonical).hexdigest()
        except (TypeError, ValueError, UnicodeError):
            return AuthorizationEvidence(
                decision=_denial(request.decision_id, "invalid_policy_input"),
                policy_revision=None,
                operation=request.operation,
            )
        try:
            async with asyncio.timeout(self._timeout_seconds):
                async with self._http.stream(
                    "POST",
                    self._decision_url,
                    params={"strict-builtin-errors": "true"},
                    content=wire_body,
                    headers={"Content-Type": "application/json"},
                    timeout=self._timeout,
                    follow_redirects=False,
                ) as response:
                    response.raise_for_status()
                    content = bytearray()
                    async for chunk in response.aiter_bytes():
                        content.extend(chunk)
                        if len(content) > self._max_response_bytes:
                            raise ValueError("OPA response exceeds configured bound")
                payload = _OPAEnvelope.model_validate_json(bytes(content))
                if payload.result.decision_id != request.decision_id:
                    raise ValueError("OPA decision correlation mismatch")
                decision = PolicyDecision(
                    decision_id=payload.result.decision_id,
                    allow=payload.result.allow,
                    effective_class=payload.result.effective_class,
                    obligations=payload.result.obligations,
                    reason_codes=payload.result.reason_codes,
                )
                return AuthorizationEvidence(
                    decision=decision,
                    policy_revision=payload.result.policy_revision,
                    canonical_input_sha256=digest,
                    operation=request.operation,
                )
        except asyncio.CancelledError:
            raise
        except (
            httpx.HTTPError,
            json.JSONDecodeError,
            UnicodeDecodeError,
            ValidationError,
            TimeoutError,
            ValueError,
        ):
            return AuthorizationEvidence(
                decision=_denial(request.decision_id, "policy_unavailable"),
                policy_revision=None,
                canonical_input_sha256=digest,
                operation=request.operation,
            )


class PolicyPortAdapter:
    def __init__(self, client: PolicyClient, facts: TrustedPolicyFactsProvider) -> None:
        self._client = client
        self._facts = facts

    async def authorize(
        self,
        context: RequestContext,
        operation: str,
        resources: Sequence[ResourceRef],
        attributes: Mapping[str, JsonValue],
    ) -> PolicyDecision:
        decision_id = new_id()
        try:
            _validate_ijson(attributes)
        except (TypeError, ValueError, UnicodeError):
            return _denial(decision_id, "invalid_policy_input")
        if SECURITY_ATTRIBUTE_KEYS.intersection(attributes) or any(
            resource.tenant_id != context.tenant_id for resource in resources
        ):
            return _denial(decision_id, "invalid_policy_input")
        try:
            facts = await self._facts.get_facts(context, operation, resources, attributes)
        except asyncio.CancelledError:
            raise
        except Exception:
            return _denial(decision_id, "policy_unavailable")
        try:
            requested = CapabilitySet(
                tools=facts.used_tools,
                object_types=frozenset(resource.kind for resource in resources),
                properties=facts.used_properties,
                actions=facts.used_actions | {operation},
                external_destinations=facts.used_external_destinations,
            )
            if context.agent_id is not None:
                facts = TrustedPolicyFacts.model_validate(
                    {**facts.model_dump(), "requested_capabilities": requested}
                )
            request = AuthorizationInput(
                decision_id=decision_id,
                actor=ActorIdentity(
                    actor_id=context.actor_id,
                    roles=context.roles,
                    scopes=context.scopes,
                    sensitivity_clearances=context.sensitivity_clearances,
                    agent_id=context.agent_id,
                ),
                tenant_id=context.tenant_id,
                resources=tuple(resources),
                operation=operation,
                attributes=attributes,
                delegation_chain=facts.delegation_chain,
                trusted_facts=facts,
            )
        except (TypeError, ValueError, ValidationError):
            return _denial(decision_id, "invalid_policy_input")
        return await self._client.authorize(request)


def _denial(decision_id: UUID, reason: str) -> PolicyDecision:
    return PolicyDecision(decision_id=decision_id, allow=False, reason_codes=(reason,))


def _valid_obligation(value: str) -> bool:
    if value == "require_approval":
        return True
    if value.startswith("max_rows:"):
        number = value.removeprefix("max_rows:")
        return number.isdigit() and int(number) > 0 and str(int(number)) == number
    if value.startswith("redact_properties:"):
        properties = value.removeprefix("redact_properties:").split(",")
        return bool(properties) and all(properties) and properties == sorted(set(properties))
    return False


def _jsonable(value: object) -> JsonValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in sorted(value.items())}
    if isinstance(value, (set, frozenset)):
        return [_jsonable(item) for item in sorted(value, key=str)]
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    raise TypeError(f"non-JSON policy value: {type(value).__name__}")


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
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            _validate_ijson(key)
            _validate_ijson(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_ijson(item)
        return
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")
