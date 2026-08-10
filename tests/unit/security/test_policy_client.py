from __future__ import annotations

import asyncio
import json
import math
import time
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

import httpx
import pytest
from nexus_contracts.platform import JsonValue, RequestContext, ResourceRef
from nexus_security.policy import (
    ActorIdentity,
    AuthorizationInput,
    CapabilitySet,
    PolicyClient,
    PolicyPortAdapter,
    TrustedPolicyFacts,
)
from pydantic import ValidationError

TENANT = UUID("018f0000-0000-7000-8000-000000000001")
ACTOR = UUID("018f0000-0000-7000-8000-000000000002")
CORRELATION = UUID("018f0000-0000-7000-8000-000000000003")
RESOURCE = UUID("018f0000-0000-7000-8000-000000000011")


def authz_input() -> AuthorizationInput:
    return AuthorizationInput(
        decision_id=UUID("018f0000-0000-7000-8000-000000000021"),
        actor=ActorIdentity(
            actor_id=ACTOR,
            roles=frozenset({"viewer"}),
            scopes=frozenset({"ontology.read"}),
            sensitivity_clearances=frozenset({"internal"}),
        ),
        tenant_id=TENANT,
        resources=(ResourceRef(tenant_id=TENANT, kind="ontology_object", id=RESOURCE, version=1),),
        operation="ontology.read",
        attributes={"purpose": "operations"},
        trusted_facts=TrustedPolicyFacts(
            resource_sensitivity=frozenset({"internal"}),
            configured_base_risk="R0",
            contextual_risk="R0",
        ),
    )


def decision_payload(value: AuthorizationInput | None = None) -> dict[str, Any]:
    item = value or authz_input()
    return {
        "result": {
            "decision_id": str(item.decision_id),
            "allow": True,
            "effective_class": "R0",
            "obligations": [],
            "reason_codes": ["explicit_grant"],
            "policy_revision": "1.0.0",
        }
    }


@pytest.mark.asyncio
async def test_success_returns_canonical_evidence() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["strict-builtin-errors"] == "true"
        assert json.loads(request.content)["input"] == authz_input().to_opa_input()
        return httpx.Response(200, json=decision_payload())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        evidence = await PolicyClient(http).authorize_with_evidence(authz_input())

    assert evidence.decision.allow
    assert evidence.policy_revision == "1.0.0"
    assert len(evidence.canonical_input_sha256) == 64
    assert evidence.decision.reason_codes == ("explicit_grant",)
    assert evidence.operation == "ontology.read"


@pytest.mark.asyncio
async def test_fail_closed_evidence_retains_the_requested_operation() -> None:
    request = authz_input().model_copy(update={"operation": "audit.read"})
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(503))
    ) as http:
        unavailable = await PolicyClient(http).authorize_with_evidence(request)
    invalid_request = request.model_copy(update={"attributes": {"unsafe": object()}})
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=decision_payload()))
    ) as http:
        invalid = await PolicyClient(http).authorize_with_evidence(invalid_request)

    assert unavailable.operation == "audit.read"
    assert unavailable.decision.reason_codes == ("policy_unavailable",)
    assert invalid.operation == "audit.read"
    assert invalid.decision.reason_codes == ("invalid_policy_input",)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(503),
        httpx.Response(200, content=b"not-json"),
        httpx.Response(200, json={}),
        httpx.Response(200, json={"result": {"allow": True}}),
        httpx.Response(200, json={**decision_payload(), "extra": 1}),
    ],
)
async def test_transport_and_schema_fail_closed(response: httpx.Response) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: response)) as http:
        decision = await PolicyClient(http).authorize(authz_input())
    assert decision.decision_id == authz_input().decision_id
    assert not decision.allow
    assert decision.reason_codes == ("policy_unavailable",)


@pytest.mark.asyncio
async def test_connection_failure_and_oversize_fail_closed() -> None:
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as http:
        assert (await PolicyClient(http).authorize(authz_input())).reason_codes == (
            "policy_unavailable",
        )
    body = b"{" + (b" " * 70_000) + b"}"
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=body))
    ) as http:
        decision = await PolicyClient(http, max_response_bytes=65_536).authorize(authz_input())
        assert not decision.allow


@pytest.mark.asyncio
async def test_cancellation_propagates() -> None:
    async def cancelled(_: httpx.Request) -> httpx.Response:
        raise asyncio.CancelledError

    async with httpx.AsyncClient(transport=httpx.MockTransport(cancelled)) as http:
        with pytest.raises(asyncio.CancelledError):
            await PolicyClient(http).authorize(authz_input())


class FactsProvider:
    async def get_facts(
        self,
        context: RequestContext,
        operation: str,
        resources: Sequence[ResourceRef],
        attributes: Mapping[str, JsonValue],
    ) -> TrustedPolicyFacts:
        return TrustedPolicyFacts(
            resource_sensitivity=frozenset({"internal"}),
            configured_base_risk="R0",
            contextual_risk="R0",
        )


@pytest.mark.asyncio
async def test_adapter_canonicalizes_trusted_context_and_rejects_security_overrides() -> None:
    captured: dict[str, Any] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content)["input"])
        value = UUID(captured["decision_id"])
        direct = authz_input().model_copy(update={"decision_id": value})
        assert captured == direct.to_opa_input()
        return httpx.Response(200, json=decision_payload(direct))

    context = RequestContext(
        tenant_id=TENANT,
        actor_id=ACTOR,
        correlation_id=CORRELATION,
        roles=frozenset({"viewer"}),
        scopes=frozenset({"ontology.read"}),
        sensitivity_clearances=frozenset({"internal"}),
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        adapter = PolicyPortAdapter(PolicyClient(http), FactsProvider())
        decision = await adapter.authorize(
            context,
            "ontology.read",
            authz_input().resources,
            {"purpose": "operations"},
        )
        assert decision.allow
        denied = await adapter.authorize(
            context,
            "ontology.read",
            authz_input().resources,
            {"roles": ["platform_admin"]},
        )
    assert captured["actor"]["roles"] == ["viewer"]
    assert denied.reason_codes == ("invalid_policy_input",)


@pytest.mark.asyncio
async def test_adapter_rejects_cross_tenant_without_http() -> None:
    called = False

    async def handler(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    context = RequestContext(
        tenant_id=TENANT,
        actor_id=ACTOR,
        correlation_id=CORRELATION,
        roles=frozenset({"viewer"}),
        scopes=frozenset({"ontology.read"}),
        sensitivity_clearances=frozenset({"internal"}),
    )
    other = UUID("018f0000-0000-7000-8000-000000000099")
    resource = ResourceRef(tenant_id=other, kind="x", id=RESOURCE)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        decision = await PolicyPortAdapter(PolicyClient(http), FactsProvider()).authorize(
            context, "ontology.read", (resource,), {}
        )
    assert not called
    assert decision.reason_codes == ("invalid_policy_input",)


def test_capability_sets_are_typed_and_frozen() -> None:
    scope = CapabilitySet(tools=frozenset({"search"}), object_types=frozenset({"shipment"}))
    assert scope.tools == frozenset({"search"})
    with pytest.raises(ValidationError):
        CapabilitySet(actions=frozenset({""}))


def test_trusted_classification_and_risk_are_explicit() -> None:
    with pytest.raises(ValidationError):
        TrustedPolicyFacts()  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        TrustedPolicyFacts(
            resource_sensitivity=frozenset(),
            configured_base_risk="R0",
            contextual_risk="R0",
        )
    public = TrustedPolicyFacts(
        resource_sensitivity=frozenset({"public"}),
        configured_base_risk="R0",
        contextual_risk="R0",
    )
    assert public.resource_sensitivity == frozenset({"public"})


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, 2**53, -(2**53)])
def test_attributes_reject_non_ijson_values(value: float | int) -> None:
    with pytest.raises(ValidationError):
        authz_input().model_copy(update={"attributes": {"unsafe": value}}).model_validate(
            authz_input().model_copy(update={"attributes": {"unsafe": value}}).model_dump()
        )


class BrokenFactsProvider:
    async def get_facts(
        self,
        context: RequestContext,
        operation: str,
        resources: Sequence[ResourceRef],
        attributes: Mapping[str, JsonValue],
    ) -> TrustedPolicyFacts:
        raise OSError("facts unavailable")


@pytest.mark.asyncio
async def test_fact_provider_failure_is_same_id_policy_unavailable() -> None:
    context = RequestContext(
        tenant_id=TENANT,
        actor_id=ACTOR,
        correlation_id=CORRELATION,
        roles=frozenset({"viewer"}),
        scopes=frozenset({"ontology.read"}),
        sensitivity_clearances=frozenset({"internal"}),
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(500))
    ) as http:
        decision = await PolicyPortAdapter(PolicyClient(http), BrokenFactsProvider()).authorize(
            context, "ontology.read", authz_input().resources, {}
        )
    assert not decision.allow
    assert decision.reason_codes == ("policy_unavailable",)


@pytest.mark.asyncio
async def test_adapter_rejects_unsupported_attribute_before_fact_lookup() -> None:
    called = False

    class CountingFacts(FactsProvider):
        async def get_facts(
            self,
            context: RequestContext,
            operation: str,
            resources: Sequence[ResourceRef],
            attributes: Mapping[str, JsonValue],
        ) -> TrustedPolicyFacts:
            nonlocal called
            called = True
            return await super().get_facts(context, operation, resources, attributes)

    context = RequestContext(
        tenant_id=TENANT,
        actor_id=ACTOR,
        correlation_id=CORRELATION,
        roles=frozenset({"viewer"}),
        scopes=frozenset({"ontology.read"}),
        sensitivity_clearances=frozenset({"internal"}),
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(500))
    ) as http:
        decision = await PolicyPortAdapter(PolicyClient(http), CountingFacts()).authorize(
            context,
            "ontology.read",
            authz_input().resources,
            {"unsupported": object()},  # type: ignore[dict-item]
        )
    assert not called
    assert decision.reason_codes == ("invalid_policy_input",)


def test_action_execution_requires_immutable_provenance() -> None:
    payload = authz_input().model_dump()
    payload["operation"] = "action.execute"
    with pytest.raises(ValidationError):
        AuthorizationInput.model_validate(payload)


@pytest.mark.asyncio
async def test_adapter_derives_agent_capability_from_operation_and_resources() -> None:
    agent_id = UUID("018f0000-0000-7000-8000-000000000030")

    class AgentFacts(FactsProvider):
        async def get_facts(
            self,
            context: RequestContext,
            operation: str,
            resources: Sequence[ResourceRef],
            attributes: Mapping[str, JsonValue],
        ) -> TrustedPolicyFacts:
            from nexus_security.policy import DelegationLink

            root = CapabilitySet(
                object_types=frozenset({"ontology_object"}),
                actions=frozenset({"ontology.read"}),
            )
            return TrustedPolicyFacts(
                resource_sensitivity=frozenset({"internal"}),
                configured_base_risk="R0",
                contextual_risk="R0",
                delegator_capabilities=root,
                delegation_chain=(
                    DelegationLink(
                        tenant_id=TENANT,
                        delegator_id=ACTOR,
                        delegate_id=agent_id,
                        capabilities=root,
                    ),
                ),
            )

    captured: dict[str, Any] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content)["input"])
        value = authz_input().model_copy(update={"decision_id": UUID(captured["decision_id"])})
        return httpx.Response(200, json=decision_payload(value))

    context = RequestContext(
        tenant_id=TENANT,
        actor_id=ACTOR,
        correlation_id=CORRELATION,
        roles=frozenset({"viewer"}),
        scopes=frozenset({"ontology.read"}),
        sensitivity_clearances=frozenset({"internal"}),
        agent_id=agent_id,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        await PolicyPortAdapter(PolicyClient(http), AgentFacts()).authorize(
            context, "ontology.read", authz_input().resources, {}
        )
    requested = captured["trusted_facts"]["requested_capabilities"]
    assert requested["actions"] == ["ontology.read"]
    assert requested["object_types"] == ["ontology_object"]


class SlowStream(httpx.AsyncByteStream):
    async def __aiter__(self):  # type: ignore[no-untyped-def]
        body = json.dumps(decision_payload()).encode()
        for offset in range(0, len(body), 20):
            await asyncio.sleep(0.03)
            yield body[offset : offset + 20]


@pytest.mark.asyncio
async def test_total_deadline_bounds_slow_multichunk_stream() -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(200, stream=SlowStream()))
    started = time.monotonic()
    async with httpx.AsyncClient(transport=transport) as http:
        decision = await PolicyClient(http, timeout_seconds=0.05).authorize(authz_input())
    assert time.monotonic() - started < 0.15
    assert decision.reason_codes == ("policy_unavailable",)
