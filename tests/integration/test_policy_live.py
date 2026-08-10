from __future__ import annotations

import os
from uuid import UUID

import httpx
import pytest
from nexus_contracts.platform import ResourceRef
from nexus_security.policy import (
    ActorIdentity,
    AuthorizationInput,
    PolicyClient,
    TrustedPolicyFacts,
)


@pytest.mark.skipif(
    os.environ.get("NEXUS_RUN_OPA_TESTS") != "1",
    reason="set NEXUS_RUN_OPA_TESTS=1 when the pinned local OPA service is running",
)
@pytest.mark.asyncio
async def test_live_policy_allows_explicit_read_and_default_denies_write() -> None:
    tenant = UUID("018f0000-0000-7000-8000-000000000001")
    actor = ActorIdentity(
        actor_id=UUID("018f0000-0000-7000-8000-000000000002"),
        roles=frozenset({"viewer"}),
        scopes=frozenset({"ontology.read", "ontology.write"}),
        sensitivity_clearances=frozenset({"internal"}),
    )
    resource = ResourceRef(
        tenant_id=tenant,
        kind="ontology_object",
        id=UUID("018f0000-0000-7000-8000-000000000011"),
        version=1,
    )
    facts = TrustedPolicyFacts(
        resource_sensitivity=frozenset({"internal"}),
        configured_base_risk="R0",
        contextual_risk="R0",
    )
    base = AuthorizationInput(
        decision_id=UUID("018f0000-0000-7000-8000-000000000021"),
        actor=actor,
        tenant_id=tenant,
        resources=(resource,),
        operation="ontology.read",
        attributes={},
        trusted_facts=facts,
    )
    url = os.environ.get(
        "NEXUS_OPA_LIVE_DECISION_URL",
        "http://127.0.0.1:8181/v1/data/nexus/authz/decision",
    )
    async with httpx.AsyncClient() as http:
        client = PolicyClient(http, url)
        allowed = await client.authorize(base)
        denied = await client.authorize(
            base.model_copy(
                update={
                    "decision_id": UUID("018f0000-0000-7000-8000-000000000022"),
                    "operation": "ontology.write",
                }
            )
        )
    assert allowed.allow
    assert allowed.effective_class == "R0"
    assert not denied.allow
    assert denied.reason_codes == ("denied",)


@pytest.mark.skipif(
    os.environ.get("NEXUS_RUN_OPA_TESTS") != "1",
    reason="set NEXUS_RUN_OPA_TESTS=1 for explicit unavailable-policy smoke",
)
@pytest.mark.asyncio
async def test_live_transport_refusal_fails_closed() -> None:
    tenant = UUID("018f0000-0000-7000-8000-000000000001")
    request = AuthorizationInput(
        decision_id=UUID("018f0000-0000-7000-8000-000000000023"),
        actor=ActorIdentity(
            actor_id=UUID("018f0000-0000-7000-8000-000000000002"),
            roles=frozenset({"viewer"}),
            scopes=frozenset({"ontology.read"}),
            sensitivity_clearances=frozenset({"internal"}),
        ),
        tenant_id=tenant,
        resources=(),
        operation="ontology.read",
        attributes={},
        trusted_facts=TrustedPolicyFacts(
            resource_sensitivity=frozenset({"internal"}),
            configured_base_risk="R0",
            contextual_risk="R0",
        ),
    )
    async with httpx.AsyncClient() as http:
        decision = await PolicyClient(
            http,
            "http://127.0.0.1:1/v1/data/nexus/authz/decision",
        ).authorize(request)
    assert not decision.allow
    assert decision.decision_id == request.decision_id
    assert decision.reason_codes == ("policy_unavailable",)


@pytest.mark.skipif(
    os.environ.get("NEXUS_RUN_OPA_TESTS") != "1",
    reason="set NEXUS_RUN_OPA_TESTS=1 for protected-surface smoke",
)
@pytest.mark.asyncio
async def test_live_opa_management_surface_rejects_mutation() -> None:
    base = os.environ.get("NEXUS_OPA_LIVE_BASE_URL", "http://127.0.0.1:8181")
    async with httpx.AsyncClient() as http:
        put = await http.put(f"{base}/v1/data/nexus/roles/viewer", json=["ontology.write"])
        delete = await http.delete(f"{base}/v1/policies/nexus-authz")
        decision = await http.post(
            f"{base}/v1/data/nexus/authz/decision",
            json={
                "input": {
                    "decision_id": "018f0000-0000-7000-8000-000000000024",
                    "tenant_id": "018f0000-0000-7000-8000-000000000001",
                    "actor": {
                        "actor_id": "018f0000-0000-7000-8000-000000000002",
                        "agent_id": None,
                        "roles": ["viewer"],
                        "scopes": ["ontology.write"],
                        "sensitivity_clearances": ["public"],
                    },
                    "resources": [],
                    "operation": "ontology.write",
                    "attributes": {},
                    "delegation_chain": [],
                    "trusted_facts": {
                        "resource_sensitivity": ["public"],
                        "configured_base_risk": "R0",
                        "contextual_risk": "R0",
                        "delegator_capabilities": None,
                        "requested_capabilities": None,
                        "used_tools": [],
                        "used_properties": [],
                        "used_actions": [],
                        "used_external_destinations": [],
                        "approval": None,
                        "action_id": None,
                        "action_version": None,
                        "plan_hash": None,
                        "consumer_enforced_obligations": [],
                        "obligations": [],
                    },
                }
            },
        )
    assert put.status_code in {401, 403}
    assert delete.status_code in {401, 403}
    assert decision.status_code == 200
    assert decision.json()["result"]["allow"] is False
