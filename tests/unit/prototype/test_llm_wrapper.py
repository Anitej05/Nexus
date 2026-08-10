"""Prototype wrapper contract over the reviewed structured-output provider port."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal
from uuid import UUID

import pytest
from _contract import require_module
from nexus_contracts.platform import RequestContext, ResourceRef
from nexus_contracts.prototype import EvidenceFact, SpecialistFinding
from nexus_llm import (
    InvalidStructuredOutput,
    ProviderTimeout,
    ProviderUnavailable,
    canonical_evidence_prompt,
)

FACT_ONLY_SUMMARY = b"Supply and IT risks exceed their fixed thresholds; human review is required."
FACT_ONLY_CITATIONS = ("PORT-MAA", "SHP-0042", "DEP-882", "svc-checkout")
EXPECTED_NODE_IDS = {
    "shift-2026-08-09",
    "PORT-MAA",
    "SHP-0042",
    "SHP-0047",
    "SHP-0051",
    "CMP-SENSOR-A",
    "PO-1107",
    "PO-1112",
    "DEP-882",
    "svc-checkout",
    "svc-payments",
    "db-ledger",
}
KEY_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _context() -> RequestContext:
    return RequestContext(
        tenant_id=UUID("018f0000-0000-7000-8000-000000000001"),
        actor_id=UUID("018f0000-0000-7000-8000-000000000002"),
        correlation_id=UUID("019fe476-8380-7000-8000-000000000003"),
        roles=frozenset({"operator"}),
        scopes=frozenset({"action.propose"}),
        sensitivity_clearances=frozenset({"internal"}),
    )


def _graph() -> Any:
    return require_module("nexus_api.prototype.seed").build_projection(
        "storm-and-checkout-shift-v1"
    )


Outcome = Literal["valid", "uncited", "injection"] | type[BaseException]


class _ReviewedStructuredOutputPort:
    """Exact fake for `OpenAICompatibleStructuredOutput.generate_object`."""

    def __init__(self, outcome: Outcome) -> None:
        self.outcome = outcome
        self.prompts: list[str] = []
        self.keys: list[str] = []
        self.cited_node_id: str | None = None

    async def generate_object(self, context, prompt, output_type, idempotency_key):
        assert context == _context()
        assert output_type is SpecialistFinding
        assert isinstance(prompt, str) and len(prompt.encode("utf-8")) <= 16_384
        raw = json.loads(prompt)
        assert set(raw) == {"schema_version", "specialist", "facts"}
        facts = tuple(EvidenceFact.model_validate(item) for item in raw["facts"])
        assert 1 <= len(facts) <= 24
        assert prompt == canonical_evidence_prompt(raw["specialist"], facts)
        assert all(fact.ref.tenant_id == context.tenant_id for fact in facts)
        assert all(fact.ref.kind and fact.ref.version == 1 for fact in facts)
        assert len({fact.ref for fact in facts}) == len(facts)
        node_facts = tuple(fact for fact in facts if fact.predicate == "prototype.graph_node")
        node_ids = tuple(
            fact.value.get("node_id")
            for fact in node_facts
            if isinstance(fact.value, dict) and isinstance(fact.value.get("node_id"), str)
        )
        assert len(facts) == 17
        assert len(node_ids) == 12
        assert set(node_ids) == EXPECTED_NODE_IDS
        rendered_facts = json.dumps([fact.value for fact in facts], sort_keys=True)
        assert "0.91" in rendered_facts and "0.94" in rendered_facts
        assert "Correlated operational priority, not a proven causal link" in rendered_facts
        assert KEY_DIGEST.fullmatch(idempotency_key)
        self.prompts.append(prompt)
        self.keys.append(idempotency_key)

        if isinstance(self.outcome, type) and issubclass(self.outcome, BaseException):
            raise self.outcome()
        if self.outcome == "uncited":
            citations = (
                ResourceRef(
                    tenant_id=context.tenant_id,
                    kind="prototype.node",
                    id=UUID("019fe476-8380-7000-8000-000000000999"),
                    version=1,
                ),
            )
        else:
            port_index = node_ids.index("PORT-MAA")
            citations = (node_facts[port_index].ref,)
            self.cited_node_id = "PORT-MAA"
        conclusion = (
            "<script>MODEL-OUTPUT-NEEDLE</script>"
            if self.outcome == "injection"
            else "Prioritize the cited port evidence for human review."
        )
        return SpecialistFinding(
            specialist=raw["specialist"],
            conclusion=conclusion,
            confidence=0.82,
            cited_evidence=citations,
            unresolved_questions=("Confirm carrier capacity.",),
            abstain=False,
        )


async def _run_with_port(port: object, key: str):
    llm = require_module("nexus_api.prototype.llm")
    orchestrator = require_module("nexus_api.prototype.orchestrator")
    return await orchestrator.PrototypeOrchestrator(llm.StructuredAdvisoryFacade(port)).run(
        _graph(), context=_context(), idempotency_key=key
    )


@pytest.mark.asyncio
async def test_valid_reviewed_finding_maps_to_safe_advisory_metadata_and_bound_key() -> None:
    port = _ReviewedStructuredOutputPort("valid")
    first = await _run_with_port(port, "valid-wrapper-command")
    replay = await _run_with_port(port, "valid-wrapper-command")
    changed = await _run_with_port(port, "different-wrapper-command")

    assert first.plan.status == "awaiting_approval"
    assert first.advisory == replay.advisory == changed.advisory
    assert first.advisory.provider_status == "available"
    assert (
        first.advisory.summary_sha256
        == hashlib.sha256(b"Prioritize the cited port evidence for human review.").hexdigest()
    )
    assert tuple(first.advisory.citation_node_ids) == (port.cited_node_id,)
    assert port.prompts[0] == port.prompts[1] == port.prompts[2]
    assert port.keys[0] == port.keys[1]
    assert port.keys[2] != port.keys[0]
    assert "valid-wrapper-command" not in port.keys[0]
    assert not {
        "summary",
        "prompt",
        "model_output",
        "score",
        "plan_hash",
        "approved",
        "execution",
    } & set(type(first.advisory).model_fields)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome,provider_status",
    [
        (ProviderUnavailable, "unavailable"),
        (ProviderTimeout, "timeout"),
        (InvalidStructuredOutput, "invalid_output"),
        ("uncited", "uncited"),
    ],
    ids=("unavailable", "timeout", "malformed", "uncited"),
)
async def test_all_reviewed_provider_failures_become_fact_only_awaiting_approval(
    outcome: Outcome, provider_status: str
) -> None:
    port = _ReviewedStructuredOutputPort(outcome)
    first = await _run_with_port(port, "degraded-wrapper-command")
    second = await _run_with_port(port, "degraded-wrapper-command")

    assert first.plan.status == second.plan.status == "awaiting_approval"
    assert first.advisory == second.advisory
    assert first.advisory.provider_status == provider_status
    assert first.advisory.summary_sha256 == hashlib.sha256(FACT_ONLY_SUMMARY).hexdigest()
    assert tuple(first.advisory.citation_node_ids) == FACT_ONLY_CITATIONS
    assert port.prompts[0] == port.prompts[1]
    assert port.keys[0] == port.keys[1]


@pytest.mark.asyncio
async def test_wrapper_response_never_exposes_bare_markup_or_model_text() -> None:
    """The explicit API response boundary stores safe metadata, never raw advisory markup."""
    result = await _run_with_port(
        _ReviewedStructuredOutputPort("injection"), "injection-wrapper-command"
    )
    serialized = json.dumps(result.advisory.model_dump(mode="json"), sort_keys=True)
    assert result.advisory.provider_status == "available"
    assert "<script>" not in serialized
    assert "MODEL-OUTPUT-NEEDLE" not in serialized
