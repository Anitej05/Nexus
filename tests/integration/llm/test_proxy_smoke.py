"""Explicitly gated live smoke for the local OpenAI-compatible Hugging Face proxy."""

from __future__ import annotations

import os
from datetime import UTC

import pytest
from nexus_contracts.platform import RequestContext
from nexus_contracts.prototype import EvidenceFact, SpecialistFinding
from nexus_llm import (
    InvalidStructuredOutput,
    LLMSettings,
    OpenAICompatibleStructuredOutput,
    ProviderTimeout,
    ProviderUnavailable,
    canonical_evidence_prompt,
)
from nexus_prototype.fixtures import (  # type: ignore[import-untyped]
    FIXTURE_SEED,
    TENANT_ID,
    build_fixture_events,
)
from nexus_prototype.models import event_ref  # type: ignore[import-untyped]

pytestmark = pytest.mark.skipif(
    os.getenv("NEXUS_RUN_LLM_SMOKE") != "1",
    reason="set NEXUS_RUN_LLM_SMOKE=1 to exercise the local proxy",
)


@pytest.mark.asyncio
async def test_local_proxy_discovers_exact_model_and_returns_structured_citations() -> None:
    """The opt-in smoke proves discovery and typed generation without printing provider text."""
    events = build_fixture_events(seed=FIXTURE_SEED)
    facts = tuple(
        EvidenceFact(
            ref=event_ref(TENANT_ID, event.event_id),
            occurred_at=event.occurred_at.astimezone(UTC),
            predicate=str(event.payload.get("fact"))
            if isinstance(event.payload, dict)
            else "event",
            value=event.payload,
        )
        for event in events
    )
    context = RequestContext(
        tenant_id=TENANT_ID,
        actor_id=events[0].event_id,
        correlation_id=events[0].correlation_id,
        roles=frozenset({"prototype_smoke"}),
        scopes=frozenset({"prototype:read"}),
        sensitivity_clearances=frozenset({"internal"}),
    )
    adapter = OpenAICompatibleStructuredOutput(LLMSettings.from_environment())

    await adapter.discover_model()
    try:
        finding = await adapter.generate_object(
            context,
            canonical_evidence_prompt("causal_investigator", facts),
            SpecialistFinding,
            "live-smoke-seed-41073",
        )
    except InvalidStructuredOutput as exc:
        pytest.fail(
            f"typed live failure: {exc.code}/{','.join(exc.validation_codes)}",
            pytrace=False,
        )
    except (ProviderUnavailable, ProviderTimeout) as exc:
        pytest.fail(f"typed live failure: {exc.code}", pytrace=False)

    allowed = {fact.ref for fact in facts}
    assert finding.abstain or finding.cited_evidence
    assert set(finding.cited_evidence) <= allowed
