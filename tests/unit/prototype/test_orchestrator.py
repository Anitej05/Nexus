"""Bounded process-local coordination contracts."""

from __future__ import annotations

import asyncio

import pytest
from _contract import require_module


@pytest.mark.asyncio
async def test_coordinator_fans_out_specialists_then_runs_the_critic() -> None:
    """The critic is allowed only after both bounded specialists complete."""
    orchestrator = require_module("nexus_api.prototype.orchestrator")
    result = await orchestrator.coordinate("storm-and-checkout-shift-v1")
    assert tuple(item.agent_role for item in result.specialists) == (
        "supply_risk_analyst",
        "it_incident_analyst",
    )
    assert result.critic.agent_role == "decision_critic"
    assert result.critic.uncertainty_code == (
        "Correlated operational priority, not a proven causal link"
    )
    assert set(result.critic.evidence_node_ids) <= set(result.allowlisted_evidence_node_ids)


@pytest.mark.asyncio
async def test_coordinator_uses_concurrent_fanout_without_leaking_unallowlisted_findings() -> None:
    """A serial coordinator or fabricated critic citation breaks the prototype boundary."""
    orchestrator = require_module("nexus_api.prototype.orchestrator")
    starts: list[str] = []
    completions: list[str] = []
    critic_inputs: list[tuple[object, ...]] = []
    release = asyncio.Event()

    async def specialist(name: str) -> dict[str, object]:
        starts.append(name)
        await release.wait()
        completions.append(name)
        return {"agent_role": name, "evidence_node_ids": ["PORT-MAA"]}

    async def critic(findings: tuple[object, ...]) -> dict[str, object]:
        critic_inputs.append(findings)
        assert set(completions) == {"supply_risk_analyst", "it_incident_analyst"}
        assert len(findings) == 2
        return {
            "agent_role": "decision_critic",
            "evidence_node_ids": ["PORT-MAA"],
            "uncertainty_code": "Correlated operational priority, not a proven causal link",
        }

    task = asyncio.create_task(
        orchestrator.coordinate(
            "storm-and-checkout-shift-v1",
            supply_specialist=lambda: specialist("supply_risk_analyst"),
            incident_specialist=lambda: specialist("it_incident_analyst"),
            decision_critic=critic,
        )
    )
    for _ in range(20):
        if len(starts) == 2:
            break
        await asyncio.sleep(0)
    assert starts == ["supply_risk_analyst", "it_incident_analyst"]
    release.set()
    result = await task
    assert len(critic_inputs) == 1
    assert tuple(item.agent_role for item in critic_inputs[0]) == (
        "supply_risk_analyst",
        "it_incident_analyst",
    )
    assert all(
        set(finding.evidence_node_ids) <= set(result.allowlisted_evidence_node_ids)
        for finding in (*result.specialists, result.critic)
    )
