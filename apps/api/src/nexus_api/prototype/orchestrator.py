"""Bounded process-local specialist fan-out and advisory synthesis."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from nexus_contracts.platform import RequestContext
from nexus_security.audit import canonical_json_bytes

from nexus_api.prototype.models import (
    AgentRole,
    FrozenPrototypeContract,
    PrototypeAdvisory,
    PrototypeAgentFinding,
    PrototypeGraph,
    PrototypeOrchestrationResult,
    PrototypePlan,
    PrototypeSignal,
)
from nexus_api.prototype.risk import incident_risk_signal, supply_risk_signal


class AdvisoryFacade(Protocol):
    async def generate(
        self,
        graph: PrototypeGraph,
        signals: tuple[PrototypeSignal, PrototypeSignal],
        findings: tuple[PrototypeAgentFinding, PrototypeAgentFinding, PrototypeAgentFinding],
        *,
        context: RequestContext | None,
        idempotency_key: str,
    ) -> PrototypeAdvisory: ...


class DeterministicAdvisoryFacade:
    """Fact-only degradation that cannot alter governed values."""

    async def generate(
        self,
        graph: PrototypeGraph,
        signals: tuple[PrototypeSignal, PrototypeSignal],
        findings: tuple[PrototypeAgentFinding, PrototypeAgentFinding, PrototypeAgentFinding],
        *,
        context: RequestContext | None,
        idempotency_key: str,
    ) -> PrototypeAdvisory:
        del graph, signals, findings, context, idempotency_key
        summary = b"Supply and IT risks exceed their fixed thresholds; human review is required."
        return PrototypeAdvisory(
            provider_status="unavailable",
            model_id="deepseek-ai/DeepSeek-V4-Flash-0731",
            summary_sha256=hashlib.sha256(summary).hexdigest(),
            citation_node_ids=("PORT-MAA", "SHP-0042", "DEP-882", "svc-checkout"),
        )


async def _supply_specialist(
    graph: PrototypeGraph,
) -> tuple[PrototypeSignal, PrototypeAgentFinding]:
    signal = supply_risk_signal(graph)
    return signal, PrototypeAgentFinding(
        agent_role="supply_risk_analyst",
        status="completed",
        finding_code="supply_delay_threshold_exceeded",
        evidence_node_ids=signal.evidence_node_ids,
        uncertainty_code="Deterministic projection; no live logistics telemetry",
    )


async def _it_specialist(graph: PrototypeGraph) -> tuple[PrototypeSignal, PrototypeAgentFinding]:
    signal = incident_risk_signal(graph)
    return signal, PrototypeAgentFinding(
        agent_role="it_incident_analyst",
        status="completed",
        finding_code="incident_risk_threshold_exceeded",
        evidence_node_ids=signal.evidence_node_ids,
        uncertainty_code="Temporal association; not a deployment root-cause proof",
    )


def build_prototype_plan() -> PrototypePlan:
    material = {
        "action_kind": "simulated_reroute",
        "destination": "sim://reroute/PORT-MAA",
        "expected_effect": "reduce_predicted_delay_by_14_hours",
        "risk_class": "R3",
        "target_id": "SHP-0042",
    }
    return PrototypePlan(plan_hash=hashlib.sha256(canonical_json_bytes(material)).hexdigest())


class PrototypeOrchestrator:
    def __init__(self, advisory: AdvisoryFacade) -> None:
        self._advisory = advisory

    async def run(
        self,
        graph: PrototypeGraph,
        *,
        idempotency_key: str,
        context: RequestContext | None = None,
    ) -> PrototypeOrchestrationResult:
        supply, incident = await asyncio.gather(_supply_specialist(graph), _it_specialist(graph))
        signals = (supply[0], incident[0])
        critic = PrototypeAgentFinding(
            agent_role="decision_critic",
            status="completed",
            finding_code="cross_domain_priority_correlated",
            evidence_node_ids=("shift-2026-08-09", "PORT-MAA", "DEP-882"),
            uncertainty_code="Correlated operational priority, not a proven causal link",
        )
        findings = (supply[1], incident[1], critic)
        advisory = await self._advisory.generate(
            graph, signals, findings, context=context, idempotency_key=idempotency_key
        )
        return PrototypeOrchestrationResult(
            signals=signals, findings=findings, advisory=advisory, plan=build_prototype_plan()
        )


class PrototypeCoordinationResult(FrozenPrototypeContract):
    specialists: tuple[PrototypeAgentFinding, PrototypeAgentFinding]
    critic: PrototypeAgentFinding
    allowlisted_evidence_node_ids: tuple[str, ...]


def _coerce_finding(
    value: PrototypeAgentFinding | dict[str, Any], *, role: AgentRole
) -> PrototypeAgentFinding:
    if isinstance(value, PrototypeAgentFinding):
        return value
    return PrototypeAgentFinding(
        agent_role=role,
        status="completed",
        finding_code=str(value.get("finding_code", f"{role}_completed")),
        evidence_node_ids=tuple(value.get("evidence_node_ids", ())),
        uncertainty_code=str(
            value.get(
                "uncertainty_code",
                "Correlated operational priority, not a proven causal link"
                if role == "decision_critic"
                else "Bounded deterministic prototype evidence",
            )
        ),
    )


async def coordinate(
    scenario_id: str,
    *,
    supply_specialist: Callable[[], Awaitable[PrototypeAgentFinding | dict[str, Any]]]
    | None = None,
    incident_specialist: Callable[[], Awaitable[PrototypeAgentFinding | dict[str, Any]]]
    | None = None,
    decision_critic: Callable[
        [tuple[PrototypeAgentFinding, ...]], Awaitable[PrototypeAgentFinding | dict[str, Any]]
    ]
    | None = None,
) -> PrototypeCoordinationResult:
    """Expose the bounded fan-out/critic sequence without provider or persistence I/O."""
    from nexus_api.prototype.seed import build_projection

    graph = build_projection(scenario_id)

    async def default_supply() -> PrototypeAgentFinding:
        return (await _supply_specialist(graph))[1]

    async def default_incident() -> PrototypeAgentFinding:
        return (await _it_specialist(graph))[1]

    supply_raw, incident_raw = await asyncio.gather(
        (supply_specialist or default_supply)(), (incident_specialist or default_incident)()
    )
    specialists = (
        _coerce_finding(supply_raw, role="supply_risk_analyst"),
        _coerce_finding(incident_raw, role="it_incident_analyst"),
    )
    if decision_critic is None:
        critic_raw: PrototypeAgentFinding | dict[str, Any] = PrototypeAgentFinding(
            agent_role="decision_critic",
            status="completed",
            finding_code="cross_domain_priority_correlated",
            evidence_node_ids=("shift-2026-08-09", "PORT-MAA", "DEP-882"),
            uncertainty_code="Correlated operational priority, not a proven causal link",
        )
    else:
        critic_raw = await decision_critic(specialists)
    critic = _coerce_finding(critic_raw, role="decision_critic")
    allowlist = tuple(node.id for node in graph.nodes)
    if any(not set(item.evidence_node_ids) <= set(allowlist) for item in (*specialists, critic)):
        raise ValueError("specialist cited evidence outside the fixed graph")
    return PrototypeCoordinationResult(
        specialists=specialists, critic=critic, allowlisted_evidence_node_ids=allowlist
    )
