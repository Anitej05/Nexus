"""Frozen internal/public models for the bounded prototype API."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Literal

from nexus_contracts.platform import FrozenContract
from pydantic import UUID7, Field

ScenarioId = Literal["storm-and-checkout-shift-v1"]
RunStatus = Literal["awaiting_approval", "approved", "rejected", "executed", "verified"]
AgentRole = Literal["supply_risk_analyst", "it_incident_analyst", "decision_critic"]
ProviderStatus = Literal[
    "available", "unavailable", "timeout", "invalid_output", "malformed", "uncited"
]
PromptVersion = Literal["prototype-briefing.v1"]


class FrozenPrototypeContract(FrozenContract):
    """Typed local alias retaining the shared immutable contract policy."""


class CreatePrototypeRunRequest(FrozenPrototypeContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    scenario_id: ScenarioId


class PrototypeApprovalCommand(FrozenPrototypeContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Literal["approve", "reject"]
    reason: str | None = Field(default=None, max_length=256)


class PrototypeExecutionCommand(FrozenPrototypeContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class PrototypeGraphNode(FrozenPrototypeContract):
    id: str = Field(min_length=1, max_length=64)
    type: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=128)
    sensitivity: Literal["internal"] = "internal"


class PrototypeGraphEdge(FrozenPrototypeContract):
    source: str = Field(min_length=1, max_length=64)
    type: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=64)


class PrototypeGraph(FrozenPrototypeContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    projection_kind: Literal["seeded_read_only_prototype"] = "seeded_read_only_prototype"
    scenario_id: ScenarioId
    seed_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    nodes: tuple[PrototypeGraphNode, ...]
    edges: tuple[PrototypeGraphEdge, ...]


class PrototypeSignal(FrozenPrototypeContract):
    domain: Literal["supply", "it"]
    model_version: Literal["demo.supply-delay.v1", "demo.incident-risk.v1"]
    target_id: str
    score: float = Field(ge=0, le=1)
    threshold: float = Field(ge=0, le=1)
    feature_map: Mapping[str, float]
    evidence_node_ids: tuple[str, ...]


class PrototypeAgentFinding(FrozenPrototypeContract):
    agent_role: AgentRole
    status: Literal["completed", "abstained"]
    finding_code: str = Field(min_length=1, max_length=128)
    evidence_node_ids: tuple[str, ...]
    uncertainty_code: str = Field(min_length=1, max_length=256)


class PrototypeAdvisory(FrozenPrototypeContract):
    provider_status: ProviderStatus
    model_id: str = Field(min_length=1, max_length=128)
    prompt_version: PromptVersion = "prototype-briefing.v1"
    summary_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    citation_node_ids: tuple[str, ...]


class PrototypePlan(FrozenPrototypeContract):
    action_kind: Literal["simulated_reroute"] = "simulated_reroute"
    target_id: Literal["SHP-0042"] = "SHP-0042"
    destination: Literal["sim://reroute/PORT-MAA"] = "sim://reroute/PORT-MAA"
    expected_effect: Literal["reduce_predicted_delay_by_14_hours"] = (
        "reduce_predicted_delay_by_14_hours"
    )
    risk_class: Literal["R3"] = "R3"
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["awaiting_approval"] = "awaiting_approval"


class PrototypeApproval(FrozenPrototypeContract):
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approver_id: UUID7
    status: Literal["approved", "rejected"]
    reason_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class PrototypeExecution(FrozenPrototypeContract):
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt_id: str = Field(min_length=1, max_length=128)
    connector_kind: Literal["in_process_simulator"] = "in_process_simulator"
    status: Literal["simulated"] = "simulated"


class PrototypeVerification(FrozenPrototypeContract):
    receipt_id: str = Field(min_length=1, max_length=128)
    status: Literal["verified"] = "verified"
    verified_effect: Literal["delay_reduced"] = "delay_reduced"
    observed_delay_hours: float = Field(ge=0, le=168)


class PrototypeAuditRef(FrozenPrototypeContract):
    event_id: UUID7
    sequence: int = Field(gt=0)
    event_type: str
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class PrototypeRunView(FrozenPrototypeContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    run_id: UUID7
    tenant_id: UUID7
    tenant_name: Literal["Authenticated tenant"] = "Authenticated tenant"
    scenario_id: ScenarioId
    seed_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: RunStatus
    proposer_id: UUID7
    signals: tuple[PrototypeSignal, ...]
    findings: tuple[PrototypeAgentFinding, ...]
    llm: PrototypeAdvisory
    plan: PrototypePlan
    approval: PrototypeApproval | None = None
    execution: PrototypeExecution | None = None
    verification: PrototypeVerification | None = None
    audit_events: tuple[PrototypeAuditRef, ...]


class PrototypeTraceEvent(FrozenPrototypeContract):
    event_id: UUID7
    sequence: int = Field(gt=0)
    occurred_at: datetime
    actor_id: UUID7
    event_type: str
    public_payload: Mapping[str, object]
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class PrototypeTrace(FrozenPrototypeContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    run_id: UUID7
    events: tuple[PrototypeTraceEvent, ...]


class PrototypeOrchestrationResult(FrozenPrototypeContract):
    signals: tuple[PrototypeSignal, PrototypeSignal]
    findings: tuple[PrototypeAgentFinding, PrototypeAgentFinding, PrototypeAgentFinding]
    advisory: PrototypeAdvisory
    plan: PrototypePlan
