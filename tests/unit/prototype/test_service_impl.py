"""Implementation-focused contracts for the prototype domain slice."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx
import pytest
from nexus_api.prototype.llm import StructuredAdvisoryFacade, prototype_llm_settings
from nexus_api.prototype.models import PrototypeExecutionCommand
from nexus_api.prototype.orchestrator import DeterministicAdvisoryFacade, PrototypeOrchestrator
from nexus_api.prototype.risk import incident_risk_signal, supply_risk_signal
from nexus_api.prototype.seed import build_prototype_graph
from nexus_api.prototype.service import (
    PrototypeController,
    PrototypeDependencyUnavailable,
    PrototypeForbidden,
    SimulatedRerouteConnector,
    _require_authorized,
)
from nexus_api.prototype.store import PrototypeStateError, reduce_prototype_events
from nexus_contracts.platform import PolicyDecision, RequestContext, ResourceRef
from nexus_contracts.prototype import SpecialistFinding
from nexus_llm import (
    InvalidStructuredOutput,
    LLMSettings,
    OpenAICompatibleStructuredOutput,
    ProviderTimeout,
    ProviderUnavailable,
)
from nexus_security.audit import AuditActor, AuditEvent, AuditPolicyEvidence
from nexus_security.ids import new_id
from nexus_security.policy import AuthorizationEvidence


class _JsonStream(httpx.AsyncByteStream):
    def __init__(self, payload: object) -> None:
        self._encoded = json.dumps(payload, separators=(",", ":")).encode()

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._encoded


def _streamed_json(payload: object) -> httpx.Response:
    stream = _JsonStream(payload)
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json", "Content-Length": str(len(stream._encoded))},
        stream=stream,
    )


class _StructuredPort:
    def __init__(self, citation_indexes: tuple[int, ...] = (1, 8)) -> None:
        self.citation_indexes = citation_indexes
        self.calls = 0
        self.prompts: list[str] = []

    async def generate_object(self, context, prompt, output_type, idempotency_key):  # type: ignore[no-untyped-def]
        del context, idempotency_key
        self.calls += 1
        self.prompts.append(prompt)
        assert output_type is SpecialistFinding
        document = json.loads(prompt)
        refs = tuple(document["facts"][index]["ref"] for index in self.citation_indexes)
        return SpecialistFinding(
            specialist="decision_critic",
            conclusion="Supply and IT risks exceed their thresholds.",
            confidence=0.82,
            cited_evidence=refs,
            unresolved_questions=("Correlation is not causation.",),
            abstain=False,
        )


class _FailingPort:
    def __init__(self, failure: BaseException) -> None:
        self.failure = failure

    async def generate_object(self, context, prompt, output_type, idempotency_key):  # type: ignore[no-untyped-def]
        del context, prompt, output_type, idempotency_key
        raise self.failure


class _MalformedPort:
    async def generate_object(self, context, prompt, output_type, idempotency_key):  # type: ignore[no-untyped-def]
        del context, prompt, output_type, idempotency_key
        return {"summary": "missing required fields"}


def _context() -> RequestContext:
    return RequestContext(
        tenant_id=new_id(),
        actor_id=new_id(),
        correlation_id=new_id(),
        roles=frozenset({"operator"}),
        scopes=frozenset(),
        sensitivity_clearances=frozenset({"internal"}),
    )


def _audit_chain() -> tuple[AuditEvent, ...]:
    context = _context()
    run_id = new_id()
    graph = build_prototype_graph()
    result = asyncio.run(
        PrototypeOrchestrator(DeterministicAdvisoryFacade()).run(
            graph, idempotency_key="reducer-chain"
        )
    )
    approver = new_id()
    payloads = [
        (
            "prototype.run.created",
            {
                "scenario_id": graph.scenario_id,
                "seed_digest": graph.seed_digest,
                "status": "created",
                "policy_operation": "action.propose",
            },
            context.actor_id,
            "R0",
        ),
        *[
            (
                "prototype.signal.published",
                {
                    **signal.model_dump(mode="json", exclude={"feature_map"}),
                    "policy_operation": "action.propose",
                },
                context.actor_id,
                "R0",
            )
            for signal in result.signals
        ],
        *[
            (
                "prototype.agent.completed",
                {**finding.model_dump(mode="json"), "policy_operation": "action.propose"},
                context.actor_id,
                "R0",
            )
            for finding in result.findings
        ],
        (
            "prototype.briefing.generated",
            {**result.advisory.model_dump(mode="json"), "policy_operation": "action.propose"},
            context.actor_id,
            "R0",
        ),
        (
            "prototype.plan.prepared",
            {
                **result.plan.model_dump(mode="json", exclude={"expected_effect"}),
                "policy_operation": "action.propose",
            },
            context.actor_id,
            "R0",
        ),
        (
            "prototype.approval.recorded",
            {
                "plan_hash": result.plan.plan_hash,
                "approver_id": str(approver),
                "status": "approved",
                "reason_sha256": None,
                "policy_operation": "action.approve",
            },
            approver,
            "R0",
        ),
        (
            "prototype.action.executed",
            {
                "plan_hash": result.plan.plan_hash,
                "receipt_id": "sim-reducer",
                "connector_kind": "in_process_simulator",
                "status": "simulated",
                "policy_operation": "action.execute",
            },
            context.actor_id,
            "R3",
        ),
        (
            "prototype.verification.completed",
            {
                "receipt_id": "sim-reducer",
                "status": "verified",
                "verified_effect": "delay_reduced",
                "observed_delay_hours": 14.0,
                "policy_operation": "action.execute",
            },
            context.actor_id,
            "R3",
        ),
    ]
    return tuple(
        AuditEvent(
            id=new_id(),
            tenant_id=context.tenant_id,
            sequence=index,
            occurred_at=datetime(2026, 8, 9, tzinfo=UTC),
            actor=AuditActor(actor_id=actor_id),
            event_type=event_type,
            resource=ResourceRef(
                tenant_id=context.tenant_id, kind="prototype.run", id=run_id, version=1
            ),
            policy_evidence=AuditPolicyEvidence(
                decision=PolicyDecision(decision_id=new_id(), allow=True, effective_class=risk),
                policy_revision="1.0.0",
                canonical_input_sha256="1" * 64,
                operation=payload["policy_operation"],
            ),
            correlation_id=context.correlation_id,
            public_payload=payload,
            previous_hash="0" * 64,
            hash=f"{index:064x}",
        )
        for index, (event_type, payload, actor_id, risk) in enumerate(payloads, 1)
    )


def test_seed_and_projection_models_are_exact_and_inspectable() -> None:
    graph = build_prototype_graph()
    identifiers = {node.id for node in graph.nodes}

    assert graph.scenario_id == "storm-and-checkout-shift-v1"
    assert {
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
        "shift-2026-08-09",
    } == identifiers
    supply = supply_risk_signal(graph)
    incident = incident_risk_signal(graph)
    assert (supply.score, supply.threshold, supply.model_version) == (
        0.91,
        0.80,
        "demo.supply-delay.v1",
    )
    assert (incident.score, incident.threshold, incident.model_version) == (
        0.94,
        0.80,
        "demo.incident-risk.v1",
    )


def test_projection_models_reject_any_graph_mutation() -> None:
    graph = build_prototype_graph()
    for mutated in (
        graph.model_copy(update={"seed_digest": "0" * 64}),
        graph.model_copy(update={"nodes": graph.nodes[:-1]}),
        graph.model_copy(update={"nodes": graph.nodes + (graph.nodes[0],)}),
        graph.model_copy(update={"edges": graph.edges[:-1]}),
        graph.model_copy(update={"edges": graph.edges + (graph.edges[0],)}),
    ):
        with pytest.raises(ValueError):
            supply_risk_signal(mutated)
        with pytest.raises(ValueError):
            incident_risk_signal(mutated)


def test_orchestrator_fans_out_specialists_then_runs_critic() -> None:
    result = asyncio.run(
        PrototypeOrchestrator(DeterministicAdvisoryFacade()).run(
            build_prototype_graph(), idempotency_key="unit-orchestration"
        )
    )
    assert [finding.agent_role for finding in result.findings] == [
        "supply_risk_analyst",
        "it_incident_analyst",
        "decision_critic",
    ]
    assert result.findings[-1].uncertainty_code == (
        "Correlated operational priority, not a proven causal link"
    )
    assert result.advisory.provider_status == "unavailable"
    assert result.plan.risk_class == "R3"
    assert result.plan.target_id == "SHP-0042"


def test_reducer_rejects_action_before_exact_approval() -> None:
    try:
        reduce_prototype_events(
            (
                ("prototype.run.created", {"scenario_id": "storm-and-checkout-shift-v1"}),
                ("prototype.action.executed", {"status": "simulated"}),
            )
        )
    except PrototypeStateError as error:
        assert "sequence" in str(error)
    else:  # pragma: no cover - demonstrates the fail-closed requirement.
        raise AssertionError("malformed prototype event order was accepted")


def test_reducer_round_trips_configured_model_and_prompt_provenance() -> None:
    chain = list(_audit_chain())
    payload = {**chain[6].public_payload, "model_id": "configured/custom-model"}
    chain[6] = chain[6].model_copy(update={"public_payload": payload})
    view = reduce_prototype_events(chain)
    assert view is not None
    assert view.llm.model_id == "configured/custom-model"
    assert view.llm.prompt_version == "prototype-briefing.v1"


def test_reducer_rejects_denied_policy_evidence_on_every_event() -> None:
    for index in range(11):
        chain = list(_audit_chain())
        evidence = chain[index].policy_evidence
        assert evidence is not None
        chain[index] = chain[index].model_copy(
            update={
                "policy_evidence": evidence.model_copy(
                    update={"decision": evidence.decision.model_copy(update={"allow": False})}
                )
            }
        )
        with pytest.raises(PrototypeStateError, match="policy evidence"):
            reduce_prototype_events(chain)


def test_reducer_rejects_wrong_operation_and_execution_risk() -> None:
    chain = list(_audit_chain())
    chain[8] = chain[8].model_copy(
        update={"public_payload": {**chain[8].public_payload, "policy_operation": "action.execute"}}
    )
    with pytest.raises(PrototypeStateError, match="policy evidence"):
        reduce_prototype_events(chain)

    chain = list(_audit_chain())
    evidence = chain[9].policy_evidence
    assert evidence is not None
    chain[9] = chain[9].model_copy(
        update={"policy_evidence": evidence.model_copy(update={"operation": "action.approve"})}
    )
    with pytest.raises(PrototypeStateError, match="policy evidence"):
        reduce_prototype_events(chain)

    chain = list(_audit_chain())
    evidence = chain[9].policy_evidence
    assert evidence is not None
    chain[9] = chain[9].model_copy(
        update={
            "policy_evidence": evidence.model_copy(
                update={"decision": evidence.decision.model_copy(update={"effective_class": "R0"})}
            )
        }
    )
    with pytest.raises(PrototypeStateError, match="policy evidence"):
        reduce_prototype_events(chain)


def test_authorization_evidence_must_bind_the_expected_operation() -> None:
    evidence = AuthorizationEvidence(
        decision=PolicyDecision(decision_id=new_id(), allow=True, effective_class="R3"),
        policy_revision="1.0.0",
        canonical_input_sha256="a" * 64,
        operation="action.approve",
    )

    with pytest.raises(PrototypeDependencyUnavailable):
        _require_authorized(evidence, "action.execute")


class _ReplaySessions:
    @asynccontextmanager
    async def begin(self, context):  # type: ignore[no-untyped-def]
        del context
        yield object()

    async def dispose(self) -> None:
        return None


class _RecordingPolicy:
    def __init__(self) -> None:
        self.operations: list[str] = []

    async def authorize(self, context, operation, **facts):  # type: ignore[no-untyped-def]
        del context, facts
        self.operations.append(operation)
        return AuthorizationEvidence(
            decision=PolicyDecision(
                decision_id=new_id(), allow=True, effective_class="R0", reason_codes=("allowed",)
            ),
            policy_revision="1.0.0",
            canonical_input_sha256="b" * 64,
            operation=operation,
        )


@pytest.mark.asyncio
async def test_exact_execution_replay_revalidates_actor_plan_and_read_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nexus_api.prototype.service as service_module

    chain = await asyncio.to_thread(_audit_chain)
    view = reduce_prototype_events(chain)
    assert view is not None
    context = _context().model_copy(
        update={"tenant_id": view.tenant_id, "actor_id": view.proposer_id}
    )
    receipt = SimulatedRerouteConnector().execute(view.run_id, view.plan.plan_hash)
    replay = chain[9].model_copy(
        update={
            "public_payload": {
                "plan_hash": view.plan.plan_hash,
                "receipt_id": receipt,
                "connector_kind": "in_process_simulator",
                "status": "simulated",
                "policy_operation": "action.execute",
            }
        }
    )

    class ReplayStore:
        def __init__(self, session) -> None:  # type: ignore[no-untyped-def]
            del session

        async def lock_tenant(self, tenant_id) -> None:  # type: ignore[no-untyped-def]
            del tenant_id

        async def load(self, trusted, run_id):  # type: ignore[no-untyped-def]
            del trusted, run_id
            return view

        async def find_command(self, trusted, key):  # type: ignore[no-untyped-def]
            del trusted, key
            return replay

    monkeypatch.setattr(service_module, "PrototypeStore", ReplayStore)
    policy = _RecordingPolicy()
    controller = PrototypeController(
        _ReplaySessions(), policy, DeterministicAdvisoryFacade()  # type: ignore[arg-type]
    )
    command = PrototypeExecutionCommand(plan_hash=view.plan.plan_hash)

    returned = await controller.execute(
        context, view.run_id, command, "exact-replay", view.plan.plan_hash
    )

    assert returned == view
    assert policy.operations == ["action.read"]


@pytest.mark.asyncio
async def test_exact_execution_replay_does_not_authorize_a_different_actor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nexus_api.prototype.service as service_module

    chain = await asyncio.to_thread(_audit_chain)
    view = reduce_prototype_events(chain)
    assert view is not None
    receipt = SimulatedRerouteConnector().execute(view.run_id, view.plan.plan_hash)
    replay = chain[9].model_copy(
        update={
            "public_payload": {
                "plan_hash": view.plan.plan_hash,
                "receipt_id": receipt,
                "connector_kind": "in_process_simulator",
                "status": "simulated",
                "policy_operation": "action.execute",
            }
        }
    )

    class ReplayStore:
        def __init__(self, session) -> None:  # type: ignore[no-untyped-def]
            del session

        async def lock_tenant(self, tenant_id) -> None:  # type: ignore[no-untyped-def]
            del tenant_id

        async def load(self, trusted, run_id):  # type: ignore[no-untyped-def]
            del trusted, run_id
            return view

        async def find_command(self, trusted, key):  # type: ignore[no-untyped-def]
            del trusted, key
            return replay

    monkeypatch.setattr(service_module, "PrototypeStore", ReplayStore)
    controller = PrototypeController(
        _ReplaySessions(), _RecordingPolicy(), DeterministicAdvisoryFacade()  # type: ignore[arg-type]
    )
    command = PrototypeExecutionCommand(plan_hash=view.plan.plan_hash)
    other_actor = _context().model_copy(update={"tenant_id": view.tenant_id})

    with pytest.raises(PrototypeForbidden):
        await controller.execute(
            other_actor, view.run_id, command, "exact-replay", view.plan.plan_hash
        )


def test_structured_advisory_accepts_allowlisted_citations_only() -> None:
    port = _StructuredPort()
    graph = build_prototype_graph()
    result = asyncio.run(
        PrototypeOrchestrator(StructuredAdvisoryFacade(port, model_id="configured/model-v2")).run(
            graph, context=_context(), idempotency_key="structured-unit"
        )
    )
    assert port.calls == 1
    assert result.advisory.provider_status == "available"
    assert result.advisory.citation_node_ids == ("PORT-MAA", "DEP-882")
    assert result.advisory.model_id == "configured/model-v2"
    assert result.advisory.prompt_version == "prototype-briefing.v1"
    document = json.loads(port.prompts[0])
    assert len(document["facts"]) == 17
    assert [fact["predicate"] for fact in document["facts"]] == (
        ["prototype.graph_node"] * 12
        + ["prototype.risk_signal"] * 2
        + ["prototype.agent_finding"] * 3
    )
    assert len(port.prompts[0].encode()) <= 16 * 1024


def test_structured_advisory_degrades_on_non_allowlisted_citation() -> None:
    class _UncitedPort(_StructuredPort):
        async def generate_object(self, context, prompt, output_type, idempotency_key):  # type: ignore[no-untyped-def]
            finding = await super().generate_object(context, prompt, output_type, idempotency_key)
            return finding.model_copy(
                update={
                    "cited_evidence": (
                        finding.cited_evidence[0].model_copy(update={"id": new_id()}),
                    )
                }
            )

    port = _UncitedPort()
    result = asyncio.run(
        PrototypeOrchestrator(StructuredAdvisoryFacade(port)).run(
            build_prototype_graph(), context=_context(), idempotency_key="uncited-unit"
        )
    )
    assert result.advisory.provider_status == "uncited"
    assert "secret-node" not in result.advisory.citation_node_ids


@pytest.mark.parametrize(
    ("port", "expected"),
    [
        (_FailingPort(ProviderUnavailable()), "unavailable"),
        (_FailingPort(ProviderTimeout()), "timeout"),
        (_FailingPort(InvalidStructuredOutput()), "invalid_output"),
        (_MalformedPort(), "malformed"),
    ],
)
def test_structured_advisory_has_typed_safe_degradation(port, expected: str) -> None:  # type: ignore[no-untyped-def]
    result = asyncio.run(
        PrototypeOrchestrator(StructuredAdvisoryFacade(port)).run(
            build_prototype_graph(), context=_context(), idempotency_key="failure-unit"
        )
    )
    assert result.advisory.provider_status == expected
    assert result.plan.risk_class == "R3"


def test_structured_advisory_does_not_swallow_cancellation() -> None:
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            PrototypeOrchestrator(
                StructuredAdvisoryFacade(_FailingPort(asyncio.CancelledError()))
            ).run(
                build_prototype_graph(),
                context=_context(),
                idempotency_key="cancel-unit",
            )
        )


def test_reviewed_adapter_malformed_success_envelope_degrades_without_escaping() -> None:
    model = "deepseek-ai/DeepSeek-V4-Flash-0731"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return _streamed_json({"data": [{"id": model}]})
        return _streamed_json({})

    settings = LLMSettings(base_url="http://provider.test/v1", model_id=model)
    port = OpenAICompatibleStructuredOutput(settings, transport=httpx.MockTransport(handler))
    result = asyncio.run(
        PrototypeOrchestrator(StructuredAdvisoryFacade(port, model_id=model)).run(
            build_prototype_graph(), context=_context(), idempotency_key="malformed-envelope"
        )
    )
    assert result.advisory.provider_status == "invalid_output"
    assert result.plan.risk_class == "R3"


def test_llm_settings_use_general_env_with_prototype_override(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("NEXUS_LLM_BASE_URL", "http://general.invalid/v1")
    monkeypatch.setenv("NEXUS_LLM_MODEL", "general-model")
    monkeypatch.setenv("NEXUS_LLM_API_KEY", "general-key")
    general = prototype_llm_settings()
    assert general.base_url == "http://general.invalid/v1"
    assert general.model_id == "general-model"
    assert general.api_key == "general-key"

    monkeypatch.setenv("NEXUS_PROTOTYPE_LLM_BASE_URL", "http://prototype.invalid/v1")
    monkeypatch.setenv("NEXUS_PROTOTYPE_LLM_MODEL", "prototype-model")
    monkeypatch.setenv("NEXUS_PROTOTYPE_LLM_API_KEY", "prototype-key")
    monkeypatch.setenv("NEXUS_PROTOTYPE_LLM_TIMEOUT_SECONDS", "12")
    specific = prototype_llm_settings()
    assert specific.base_url == "http://prototype.invalid/v1"
    assert specific.model_id == "prototype-model"
    assert specific.api_key == "prototype-key"
    assert specific.total_timeout_seconds == 12
