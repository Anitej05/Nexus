import asyncio
import hashlib

from nexus_api.prototype.orchestrator import (
    DeterministicAdvisoryFacade,
    PrototypeOrchestrator,
    calculate_verification,
)
from nexus_api.prototype.seed import build_projection, scenario_catalog


def test_scenarios_drive_findings_and_simulated_results():
    catalog = scenario_catalog()
    assert len(catalog) >= 3
    results = [
        asyncio.run(
            PrototypeOrchestrator(DeterministicAdvisoryFacade()).run(
                build_projection(item["scenario_id"]), idempotency_key="test"
            )
        )
        for item in catalog
    ]
    assert len({(r.signals[0].score, r.signals[1].score) for r in results}) >= 3
    assert len({r.findings[0].finding_code for r in results}) >= 2
    assert len({r.plan.baseline_delay_hours for r in results}) >= 2
    assert len({r.plan.plan_hash for r in results}) == len(results)
    assert all(
        {"no_action", "simulated_reroute"} == {o.option_id for o in r.plan.options} for r in results
    )
    for result in results:
        assert (
            hashlib.sha256(result.advisory.summary.encode()).hexdigest()
            == result.advisory.summary_sha256
        )
        verification = calculate_verification(result.plan, "sim-test")
        assert (
            verification.observed_delay_hours
            == result.plan.baseline_delay_hours - result.plan.expected_delay_reduction_hours
        )


def test_scenario_ledger_replay_rejects_changed_score_and_outcome():
    import pytest
    from nexus_api.prototype.store import PrototypeStateError, reduce_prototype_events
    from test_store import _event

    graph = build_projection("it-heavy-v1")
    result = asyncio.run(
        PrototypeOrchestrator(DeterministicAdvisoryFacade()).run(graph, idempotency_key="ledger")
    )
    events = [
        (
            "prototype.run.created",
            {
                "scenario_id": graph.scenario_id,
                "seed_digest": graph.seed_digest,
                "status": "created",
            },
        )
    ]
    events += [
        ("prototype.signal.published", signal.model_dump(mode="json", exclude={"feature_map"}))
        for signal in result.signals
    ]
    events += [
        ("prototype.agent.completed", finding.model_dump(mode="json"))
        for finding in result.findings
    ]
    events += [("prototype.briefing.generated", result.advisory.model_dump(mode="json"))]
    events += [
        (
            "prototype.plan.prepared",
            result.plan.model_dump(
                mode="json",
                exclude={
                    "expected_effect",
                    "baseline_delay_hours",
                    "expected_delay_reduction_hours",
                    "options",
                },
            ),
        )
    ]
    audited = tuple(
        _event(i, name, {**payload, "policy_operation": "action.propose"})
        for i, (name, payload) in enumerate(events, 1)
    )
    view = reduce_prototype_events(audited)
    assert view is not None and view.plan == result.plan
    changed = list(audited)
    changed[1] = changed[1].model_copy(
        update={"public_payload": {**changed[1].public_payload, "score": 0.99}}
    )
    with pytest.raises(PrototypeStateError):
        reduce_prototype_events(changed)


def test_scenario_graph_binds_and_cites_numeric_inputs():
    import pytest
    from nexus_api.prototype.risk import incident_risk_signal, supply_risk_signal
    from nexus_api.prototype.seed import seed_digest

    graph = build_projection("it-heavy-v1")
    assert seed_digest(graph) == graph.seed_digest
    nodes = {node.id: node for node in graph.nodes}
    assert "12" in nodes["input-delay-hours"].label
    assert "8" in nodes["input-latency-minutes"].label
    assert "input-delay-hours" in supply_risk_signal(graph).evidence_node_ids
    assert "input-latency-minutes" in incident_risk_signal(graph).evidence_node_ids
    tampered = graph.model_copy(
        update={"nodes": graph.nodes[:-1] + (graph.nodes[-1].model_copy(update={"label": "999"}),)}
    )
    with pytest.raises(ValueError):
        incident_risk_signal(tampered)
    from nexus_api.prototype.orchestrator import build_prototype_plan

    with pytest.raises(ValueError):
        build_prototype_plan(tampered)
