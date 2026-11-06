"""Acceptance metrics must come from executed flows, with explicit scope."""

from __future__ import annotations

import pytest
from nexus_api.academic_evaluation import evaluate


@pytest.mark.asyncio
async def test_evaluation_measures_four_scenarios_and_real_governance() -> None:
    report = await evaluate(repetitions=1)
    assert report["workflow_count"] == 4
    assert report["all_checks_passed"] is True
    assert len(report["scenarios"]) == 4
    assert report["negative_checks"] >= 12
    assert report["citation_checks"] == 4
    assert report["latency_ms"]["p95"] > 0
    assert {row["delay_reduction_hours"] for row in report["scenarios"]} == {4, 6, 14, 24}
    assert report["provider_mode"] == "deterministic_fallback"


@pytest.mark.asyncio
async def test_evaluation_rejects_empty_or_excessive_runs() -> None:
    with pytest.raises(ValueError):
        await evaluate(repetitions=0)
    with pytest.raises(ValueError):
        await evaluate(repetitions=101)
