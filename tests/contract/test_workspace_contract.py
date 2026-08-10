import re
from pathlib import Path
from uuid import UUID

from nexus_api.main import app
from nexus_contracts.platform import RequestContext


def test_api_metadata_and_context_are_stable() -> None:
    assert app.title == "NEXUS API"
    assert app.version == "0.1.0"
    ctx = RequestContext(
        tenant_id=UUID("018f0000-0000-7000-8000-000000000001"),
        actor_id=UUID("018f0000-0000-7000-8000-000000000002"),
        correlation_id=UUID("018f0000-0000-7000-8000-000000000003"),
        roles=frozenset({"viewer"}),
        scopes=frozenset({"ontology.read"}),
        sensitivity_clearances=frozenset({"internal"}),
    )
    assert ctx.agent_id is None
    assert set(app.openapi()["paths"]) == {
        "/api/v1/audit/events",
        "/api/v1/prototype/runs",
        "/api/v1/prototype/runs/{run_id}",
        "/api/v1/prototype/runs/{run_id}/approval",
        "/api/v1/prototype/runs/{run_id}/execute",
        "/api/v1/prototype/runs/{run_id}/graph",
        "/api/v1/prototype/runs/{run_id}/trace",
        "/health/live",
        "/health/ready",
        "/prototype",
    }


def test_trivy_image_scans_block_high_and_critical_vulnerabilities() -> None:
    workflow = (Path(__file__).parents[2] / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    for scan_name in ("Scan API image", "Scan worker image"):
        match = re.search(
            rf"- name: {scan_name}\n(?P<block>.*?)(?=\n      - name:|\Z)",
            workflow,
            flags=re.DOTALL,
        )
        assert match is not None
        assert "scan-type: image" in match["block"]
        assert "severity: CRITICAL,HIGH" in match["block"]
        assert "exit-code: '1'" in match["block"]
