"""Guarded black-box acceptance gate for a real Keycloak, OPA, and PostgreSQL stack."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("NEXUS_RUN_COMPOSE_TESTS") != "1",
    reason="set NEXUS_RUN_COMPOSE_TESTS=1 for the guarded live prototype acceptance gate",
)


def test_guarded_http_e2e_writes_sanitized_evidence() -> None:
    """The runner, not a mock, validates approval, replay, isolation, and degraded LLM behavior."""
    environment = {**os.environ, "NEXUS_RUN_COMPOSE_TESTS": "1"}
    completed = subprocess.run(  # noqa: S603 -- fixed repository script and interpreter.
        [
            sys.executable,
            "scripts/prototype/run_e2e.py",
            "--scenario",
            "storm-and-checkout-shift-v1",
        ],
        check=False,
        cwd=".",
        env=environment,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
