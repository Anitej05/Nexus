# ruff: noqa: S603, S607
"""Behavioral release checks for the public local-development surface."""

from __future__ import annotations

import json
import os
import re
import subprocess
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).parents[2]
COMPOSE = ROOT / "infrastructure" / "compose" / "compose.yml"
EXPECTED_PUBLISHED_PORTS = {
    ("api", 8000),
    ("grafana", 3000),
    ("keycloak", 8080),
    ("minio", 9000),
    ("mlflow", 5000),
    ("neo4j", 7687),
    ("otel-collector", 4317),
    ("postgres", 5432),
    ("prometheus", 9090),
    ("redis", 6379),
    ("redpanda", 9092),
    ("temporal", 7233),
}
CANONICAL_APACHE_2_LF_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"


def test_effective_local_compose_publishes_only_on_loopback() -> None:
    """Removing a loopback host binding must expose this test failure."""
    result = subprocess.run(
        (
            "docker",
            "compose",
            "--env-file",
            ".env.example",
            "-f",
            str(COMPOSE),
            "config",
            "--format",
            "json",
        ),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    document = json.loads(result.stdout)
    published = {
        (service_name, int(port["target"])): port.get("host_ip")
        for service_name, service in document["services"].items()
        for port in service.get("ports", ())
    }

    assert set(published) == EXPECTED_PUBLISHED_PORTS
    assert set(published.values()) == {"127.0.0.1"}


def test_local_secret_and_generated_output_names_are_ignored() -> None:
    """A common local environment or evidence file must never become addable by default."""
    candidates = (
        ".env",
        ".env.local",
        ".env.development",
        ".envrc",
        ".direnv/cache",
        "services/api/.env",
        "services/api/.env.local",
        "services/api/.env.development",
        "services/api/.envrc",
        "services/api/.direnv/cache",
        "artifacts/prototype/evidence.json",
        "work/release-notes.txt",
        ".superpowers/private-review.md",
        "application.log",
    )
    environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1"}
    for candidate in candidates:
        result = subprocess.run(
            ("git", "check-ignore", "--verbose", "--no-index", candidate),
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, candidate
        assert result.stdout.startswith(".gitignore:"), candidate


def test_public_example_environment_remains_trackable() -> None:
    """Broad environment ignores must retain the documented safe template."""
    for candidate in (".env.example", "services/api/.env.example"):
        result = subprocess.run(
            ("git", "check-ignore", "--no-index", candidate),
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1, candidate
        assert result.stdout == "", candidate


def test_gitleaks_scans_the_complete_reachable_history_without_github_credentials() -> None:
    """The pinned CLI scans orphan-root history without GitHub write credentials."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    verify_job = workflow.split("  verify:\n", maxsplit=1)[1].split(
        "\n  container-scan:", maxsplit=1
    )[0]

    assert "    permissions:\n      contents: read\n" in verify_job
    image = (
        "gitleaks@sha256:"
        "b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb"
    )
    assert image in verify_job
    assert "detect --source=/repo --no-banner --redact --verbose" in verify_job
    assert "GITHUB_TOKEN" not in verify_job


def test_internal_agent_plans_are_not_part_of_the_public_tree() -> None:
    """Implementation journals must not be published as end-user documentation."""
    internal_docs = ROOT / "docs" / "superpowers"

    assert not internal_docs.exists() or not any(
        path.is_file() for path in internal_docs.rglob("*")
    )


def test_security_policy_has_a_safe_non_email_fallback() -> None:
    """A reporter can request a private channel if GitHub private reporting is unavailable."""
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

    assert "private vulnerability" in policy.lower()
    assert "https://github.com/Anitej05" in policy
    assert "do not include vulnerability details" in policy.lower()
    assert re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", policy) is None


def test_license_is_canonical_and_project_attribution_is_in_notice() -> None:
    """Apache's license text remains unmodified while NOTICE identifies NEXUS."""
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8").replace("\r\n", "\n")
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")

    assert sha256(license_text.encode()).hexdigest() == CANONICAL_APACHE_2_LF_SHA256
    assert "NEXUS" in notice
    assert "Copyright 2026 Anitej05" in notice
