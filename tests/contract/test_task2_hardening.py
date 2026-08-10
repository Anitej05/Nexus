"""Executable configuration contracts for Task 2 hardening fixes."""

from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_application_images_use_pinned_tools_and_noneditable_workspace_installs() -> None:
    """Removing a sibling manifest or relocating an editable venv breaks runtime images."""
    for app in ("api", "worker"):
        dockerfile = (ROOT / "apps" / app / "Dockerfile").read_text(encoding="utf-8")
        sibling = "worker" if app == "api" else "api"
        assert "# syntax=docker/dockerfile:1.7.0@sha256:" in dockerfile
        assert "FROM ghcr.io/astral-sh/uv:0.6.5@sha256:" in dockerfile
        assert f"COPY apps/{sibling}/pyproject.toml apps/{sibling}/pyproject.toml" in dockerfile
        assert "uv sync --frozen --no-dev --no-editable" in dockerfile
        assert "WORKDIR /workspace" in dockerfile
        assert "COPY --from=builder /workspace/.venv /workspace/.venv" in dockerfile


def test_compose_healthchecks_probe_running_endpoints() -> None:
    """Replacing endpoint probes with binary checks marks unavailable services healthy."""
    compose = (ROOT / "infrastructure" / "compose" / "compose.yml").read_text(encoding="utf-8")
    assert "http://localhost:8000/health/ready" in compose
    assert "OTEL_HEALTH_URL: http://opa:8181/health?plugins" in compose
    assert "OTEL_HEALTH_URL: http://otel-collector:13133/" in compose


def test_otel_receivers_bind_for_compose_clients() -> None:
    """A localhost-only OTLP receiver makes API optional readiness time out."""
    collector = (ROOT / "infrastructure" / "observability" / "otel-collector.yaml").read_text(
        encoding="utf-8"
    )
    assert "grpc:\n        endpoint: 0.0.0.0:4317" in collector


def test_migration_owner_and_runtime_boundary_are_explicit() -> None:
    """A grant alone does not give migrations schema ownership or constrain runtime bypass."""
    bootstrap = (ROOT / "infrastructure" / "compose" / "postgres" / "init-users.sh").read_text(
        encoding="utf-8"
    )
    assert "BYPASSRLS" in bootstrap
    assert "NOBYPASSRLS" in bootstrap
    assert "ALTER DATABASE %I OWNER TO %I" in bootstrap
    assert "ALTER SCHEMA public OWNER TO %I" in bootstrap


def test_redpanda_bootstrap_does_not_swallow_creation_failures() -> None:
    """A blanket success handler can hide missing topics or wrong retention settings."""
    bootstrap = (ROOT / "infrastructure" / "compose" / "redpanda" / "bootstrap.sh").read_text(
        encoding="utf-8"
    )
    assert "|| true" not in bootstrap
    assert "rpk topic alter-config" in bootstrap
    assert "rpk topic describe" in bootstrap
