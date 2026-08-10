"""Round 2 configuration contracts for live Compose defects."""

from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_compose_uses_runnable_health_and_database_configuration() -> None:
    """Old command flags and missing drivers cause live services to restart or stay unhealthy."""
    compose = (ROOT / "infrastructure" / "compose" / "compose.yml").read_text(encoding="utf-8")
    health_command = '"rpk", "cluster", "health", "--exit-when-healthy", "-X", '
    assert health_command + '"brokers=localhost:9092"' in compose
    bootstrap = (ROOT / "infrastructure" / "compose" / "redpanda" / "bootstrap.sh").read_text(
        encoding="utf-8"
    )
    assert "broker='redpanda:9092'" in bootstrap
    assert '-X "brokers=$broker"' in bootstrap
    assert "--brokers" not in bootstrap
    assert "SQL_MAX_CONNS: 5" in compose
    assert "nexus-mlflow:dev" in compose
    assert "nexus-otel-health-probe:dev" in compose
    otel_section = compose.split("  otel-collector:", maxsplit=1)[1].split(
        "  prometheus:", maxsplit=1
    )[0]
    assert "CMD-SHELL" not in otel_section
    assert "wget" not in otel_section


def test_infrastructure_helpers_are_pinned_and_documented() -> None:
    """An unpinned helper silently becomes a fourth mutable application-style image."""
    probe = (ROOT / "infrastructure" / "observability" / "otel-health-probe.Dockerfile").read_text(
        encoding="utf-8"
    )
    mlflow = (ROOT / "infrastructure" / "mlflow" / "Dockerfile").read_text(encoding="utf-8")
    readme = (ROOT / "infrastructure" / "compose" / "README.md").read_text(encoding="utf-8")
    assert "@sha256:" in probe
    assert "@sha256:" in mlflow
    lock = (ROOT / "infrastructure" / "mlflow" / "requirements.lock").read_text(encoding="utf-8")
    assert "--require-hashes" in mlflow
    requirement = "psycopg2-binary==2.9.10 --hash=sha256:7f4152f8f76d2023"
    assert requirement + "aac16285576a9ecd2b11a9895373a1f10fd9db54b3ff06b4" in lock
    assert "infrastructure-only" in readme


def test_opa_config_does_not_enable_an_unregistered_plugin() -> None:
    """The status plugin configuration makes the pinned OPA server restart-loop."""
    config = (ROOT / "infrastructure" / "opa" / "config.yaml").read_text(encoding="utf-8")
    assert "plugins:" not in config


def test_redpanda_bootstrap_is_a_resident_healthy_dependency() -> None:
    """A successful one-shot bootstrap makes Compose --wait fail despite valid topics."""
    compose = (ROOT / "infrastructure" / "compose" / "compose.yml").read_text(encoding="utf-8")
    bootstrap_service = compose.split("  redpanda-bootstrap:", maxsplit=1)[1].split(
        "  minio:", maxsplit=1
    )[0]
    script = (ROOT / "infrastructure" / "compose" / "redpanda" / "bootstrap.sh").read_text(
        encoding="utf-8"
    )

    assert 'restart: unless-stopped' in bootstrap_service
    assert 'read_only: true' in bootstrap_service
    assert (
        'tmpfs: ["/run/redpanda-bootstrap:rw,nosuid,nodev,size=1m,uid=101,gid=101,mode=1777"]'
        in bootstrap_service
    )
    assert 'test: ["CMD", "/bin/sh", "/bootstrap.sh", "--healthcheck"]' in bootstrap_service
    assert "touch \"$ready_marker\"" in script
    assert 'while :; do sleep 3600; done' in script
