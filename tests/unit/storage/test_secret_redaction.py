"""Behavior tests for secret resolution and safe diagnostic payloads."""

import logging
from uuid import UUID

import pytest
from nexus_contracts.platform import RequestContext, ResourceRef
from nexus_storage.secrets import (
    EnvironmentSecretPort,
    SafeAuditSerializer,
    SecretRedactingFilter,
    UnknownSecretReference,
    install_secret_redaction,
    production_audit_json,
    redact_secrets,
)


def _context() -> RequestContext:
    return RequestContext(
        tenant_id=UUID("018f0000-0000-7000-8000-000000000001"),
        actor_id=UUID("018f0000-0000-7000-8000-000000000002"),
        correlation_id=UUID("018f0000-0000-7000-8000-000000000003"),
        roles=frozenset({"operator"}),
        scopes=frozenset(),
        sensitivity_clearances=frozenset(),
    )


def _secret_ref() -> ResourceRef:
    return ResourceRef(
        tenant_id=UUID("018f0000-0000-7000-8000-000000000001"),
        kind="secret",
        id=UUID("018f0000-0000-7000-8000-000000000004"),
        version=1,
    )


def _second_secret_ref() -> ResourceRef:
    return ResourceRef(
        tenant_id=UUID("018f0000-0000-7000-8000-000000000001"),
        kind="secret",
        id=UUID("018f0000-0000-7000-8000-000000000005"),
        version=1,
    )


@pytest.mark.asyncio
async def test_resolved_secret_never_occurs_in_redacted_log_or_audit_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing value-based redaction would expose a resolved credential."""
    monkeypatch.setenv("NEXUS_TEST_TOKEN", "super-secret-token")
    port = EnvironmentSecretPort({_secret_ref(): "NEXUS_TEST_TOKEN"})

    values = await port.resolve(_context(), _secret_ref())
    payload = {
        "authorization": values["value"],
        "nested": {"message": f"token={values['value']}"},
    }

    redacted = redact_secrets(payload, values.values())

    assert "super-secret-token" not in repr(redacted)
    assert redacted == {
        "authorization": "[REDACTED]",
        "nested": {"message": "token=[REDACTED]"},
    }


@pytest.mark.asyncio
async def test_secret_port_rejects_unregistered_reference() -> None:
    """Dropping the registration check would allow arbitrary environment reads."""
    port = EnvironmentSecretPort({})

    with pytest.raises(UnknownSecretReference):
        await port.resolve(_context(), _secret_ref())


def test_logging_filter_redacts_registered_values_before_emission() -> None:
    """Removing the filter would leave a secret in the emitted log record."""
    record = logging.LogRecord(
        "nexus.storage",
        logging.INFO,
        __file__,
        1,
        "upstream token=%s",
        ("super-secret-token",),
        None,
    )

    assert SecretRedactingFilter(("super-secret-token",)).filter(record)
    assert record.getMessage() == "upstream token=[REDACTED]"


def test_logging_filter_materializes_a_generator_for_every_record() -> None:
    """A one-shot iterable must not leak a later record after its first use."""
    filter_ = SecretRedactingFilter(value for value in ("generator-secret",))
    first = logging.LogRecord(
        "nexus.storage", logging.INFO, __file__, 1, "token=%s", ("generator-secret",), None
    )
    second = logging.LogRecord(
        "nexus.storage", logging.INFO, __file__, 1, "token=%s", ("generator-secret",), None
    )

    assert filter_.filter(first)
    assert filter_.filter(second)
    assert first.getMessage() == "token=[REDACTED]"
    assert second.getMessage() == "token=[REDACTED]"


def test_installed_logging_and_audit_paths_do_not_emit_resolved_secret() -> None:
    """An uninstalled filter or raw audit serialization would expose credentials."""
    logger = logging.getLogger("nexus.storage.secret-redaction-test")
    stream = __import__("io").StringIO()
    handler = logging.StreamHandler(stream)
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    install_secret_redaction(logger, ("super-secret-token",))

    logger.info("sending token=%s", "super-secret-token")
    audit_json = SafeAuditSerializer(("super-secret-token",)).serialize(
        {"authorization": "super-secret-token"}
    )

    assert "super-secret-token" not in stream.getvalue()
    assert "super-secret-token" not in audit_json


@pytest.mark.asyncio
async def test_resolving_a_secret_automatically_protects_production_log_and_audit_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Requiring callers to install filters manually leaks newly resolved secrets."""
    monkeypatch.setenv("NEXUS_TEST_TOKEN", "automatic-secret")
    logger = logging.getLogger("nexus.production-redaction-test")
    stream = __import__("io").StringIO()
    logger.handlers = [logging.StreamHandler(stream)]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    port = EnvironmentSecretPort({_secret_ref(): "NEXUS_TEST_TOKEN"}, logger=logger)

    values = await port.resolve(_context(), _secret_ref())
    logger.info("token=%s", values["value"])

    assert "automatic-secret" not in stream.getvalue()
    assert "automatic-secret" not in production_audit_json({"token": values["value"]})


@pytest.mark.asyncio
async def test_production_boundary_redacts_later_root_and_descendant_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Later handlers and later registrations use the live production secret set."""
    monkeypatch.setenv("NEXUS_TEST_TOKEN", "first-boundary-secret")
    monkeypatch.setenv("NEXUS_SECOND_TEST_TOKEN", "second-boundary-secret")
    root = logging.getLogger()
    production_logger = logging.getLogger("nexus.production-boundary-test")
    descendant = logging.getLogger("nexus.production-boundary-test.child")
    root_handlers, root_level = root.handlers[:], root.level
    logger_handlers, logger_propagate = production_logger.handlers[:], production_logger.propagate
    child_handlers, child_propagate = descendant.handlers[:], descendant.propagate
    root_stream, child_stream = __import__("io").StringIO(), __import__("io").StringIO()
    try:
        root.handlers = []
        production_logger.handlers = []
        production_logger.propagate = True
        descendant.handlers = []
        descendant.propagate = False
        root.setLevel(logging.INFO)
        descendant.setLevel(logging.INFO)
        port = EnvironmentSecretPort(
            {
                _secret_ref(): "NEXUS_TEST_TOKEN",
                _second_secret_ref(): "NEXUS_SECOND_TEST_TOKEN",
            },
            logger=production_logger,
        )

        await port.resolve(_context(), _secret_ref())
        root.addHandler(logging.StreamHandler(root_stream))
        descendant.addHandler(logging.StreamHandler(child_stream))
        production_logger.info("first=%s", "first-boundary-secret")
        descendant.info("first=%s", "first-boundary-secret")

        await port.resolve(_context(), _second_secret_ref())
        production_logger.info(
            "first=%s second=%s", "first-boundary-secret", "second-boundary-secret"
        )

        emitted = root_stream.getvalue() + child_stream.getvalue()
        assert "first-boundary-secret" not in emitted
        assert "second-boundary-secret" not in emitted
    finally:
        root.handlers, root.level = root_handlers, root_level
        production_logger.handlers, production_logger.propagate = logger_handlers, logger_propagate
        descendant.handlers, descendant.propagate = child_handlers, child_propagate
