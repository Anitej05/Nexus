"""Registered environment-secret resolution and recursive safe redaction."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable, Iterator, Mapping
from datetime import UTC, datetime, timedelta

from nexus_contracts.platform import RequestContext, ResourceRef


class UnknownSecretReference(PermissionError):
    """A caller attempted to resolve an unregistered secret resource."""


class ExpiredSecretValues(RuntimeError):
    """Secret values have passed their intentionally short exposure window."""


class SecretValues(Mapping[str, str]):
    """A short-lived immutable mapping returned by ``EnvironmentSecretPort``."""

    def __init__(self, values: Mapping[str, str], *, ttl: timedelta = timedelta(minutes=5)) -> None:
        self._values = dict(values)
        self._expires_at = datetime.now(UTC) + ttl

    def _ensure_live(self) -> None:
        if datetime.now(UTC) >= self._expires_at:
            raise ExpiredSecretValues("resolved secret values have expired")

    def __getitem__(self, key: str) -> str:
        self._ensure_live()
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        self._ensure_live()
        return iter(self._values)

    def __len__(self) -> int:
        self._ensure_live()
        return len(self._values)


class EnvironmentSecretPort:
    """Resolve only explicitly registered resource references from the environment."""

    def __init__(
        self,
        registered_references: Mapping[ResourceRef, str],
        *,
        logger: logging.Logger | None = None,
    ) -> None:
        self._registered_references = dict(registered_references)
        self._logger = logger or logging.getLogger("nexus")

    async def resolve(self, context: RequestContext, secret_ref: ResourceRef) -> Mapping[str, str]:
        if secret_ref.tenant_id != context.tenant_id:
            raise UnknownSecretReference("secret references are tenant-scoped")
        try:
            environment_name = self._registered_references[secret_ref]
        except KeyError as error:
            raise UnknownSecretReference("secret reference is not registered") from error
        value = os.environ.get(environment_name)
        if not value:
            raise UnknownSecretReference("registered secret is not configured")
        register_production_secret(value, self._logger)
        return SecretValues({"value": value})


def redact_secrets(payload: object, secrets: Iterable[str]) -> object:
    """Recursively replace secret substrings before a log or audit payload is emitted."""
    values = tuple(value for value in secrets if value)
    if isinstance(payload, str):
        redacted = payload
        for value in values:
            redacted = redacted.replace(value, "[REDACTED]")
        return redacted
    if isinstance(payload, Mapping):
        return {str(key): redact_secrets(value, values) for key, value in payload.items()}
    if isinstance(payload, list):
        return [redact_secrets(value, values) for value in payload]
    if isinstance(payload, tuple):
        return tuple(redact_secrets(value, values) for value in payload)
    return payload


class SecretRedactingFilter(logging.Filter):
    """Redact registered values from a record before any handler serializes it."""

    def __init__(self, secrets: Iterable[str]) -> None:
        super().__init__()
        self._secrets = tuple(secrets)

    def filter(self, record: logging.LogRecord) -> bool:
        message = redact_secrets(record.getMessage(), self._secrets)
        record.msg = str(message)
        record.args = ()
        return True


_production_secrets: set[str] = set()
_record_factory_installed = False


def register_production_secret(value: str, logger: logging.Logger) -> None:
    """Register resolved values and automatically protect the production logger."""
    _production_secrets.add(value)
    _install_production_record_boundary()
    for handler in {*logger.handlers, *logging.getLogger().handlers}:
        if not any(isinstance(item, SecretRedactingFilter) for item in handler.filters):
            handler.addFilter(SecretRedactingFilter(_production_secrets))


def _install_production_record_boundary() -> None:
    """Redact every production record before handlers, including future descendants."""
    global _record_factory_installed
    if _record_factory_installed:
        return
    previous = logging.getLogRecordFactory()

    def factory(*args: object, **kwargs: object) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        message = redact_secrets(record.getMessage(), _production_secrets)
        record.msg = str(message)
        record.args = ()
        return record

    logging.setLogRecordFactory(factory)
    _record_factory_installed = True


def install_secret_redaction(logger: logging.Logger, secrets: Iterable[str]) -> None:
    """Install value redaction on the logger that emits adapter diagnostics."""
    logger.addFilter(SecretRedactingFilter(secrets))


class SafeAuditSerializer:
    """Serialize audit payloads only after recursive secret redaction."""

    def __init__(self, secrets: Iterable[str]) -> None:
        self._secrets = tuple(secrets)

    def serialize(self, payload: Mapping[str, object]) -> str:
        return json.dumps(redact_secrets(payload, self._secrets), sort_keys=True)


def production_audit_json(payload: Mapping[str, object]) -> str:
    """Production audit emission boundary with automatic resolved-secret redaction."""
    return SafeAuditSerializer(_production_secrets).serialize(payload)
