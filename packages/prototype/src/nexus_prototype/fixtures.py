"""Deterministic, small acceptance fixture for the port-closure prototype."""

from __future__ import annotations

import hashlib
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from nexus_contracts.platform import EventEnvelope, JsonValue, OntologySnapshotRef, ResourceRef
from uuid6 import UUID as UUID6

from nexus_prototype.models import validate_uuid7

FIXTURE_SEED = 41_073
TENANT_ID = UUID("018f0000-0000-7000-8000-000000000001")
_FIXTURE_START = datetime(2026, 8, 9, 3, tzinfo=UTC)


def _fixture_uuid7(timestamp: datetime, namespace: str, seed: int) -> UUID:
    timestamp_ms = int(timestamp.timestamp() * 1_000)
    entropy = int.from_bytes(hashlib.sha256(f"{seed}:{namespace}".encode()).digest(), "big") & (
        (1 << 76) - 1
    )
    return validate_uuid7(UUID6(int=(timestamp_ms << 80) | entropy, version=7))


def _source(tenant_id: UUID, seed: int) -> ResourceRef:
    return ResourceRef(
        tenant_id=tenant_id,
        kind="connector.synthetic",
        id=_fixture_uuid7(_FIXTURE_START, "source", seed),
        version=1,
    )


def _event(
    tenant_id: UUID,
    key: str,
    occurred_at: datetime,
    payload: dict[str, JsonValue],
    *,
    seed: int,
    ingested_at: datetime | None = None,
) -> EventEnvelope:
    return EventEnvelope(
        event_id=_fixture_uuid7(occurred_at, f"event:{key}", seed),
        event_type="prototype.synthetic.observed",
        tenant_id=tenant_id,
        source=_source(tenant_id, seed),
        subject=str(payload.get("port_id", payload.get("shipment_id", key))),
        occurred_at=occurred_at,
        ingested_at=ingested_at or occurred_at,
        correlation_id=_fixture_uuid7(_FIXTURE_START, "correlation", seed),
        sensitivity=frozenset({"internal"}),
        payload=payload,
    )


def build_fixture_events(
    *, seed: int = FIXTURE_SEED, tenant_id: UUID = TENANT_ID
) -> tuple[EventEnvelope, ...]:
    """Build the 12-event seed-41073 scenario, including one duplicate and one late event."""
    randomizer = random.Random(seed)  # noqa: S311 - fixture reproducibility requires this PRNG.
    base = _FIXTURE_START
    rows = [
        _event(
            tenant_id,
            "port-closed",
            base,
            {"fact": "port_status", "port_id": "PORT-MAA", "value": "closed"},
            seed=seed,
        ),
        _event(
            tenant_id,
            "shipment-0042",
            base + timedelta(minutes=1),
            {"fact": "shipment", "shipment_id": "SHP-0042", "port_id": "PORT-MAA"},
            seed=seed,
        ),
        _event(
            tenant_id,
            "shipment-0047",
            base + timedelta(minutes=2),
            {"fact": "shipment", "shipment_id": "SHP-0047", "port_id": "PORT-MAA"},
            seed=seed,
        ),
        _event(
            tenant_id,
            "shipment-0051",
            base + timedelta(minutes=3),
            {"fact": "shipment", "shipment_id": "SHP-0051", "port_id": "PORT-MAA"},
            seed=seed,
        ),
        _event(
            tenant_id,
            "component-shortage",
            base + timedelta(minutes=4),
            {
                "fact": "component_shortage",
                "component_id": "CMP-SENSOR-A",
                "order_ids": ["PO-1107", "PO-1112"],
            },
            seed=seed,
        ),
        _event(
            tenant_id,
            "late-inventory",
            base + timedelta(minutes=5),
            {"fact": "inventory", "lot_id": "LOT-0991", "value": "observed"},
            seed=seed,
            ingested_at=base + timedelta(minutes=16),
        ),
        _event(
            tenant_id,
            "unrelated-1",
            base + timedelta(minutes=6),
            {"fact": "inventory", "lot_id": "LOT-1001", "value": "available"},
            seed=seed,
        ),
        _event(
            tenant_id,
            "unrelated-2",
            base + timedelta(minutes=7),
            {"fact": "weather", "port_id": "PORT-DEL", "value": "clear"},
            seed=seed,
        ),
        _event(
            tenant_id,
            "unrelated-3",
            base + timedelta(minutes=8),
            {"fact": "shipment", "shipment_id": "SHP-0099", "port_id": "PORT-DEL"},
            seed=seed,
        ),
        _event(
            tenant_id,
            "unrelated-4",
            base + timedelta(minutes=9),
            {"fact": "inventory", "lot_id": "LOT-1002", "value": "available"},
            seed=seed,
        ),
        _event(
            tenant_id,
            "unrelated-5",
            base + timedelta(minutes=10),
            {"fact": "supplier", "supplier_id": "SUP-0007", "value": "active"},
            seed=seed,
        ),
    ]
    rows = [
        event.model_copy(
            update={
                "payload": {
                    **_payload(event),
                    "fixture_sequence": randomizer.randrange(1_000_000),
                }
            }
        )
        for event in rows
    ]
    rows.append(rows[1])
    randomizer.shuffle(rows)
    return tuple(sorted(rows, key=lambda event: (event.occurred_at, str(event.event_id))))


def fixture_ndjson(events: tuple[EventEnvelope, ...]) -> bytes:
    """Serialize fixture envelopes with a portable newline and stable JSON ordering."""
    return b"".join(
        (
            json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
            + b"\n"
        )
        for event in events
    )


def _payload(event: EventEnvelope) -> dict[str, JsonValue]:
    if not isinstance(event.payload, dict):
        raise ValueError("fixture event payload must be an object")
    return event.payload


def build_fixture_snapshot(tenant_id: UUID = TENANT_ID) -> OntologySnapshotRef:
    """Return the deterministic snapshot used to evaluate the seeded event set."""
    content = fixture_ndjson(build_fixture_events(tenant_id=tenant_id))
    return OntologySnapshotRef(
        snapshot_id=_fixture_uuid7(
            datetime(2026, 8, 9, 3, 16, tzinfo=UTC), f"snapshot:{tenant_id}", FIXTURE_SEED
        ),
        tenant_id=tenant_id,
        schema_version_id=_fixture_uuid7(_FIXTURE_START, "schema", FIXTURE_SEED),
        transaction_time=datetime(2026, 8, 9, 3, 16, tzinfo=UTC),
        valid_time=datetime(2026, 8, 9, 3, 16, tzinfo=UTC),
        event_watermark=12,
        content_hash=hashlib.sha256(content).hexdigest(),
    )


def write_fixture(destination: Path, *, seed: int = FIXTURE_SEED) -> dict[str, str]:
    """Materialize the committed small fixture and return its content digest."""
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / "storm_shift_12.ndjson"
    output.write_bytes(fixture_ndjson(build_fixture_events(seed=seed)))
    return {output.name: hashlib.sha256(output.read_bytes()).hexdigest()}
