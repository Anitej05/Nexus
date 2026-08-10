"""Acceptance checks for the bounded, deterministic prototype fixture."""

import hashlib
from pathlib import Path

from nexus_prototype.fixtures import FIXTURE_SEED, build_fixture_events, write_fixture

EXPECTED_FIXTURE_SHA256 = "7664a4a52057069c7987f14221252bc56af4414f5bd4a985dc1dab4f944c167b"


def test_seeded_fixture_is_byte_stable_and_contains_twelve_events(tmp_path: Path) -> None:
    """Changing event construction must not silently alter the known signal scenario."""
    left = tmp_path / "left"
    right = tmp_path / "right"
    alternate = tmp_path / "alternate"

    left_digests = write_fixture(left, seed=FIXTURE_SEED)
    right_digests = write_fixture(right, seed=FIXTURE_SEED)
    alternate_digests = write_fixture(alternate, seed=FIXTURE_SEED + 1)

    assert left_digests == right_digests
    assert alternate_digests != left_digests
    assert len(build_fixture_events(seed=FIXTURE_SEED)) == 12
    assert (left / "storm_shift_12.ndjson").read_bytes() == (
        Path("tests/fixtures/prototype/storm_shift_12.ndjson").read_bytes()
    )
    assert left_digests == {"storm_shift_12.ndjson": EXPECTED_FIXTURE_SHA256}
    assert hashlib.sha256((left / "storm_shift_12.ndjson").read_bytes()).hexdigest() == (
        EXPECTED_FIXTURE_SHA256
    )


def test_fixture_uuid7_timestamps_match_their_event_times() -> None:
    """Fixture UUIDv7 values must carry their event's Unix-epoch millisecond timestamp."""
    for event in build_fixture_events(seed=FIXTURE_SEED):
        assert event.event_id.int >> 80 == int(event.occurred_at.timestamp() * 1_000)
