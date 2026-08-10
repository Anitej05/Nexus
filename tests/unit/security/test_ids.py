"""UUIDv7 identifiers exposed by the persistence boundary."""

from uuid import UUID

from nexus_security.ids import new_id


def test_new_ids_are_uuid7_and_process_call_ordered() -> None:
    """A non-v7 or non-monotonic generated identifier breaks public ordering."""
    values = [new_id() for _ in range(20)]

    assert all(value.version == 7 for value in values)
    assert values == sorted(values)


def test_new_id_is_a_uuid_with_canonical_lowercase_text() -> None:
    """Returning a non-UUID or noncanonical text breaks service boundaries."""
    value = new_id()

    assert isinstance(value, UUID)
    assert str(value) == str(value).lower()
