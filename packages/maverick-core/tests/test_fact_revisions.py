"""Authored regression coverage; no live providers required."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from maverick.fact_revision import FactConflict
from maverick.world_model import WorldModel


def test_stale_edit_delete_and_delete_recreate_never_overwrite(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    world = WorldModel(tmp_path / "facts.db")
    first = world.upsert_fact("hours", "nine", expected_revision=0)
    second = world.upsert_fact("hours", "ten", expected_revision=first)
    assert second > first
    before = world.fact_history("hours")
    for action in (lambda: world.upsert_fact("hours", "stale", expected_revision=first),
                   lambda: world.delete_fact("hours", expected_revision=first)):
        with pytest.raises(FactConflict):
            action()
    assert world.fact_history("hours") == before
    assert world.get_fact("hours") == "ten"
    world.delete_fact("hours", expected_revision=second)
    third = world.upsert_fact("hours", "eleven", expected_revision=0)
    assert third > second
    with pytest.raises(FactConflict):
        world.upsert_fact("hours", "stale", expected_revision=second)
    world.close()


def test_independent_connections_admit_only_one_same_revision_writer(tmp_path):
    path = tmp_path / "facts.db"
    initial = WorldModel(path)
    revision = initial.upsert_fact("name", "old", expected_revision=0)
    initial.close()
    readers = [WorldModel(path), WorldModel(path)]
    barrier = Barrier(2)

    def write(index):
        barrier.wait()
        try:
            readers[index].upsert_fact("name", str(index), expected_revision=revision)
            return "saved"
        except FactConflict:
            return "conflict"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(write, (0, 1))) == ["conflict", "saved"]
        # An unrelated key does not conflict with the observed name revision.
        readers[0].upsert_fact("other", "kept", expected_revision=0)
        assert readers[1].get_fact("other") == "kept"
    finally:
        for world in readers:
            world.close()


def test_agent_must_read_again_after_other_writer_and_cannot_bypass_with_null(tmp_path):
    from maverick.tools.kv_memory import kv_memory

    world = WorldModel(tmp_path / "facts.db")
    run = kv_memory(world, 7).fn
    assert run({"op": "set", "key": "color", "value": "blue"}).startswith("set")
    assert run({"op": "get", "key": "color"}) == "blue"
    world.upsert_fact("goal:7:color", "green")
    assert run({"op": "set", "key": "color", "value": "stale", "expected_revision": None}).startswith("ERROR")
    assert run({"op": "delete", "key": "color"}).startswith("ERROR")
    assert run({"op": "get", "key": "color"}) == "green"
    assert run({"op": "set", "key": "color", "value": "reviewed"}).startswith("set")
    assert world.get_fact("goal:7:color") == "reviewed"
    world.close()


def test_ten_thousand_fact_metadata_page_is_bounded_and_excludes_private_scopes(tmp_path):
    world = WorldModel(tmp_path / "facts.db")
    for index in range(10_000):
        world.upsert_fact(f"business-{index:05d}", "detail", source="import")
    world.upsert_fact("goal:9:private", "private task note", source="import")
    world.upsert_fact("user:alice:private", "private personal note", source="import")
    world.upsert_fact("business-09999", "detail", source="import", tags=["Renewal", "review"] )
    assert [row["key"] for row in world.fact_records(tag="renewal", shared_only=True)] == ["business-09999"]
    page = world.fact_records(query="business-09999", source="import", shared_only=True)
    assert [row["key"] for row in page] == ["business-09999"]
    assert len(world.fact_records(limit=10_000, shared_only=True)) == 101
    assert world.fact_records(query="private", shared_only=True) == []
    assert world.fact_records(query="%", shared_only=True) == []
    assert world.fact_records(updated_before=0, shared_only=True) == []
    world.close()


def test_tags_preserve_encryption_cas_and_catalog_revision(tmp_path):
    world = WorldModel(tmp_path / "facts.db")
    first = world.upsert_fact("hours", "nine", tags=["Team", "team"])
    before = world.fact_catalog_revision()
    second = world.upsert_fact("hours", "nine", tags=["Office"], expected_revision=first)
    assert world.fact_catalog_revision() != before
    assert world.fact_record("hours")["tags"] == ["office"]
    with pytest.raises(FactConflict):
        world.upsert_fact("hours", "stale", tags=["wrong"], expected_revision=first)
    world.upsert_fact("hours", "ten", expected_revision=second)
    assert world.fact_record("hours")["tags"] == ["office"]
    before = world.fact_catalog_revision()
    world.upsert_fact("user:alice:private", "secret", tags=["office"])
    assert world.fact_catalog_revision() == before
    assert [row["key"] for row in world.fact_records(tag="office", shared_only=True)] == ["hours"]
    world.close()
