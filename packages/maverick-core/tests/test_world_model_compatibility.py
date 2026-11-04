"""Opening an incompatible world must not mutate its database or journal."""
from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest
from maverick.world_model import SCHEMA_VERSION, WorldModel


def _versioned_db(path, versions):
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("CREATE TABLE schema_version (version)")
        conn.executemany("INSERT INTO schema_version VALUES (?)", [(version,) for version in versions])
        conn.execute("CREATE TABLE future_records (payload TEXT)")
        conn.execute("INSERT INTO future_records VALUES ('preserve customer data')")
        conn.commit()


def _bytes(path):
    return {suffix: candidate.read_bytes() if candidate.exists() else None
            for suffix in ("", "-wal", "-journal")
            for candidate in [path.with_name(path.name + suffix)]}


@pytest.mark.parametrize("name", ["world.db", "world #% space.db"])
def test_future_schema_rejected_before_database_changes(tmp_path, name):
    path = tmp_path / name
    _versioned_db(path, [SCHEMA_VERSION + 1])
    before = _bytes(path)
    with pytest.raises(RuntimeError, match="newer Lightwork.*compatible backup") as error:
        WorldModel(path)
    assert getattr(error.value, "code", None) == "unsupported_world_schema"
    assert _bytes(path) == before
    assert not list(tmp_path.glob("*.pre-migration-*.bak"))


def test_future_version_in_committed_wal_is_not_hidden_by_main_file(tmp_path):
    path = tmp_path / "world.db"
    _versioned_db(path, [SCHEMA_VERSION])
    with closing(sqlite3.connect(path)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("UPDATE schema_version SET version=?", (SCHEMA_VERSION + 1,))
        writer.commit()
        before = _bytes(path)
        assert before["-wal"]
        with pytest.raises(RuntimeError, match="newer Lightwork"):
            WorldModel(path)
        assert _bytes(path) == before


@pytest.mark.parametrize("versions", [[0], [-1], ["future"], [34.5], [None], [34, 35], [34, 34]])
def test_ambiguous_version_metadata_blocks_without_repairing_in_place(tmp_path, versions):
    path = tmp_path / "world.db"
    _versioned_db(path, versions)
    before = _bytes(path)
    with pytest.raises(RuntimeError, match="schema metadata.*compatible backup") as error:
        WorldModel(path)
    assert getattr(error.value, "code", None) == "invalid_world_schema"
    assert _bytes(path) == before


@pytest.mark.parametrize("schema", [
    "CREATE TABLE schema_version (unexpected INTEGER)",
    "CREATE VIEW schema_version AS SELECT 34 AS version",
])
def test_unrecognized_version_structure_is_actionable_and_read_only(tmp_path, schema):
    path = tmp_path / "world.db"
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(schema)
        conn.commit()
    before = _bytes(path)
    with pytest.raises(RuntimeError, match="schema metadata.*compatible backup"):
        WorldModel(path)
    assert _bytes(path) == before


def test_current_world_remains_readable_after_compatibility_admission(tmp_path):
    path = tmp_path / "world.db"
    with WorldModel(path) as world:
        goal_id = world.create_goal("Retain current record")
    with WorldModel(path) as reopened:
        assert reopened.get_goal(goal_id).title == "Retain current record"
        assert reopened.schema_version == SCHEMA_VERSION
