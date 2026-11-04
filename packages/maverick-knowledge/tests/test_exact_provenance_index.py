"""A cached exact lookup must never weaken provenance or erasure semantics."""
from __future__ import annotations

import json
import sqlite3

import pytest
from maverick_knowledge.store import SqliteVectorStore


def test_exact_index_reuses_a_fully_validated_snapshot_and_keeps_order():
    store = SqliteVectorStore()
    store.add("docs", [
        ("3", "third", [1.0], {"source": "a"}),
        ("1", "first", [1.0], {"source": "a"}),
        ("2", "other", [1.0], {"source": "b"}),
        ("4", "fourth", [1.0], {"source": "a"}),
    ])
    assert store.count_where("docs", "source", "a") == 3
    statements = []
    store._db.set_trace_callback(statements.append)
    assert store.count_where("docs", "source", "a") == 3
    assert [row.text for row in store.read_where("docs", "source", "a", limit=1)] == ["first", "third"]
    assert not any(sql.startswith("SELECT id, meta FROM chunks") for sql in statements)
    assert any(" AND id IN (" in sql for sql in statements)


def test_exact_index_keeps_order_across_bounded_candidate_queries():
    store = SqliteVectorStore()
    store.add("docs", [
        (f"{index:04d}", str(index), [1.0], {"source": "a"})
        for index in reversed(range(425))
    ])
    assert store.count_where("docs", "source", "a") == 425
    results = store.read_where("docs", "source", "a", limit=420)
    assert [row.text for row in results] == [str(index) for index in range(421)]


@pytest.mark.skipif(not hasattr(sqlite3.Connection, "setlimit"), reason="SQLite limits unavailable")
def test_exact_index_falls_back_when_sql_variable_limit_is_lowered():
    store = SqliteVectorStore()
    store.add("docs", [
        (str(index), str(index), [1.0], {"source": "a"}) for index in range(20)
    ])
    assert store.count_where("docs", "source", "a") == 20
    store._db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 10)
    rows = store.read_where("docs", "source", "a", limit=20)
    assert [row.chunk_id for row in rows] == sorted(str(index) for index in range(20))


def test_exact_index_observes_external_replacements_and_erasure(tmp_path):
    path = tmp_path / "knowledge.sqlite"
    first, other = SqliteVectorStore(path), SqliteVectorStore(path)
    first.add("docs", [("1", "original", [1.0], {"subject": "alice"})])
    assert first.count_where("docs", "subject", "alice") == 1
    other.add("docs", [("1", "replacement", [1.0], {"subject": "bob"})])
    assert first.read_where("docs", "subject", "alice", limit=3) == []
    assert first.count_where("docs", "subject", "alice") == 0
    assert first.count_where("docs", "subject", "bob") == 1
    assert other.delete_where("docs", "subject", "bob") == 1
    assert first.count_where("docs", "subject", "bob") == 0
    assert first.read_where("docs", "subject", "bob", limit=3) == []


def test_exact_index_observes_same_connection_writes_and_rollbacks():
    store = SqliteVectorStore()
    store.add("docs", [("1", "original", [1.0], {"source": "a"})])
    assert store.count_where("docs", "source", "a") == 1
    store._db.execute("BEGIN")
    store._db.execute("UPDATE chunks SET meta=? WHERE collection=? AND id=?", (
        json.dumps({"source": "b"}), "docs", "1",
    ))
    assert store.count_where("docs", "source", "a") == 0
    assert [row.text for row in store.read_where("docs", "source", "b", limit=1)] == ["original"]
    store._db.rollback()
    assert store.count_where("docs", "source", "a") == 1
    assert store.count_where("docs", "source", "b") == 0


def test_exact_index_falls_back_for_nonstring_values_and_duplicate_keys():
    store = SqliteVectorStore()
    store._db.executemany("INSERT INTO chunks VALUES (?, ?, ?, ?, ?)", [
        ("docs", "1", "missing", "[1.0]", "{}"),
        ("docs", "2", "null", "[1.0]", '{"source":null}'),
        ("docs", "3", "duplicate", "[1.0]", '{"source":"old","source":"new"}'),
    ])
    store._db.commit()
    assert store.count_where("docs", "source", None) == 2
    assert [row.text for row in store.read_where("docs", "source", None, limit=2)] == ["missing", "null"]
    assert store.count_where("docs", "source", "new") == 1
    assert [row.text for row in store.read_where("docs", "source", "new", limit=1)] == ["duplicate"]
    assert store.count_where("docs", "source", "old") == 0


def test_malformed_metadata_never_becomes_a_false_zero_or_partial_erasure(tmp_path):
    path = tmp_path / "knowledge.sqlite"
    store, other = SqliteVectorStore(path), SqliteVectorStore(path)
    store.add("docs", [("1", "wanted", [1.0], {"source": "a"})])
    assert store.count_where("docs", "source", "a") == 1
    other._db.execute("INSERT INTO chunks VALUES (?, ?, ?, ?, ?)", ("docs", "2", "bad", "[1.0]", "{"))
    other._db.commit()
    with pytest.raises(ValueError):
        store.count_where("docs", "source", "a")
    with pytest.raises(ValueError):
        store.delete_where("docs", "source", "a")
    assert store.count("docs") == 2


def test_malformed_metadata_after_the_read_sentinel_does_not_change_read_semantics(tmp_path):
    path = tmp_path / "knowledge.sqlite"
    store, other = SqliteVectorStore(path), SqliteVectorStore(path)
    store.add("docs", [
        ("1", "first", [1.0], {"source": "a"}),
        ("2", "overflow", [1.0], {"source": "a"}),
    ])
    assert store.count_where("docs", "source", "a") == 2
    other._db.execute("INSERT INTO chunks VALUES (?, ?, ?, ?, ?)", ("docs", "3", "bad", "[1.0]", "{"))
    other._db.commit()
    assert [row.text for row in store.read_where("docs", "source", "a", limit=1)] == ["first", "overflow"]


def test_index_is_rebuilt_after_reopen_with_legacy_database(tmp_path):
    path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE chunks (collection TEXT, id TEXT, text TEXT, vec TEXT, meta TEXT, "
                   "PRIMARY KEY (collection, id))")
        db.execute("INSERT INTO chunks VALUES (?, ?, ?, ?, ?)", ("docs", "1", "first", "[1.0]", '{"source":"a"}'))
    with SqliteVectorStore(path) as first:
        assert first.count_where("docs", "source", "a") == 1
        assert first._exact_index is not None
    with sqlite3.connect(path) as db:
        db.execute("UPDATE chunks SET meta=? WHERE id=?", ('{"source":"b"}', "1"))
    with SqliteVectorStore(path) as reopened:
        assert reopened._exact_index is None
        assert reopened.count_where("docs", "source", "a") == 0
        assert reopened.count_where("docs", "source", "b") == 1


def test_oversized_indexes_and_missing_data_version_use_the_scan(monkeypatch):
    from maverick_knowledge import store as store_module

    monkeypatch.setattr(store_module, "_MAX_EXACT_INDEX_IDS", 1)
    store = SqliteVectorStore()
    store.add("docs", [("1", "first", [1.0], {"source": "a"}), ("2", "second", [1.0], {"source": "a"})])
    assert store.count_where("docs", "source", "a") == 2
    assert store._exact_index is None

    class NoVersionConnection:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, sql, *args):
            if sql == "PRAGMA data_version":
                raise sqlite3.OperationalError("unavailable")
            return self.connection.execute(sql, *args)

    underlying = store._db
    store._db = NoVersionConnection(underlying)
    try:
        assert store.count_where("docs", "source", "a") == 2
        assert [row.text for row in store.read_where("docs", "source", "a", limit=1)] == ["first", "second"]
        assert store.delete_where("docs", "source", "a") == 2
    finally:
        store._db = underlying


def test_external_commit_before_snapshot_invalidates_cached_ids(tmp_path):
    path = tmp_path / "knowledge.sqlite"
    reader, writer = SqliteVectorStore(path), SqliteVectorStore(path)
    reader._db.execute("PRAGMA journal_mode=WAL")
    reader.add("docs", [("1", "before", [1.0], {"source": "a"})])
    assert reader.count_where("docs", "source", "a") == 1
    wrote = []

    def mutate_before_anchor(sql):
        if not wrote and sql.startswith("SELECT id FROM chunks"):
            wrote.append(True)
            writer.add("docs", [("1", "after", [1.0], {"source": "b"})])

    reader._db.set_trace_callback(mutate_before_anchor)
    try:
        assert reader.read_where("docs", "source", "a", limit=1) == []
        assert reader.count_where("docs", "source", "b") == 1
    finally:
        reader._db.set_trace_callback(None)
    assert wrote == [True]


def test_external_commit_after_snapshot_never_mixes_metadata_versions(tmp_path):
    path = tmp_path / "knowledge.sqlite"
    reader, writer = SqliteVectorStore(path), SqliteVectorStore(path)
    reader._db.execute("PRAGMA journal_mode=WAL")
    reader.add("docs", [("1", "before", [1.0], {"source": "a"})])
    assert reader.count_where("docs", "source", "a") == 1
    versions = []

    def mutate_after_anchor(sql):
        if sql == "PRAGMA data_version":
            versions.append(True)
            if len(versions) == 2:
                writer.add("docs", [("1", "after", [1.0], {"source": "b"})])

    reader._db.set_trace_callback(mutate_after_anchor)
    try:
        # Either snapshot is permitted. It must never combine the new payload
        # with the old metadata match.
        results = reader.read_where("docs", "source", "a", limit=1)
    finally:
        reader._db.set_trace_callback(None)
    assert [row.text for row in results] in ([], ["before"])
    assert len(versions) >= 2
    assert reader.count_where("docs", "source", "a") == 0
    assert [row.text for row in reader.read_where("docs", "source", "b", limit=1)] == ["after"]
