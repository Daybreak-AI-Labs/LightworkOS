"""MongoDB tool: find() must not silently drop an unparseable sort spec.

Regression: a malformed sort (e.g. direction "desc" instead of -1) raised
inside the sort-pair comprehension and was swallowed by an except/pass, so
the query ran UNSORTED but still applied .limit() — returning an arbitrary
subset of documents presented as a successful sorted query.
"""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _install_fake_mongo(monkeypatch, docs):
    """Wire a pymongo stub whose cursor records the sort spec it receives."""
    monkeypatch.setenv("MONGODB_URI", "mongodb://x")
    monkeypatch.setenv("MONGODB_DB", "test")
    pymongo = types.ModuleType("pymongo")
    calls: dict = {"sort": None}

    class _Cursor:
        def sort(self, spec):
            calls["sort"] = spec
            return self

        def limit(self, n):
            return iter(docs[:n])

    class _Col:
        def find(self, flt):
            return _Cursor()

    class _DB:
        def __getitem__(self, _name):
            return _Col()

    class _MongoClient:
        def __init__(self, *a, **k):
            pass

        def __getitem__(self, _name):
            return _DB()

        def close(self):
            pass

    pymongo.MongoClient = _MongoClient
    monkeypatch.setitem(sys.modules, "pymongo", pymongo)
    return calls


def test_find_bad_sort_direction_errors(monkeypatch):
    calls = _install_fake_mongo(monkeypatch, [{"_id": 1, "name": "alice"}])
    from maverick.tools.mongodb_tool import mongodb_tool
    out = mongodb_tool().fn({
        "op": "find", "collection": "orders",
        "sort": [["created_at", "desc"]], "limit": 10,
    })
    assert out.startswith("ERROR") and "sort" in out
    assert calls["sort"] is None  # the unsorted query never ran


def test_find_one_element_sort_pair_errors(monkeypatch):
    _install_fake_mongo(monkeypatch, [{"_id": 1}])
    from maverick.tools.mongodb_tool import mongodb_tool
    out = mongodb_tool().fn({
        "op": "find", "collection": "orders", "sort": [["created_at"]],
    })
    assert out.startswith("ERROR") and "sort" in out


def test_find_valid_sort_still_applies(monkeypatch):
    calls = _install_fake_mongo(monkeypatch, [{"_id": 1, "name": "alice"}])
    from maverick.tools.mongodb_tool import mongodb_tool
    out = mongodb_tool().fn({
        "op": "find", "collection": "orders",
        "sort": [["created_at", -1]], "limit": 5,
    })
    assert "alice" in out and "ERROR" not in out
    assert calls["sort"] == [("created_at", -1)]


def _install_mongo_stub(monkeypatch, *, db_name="test", collections=None,
                       find_docs=None, find_one=None,
                       insert_id="abc", update_result=None,
                       delete_count=0, count=0):
    """Wire a minimal pymongo stub into sys.modules."""
    pymongo = types.ModuleType("pymongo")

    class _Cursor:
        def __init__(self, docs):
            self._docs = list(docs or [])

        def sort(self, *a, **k):
            return self

        def limit(self, n):
            return iter(self._docs[:n])

        def __iter__(self):
            return iter(self._docs)

    class _Col:
        def find(self, flt):
            return _Cursor(find_docs or [])

        def find_one(self, flt):
            return find_one

        def insert_one(self, doc):
            m = MagicMock()
            m.inserted_id = insert_id
            return m

        def update_many(self, flt, doc, upsert=False):
            return update_result or MagicMock(
                matched_count=1, modified_count=1, upserted_id=None,
            )

        def delete_many(self, flt):
            m = MagicMock()
            m.deleted_count = delete_count
            return m

        def count_documents(self, flt):
            return count

    class _DB:
        def list_collection_names(self):
            return collections or []

        def __getitem__(self, _name):
            return _Col()

    class _MongoClient:
        def __init__(self, *a, **k):
            pass

        def __getitem__(self, _name):
            return _DB()

    pymongo.MongoClient = _MongoClient
    monkeypatch.setitem(sys.modules, "pymongo", pymongo)


# ---------- MongoDB ----------

def test_mongodb_requires_op():
    from maverick.tools.mongodb_tool import mongodb_tool
    assert "op is required" in mongodb_tool().fn({})


def test_mongodb_missing_pymongo(monkeypatch):
    monkeypatch.setitem(sys.modules, "pymongo", None)
    from maverick.tools.mongodb_tool import mongodb_tool
    out = mongodb_tool().fn({"op": "collections"})
    assert "pymongo not installed" in out


def test_mongodb_collections(monkeypatch):
    monkeypatch.setenv("MONGODB_URI", "mongodb://x")
    monkeypatch.setenv("MONGODB_DB", "test")
    _install_mongo_stub(monkeypatch, collections=["users", "orders"])
    from maverick.tools.mongodb_tool import mongodb_tool
    out = mongodb_tool().fn({"op": "collections"})
    assert "users" in out and "orders" in out


def test_mongodb_find(monkeypatch):
    monkeypatch.setenv("MONGODB_URI", "mongodb://x")
    monkeypatch.setenv("MONGODB_DB", "test")
    _install_mongo_stub(
        monkeypatch,
        find_docs=[{"_id": 1, "name": "alice"}, {"_id": 2, "name": "bob"}],
    )
    from maverick.tools.mongodb_tool import mongodb_tool
    out = mongodb_tool().fn({"op": "find", "collection": "users", "filter": {}})
    assert "alice" in out and "bob" in out


def test_mongodb_count(monkeypatch):
    monkeypatch.setenv("MONGODB_URI", "mongodb://x")
    monkeypatch.setenv("MONGODB_DB", "test")
    _install_mongo_stub(monkeypatch, count=42)
    from maverick.tools.mongodb_tool import mongodb_tool
    out = mongodb_tool().fn({"op": "count", "collection": "users",
                              "filter": {"active": True}})
    assert "42" in out


def test_mongodb_insert_dry_run(monkeypatch):
    monkeypatch.setenv("MONGODB_URI", "mongodb://x")
    monkeypatch.setenv("MONGODB_DB", "test")
    _install_mongo_stub(monkeypatch)
    from maverick.tools.mongodb_tool import mongodb_tool
    out = mongodb_tool().fn({
        "op": "insert", "collection": "users", "doc": {"name": "x"},
    })
    assert "DRY RUN" in out


def test_mongodb_insert_confirmed(monkeypatch):
    monkeypatch.setenv("MONGODB_URI", "mongodb://x")
    monkeypatch.setenv("MONGODB_DB", "test")
    _install_mongo_stub(monkeypatch, insert_id="newid")
    from maverick.tools.mongodb_tool import mongodb_tool
    out = mongodb_tool().fn({
        "op": "insert", "collection": "users", "doc": {"name": "x"},
        "confirm": True,
    })
    assert "newid" in out


def test_mongodb_update_dry_run(monkeypatch):
    monkeypatch.setenv("MONGODB_URI", "mongodb://x")
    monkeypatch.setenv("MONGODB_DB", "test")
    _install_mongo_stub(monkeypatch)
    from maverick.tools.mongodb_tool import mongodb_tool
    out = mongodb_tool().fn({
        "op": "update", "collection": "u", "filter": {"id": 1},
        "set_": {"name": "y"},
    })
    assert "DRY RUN" in out


def test_mongodb_delete_dry_run(monkeypatch):
    monkeypatch.setenv("MONGODB_URI", "mongodb://x")
    monkeypatch.setenv("MONGODB_DB", "test")
    _install_mongo_stub(monkeypatch)
    from maverick.tools.mongodb_tool import mongodb_tool
    out = mongodb_tool().fn({
        "op": "delete", "collection": "u", "filter": {"id": 1},
    })
    assert "DRY RUN" in out
