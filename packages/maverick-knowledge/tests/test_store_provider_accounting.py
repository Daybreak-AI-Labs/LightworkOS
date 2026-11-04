"""Physical provider receipts for hosted knowledge vector stores."""

from __future__ import annotations

import sys
import types

import pytest
from maverick import provider_cost_cap as cap
from maverick.paths import tenant_scope


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    path = tmp_path / "provider-spend.json"
    monkeypatch.setattr(cap, "caps_from_config", dict)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "_ledger_path", lambda: path)
    monkeypatch.setattr(
        cap,
        "period_key",
        lambda now=None, period=None: "2026-09-08",
    )
    return path


class _PgCursor:
    def __init__(self, connection):
        self.connection = connection
        self.last_sql = ""
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        self.connection.calls.append(("execute", sql, params))
        self.last_sql = sql
        return self

    def executemany(self, sql, params):
        self.connection.calls.append(("executemany", sql, params))
        return self

    def fetchone(self):
        if "information_schema.columns" in self.last_sql:
            return (1,)
        return (0,)

    def fetchall(self):
        return []


class _PgConnection:
    def __init__(self, calls):
        self.calls = calls

    def execute(self, sql, params=None):
        self.calls.append(("execute", sql, params))
        return _PgCursor(self)

    def cursor(self):
        return _PgCursor(self)

    def close(self):
        return None


def _install_pg(monkeypatch):
    calls = []
    connection = _PgConnection(calls)
    module = types.ModuleType("psycopg")

    def connect(dsn, *, autocommit):
        calls.append(("connect", dsn, autocommit))
        return connection

    module.connect = connect
    monkeypatch.setitem(sys.modules, "psycopg", module)
    return calls


class _QdrantClient:
    def __init__(self):
        self.calls = []
        self.factory_calls = []
        self.names: set[str] = set()
        self.create_error: BaseException | None = None

    def collection_exists(self, name):
        self.calls.append(("collection_exists", name))
        return name in self.names

    def create_collection(self, *, collection_name, vectors_config):
        self.calls.append(("create_collection", collection_name, vectors_config))
        if self.create_error is not None:
            raise self.create_error
        self.names.add(collection_name)

    def upsert(self, *, collection_name, points):
        self.calls.append(("upsert", collection_name, points))

    def query_points(self, **kwargs):
        self.calls.append(("query_points", kwargs))
        return types.SimpleNamespace(points=[])

    def delete_collection(self, name):
        self.calls.append(("delete_collection", name))
        self.names.discard(name)

    def get_collections(self):
        self.calls.append(("get_collections",))
        return types.SimpleNamespace(
            collections=[types.SimpleNamespace(name=name) for name in self.names]
        )

    def count(self, **kwargs):
        self.calls.append(("count", kwargs))
        return types.SimpleNamespace(count=1)

    def delete(self, **kwargs):
        self.calls.append(("delete", kwargs))

    def close(self):
        return None


def _install_qdrant(monkeypatch):
    client = _QdrantClient()
    module = types.ModuleType("qdrant_client")

    def factory(**kwargs):
        client.factory_calls.append(kwargs)
        return client

    module.QdrantClient = factory
    models = types.ModuleType("qdrant_client.models")

    class VectorParams:
        def __init__(self, *, size, distance):
            self.size = size
            self.distance = distance

    class Distance:
        COSINE = "cosine"

    class PointStruct:
        def __init__(self, *, id, vector, payload):
            self.id = id
            self.vector = vector
            self.payload = payload

    class MatchValue:
        def __init__(self, *, value):
            self.value = value

    class FieldCondition:
        def __init__(self, *, key, match):
            self.key = key
            self.match = match

    class Filter:
        def __init__(self, *, must):
            self.must = must

    class FilterSelector:
        def __init__(self, *, filter):
            self.filter = filter

    models.VectorParams = VectorParams
    models.Distance = Distance
    models.PointStruct = PointStruct
    models.MatchValue = MatchValue
    models.FieldCondition = FieldCondition
    models.Filter = Filter
    models.FilterSelector = FilterSelector
    module.models = models
    monkeypatch.setitem(sys.modules, "qdrant_client", module)
    monkeypatch.setitem(sys.modules, "qdrant_client.models", models)
    return client


def _operation_groups(receipts):
    groups = {}
    for receipt in receipts:
        groups.setdefault(receipt.operation["operation_id"], []).append(receipt)
    return groups


def _assert_operation(groups, prefix, *, attempts, category):
    matches = [
        rows
        for operation, rows in groups.items()
        if operation.startswith(prefix) and len(operation) == len(prefix) + 32
    ]
    assert len(matches) == 1
    rows = sorted(matches[0], key=lambda row: row.operation["attempt_no"])
    assert [row.operation["attempt_no"] for row in rows] == list(range(1, attempts + 1))
    assert all(row.operation["category"] == category for row in rows)
    assert all(row.operation["attempt_state"] == "succeeded" for row in rows)


def test_pgvector_all_physical_calls_share_complete_operation_receipts(
    monkeypatch,
    ledger,
):
    calls = _install_pg(monkeypatch)
    from maverick_knowledge.store import PgVectorStore

    work_item = "research:KNOWLEDGE-PGVECTOR"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        store = PgVectorStore(
            "postgresql://user:secret@example.test/db",  # pragma: allowlist secret
            dim=2,
            namespace="workspace:one",
        )
        store.add("docs", [("one", "text", [1.0, 0.0], {})])
        assert store.search("docs", [1.0, 0.0]) == []
        assert store.collections() == []
        assert store.count_where("docs", "subject", "alice") == 0
        assert store.count("docs") == 0
        assert store.delete_where("docs", "subject", "alice") == 0
        store.delete_collection("docs")
        receipts = cap.reservation_catalogue_for_work_item(
            work_item,
            path=ledger,
        ).receipts

    assert len(receipts) == len(calls) == 12
    assert all(row.provider == "pgvector" for row in receipts)
    assert all(row.state == "unknown" and row.actual is None for row in receipts)
    assert all(row.operation["service"] == "vector-store:pgvector" for row in receipts)
    assert all("secret" not in row.operation["service"] for row in receipts)
    groups = _operation_groups(receipts)
    _assert_operation(
        groups,
        "knowledge-pgvector-initialize-",
        attempts=5,
        category="update",
    )
    _assert_operation(groups, "knowledge-pgvector-add-", attempts=1, category="storage")
    _assert_operation(groups, "knowledge-pgvector-search-", attempts=1, category="retrieval")
    _assert_operation(groups, "knowledge-pgvector-collections-", attempts=1, category="retrieval")
    _assert_operation(groups, "knowledge-pgvector-count-where-", attempts=1, category="retrieval")
    _assert_operation(groups, "knowledge-pgvector-count-", attempts=1, category="retrieval")
    _assert_operation(groups, "knowledge-pgvector-delete-where-", attempts=1, category="update")
    _assert_operation(
        groups,
        "knowledge-pgvector-delete-collection-",
        attempts=1,
        category="update",
    )


def test_pgvector_unknown_price_cap_blocks_before_connect(monkeypatch, ledger):
    calls = _install_pg(monkeypatch)
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"pgvector": 10.0})
    from maverick_knowledge.store import PgVectorStore

    with (
        tenant_scope(tenant="knowledge-tenant"),
        cap.work_item_scope("research:KNOWLEDGE-PGVECTOR-CAPPED"),
    ):
        with pytest.raises(cap.ProviderAccountingUnavailable):
            PgVectorStore("postgresql://example.test/db", dim=2)

    assert calls == []
    assert not ledger.exists()


def test_qdrant_all_physical_calls_share_complete_operation_receipts(
    monkeypatch,
    ledger,
):
    client = _install_qdrant(monkeypatch)
    from maverick_knowledge.store import QdrantStore

    work_item = "research:KNOWLEDGE-QDRANT"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        store = QdrantStore(
            url="https://qdrant.example.test",
            dim=2,
            namespace="ws",
        )
        store.add("docs", [("one", "text", [1.0, 0.0], {})])
        assert store.search("docs", [1.0, 0.0]) == []
        assert store.collections() == ["docs"]
        assert store.count_where("docs", "subject", "alice") == 1
        assert store.count("docs") == 1
        assert store.delete_where("docs", "subject", "alice") == 1
        store.delete_collection("docs")
        receipts = cap.reservation_catalogue_for_work_item(
            work_item,
            path=ledger,
        ).receipts

    assert len(receipts) == len(client.calls) + len(client.factory_calls) == 16
    assert all(row.provider == "qdrant" for row in receipts)
    assert all(row.state == "unknown" and row.actual is None for row in receipts)
    assert all(row.operation["service"] == "vector-store:qdrant" for row in receipts)
    groups = _operation_groups(receipts)
    _assert_operation(
        groups,
        "knowledge-qdrant-initialize-",
        attempts=1,
        category="retrieval",
    )
    _assert_operation(groups, "knowledge-qdrant-add-", attempts=3, category="storage")
    _assert_operation(groups, "knowledge-qdrant-search-", attempts=2, category="retrieval")
    _assert_operation(groups, "knowledge-qdrant-collections-", attempts=1, category="retrieval")
    _assert_operation(groups, "knowledge-qdrant-count-where-", attempts=2, category="retrieval")
    _assert_operation(groups, "knowledge-qdrant-count-", attempts=2, category="retrieval")
    _assert_operation(groups, "knowledge-qdrant-delete-where-", attempts=3, category="update")
    _assert_operation(
        groups,
        "knowledge-qdrant-delete-collection-",
        attempts=2,
        category="update",
    )


def test_qdrant_unknown_price_cap_blocks_before_transport(monkeypatch, ledger):
    client = _install_qdrant(monkeypatch)
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"qdrant": 10.0})
    from maverick_knowledge.store import QdrantStore

    with (
        tenant_scope(tenant="knowledge-tenant"),
        cap.work_item_scope("research:KNOWLEDGE-QDRANT-CAPPED"),
    ):
        with pytest.raises(cap.ProviderAccountingUnavailable):
            QdrantStore(url="https://qdrant.example.test", dim=2)

    assert client.calls == []
    assert client.factory_calls == []
    assert not ledger.exists()


def test_qdrant_multicall_failure_retains_prior_and_failed_attempt(
    monkeypatch,
    ledger,
):
    original = OSError("synthetic create failure")
    client = _install_qdrant(monkeypatch)
    client.create_error = original
    from maverick_knowledge.store import QdrantStore

    store = QdrantStore(url="https://qdrant.example.test", dim=2)
    work_item = "research:KNOWLEDGE-QDRANT-FAIL"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        with pytest.raises(OSError) as captured:
            store.add("docs", [("one", "text", [1.0, 0.0], {})])
        receipts = cap.reservation_catalogue_for_work_item(
            work_item,
            path=ledger,
        ).receipts

    assert captured.value is original
    assert [call[0] for call in client.calls] == [
        "collection_exists",
        "create_collection",
    ]
    assert len(receipts) == 2
    operation_ids = {row.operation["operation_id"] for row in receipts}
    assert len(operation_ids) == 1
    rows = sorted(receipts, key=lambda row: row.operation["attempt_no"])
    assert [row.operation["attempt_no"] for row in rows] == [1, 2]
    assert [row.operation["attempt_state"] for row in rows] == [
        "succeeded",
        "failed",
    ]


def test_sqlite_store_never_creates_provider_receipts(ledger):
    from maverick_knowledge.store import SqliteVectorStore

    store = SqliteVectorStore(":memory:")
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope("research:KNOWLEDGE-SQLITE"):
        store.add("docs", [("one", "text", [1.0, 0.0], {})])
        assert store.search("docs", [1.0, 0.0])
        assert store.count("docs") == 1
        store.delete_collection("docs")

    assert not ledger.exists()
