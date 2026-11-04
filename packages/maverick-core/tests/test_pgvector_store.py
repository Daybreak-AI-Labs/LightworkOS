"""Tests for the pgvector vector store adapter.

psycopg is an optional ([postgres]) dep; we test the missing-import path and
the wired-up path with a fake connection that records executed SQL, with no
real Postgres. The adapter never embeds — an embedder is injected.
"""
from __future__ import annotations

import sys
import types

import pytest
from maverick import provider_cost_cap as cap
from maverick.paths import tenant_scope


@pytest.fixture
def provider_ledger(tmp_path, monkeypatch):
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


class _FakeCursor:
    def __init__(self, conn):
        self._conn = conn
        self._one = (0,)
        self._all: list = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._conn.executed.append((sql, params))
        low = sql.lower()
        if self._conn.error is not None and self._conn.error_match in low:
            raise self._conn.error
        if "count(*)" in low:
            self._one = (self._conn.count_value,)
        elif low.lstrip().startswith("select"):
            self._all = list(self._conn.query_rows)

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


class _FakeConn:
    def __init__(self):
        self.executed: list = []
        self.count_value = 0
        self.query_rows: list = []
        self.closed = False
        self.error: BaseException | None = None
        self.error_match = ""

    def cursor(self):
        return _FakeCursor(self)

    def close(self):
        self.closed = True


def _install_fake_psycopg(monkeypatch) -> _FakeConn:
    conn = _FakeConn()
    fake = types.ModuleType("psycopg")
    fake.connect = lambda dsn, autocommit=True: conn  # noqa: ARG005
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    return conn


def _embedder(dim=3):
    return lambda texts: [[0.1 * (i + 1)] * dim for i, _ in enumerate(texts)]


def test_pgvector_missing_import_raises(monkeypatch):
    monkeypatch.setitem(sys.modules, "psycopg", None)
    from maverick.vector_store.pgvector_store import PgVectorStore
    with pytest.raises(ImportError, match="psycopg not installed"):
        PgVectorStore(dsn="postgresql://x")


def test_pgvector_needs_dsn(monkeypatch):
    _install_fake_psycopg(monkeypatch)
    monkeypatch.delenv("MAVERICK_PG_DSN", raising=False)
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", dict)
    from maverick.vector_store.pgvector_store import PgVectorStore
    with pytest.raises(ValueError, match="needs a DSN"):
        PgVectorStore(dsn=None)


def test_pgvector_init_creates_schema(monkeypatch):
    conn = _install_fake_psycopg(monkeypatch)
    from maverick.vector_store.pgvector_store import PgVectorStore
    PgVectorStore(dsn="postgresql://x")
    sql = " | ".join(s for s, _ in conn.executed)
    assert "CREATE EXTENSION IF NOT EXISTS vector" in sql
    assert "CREATE TABLE IF NOT EXISTS mvk_vectors" in sql
    assert "tenant_id text" in sql
    assert "idx_mvk_vectors_collection_tenant" in sql
    # The row key is (collection, id), not id alone -- a sole-id key let an add()
    # in one collection overwrite a same-id row in another (see the upsert test).
    assert "PRIMARY KEY (collection, id)" in sql


def test_pgvector_add_upserts_with_vectors(monkeypatch):
    conn = _install_fake_psycopg(monkeypatch)
    from maverick.vector_store.pgvector_store import PgVectorStore
    store = PgVectorStore(dsn="postgresql://x", embedder=_embedder())
    store.add(["a", "b"], ids=["i1", "i2"], metadatas=[{"k": 1}, {"k": 2}])
    # vector column added once the dim is known
    assert any("ADD COLUMN IF NOT EXISTS embedding vector(3)" in s
               for s, _ in conn.executed)
    inserts = [(s, p) for s, p in conn.executed if s.lstrip().startswith("INSERT")]
    assert len(inserts) == 2
    # Conflict target is (collection, id) so an add() in one collection can't
    # overwrite a same-id row that belongs to another collection/tenant.
    assert "ON CONFLICT (collection, id) DO UPDATE" in inserts[0][0]
    assert "ON CONFLICT (id) DO UPDATE" not in inserts[0][0]
    # the embedded vector is the last bound param, serialized as a pgvector literal
    assert inserts[0][1][-1].startswith("[") and inserts[0][1][-1].endswith("]")


def test_atomic_single_record_contract_prepares_before_sql(monkeypatch):
    conn = _install_fake_psycopg(monkeypatch)
    from maverick.vector_store.pgvector_store import PgVectorStore

    store = PgVectorStore(dsn="postgresql://x", embedder=_embedder(), dim=3)
    before = len(conn.executed)
    with pytest.raises(ValueError):
        store.upsert_one("bad", id="same", metadata={"goal_id": 1}, embedding=[float("nan"), 0.0, 0.0])
    assert len(conn.executed) == before
    store.upsert_one("prior", id="same", metadata={"goal_id": 1}, embedding=[1.0, 0.0, 0.0])
    conn.error_match, conn.error = "insert", OSError("write unavailable")
    with pytest.raises(Exception, match="write unavailable"):
        store.upsert_one("replacement", id="same", metadata={"goal_id": 1}, embedding=[0.0, 1.0, 0.0])
    statements = [sql for sql, _ in conn.executed[before:]]
    assert not any("DELETE" in sql for sql in statements)
    assert sum("ON CONFLICT (collection, id) DO UPDATE" in sql for sql in statements) == 2


def test_pgvector_add_empty_noop(monkeypatch):
    conn = _install_fake_psycopg(monkeypatch)
    from maverick.vector_store.pgvector_store import PgVectorStore
    store = PgVectorStore(dsn="postgresql://x", embedder=_embedder())
    before = len(conn.executed)
    store.add([])
    assert len(conn.executed) == before


def test_pgvector_add_without_embedder_raises(monkeypatch):
    _install_fake_psycopg(monkeypatch)
    from maverick.vector_store.pgvector_store import PgVectorStore
    store = PgVectorStore(dsn="postgresql://x")
    with pytest.raises(RuntimeError, match="no embedder"):
        store.add(["a"])


def test_pgvector_dim_mismatch_raises(monkeypatch):
    _install_fake_psycopg(monkeypatch)
    from maverick.vector_store.pgvector_store import PgVectorStore
    ragged = lambda texts: [[0.1, 0.2, 0.3], [0.1, 0.2]]  # noqa: E731
    store = PgVectorStore(dsn="postgresql://x", embedder=ragged)
    with pytest.raises(ValueError, match="embedding dim"):
        store.add(["a", "b"])


def test_pgvector_invalid_embedding_count_does_not_meter_transport(
    monkeypatch,
    provider_ledger,
):
    _install_fake_psycopg(monkeypatch)
    from maverick.vector_store.pgvector_store import PgVectorStore

    store = PgVectorStore(
        dsn="postgresql://example.test/db",
        embedder=lambda texts: [],  # noqa: ARG005
    )
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(
        "research:PGVECTOR-INVALID"
    ):
        with pytest.raises(ValueError, match="embedding count"):
            store.add(["doc"])

    assert not provider_ledger.exists()


def test_pgvector_query_uses_cosine_and_collection_tenant(monkeypatch):
    conn = _install_fake_psycopg(monkeypatch)
    conn.query_rows = [("i1", "doc one", {"k": 1}, 0.25)]
    from maverick.vector_store.pgvector_store import PgVectorStore
    store = PgVectorStore(dsn="postgresql://x", collection="goals",
                          embedder=_embedder())
    out = store.query("hi", top_k=3)
    select = [(s, p) for s, p in conn.executed if s.lstrip().startswith("SELECT")
              and "embedding" in s]
    assert select, "expected a vector search SELECT"
    sql, params = select[0]
    assert "<=>" in sql
    assert "collection = %s" in sql
    assert "tenant_id IS NULL" in sql
    assert "goals" in params
    assert out == [{"id": "i1", "document": "doc one",
                    "distance": 0.25, "metadata": {"k": 1}}]


def test_pgvector_scopes_operations_to_active_tenant(monkeypatch):
    conn = _install_fake_psycopg(monkeypatch)
    from maverick.paths import reset_tenant, set_tenant
    from maverick.vector_store.pgvector_store import PgVectorStore

    token = set_tenant("tenant-a")
    try:
        store = PgVectorStore(
            dsn="postgresql://x", collection="goals", embedder=_embedder())
        store.add(["a"], ids=["goal:1"], metadatas=[{"k": 1}])
        store.query("hi", top_k=3)
        store.count()
        store.delete(["goal:1"])
        store.reset()
    finally:
        reset_tenant(token)

    inserts = [(s, p) for s, p in conn.executed if s.lstrip().startswith("INSERT")]
    assert inserts
    assert inserts[0][1][0] == "tenant:tenant-a:goal:1"
    assert inserts[0][1][2] == "tenant-a"

    scoped_statements = [
        (s, p) for s, p in conn.executed
        if (s.lstrip().startswith(("SELECT", "DELETE")) and "mvk_vectors" in s)
    ]
    assert scoped_statements
    for sql, params in scoped_statements:
        assert "tenant_id = %s" in sql
        assert "tenant-a" in params

    delete_params = [
        p for s, p in conn.executed
        if s.lstrip().startswith("DELETE") and "= ANY(" in s
    ][0]
    assert delete_params[-1] == ["tenant:tenant-a:goal:1"]


def test_pgvector_query_strips_tenant_prefix_from_returned_id(monkeypatch):
    # Regression: query() returned the tenant-namespaced stored id
    # ('tenant:t:x') instead of the caller's original doc id, so a
    # query->delete round-trip re-prefixed and deleted nothing. The prefix
    # must be stripped (mirroring qdrant_store).
    conn = _install_fake_psycopg(monkeypatch)
    conn.query_rows = [("tenant:tenant-a:x", "doc", {"k": 1}, 0.1)]
    from maverick.paths import reset_tenant, set_tenant
    from maverick.vector_store.pgvector_store import PgVectorStore

    token = set_tenant("tenant-a")
    try:
        store = PgVectorStore(dsn="postgresql://x", collection="goals",
                              embedder=_embedder())
        out = store.query("hi", top_k=3)
    finally:
        reset_tenant(token)
    assert out == [{"id": "x", "document": "doc",
                    "distance": 0.1, "metadata": {"k": 1}}]


def test_pgvector_query_empty_text(monkeypatch):
    _install_fake_psycopg(monkeypatch)
    from maverick.vector_store.pgvector_store import PgVectorStore
    store = PgVectorStore(dsn="postgresql://x", embedder=_embedder())
    assert store.query("") == []


def test_pgvector_count_and_reset_and_delete(monkeypatch):
    conn = _install_fake_psycopg(monkeypatch)
    conn.count_value = 9
    from maverick.vector_store.pgvector_store import PgVectorStore
    store = PgVectorStore(dsn="postgresql://x", collection="c",
                          embedder=_embedder())
    assert store.count() == 9
    store.delete(["i1", "i2"])
    assert any(s.lstrip().startswith("DELETE") and "= ANY(" in s
               for s, _ in conn.executed)
    store.reset()
    assert any(s.lstrip().startswith("DELETE") and "= ANY(" not in s
               for s, _ in conn.executed)


def test_pgvector_close(monkeypatch):
    conn = _install_fake_psycopg(monkeypatch)
    from maverick.vector_store.pgvector_store import PgVectorStore
    store = PgVectorStore(dsn="postgresql://x")
    store.close()
    assert conn.closed is True


def test_semantic_recall_recognizes_pgvector(monkeypatch):
    monkeypatch.setenv("MAVERICK_VECTOR_STORE", "pgvector")
    from maverick import semantic_recall
    assert semantic_recall.backend_name() == "pgvector"


def test_pgvector_operations_publish_unknown_cost_receipts(
    monkeypatch,
    provider_ledger,
):
    conn = _install_fake_psycopg(monkeypatch)
    conn.count_value = 1
    from maverick.vector_store.pgvector_store import PgVectorStore

    store = PgVectorStore(
        dsn="postgresql://user:secret@example.test/db",  # pragma: allowlist secret
        collection="research",
        embedder=_embedder(),
    )
    work_item = "research:PGVECTOR-1"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        store.add([])
        assert store.query("") == []
        store.delete([])
        store.add(["doc"], ids=["doc-1"])
        assert store.query("query") == []
        store.delete(["doc-1"])
        assert store.count() == 1
        store.reset()
        receipts = cap.reservation_catalogue_for_work_item(
            work_item,
            path=provider_ledger,
        ).receipts

    assert len(receipts) == 5
    assert [row.operation["category"] for row in receipts].count("storage") == 1
    assert [row.operation["category"] for row in receipts].count("retrieval") == 2
    assert [row.operation["category"] for row in receipts].count("update") == 2
    assert all(row.provider == "pgvector" for row in receipts)
    assert all(row.state == "unknown" and row.actual is None for row in receipts)
    assert all(row.operation["attempt_state"] == "succeeded" for row in receipts)
    assert all(
        row.operation["service"] == "vector-store:pgvector" for row in receipts
    )
    assert all("secret" not in row.operation["service"] for row in receipts)


def test_pgvector_transport_failure_is_retained_and_reraised(
    monkeypatch,
    provider_ledger,
):
    original = OSError("synthetic postgres outage")
    conn = _install_fake_psycopg(monkeypatch)
    from maverick.vector_store.pgvector_store import PgVectorStore

    store = PgVectorStore(
        dsn="postgresql://example.test/db",
        embedder=_embedder(),
    )
    conn.error = original
    conn.error_match = "embedding <=>"
    work_item = "research:PGVECTOR-FAIL"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        with pytest.raises(OSError) as captured:
            store.query("query")
        receipt = cap.reservation_catalogue_for_work_item(
            work_item,
            path=provider_ledger,
        ).receipts[0]

    assert captured.value is original
    assert receipt.state == "unknown"
    assert receipt.operation["category"] == "retrieval"
    assert receipt.operation["attempt_state"] == "failed"


def test_pgvector_unknown_price_cap_blocks_before_database_dispatch(
    monkeypatch,
    provider_ledger,
):
    conn = _install_fake_psycopg(monkeypatch)
    from maverick.vector_store.pgvector_store import PgVectorStore

    store = PgVectorStore(dsn="postgresql://example.test/db")
    before = len(conn.executed)
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"pgvector": 10.0})
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(
        "research:PGVECTOR-CAPPED"
    ):
        with pytest.raises(cap.ProviderAccountingUnavailable):
            store.count()

    assert len(conn.executed) == before
    assert not provider_ledger.exists()
