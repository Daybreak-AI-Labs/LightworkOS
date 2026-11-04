"""Native pgvector migration checks; only the explicit test DSN is used."""
from __future__ import annotations

import os
import uuid

import pytest
from maverick_knowledge import KnowledgeBase
from maverick_knowledge.embed import DeterministicEmbedder
from maverick_knowledge.store import PgVectorStore


class VersionedSpace(DeterministicEmbedder):
    def __init__(self, revision):
        super().__init__(16)
        self.revision = revision

    def embedding_identity(self):
        return {"provider": "offline-fixture", "model": "hash-space", "revision": self.revision}


@pytest.fixture
def native_stores():
    knowledge_dsn = os.environ.get("MAVERICK_KNOWLEDGE_DSN")
    dsn = knowledge_dsn or os.environ.get("MAVERICK_PG_DSN")
    if not dsn:
        pytest.skip("MAVERICK_PG_DSN not set (no dedicated pgvector test service)")
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql

    # A general PostgreSQL fixture may not provide the optional extension.
    # An explicitly selected knowledge service must meet its vector contract.
    if not knowledge_dsn:
        with psycopg.connect(dsn, autocommit=True) as connection:
            available = connection.execute(
                "SELECT 1 FROM pg_available_extensions WHERE name = 'vector'",
            ).fetchone()
        if available is None:
            pytest.skip("native pgvector server extension is not available in the general PostgreSQL fixture")

    table = "kb_reindex_" + uuid.uuid4().hex
    stores = []
    try:
        for namespace in ("one", "two"):
            stores.append(PgVectorStore(dsn, dim=16, table=table, namespace=namespace))
        yield stores
    finally:
        for store in stores:
            store.close()
        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(table)))


def test_pg_reindex_preserves_content_and_other_namespace_after_restart(native_stores):
    one, two = native_stores
    first = KnowledgeBase(store=one, embedder=VersionedSpace("a"))
    other = KnowledgeBase(store=two, embedder=VersionedSpace("a"))
    text = "The full admitted policy includes a ninety-day notice period."
    first.ingest_text("policies", text, source="one.txt", subject="email:one")
    other.ingest_text("policies", "Private second namespace", source="two.txt")
    before = one.read_collection("policies", limit=10)
    untouched = two.read_collection("policies", limit=10)
    changed = KnowledgeBase(store=one, embedder=VersionedSpace("b"))
    with pytest.raises(RuntimeError, match="reindex"):
        changed.search("policies", "notice period")
    assert changed.reindex("policies") == len(before)
    after = one.read_collection("policies", limit=10)
    assert [(r.chunk_id, r.text, r.meta["source"], r.meta["doc_sha256"], r.meta["ingested_at"])
            for r in after] == [(r.chunk_id, r.text, r.meta["source"], r.meta["doc_sha256"], r.meta["ingested_at"])
                               for r in before]
    assert after[0].meta["embedding_fingerprint"] != before[0].meta["embedding_fingerprint"]
    assert two.read_collection("policies", limit=10) == untouched
    with KnowledgeBase(store=PgVectorStore(one._dsn, dim=16, table=one._table, namespace="one"),
                       embedder=VersionedSpace("b")) as restarted:
        assert restarted.search("policies", "notice")


def test_pg_reindex_failure_rolls_back_and_erasure_cannot_be_resurrected(native_stores, monkeypatch):
    store, _ = native_stores
    kb = KnowledgeBase(store=store, embedder=VersionedSpace("a"))
    kb.ingest_text("ops", "Original evidence", source="evidence.txt")
    before = store.read_collection("ops", limit=10)
    kb.embedder = VersionedSpace("b")
    monkeypatch.setattr(kb.embedder, "embed", lambda texts: [[float("nan")] * 16 for _ in texts])
    with pytest.raises(ValueError, match="invalid"):
        kb.reindex("ops")
    assert store.read_collection("ops", limit=10) == before
    kb.embedder = VersionedSpace("b")
    original = kb.embedder.embed

    def erased_during_embedding(texts):
        store.delete_collection("ops")
        return original(texts)

    monkeypatch.setattr(kb.embedder, "embed", erased_during_embedding)
    with pytest.raises(RuntimeError, match="changed"):
        kb.reindex("ops")
    assert store.count("ops") == 0
