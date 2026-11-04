"""Independent-connection races at the document publication boundary."""
from __future__ import annotations

import hashlib
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick_knowledge import KnowledgeBase, SqliteVectorStore
from maverick_knowledge.embed import DeterministicEmbedder
from maverick_knowledge.store import PgVectorStore

TEXT = "The admitted document keeps its source and subject across concurrent retries."
DIGEST = hashlib.sha256(TEXT.encode()).hexdigest()


@pytest.fixture(params=["sqlite", "pgvector"])
def publication_stores(request, tmp_path):
    """Two real connections to one collection, never a shared Python lock."""
    if request.param == "sqlite":
        path = tmp_path / "knowledge.db"
        stores = [SqliteVectorStore(path), SqliteVectorStore(path)]
        try:
            yield stores
        finally:
            for store in stores:
                store.close()
        return
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

    table = "kb_publication_" + uuid.uuid4().hex
    stores = []
    try:
        for _ in range(2):
            stores.append(PgVectorStore(dsn, dim=16, table=table, namespace="publication"))
        yield stores
    finally:
        for store in stores:
            store.close()
        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(table)))


def _base(store):
    return KnowledgeBase(store=store, embedder=DeterministicEmbedder(16),
                         chunk_size=24, chunk_overlap=5)


@pytest.mark.parametrize("matching", [False, True], ids=["conflicting", "matching"])
def test_overlapping_admission_preserves_the_first_provenance(publication_stores, monkeypatch, matching):
    delayed, winner = map(_base, publication_stores)
    barrier = threading.Barrier(2)
    published = threading.Event()
    before = []
    for kb in (delayed, winner):
        original = kb.embedder.embed

        def embed(texts, *, delegate=original, wait_for_winner=kb is delayed):
            # Both callers have read absence before either may publish.
            barrier.wait(timeout=15)
            if wait_for_winner:
                assert published.wait(timeout=15)
            return delegate(texts)

        monkeypatch.setattr(kb.embedder, "embed", embed)

    def first_publication():
        try:
            result = winner.ingest_text("records", TEXT, source="winner.txt", subject="subject:winner")
            before.extend(winner.store.read_where("records", "doc_sha256", DIGEST, limit=100))
            return result
        finally:
            published.set()

    source = "winner.txt" if matching else "loser.txt"
    subject = "subject:winner" if matching else "subject:loser"
    with ThreadPoolExecutor(max_workers=2) as executor:
        later = executor.submit(delayed.ingest_text, "records", TEXT, source=source, subject=subject)
        first = executor.submit(first_publication)
        count = first.result(timeout=25)
        assert count > 1
        if matching:
            assert later.result(timeout=25) == count
        else:
            with pytest.raises(RuntimeError, match="bound to different provenance"):
                later.result(timeout=25)
    # A matching retry must keep original timestamps, layout and provenance.
    assert delayed.store.read_where("records", "doc_sha256", DIGEST, limit=100) == before
    exact = delayed.exact_document("records", DIGEST)
    assert exact["source"] == "winner.txt" and exact["subject"] == "subject:winner"
    assert delayed.erase_subject("subject:loser", ["records"]) == {}
    assert winner.erase_subject("subject:winner", ["records"]) == {"records": count}
    assert delayed.store.count("records") == 0


def test_matching_repair_keeps_admitted_timestamp_and_conflict_is_atomic(publication_stores):
    original, restarted = map(_base, publication_stores)
    count = original.ingest_text("records", TEXT, source="winner.txt", subject="subject:winner")
    before = original.store.read_where("records", "doc_sha256", DIGEST, limit=100)
    missing = before[0].chunk_id
    store = original.store
    if isinstance(store, SqliteVectorStore):
        store._db.execute("DELETE FROM chunks WHERE collection=? AND id=?", ("records", missing))
        store._db.commit()
    else:
        store._db.execute(f"DELETE FROM {store._table} WHERE namespace=%s AND collection=%s AND id=%s",
                          (store._namespace, "records", missing))
    partial = restarted.store.read_where("records", "doc_sha256", DIGEST, limit=100)
    with pytest.raises(RuntimeError, match="different provenance"):
        restarted.ingest_text("records", TEXT, source="other.txt", subject="subject:other")
    assert restarted.store.read_where("records", "doc_sha256", DIGEST, limit=100) == partial
    assert restarted.ingest_text("records", TEXT, source="winner.txt", subject="subject:winner") == count
    assert restarted.store.read_where("records", "doc_sha256", DIGEST, limit=100) == before


def test_writer_rejects_conflicting_chunk_without_partial_batch(publication_stores):
    first, second = map(_base, publication_stores)
    first.ingest_text("records", TEXT, source="winner.txt", subject="subject:winner")
    before = first.store.read_where("records", "doc_sha256", DIGEST, limit=100)
    row = before[0]
    incoming = [
        ("new-uncommitted", "different document", [1.] * 16,
         {**row.meta, "doc_sha256": "a" * 64}),
        (row.chunk_id, row.text, [1.] * 16, {**row.meta, "source": "conflict.txt"}),
    ]
    with pytest.raises(RuntimeError, match="different provenance"):
        second.store.add_with_identity("records", incoming, row.meta["embedding_fingerprint"])
    assert second.store.read_collection("records", limit=100) == before


def test_staged_source_revision_cannot_overwrite_a_concurrent_revision(publication_stores, monkeypatch):
    delayed, winner = map(_base, publication_stores)
    winner.ingest_text("records", TEXT, source="policy.txt")
    staged = threading.Event()
    published = threading.Event()
    embed = delayed.embedder.embed

    def wait_for_winner(texts):
        staged.set()
        assert published.wait(timeout=15)
        return embed(texts)

    monkeypatch.setattr(delayed.embedder, "embed", wait_for_winner)
    revision = TEXT + " The accepted revision adds a new retention requirement."
    with ThreadPoolExecutor(max_workers=1) as executor:
        later = executor.submit(
            delayed.ingest_text, "records", TEXT + " A stale staged revision.",
            source="policy.txt", replace_source=True,
        )
        try:
            assert staged.wait(timeout=15)
            count = winner.ingest_text("records", revision, source="policy.txt", replace_source=True)
            accepted = winner.store.read_collection("records", limit=100)
        finally:
            published.set()
        with pytest.raises(RuntimeError, match="source changed during replacement"):
            later.result(timeout=20)
    assert delayed.store.read_collection("records", limit=100) == accepted
    assert len(accepted) == count
    assert winner.exact_document("records", hashlib.sha256(revision.encode()).hexdigest())["text"] == revision
    with pytest.raises(LookupError):
        winner.exact_document("records", DIGEST)


def test_source_replacement_cannot_claim_another_documents_provenance(publication_stores):
    first, second = map(_base, publication_stores)
    first.ingest_text("records", TEXT, source="accepted.txt", subject="subject:accepted")
    first.ingest_text("records", "The old reference awaiting replacement.", source="revised.txt")
    before = first.store.read_collection("records", limit=100)
    with pytest.raises(RuntimeError, match="different provenance"):
        second.ingest_text("records", TEXT, source="revised.txt", replace_source=True)
    assert second.store.read_collection("records", limit=100) == before
