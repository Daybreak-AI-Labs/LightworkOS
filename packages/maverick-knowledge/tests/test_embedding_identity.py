"""Offline persisted vector-space migration contracts."""
from __future__ import annotations

import hashlib
import json
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from maverick_knowledge import KnowledgeBase, SqliteVectorStore
from maverick_knowledge.embed import DeterministicEmbedder
from maverick_knowledge.store import PgVectorStore, StoredChunk


def test_local_identity_reuses_resolved_commit_but_not_unverified_branch():
    from maverick_knowledge.embedding_identity import identity
    from maverick_knowledge.local_embed import LocalEmbedder

    first, second = LocalEmbedder("fixture", revision="main"), LocalEmbedder("fixture", revision="main")
    first._model = second._model = SimpleNamespace()
    assert identity(first)[1] != identity(second)[1]
    transformer = SimpleNamespace(auto_model=SimpleNamespace(config=SimpleNamespace(_commit_hash="a" * 40)))
    first._model = second._model = SimpleNamespace(_first_module=lambda: transformer)
    assert identity(first)[1] == identity(second)[1]


class Space(DeterministicEmbedder):
    def __init__(self, revision="a", preprocessing="tokens.v1"):
        super().__init__(16)
        self.revision = revision
        self.preprocessing = preprocessing

    def embedding_identity(self):
        return {"provider": "test", "model": "rotating", "revision": self.revision,
                "preprocessing": self.preprocessing}

    def embed(self, texts):
        vectors = super().embed(texts)
        return [vector[1:] + vector[:1] if self.revision == "b" else vector for vector in vectors]


def test_same_dimension_change_blocks_search_and_ingest_until_explicit_reindex(tmp_path):
    path = tmp_path / "knowledge.db"
    kb = KnowledgeBase(store=SqliteVectorStore(path), embedder=Space())
    count = kb.ingest_text("ops", "the precise procedure", source="policy", subject="person")
    before = kb.exact_document("ops", hashlib.sha256(b"the precise procedure").hexdigest())
    kb.close()
    kb = KnowledgeBase(store=SqliteVectorStore(path), embedder=Space("b"))
    for operation in (lambda: kb.search("ops", "procedure"),
                      lambda: kb.search_formatted(["ops"], "procedure"),
                      lambda: kb.ingest_text("ops", "the precise procedure", source="policy", subject="person"),
                      lambda: kb.ingest_text("ops", "another procedure")):
        with pytest.raises(RuntimeError, match="reindex"):
            operation()
    assert kb.reindex("ops") == count
    after = kb.exact_document("ops", before["doc_sha256"])
    assert after["chunks"] == before["chunks"]
    assert after["ingested_at"] == before["ingested_at"]
    assert after["subject"] == "person"
    assert kb.search("ops", "procedure")[0].source == "policy"
    assert kb.ingest_text("ops", "the precise procedure", source="policy", subject="person") == count
    kb.close()
    with KnowledgeBase(store=SqliteVectorStore(path), embedder=Space("b")) as restarted:
        assert restarted.search("ops", "procedure")
        restarted.embedder.preprocessing = "tokens.v2"
        with pytest.raises(RuntimeError, match="reindex"):
            restarted.search("ops", "procedure")


def test_legacy_and_mixed_rows_fail_closed_and_reindex_preserves_rows():
    with KnowledgeBase(embedder=Space()) as kb:
        kb.ingest_text("ops", "first document")
        kb.store.add("ops", [("legacy", "legacy document", [1.0] * 16, {"source": "legacy"})])
        with pytest.raises(RuntimeError, match="reindex"):
            kb.search("ops", "first")
        assert kb.reindex("ops") == 2
        assert kb.store.count("ops") == 2
        assert kb.search("ops", "legacy")


def test_failed_or_raced_reindex_never_replaces_old_vectors(monkeypatch):
    with KnowledgeBase(embedder=Space()) as kb:
        kb.ingest_text("ops", "a document")
        before = kb.store._db.execute("SELECT vec,meta FROM chunks").fetchall()
        kb.embedder = Space("b")
        monkeypatch.setattr(kb.embedder, "embed", lambda texts: [[float("nan")] * 16 for _ in texts])
        with pytest.raises(ValueError, match="invalid"):
            kb.reindex("ops")
        assert kb.store._db.execute("SELECT vec,meta FROM chunks").fetchall() == before
        kb.embedder = Space("b")
        original = kb.embedder.embed

        def erased_during_embedding(texts):
            kb.store.delete_collection("ops")
            return original(texts)

        monkeypatch.setattr(kb.embedder, "embed", erased_during_embedding)
        with pytest.raises(RuntimeError, match="changed"):
            kb.reindex("ops")
        assert kb.store.count("ops") == 0


def test_untransactional_backend_rejects_before_embedding():
    class ExternalStore:
        pass

    kb = KnowledgeBase(store=ExternalStore(), embedder=Space())
    with pytest.raises(RuntimeError, match="new collection"):
        kb.reindex("ops")


def test_returned_match_cannot_cross_identity(monkeypatch):
    with KnowledgeBase(embedder=Space()) as kb:
        kb.ingest_text("ops", "a document")
        search = kb.store.search

        def stale(collection, vector, k):
            rows = search(collection, vector, k)
            rows[0].meta["embedding_fingerprint"] = "old"
            return rows

        monkeypatch.setattr(kb.store, "search", stale)
        with pytest.raises(RuntimeError, match="changed"):
            kb.search("ops", "document")
        assert json.loads(kb.store._db.execute("SELECT meta FROM chunks").fetchone()[0])["embedding_fingerprint"] != "old"


def test_pg_reindex_locks_compares_and_updates_in_one_namespace_transaction(monkeypatch):
    """Actual adapter against a transaction-shaped fixture; not live PostgreSQL."""
    from maverick_knowledge import store as module

    events = []

    @contextmanager
    def accounting(*args, **kwargs):
        yield lambda dispatch: dispatch()

    monkeypatch.setattr(module, "metered_operation", accounting)

    class Connection:
        rows = [("one", "policy", {"source": "policy.txt"})]

        @contextmanager
        def transaction(self):
            events.append("begin")
            try:
                yield
            except Exception:
                events.append("rollback")
                raise
            else:
                events.append("commit")

        @contextmanager
        def cursor(self):
            yield self

        def execute(self, sql, params):
            events.append((sql, params))
            return self

        def fetchall(self):
            return self.rows

        def executemany(self, sql, params):
            events.append((sql, params))

    adapter = object.__new__(PgVectorStore)
    adapter._db = Connection()
    adapter._lock = threading.Lock()
    adapter._namespace = "tenant-a"
    adapter._table = "knowledge_chunks"
    snapshot = [StoredChunk("one", "policy", {"source": "policy.txt"})]
    adapter.replace_embeddings("ops", snapshot, [("one", "policy", [1., 0.], snapshot[0].meta)])
    assert events[0] == "begin" and events[-1] == "commit"
    assert "pg_advisory_xact_lock" in events[1][0]
    assert "FOR UPDATE" in events[2][0] and events[2][1] == ("tenant-a", "ops")
    assert events[3][1][0][-3:] == ("tenant-a", "ops", "one")
    events.clear()
    adapter._db.rows = []
    with pytest.raises(RuntimeError, match="changed"):
        adapter.replace_embeddings("ops", snapshot, [])
    assert events[-1] == "rollback" and len(events) == 4


def test_ingestion_cannot_publish_old_identity_after_concurrent_reindex(tmp_path, monkeypatch):
    path = tmp_path / "knowledge.db"
    with KnowledgeBase(store=SqliteVectorStore(path), embedder=Space()) as old:
        old.ingest_text("ops", "original source")
        with KnowledgeBase(store=SqliteVectorStore(path), embedder=Space("b")) as migrated:
            original_check = old._require_embedding_identity
            checks = 0

            def migrate_after_check(collection, fingerprint):
                nonlocal checks
                original_check(collection, fingerprint)
                checks += 1
                if checks == 2:
                    migrated.reindex(collection)

            monkeypatch.setattr(old, "_require_embedding_identity", migrate_after_check)
            with pytest.raises(RuntimeError, match="identity.*reindex"):
                old.ingest_text("ops", "stale worker new source")
            assert migrated.store.count("ops") == 1
            assert migrated.search("ops", "original")
