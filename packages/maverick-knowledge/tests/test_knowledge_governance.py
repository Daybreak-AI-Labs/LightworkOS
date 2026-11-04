"""Governed knowledge plane: provenance stamping, erasure by subject/source,
verification counts, and store-layer delete_where/count_where/collections
across the SQLite store and the Qdrant adapter (via a fake client)."""
from __future__ import annotations

import sys
import types
from hashlib import sha256

import pytest
from maverick_knowledge import DeterministicEmbedder, KnowledgeBase, SqliteVectorStore
from maverick_knowledge.store import QdrantStore

# ---- store layer -------------------------------------------------------------

def test_sqlite_delete_where_and_count_where():
    s = SqliteVectorStore(":memory:")
    s.add("c", [
        ("id1", "alice doc", [1.0, 0.0], {"subject": "u:alice", "source": "a.txt"}),
        ("id2", "bob doc", [0.0, 1.0], {"subject": "u:bob", "source": "b.txt"}),
        ("id3", "alice doc 2", [1.0, 1.0], {"subject": "u:alice", "source": "a2.txt"}),
    ])
    assert s.count("c") == 3
    assert s.count_where("c", "subject", "u:alice") == 2
    assert sorted(s.collections()) == ["c"]
    removed = s.delete_where("c", "subject", "u:alice")
    assert removed == 2
    assert s.count_where("c", "subject", "u:alice") == 0
    assert s.count("c") == 1
    # by source too
    assert s.delete_where("c", "source", "b.txt") == 1
    assert s.count("c") == 0


# ---- KnowledgeBase provenance + erasure --------------------------------------

def test_ingest_stamps_provenance():
    s = SqliteVectorStore(":memory:")
    kb = KnowledgeBase(store=s)
    kb.ingest_text("c", "some content here", source="doc.txt",
                   subject="slack:U1", trust_tier=1, sensitivity="confidential",
                   ingested_by="admin@co")
    rows = s._db.execute("SELECT meta FROM chunks WHERE collection='c'").fetchall()
    import json
    meta = json.loads(rows[0][0])
    assert meta["subject"] == "slack:U1"
    assert meta["trust_tier"] == 1
    assert meta["sensitivity"] == "confidential"
    assert meta["ingested_by"] == "admin@co"
    assert meta["source"] == "doc.txt"
    assert len(meta["doc_sha256"]) == 64
    assert "ingested_at" in meta


def test_erase_subject_isolates_and_verifies():
    kb = KnowledgeBase(store=SqliteVectorStore(":memory:"))
    kb.ingest_text("itgrc", "alice's private file", source="a.txt", subject="slack:UA")
    kb.ingest_text("itgrc", "bob's private file", source="b.txt", subject="slack:UB")
    kb.ingest_text("itgrc", "public GDPR reference text", source="gdpr.txt")  # no subject
    assert kb.count_subject("slack:UA") == 1
    removed = kb.erase_subject("slack:UA")
    assert removed == {"itgrc": 1}
    assert kb.count_subject("slack:UA") == 0
    assert kb.count_subject("slack:UB") == 1          # other subject untouched
    assert kb.store.count("itgrc") == 2               # reference material survives


def test_erase_source_retracts_a_document():
    kb = KnowledgeBase(store=SqliteVectorStore(":memory:"))
    kb.ingest_text("c", "doc one text", source="one.txt")
    kb.ingest_text("c", "doc two text", source="two.txt")
    assert kb.erase_source("one.txt") == {"c": 1}
    assert kb.store.count("c") == 1


def test_erase_empty_subject_is_noop():
    kb = KnowledgeBase(store=SqliteVectorStore(":memory:"))
    kb.ingest_text("c", "text", source="x.txt", subject="slack:U1")
    assert kb.erase_subject("") == {}
    assert kb.count_subject("") == 0
    assert kb.store.count("c") == 1


def test_collections_lists_all():
    kb = KnowledgeBase(store=SqliteVectorStore(":memory:"))
    kb.ingest_text("itgrc", "a", source="a")
    kb.ingest_text("legal", "b", source="b")
    assert sorted(kb.collections()) == ["itgrc", "legal"]


# ---- Qdrant adapter against a fake client ------------------------------------

class _FakePoint:
    def __init__(self, score, payload, point_id="point"):
        self.score = score
        self.payload = payload
        self.id = point_id


class _FakeQdrantClient:
    """Minimal in-memory stand-in for qdrant_client.QdrantClient covering the
    surface QdrantStore uses."""

    def __init__(self, *a, **k):
        self._collections: dict[str, dict] = {}

    def collection_exists(self, collection_name):
        return collection_name in self._collections

    def create_collection(self, collection_name, vectors_config):
        self._collections[collection_name] = {}

    def upsert(self, collection_name, points):
        col = self._collections.setdefault(collection_name, {})
        for p in points:
            col[p.id] = {"vector": p.vector, "payload": p.payload}

    def query_points(self, collection_name, query, limit, with_payload=True):
        col = self._collections.get(collection_name, {})
        pts = [_FakePoint(1.0, v["payload"]) for v in col.values()][:limit]
        return types.SimpleNamespace(points=pts)

    def delete_collection(self, collection_name):
        self._collections.pop(collection_name, None)

    def get_collections(self):
        cols = [types.SimpleNamespace(name=n) for n in self._collections]
        return types.SimpleNamespace(collections=cols)

    def _matches(self, payload, flt):
        for cond in flt.must:
            key = cond.key.split(".", 1)[1]   # "meta.subject" -> "subject"
            if (payload.get("meta") or {}).get(key) != cond.match.value:
                return False
        return True

    def delete(self, collection_name, points_selector):
        col = self._collections.get(collection_name, {})
        flt = points_selector.filter
        doomed = [pid for pid, v in col.items() if self._matches(v["payload"], flt)]
        for pid in doomed:
            del col[pid]

    def count(self, collection_name, count_filter=None, exact=True):
        col = self._collections.get(collection_name, {})
        if count_filter is None:
            return types.SimpleNamespace(count=len(col))
        n = sum(1 for v in col.values() if self._matches(v["payload"], count_filter))
        return types.SimpleNamespace(count=n)

    def scroll(
        self,
        collection_name,
        scroll_filter,
        limit,
        with_payload=True,
        with_vectors=False,
    ):
        del with_payload, with_vectors
        col = self._collections.get(collection_name, {})
        points = [
            _FakePoint(1.0, value["payload"], point_id)
            for point_id, value in col.items()
            if self._matches(value["payload"], scroll_filter)
        ][:limit]
        return points, None

    def close(self):
        pass


def _install_fake_qdrant(monkeypatch):
    mod = types.ModuleType("qdrant_client")
    mod.QdrantClient = _FakeQdrantClient

    models = types.ModuleType("qdrant_client.models")

    class _VP:
        def __init__(self, size, distance): ...

    class _Dist:
        COSINE = "Cosine"

    class _Point:
        def __init__(self, id, vector, payload):
            self.id, self.vector, self.payload = id, vector, payload

    class _MatchValue:
        def __init__(self, value): self.value = value

    class _FieldCondition:
        def __init__(self, key, match): self.key, self.match = key, match

    class _Filter:
        def __init__(self, must): self.must = must

    class _FilterSelector:
        def __init__(self, filter): self.filter = filter

    models.VectorParams = _VP
    models.Distance = _Dist
    models.PointStruct = _Point
    models.MatchValue = _MatchValue
    models.FieldCondition = _FieldCondition
    models.Filter = _Filter
    models.FilterSelector = _FilterSelector
    mod.models = models
    monkeypatch.setitem(sys.modules, "qdrant_client", mod)
    monkeypatch.setitem(sys.modules, "qdrant_client.models", models)


def test_qdrant_store_full_governance_cycle(monkeypatch):
    _install_fake_qdrant(monkeypatch)
    store = QdrantStore(url="http://fake:6333", dim=2, namespace="ws1")
    store.add("itgrc", [
        ("id1", "alice", [1.0, 0.0], {"subject": "u:alice", "source": "a"}),
        ("id2", "bob", [0.0, 1.0], {"subject": "u:bob", "source": "b"}),
    ])
    assert store.count("itgrc") == 2
    assert store.collections() == ["itgrc"]
    hits = store.search("itgrc", [1.0, 0.0], k=5)
    assert {h.text for h in hits} == {"alice", "bob"}
    assert hits[0].meta.get("subject") in {"u:alice", "u:bob"}
    assert store.count_where("itgrc", "subject", "u:alice") == 1
    exact = store.read_where("itgrc", "subject", "u:alice", limit=10)
    assert [(row.text, row.meta["source"]) for row in exact] == [("alice", "a")]
    assert store.delete_where("itgrc", "subject", "u:alice") == 1
    assert store.count_where("itgrc", "subject", "u:alice") == 0
    assert store.count("itgrc") == 1
    # namespace isolation: a different namespace sees nothing
    store2 = QdrantStore(url="http://fake:6333", dim=2, namespace="ws2")
    store2._client = store._client  # share the fake backend
    assert store2.count("itgrc") == 0


def test_qdrant_preserves_existing_reads_and_refuses_unfenced_publication(monkeypatch):
    _install_fake_qdrant(monkeypatch)
    store = QdrantStore(url="http://fake:6333", dim=8, namespace="tenant-a")
    kb = KnowledgeBase(
        store=store,
        embedder=DeterministicEmbedder(dim=8),
        chunk_size=18,
        chunk_overlap=4,
    )
    text = "alpha beta gamma delta epsilon zeta eta theta"
    digest = sha256(text.encode("utf-8")).hexdigest()

    # Seed an existing exact document through the low-level adapter, without
    # pretending that its upsert supplies atomic governed admission.
    with KnowledgeBase(embedder=DeterministicEmbedder(dim=8), chunk_size=18, chunk_overlap=4) as admitted:
        count = admitted.ingest_text("finance", text, source="quarterly.txt")
        rows = admitted.store.read_where("finance", "doc_sha256", digest, limit=100)
        store.add("finance", [(row.chunk_id, row.text, kb.embedder.embed([row.text])[0], row.meta)
                              for row in rows])
    monkeypatch.setattr(kb.embedder, "embed", lambda _texts: pytest.fail("unexpected embedding work"))
    monkeypatch.setattr(store, "add", lambda *_args: pytest.fail("unexpected unfenced publication"))
    monkeypatch.setattr(store._client, "create_collection", lambda **_kwargs: pytest.fail("unexpected collection creation"))
    monkeypatch.setattr(store._client, "upsert", lambda **_kwargs: pytest.fail("unexpected point publication"))
    assert kb.ingest_text("finance", text, source="quarterly.txt") == count
    assert store.count_where("finance", "doc_sha256", digest) == count
    assert kb.exact_document("finance", digest)["text"] == text
    with pytest.raises(RuntimeError, match="atomically publish.*SQLite or pgvector"):
        kb.ingest_text("finance", "A new document", source="new.txt")
    with pytest.raises(RuntimeError, match="atomically publish.*SQLite or pgvector"):
        kb.ingest_text("empty", "A new document", source="new.txt")
    with pytest.raises(RuntimeError, match="different provenance"):
        kb.ingest_text("finance", text, source="different.txt")
    assert store.count("finance") == count and store.count("empty") == 0

    other = QdrantStore(url="http://fake:6333", dim=8, namespace="tenant-b")
    other._client = store._client
    assert other.read_where("finance", "doc_sha256", digest, limit=10) == []
    assert kb.erase_source("quarterly.txt") == {"finance": count}
    assert store.count("finance") == 0


def test_qdrant_dim_mismatch_raises(monkeypatch):
    _install_fake_qdrant(monkeypatch)
    store = QdrantStore(url="http://fake:6333", dim=3, namespace="ws1")
    store.add("c", [("id1", "x", [1.0, 0.0, 0.0], {})])
    with pytest.raises(ValueError, match="dim"):
        store.search("c", [1.0, 0.0], k=1)
