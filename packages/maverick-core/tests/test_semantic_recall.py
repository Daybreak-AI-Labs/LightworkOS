"""Semantic cross-run recall over the vector_store adapters.

The heavy backends (chromadb/qdrant) aren't installed in CI, so the wiring
is exercised with a FakeStore implementing the same add/query/delete
interface, injected via the `store=` parameter. The orchestrator path is
covered by monkeypatching semantic_recall.build_store.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import semantic_recall as sr
from maverick.budget import Budget
from maverick.orchestrator import _maybe_recall_prior_work, run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel


@pytest.fixture()
def _unsealed_vector_backend(monkeypatch):
    """These tests target the ACTIVE qdrant vector path (collection
    naming, index/search). Under the secure posture, at-rest encryption
    deliberately disables qdrant (sealing its documents is not
    implemented) and falls back to lexical recall — that fallback has
    its own coverage in TestAtRestSealing; here encryption is explicitly
    off so the vector path under test actually runs."""
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")


class FakeStore:
    """In-memory stand-in for ChromaStore/QdrantStore.

    Ranks by token-overlap so tests are deterministic without embeddings;
    returns the same {id, document, distance, metadata} shape.
    """

    def __init__(self):
        # id -> (document, metadata, embedding|None)
        self.docs: dict[str, tuple[str, dict, list | None]] = {}

    def add(self, documents, *, ids=None, metadatas=None, embeddings=None):
        for i, doc in enumerate(documents):
            emb = embeddings[i] if embeddings is not None else None
            self.docs[ids[i]] = (doc, (metadatas or [{}])[i], emb)

    def upsert_one(self, document, *, id, metadata, embedding=None):
        self.docs[id] = (document, metadata, embedding)

    def delete(self, ids):
        for i in ids:
            self.docs.pop(i, None)

    def count(self):
        return len(self.docs)

    def query(self, text=None, *, top_k=5, embedding=None):
        scored = []
        if embedding is not None:
            # Sealed mode: rank by Euclidean distance to the stored vectors.
            for doc_id, (doc, meta, emb) in self.docs.items():
                if emb is None:
                    dist = 1.0
                else:
                    dist = sum((a - b) ** 2
                               for a, b in zip(embedding, emb, strict=False)) ** 0.5
                scored.append((dist, doc_id, doc, meta))
            scored.sort(key=lambda r: r[0])
            return [{"id": i, "document": d, "distance": dist, "metadata": m}
                    for dist, i, d, m in scored[:top_k]]
        q = set((text or "").lower().split())
        for doc_id, (doc, meta, _emb) in self.docs.items():
            d = set(doc.lower().split())
            overlap = len(q & d) / len(q | d) if (q | d) else 0.0
            scored.append((overlap, doc_id, doc, meta))
        scored.sort(key=lambda r: r[0], reverse=True)
        return [{"id": doc_id, "document": doc,
                 "distance": 1.0 - overlap, "metadata": meta}
                for overlap, doc_id, doc, meta in scored[:top_k]]


class _Goal:
    def __init__(self, gid, title, description="", status="done", result=""):
        self.id = gid
        self.title = title
        self.description = description
        self.status = status
        self.result = result


class TestBackendName:
    def test_none_by_default(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_VECTOR_STORE", raising=False)
        assert sr.backend_name() is None

    def test_env_selects_backend(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_VECTOR_STORE", "chroma")
        assert sr.backend_name() == "chroma"

    def test_unknown_backend_is_none(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_VECTOR_STORE", "pinecone")
        assert sr.backend_name() is None

    def test_weaviate_backend_recognized(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_VECTOR_STORE", "weaviate")
        assert sr.backend_name() == "weaviate"


@pytest.mark.usefixtures("_unsealed_vector_backend")
class TestIndexAndSearch:
    def test_index_then_search_finds_goal(self):
        store = FakeStore()
        sr.index_goal(_Goal(1, "deploy the web app", result="used docker"), store=store)
        hits = sr.search("deploy the web app", store=store)
        assert hits is not None
        assert hits[0][1]["goal_id"] == 1
        # Sensitive fields are NOT duplicated into the vector store's metadata --
        # callers hydrate title/result from the sealed world DB by goal_id.
        assert "result" not in hits[0][1]
        assert "title" not in hits[0][1]

    def test_index_omits_sensitive_metadata(self):
        store = FakeStore()
        sr.index_goal(_Goal(1, "deploy app", result="SECRET 4111111111111111"),
                      store=store)
        # The stored metadata holds no verbatim copy of the sensitive result.
        _doc, meta, _emb = store.docs["goal:1"]
        assert "4111111111111111" not in str(meta)
        assert set(meta) <= {"goal_id", "status"}

    def test_index_upserts_not_duplicates(self):
        store = FakeStore()
        g = _Goal(1, "summarize sales", result="v1")
        sr.index_goal(g, store=store)
        g.result = "v2"
        sr.index_goal(g, store=store)
        assert store.count() == 1
        hits = sr.search("summarize sales", store=store)
        assert hits[0][1]["goal_id"] == 1

    def test_search_excludes_current_goal(self):
        store = FakeStore()
        sr.index_goal(_Goal(7, "unique task alpha", result="done"), store=store)
        hits = sr.search("unique task alpha", store=store, exclude_goal_id=7)
        assert hits == []

    def test_search_returns_none_without_backend(self):
        # No store passed + no backend configured -> None (signals fallback).
        assert sr.search("anything") is None

    def test_index_noop_without_backend(self):
        assert sr.index_goal(_Goal(1, "x")) is False

    def test_distance_maps_to_similarity(self):
        store = FakeStore()
        sr.index_goal(_Goal(1, "alpha beta gamma", result="r"), store=store)
        hits = sr.search("alpha beta gamma", store=store)
        # Identical text -> overlap 1.0 -> distance 0.0 -> similarity ~1.0.
        assert hits[0][0] == pytest.approx(1.0)


class TestOrchestratorRouting:
    def test_recall_uses_semantic_when_available(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTO_RECALL", "1")
        store = FakeStore()
        monkeypatch.setattr(sr, "build_store", lambda backend=None: store)
        world = WorldModel(tmp_path / "w.db")
        # The prior goal is a REAL world goal (title/result come from the sealed
        # DB now, not from vector metadata); index that world goal.
        prior = world.create_goal("build a sales CSV report", "group + sum")
        world.set_goal_status(prior, "done", result="wrote report.csv")
        sr.index_goal(world.get_goal(prior), store=store)
        cur = world.get_goal(
            world.create_goal("build a sales CSV report v2", "group + sum")
        )
        block = _maybe_recall_prior_work(world, cur, None)
        assert block is not None
        assert "Relevant prior work" in block
        assert "wrote report.csv" in block

    def test_recall_falls_back_when_no_backend(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTO_RECALL", "1")
        monkeypatch.setattr(sr, "build_store", lambda backend=None: None)
        world = WorldModel(tmp_path / "w.db")
        gid = world.create_goal("translate a document to French", "fr")
        world.set_goal_status(gid, "done", result="translated via tool")
        cur = world.get_goal(
            world.create_goal("translate a document to French again", "fr")
        )
        # Falls back to recall_past_goals (lexical) and still finds the prior.
        block = _maybe_recall_prior_work(world, cur, None)
        assert block is not None
        assert "translated via tool" in block


@pytest.mark.asyncio
@pytest.mark.usefixtures("_unsealed_vector_backend")
async def test_run_goal_indexes_on_success(tmp_path: Path, fake_llm, make_llm_response, monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(sr, "build_store", lambda backend=None: store)
    fake_llm.scripted = [
        make_llm_response(text="FINAL: done"),
        make_llm_response(
            text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}',
        ),
        make_llm_response(text="FINAL: (no skill)"),
    ]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("index me on success", "please")
    await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )
    # The finished goal was indexed into the semantic store.
    assert store.count() == 1
    hits = sr.search("index me on success", store=store)
    assert hits[0][1]["goal_id"] == gid


@pytest.mark.usefixtures("_unsealed_vector_backend")
class TestTenantCollectionIsolation:
    """build_store gives each tenant its OWN collection on the shared external
    backends (chroma/qdrant/weaviate) so similarity SEARCH can't cross tenants.
    """

    def _capture(self, monkeypatch):
        import maverick.vector_store as vs
        captured = {}

        class _Fake:
            def __init__(self, collection=None, **kw):
                captured["collection"] = collection

        monkeypatch.setattr(vs, "ChromaStore", _Fake)
        monkeypatch.setattr(vs, "QdrantStore", _Fake)
        monkeypatch.setattr(vs, "WeaviateStore", _Fake)
        return captured

    def test_collection_is_tenant_namespaced(self, monkeypatch):
        captured = self._capture(monkeypatch)
        from maverick import paths
        monkeypatch.setattr(paths, "current_tenant", lambda: "acme-1")

        sr.build_store("chroma")
        assert captured["collection"].startswith("t_acme_1_")
        assert captured["collection"].endswith("__goals")
        sr.build_store("qdrant")
        assert captured["collection"].startswith("t_acme_1_")
        assert captured["collection"].endswith("__goals_v2")
        sr.build_store("weaviate")  # class names must start uppercase
        assert captured["collection"].startswith("T_acme_1_")
        assert captured["collection"].endswith("__Goals")

    def test_single_tenant_collection_unchanged(self, monkeypatch):
        captured = self._capture(monkeypatch)
        from maverick import paths
        monkeypatch.setattr(paths, "current_tenant", lambda: None)

        sr.build_store("chroma")
        assert captured["collection"] == "goals"
        sr.build_store("weaviate")
        assert captured["collection"] == "Goals"

    def test_two_tenants_get_distinct_collections(self, monkeypatch):
        captured = self._capture(monkeypatch)
        from maverick import paths

        monkeypatch.setattr(paths, "current_tenant", lambda: "tenant_a")
        sr.build_store("qdrant")
        a = captured["collection"]
        monkeypatch.setattr(paths, "current_tenant", lambda: "tenant_b")
        sr.build_store("qdrant")
        b = captured["collection"]
        assert a != b
        assert a.startswith("t_tenant_a_") and a.endswith("__goals_v2")
        assert b.startswith("t_tenant_b_") and b.endswith("__goals_v2")

    @pytest.mark.parametrize(("tenant_a", "tenant_b"), [
        ("acme-1", "acme_1"),
        ("acme_1", "acme.1"),
        ("A" * 60 + "1", "A" * 60 + "2"),
    ])
    def test_collision_prone_tenants_get_distinct_collections(
        self, monkeypatch, tenant_a, tenant_b
    ):
        captured = self._capture(monkeypatch)
        from maverick import paths

        monkeypatch.setattr(paths, "current_tenant", lambda: tenant_a)
        sr.build_store("chroma")
        a = captured["collection"]
        monkeypatch.setattr(paths, "current_tenant", lambda: tenant_b)
        sr.build_store("chroma")
        b = captured["collection"]
        assert a != b
        assert a.startswith("t_") and a.endswith("__goals")
        assert b.startswith("t_") and b.endswith("__goals")
        assert len(a) <= 63
        assert len(b) <= 63


import importlib.util  # noqa: E402

requires_crypto = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra is not installed",
)


def _fake_embed(texts):
    """Deterministic stand-in for the fastembed model: identical text -> identical
    vector (so the FakeStore can match by vector), different text -> different."""
    out = []
    for t in texts:
        toks = t.lower().split()
        out.append([float(len(toks)), float(len(t)), float(sum(map(ord, t)) % 97)])
    return out


class TestAtRestSealing:
    """Under at-rest encryption the stored document is sealed and the embedding is
    precomputed client-side (so search still works); qdrant/weaviate fall back."""

    @pytest.fixture
    def _sealed(self, monkeypatch, tmp_path):
        import maverick.crypto_at_rest as car
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
        monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
        monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
        monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "keys" / "at_rest.key")
        monkeypatch.setattr("maverick.skill.embeddings.embed", _fake_embed)

    @requires_crypto
    def test_document_is_sealed_and_embedding_precomputed(self, _sealed):
        import maverick.crypto_at_rest as car
        store = FakeStore()
        sr.index_goal(_Goal(1, "alpha task", result="SSN 123-45-6789"), store=store)
        doc, meta, emb = store.docs["goal:1"]
        assert car.is_sealed_str(doc)              # ciphertext, not plaintext
        assert "alpha task" not in doc
        assert emb == _fake_embed(["alpha task"])[0]   # vector from plaintext
        assert set(meta) <= {"goal_id", "status"}

    @requires_crypto
    def test_sealed_search_matches_by_vector(self, _sealed):
        store = FakeStore()
        sr.index_goal(_Goal(1, "alpha unique"), store=store)
        sr.index_goal(_Goal(2, "beta different"), store=store)
        hits = sr.search("alpha unique", store=store)
        assert hits and hits[0][1]["goal_id"] == 1

    def test_no_embedder_skips_index_under_at_rest(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
        monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
        monkeypatch.setattr("maverick.skill.embeddings.embed", lambda texts: None)
        store = FakeStore()
        # No local embedder under at-rest -> skip rather than leak plaintext.
        assert sr.index_goal(_Goal(1, "x y z"), store=store) is False
        assert store.count() == 0

    @requires_crypto
    @pytest.mark.parametrize("failure", ["unavailable-embedder", "embedding-error", "sealing-error"])
    def test_failed_preparation_preserves_prior_index_and_allows_retry(
        self, _sealed, monkeypatch, failure,
    ):
        store = FakeStore()
        assert sr.index_goal(_Goal(1, "prior reviewed report"), store=store)
        previous = dict(store.docs)

        def unavailable(*args, **kwargs):
            raise RuntimeError("temporary preparation failure")

        with monkeypatch.context() as patch:
            if failure == "unavailable-embedder":
                patch.setattr("maverick.skill.embeddings.embed", lambda texts: None)
            elif failure == "embedding-error":
                patch.setattr("maverick.skill.embeddings.embed", unavailable)
            else:
                patch.setattr("maverick.crypto_at_rest.seal_to_str", unavailable)
            assert sr.index_goal(_Goal(1, "revised report"), store=store) is False
            assert store.docs == previous

        # Prior bytes survive, but the failed refresh is incomplete. Force the
        # orchestrator's lexical path until this exact goal is retried.
        assert sr.index_status(store=store) == "rebuild_required"
        assert sr.search("prior reviewed report", store=store) is None
        assert sr.index_goal(_Goal(1, "revised report"), store=store)
        assert store.count() == 1
        assert store.docs != previous

    def test_at_rest_off_stores_plaintext_unchanged(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
        store = FakeStore()
        sr.index_goal(_Goal(1, "plain text goal"), store=store)
        doc, _meta, emb = store.docs["goal:1"]
        assert doc == "plain text goal" and emb is None

    def test_qdrant_and_weaviate_disabled_under_at_rest(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
        monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
        sr._sealed_warned.clear()
        with caplog.at_level(logging.WARNING, logger="maverick.semantic_recall"):
            assert sr.build_store("qdrant") is None
            assert sr.build_store("weaviate") is None
        assert any("disabled for the 'qdrant'" in r.message for r in caplog.records)

    def test_chroma_collection_gets_sealed_suffix(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
        monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
        import maverick.vector_store as vs
        from maverick import paths
        captured = {}

        class _Fake:
            def __init__(self, collection=None, **kw):
                captured["c"] = collection

        monkeypatch.setattr(vs, "ChromaStore", _Fake)
        monkeypatch.setattr(paths, "current_tenant", lambda: None)
        sr.build_store("chroma")
        assert captured["c"] == "goals_s"
