"""Optional native LOCAL adapters, explicit vectors only; never model downloads."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from maverick import semantic_recall as sr
from maverick.paths import tenant_scope


@pytest.fixture(params=["chroma", "qdrant"])
def native_store(request, tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("ANONYMIZED_TELEMETRY", "False")
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    monkeypatch.delenv("MAVERICK_QDRANT_API_KEY", raising=False)
    monkeypatch.setattr(sr, "_embed_texts", lambda texts: [[1.0, 0.0] for _ in texts])
    if request.param == "chroma":
        pytest.importorskip("chromadb")
        from maverick.vector_store.chroma_store import ChromaStore
        store = ChromaStore(collection="native_recall", path=tmp_path / "chroma", embedding_function=None)
    else:
        pytest.importorskip("qdrant_client")
        from maverick.vector_store.qdrant_store import QdrantStore
        store = QdrantStore(collection="native_recall", path=tmp_path / "qdrant")
    yield store
    if request.param == "qdrant":
        store._client.close()


def goal(title):
    return SimpleNamespace(id=1, title=title, description="", status="done")


def test_native_replace_dimension_failure_preserves_prior_and_recovers(native_store, monkeypatch):
    store = native_store
    assert sr.index_goal(goal("prior document"), store=store)
    assert sr.search("prior", store=store)
    monkeypatch.setattr(sr, "_embed_texts", lambda texts: [[1.0, 0.0, 0.0] for _ in texts])
    assert not sr.index_goal(goal("replacement"), store=store)
    assert store.count() == 1
    prior = store.query(embedding=[1.0, 0.0])
    assert prior[0]["document"] == "prior document"
    assert sr.index_status(store=store) == "rebuild_required"
    assert sr.search("prior", store=store) is None
    monkeypatch.setattr(sr, "_embed_texts", lambda texts: [[0.0, 1.0] for _ in texts])
    assert sr.index_goal(goal("replacement"), store=store)
    assert store.count() == 1
    assert store.query(embedding=[0.0, 1.0])[0]["document"] == "replacement"
    assert sr.index_status(store=store) == "ready"


def test_native_failed_preparation_and_delete_do_not_resurrect(native_store):
    store = native_store
    store.upsert_one("prior", id="goal:1", metadata={"goal_id": 1}, embedding=[1.0, 0.0])
    with pytest.raises(ValueError):
        store.upsert_one("invalid", id="goal:1", metadata={"goal_id": 1}, embedding=[float("nan"), 0.0])
    assert store.query(embedding=[1.0, 0.0])[0]["document"] == "prior"
    assert sr.remove_goal(1, store=store)
    assert store.count() == 0
    assert store.query(embedding=[1.0, 0.0]) == []
    assert not sr.index_goal(goal("late retry"), store=store)
    assert store.count() == 0


def test_native_qdrant_exact_tenant_filter_and_uuid_collision(native_store):
    from maverick.vector_store.qdrant_store import QdrantStore

    if not isinstance(native_store, QdrantStore):
        pytest.skip("Qdrant exact payload filter contract")
    store = native_store
    for tenant, text in [("acme-1", "a"), ("acme_1", "b")]:
        with tenant_scope(tenant=tenant):
            store.upsert_one(text, id="same", metadata={"goal_id": 1}, embedding=[1.0, 0.0])
    with tenant_scope(tenant="acme-1"):
        assert [h["document"] for h in store.query(embedding=[1.0, 0.0])] == ["a"]
        store.delete(["same"])
        assert store.query(embedding=[1.0, 0.0]) == []
    with tenant_scope(tenant="acme_1"):
        assert [h["document"] for h in store.query(embedding=[1.0, 0.0])] == ["b"]
