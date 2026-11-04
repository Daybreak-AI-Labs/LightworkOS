"""Tests for the Chroma vector store (maverick.vector_store.chroma_store)."""
from __future__ import annotations

import importlib.util
import sys

import pytest

# ---------- Chroma vector store ----------

_HAS_CHROMA = importlib.util.find_spec("chromadb") is not None


@pytest.mark.skipif(not _HAS_CHROMA, reason="chromadb not installed")
def test_chroma_store_round_trip(tmp_path, monkeypatch):
    from maverick.vector_store import ChromaStore
    monkeypatch.setenv("ANONYMIZED_TELEMETRY", "False")
    store = ChromaStore(collection="test_round_trip", path=tmp_path / "vs", embedding_function=None)
    store.add(
        ["the user prefers dark mode", "morning is best for cold calls"],
        ids=["fact-1", "fact-2"],
        metadatas=[{"topic": "ui"}, {"topic": "sales"}],
        embeddings=[[1.0, 0.0], [0.0, 1.0]],
    )
    assert store.count() == 2
    hits = store.query(embedding=[1.0, 0.0], top_k=1)
    assert len(hits) == 1
    assert hits[0]["id"] == "fact-1"
    assert hits[0]["document"] == "the user prefers dark mode"
    assert hits[0]["metadata"] == {"topic": "ui"}


@pytest.mark.skipif(not _HAS_CHROMA, reason="chromadb not installed")
def test_chroma_store_delete_and_reset(tmp_path, monkeypatch):
    from maverick.vector_store import ChromaStore
    monkeypatch.setenv("ANONYMIZED_TELEMETRY", "False")
    store = ChromaStore(collection="test_delete_reset", path=tmp_path / "vs", embedding_function=None)
    store.add(["a", "b", "c"], ids=["i1", "i2", "i3"],
              embeddings=[[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]])
    store.delete(["i2"])
    assert store.count() == 2
    assert {hit["id"] for hit in store.query(embedding=[1.0, 0.0, 0.0], top_k=3)} == {"i1", "i3"}
    store.reset()
    assert store.count() == 0


def test_chroma_store_missing_dep_raises_importable_error(tmp_path, monkeypatch):
    """When chromadb isn't installed, instantiation raises a useful error."""
    if _HAS_CHROMA:
        # Hide it.
        monkeypatch.setitem(sys.modules, "chromadb", None)
    # Force reimport so the lazy check trips.
    import maverick.vector_store.chroma_store as cs
    importlib.reload(cs)
    if _HAS_CHROMA:
        # If chromadb is really installed, setting sys.modules to None
        # turns `import chromadb` into ImportError. So our error path
        # should still fire.
        with pytest.raises(ImportError, match="packages/maverick-core\\[chroma\\]"):
            cs.ChromaStore(path=tmp_path)
    else:
        with pytest.raises(ImportError, match="packages/maverick-core\\[chroma\\]"):
            cs.ChromaStore(path=tmp_path)
