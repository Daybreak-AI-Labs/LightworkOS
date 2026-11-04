"""Tests for the embeddings tool (maverick.tools.embeddings)."""
from __future__ import annotations

import sys
import types

# ---------- embeddings tool ----------

def test_embeddings_requires_op():
    from maverick.tools.embeddings import embeddings
    assert "op is required" in embeddings().fn({})


def test_embeddings_missing_fastembed(monkeypatch):
    # Force ImportError even if fastembed is somehow installed.
    monkeypatch.setitem(sys.modules, "fastembed", None)
    from maverick.tools.embeddings import embeddings
    out = embeddings().fn({"op": "embed", "text": "hello"})
    assert "fastembed not installed" in out


def test_embeddings_embed_uses_fastembed(monkeypatch):
    """With a stub fastembed, embed returns dim + head."""
    fake_emb = types.ModuleType("fastembed")

    class _FakeModel:
        def __init__(self, model_name=None):
            self.model_name = model_name

        def embed(self, texts):
            for _ in texts:
                yield [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

    fake_emb.TextEmbedding = _FakeModel
    monkeypatch.setitem(sys.modules, "fastembed", fake_emb)
    # Reset the cache so the new fake gets picked up.
    from maverick.tools import embeddings as embmod
    embmod._model_cache.clear()

    out = embmod.embeddings().fn({"op": "embed", "text": "hello"})
    assert "dim=10" in out
    assert "0.1000" in out


def test_embeddings_similarity_cosine(monkeypatch):
    fake_emb = types.ModuleType("fastembed")

    class _FakeModel:
        def __init__(self, model_name=None):
            self._next = 0

        def embed(self, texts):
            for _ in texts:
                # Deterministic but distinct vectors per call.
                self._next += 1
                if self._next % 2 == 1:
                    yield [1.0, 0.0]
                else:
                    yield [1.0, 0.0]  # identical -> cosine 1.0

    fake_emb.TextEmbedding = _FakeModel
    monkeypatch.setitem(sys.modules, "fastembed", fake_emb)
    from maverick.tools import embeddings as embmod
    embmod._model_cache.clear()

    out = embmod.embeddings().fn(
        {"op": "similarity", "text_a": "x", "text_b": "y"},
    )
    assert "cosine = 1.0000" in out


def test_embeddings_rank_orders_by_similarity(monkeypatch):
    fake_emb = types.ModuleType("fastembed")
    # Return [1,0] for query, [1,0]/[0,1]/[0.5,0.5] for the candidates.
    sequence = iter([
        [1.0, 0.0],     # query
        [1.0, 0.0],     # candidate 0 (perfect match)
        [0.0, 1.0],     # candidate 1 (orthogonal)
        [0.5, 0.5],     # candidate 2 (mid)
    ])

    class _FakeModel:
        def __init__(self, model_name=None):
            pass

        def embed(self, texts):
            for _ in texts:
                yield next(sequence)

    fake_emb.TextEmbedding = _FakeModel
    monkeypatch.setitem(sys.modules, "fastembed", fake_emb)
    from maverick.tools import embeddings as embmod
    embmod._model_cache.clear()

    out = embmod.embeddings().fn({
        "op": "rank", "query": "q",
        "candidates": ["a", "b", "c"], "top_k": 3,
    })
    lines = [line for line in out.splitlines() if line.strip()]
    # First line should be candidate 0 (cosine 1.0).
    assert "#0" in lines[0]
    # Last should be candidate 1 (cosine 0.0).
    assert "#1" in lines[-1]
