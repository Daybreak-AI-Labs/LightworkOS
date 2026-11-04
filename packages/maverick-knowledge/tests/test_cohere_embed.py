"""Cohere embedder: v2 request shape + build_embedder selection."""
from __future__ import annotations

import sys
import types

import pytest
from maverick_knowledge.embed import CohereEmbedder, build_embedder


def _fake_httpx(capture: dict, payload: dict):
    mod = types.ModuleType("httpx")

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    def post(url, headers=None, json=None, timeout=None):
        capture["url"] = url
        capture["headers"] = headers
        capture["json"] = json
        return _Resp()

    mod.post = post
    return mod


def test_cohere_v2_nested_embeddings(monkeypatch):
    cap: dict = {}
    payload = {"embeddings": {"float": [[0.1, 0.2], [0.3, 0.4]]}}
    monkeypatch.setitem(sys.modules, "httpx", _fake_httpx(cap, payload))
    emb = CohereEmbedder(model="embed-v4.0", api_key="k")
    out = emb.embed(["a", "b"])
    assert out == [[0.1, 0.2], [0.3, 0.4]]
    assert cap["url"].endswith("/v2/embed")
    assert cap["json"]["texts"] == ["a", "b"]
    assert cap["json"]["input_type"] == "search_document"
    assert cap["json"]["embedding_types"] == ["float"]
    assert cap["headers"]["Authorization"] == "Bearer k"


def test_cohere_v1_flat_list_fallback(monkeypatch):
    cap: dict = {}
    payload = {"embeddings": [[1.0], [2.0]]}
    monkeypatch.setitem(sys.modules, "httpx", _fake_httpx(cap, payload))
    emb = CohereEmbedder(model="m", api_key="k")
    assert emb.embed(["x", "y"]) == [[1.0], [2.0]]


def test_build_embedder_selects_cohere(monkeypatch):
    monkeypatch.delenv("MAVERICK_EMBED_PROVIDER", raising=False)
    monkeypatch.setenv("COHERE_API_KEY", "ck")
    emb = build_embedder({"embedder": "cohere", "model": "embed-v4.0"})
    assert isinstance(emb, CohereEmbedder)
    assert emb.model == "embed-v4.0"
    assert emb.api_key == "ck"  # pragma: allowlist secret


def test_build_embedder_cohere_requires_key(monkeypatch):
    monkeypatch.delenv("MAVERICK_EMBED_PROVIDER", raising=False)
    monkeypatch.delenv("COHERE_API_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_EMBED_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="cohere embedder selected but no API key"):
        build_embedder({"embedder": "cohere"})


def test_cohere_query_input_type(monkeypatch):
    cap: dict = {}
    monkeypatch.setitem(sys.modules, "httpx",
                        _fake_httpx(cap, {"embeddings": {"float": [[0.0]]}}))
    emb = CohereEmbedder(model="m", api_key="k", input_type="search_query")
    emb.embed(["q"])
    assert cap["json"]["input_type"] == "search_query"


def test_knowledge_base_uses_paired_query_mode_without_mutating_document_mode(monkeypatch):
    from maverick_knowledge import KnowledgeBase

    cap = {}
    monkeypatch.setitem(sys.modules, "httpx",
                        _fake_httpx(cap, {"embeddings": {"float": [[1.0, 0.5]]}}))
    embedder = CohereEmbedder(model="fixture", api_key="unused", dim=2)
    with KnowledgeBase(embedder=embedder) as base:
        base.ingest_text("ops", "one small policy")
        assert cap["json"]["input_type"] == "search_document"
        base.search("ops", "policy")
        assert cap["json"]["input_type"] == "search_query"
        base.search_formatted(["ops"], "policy")
        assert cap["json"]["input_type"] == "search_query"
        base.ingest_text("ops", "another policy")
        assert cap["json"]["input_type"] == "search_document"
        assert embedder.input_type == "search_document"
