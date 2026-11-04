"""multimodal_rag: lexical Jaccard ranking of multi-modal chunks."""
from __future__ import annotations

from maverick.tools.multimodal_rag import multimodal_rag


def _run(**kw):
    return multimodal_rag().fn({"op": "rank", **kw})


def test_ranks_by_lexical_overlap():
    out = _run(query="quarterly revenue growth", chunks=[
        {"id": "c1", "modality": "text", "content_or_caption": "weather forecast sunny"},
        {"id": "c2", "modality": "text", "content_or_caption": "quarterly revenue growth chart"},
    ])
    lines = out.splitlines()
    assert lines[1].strip().startswith("1. c2")  # best lexical match first


def test_top_k_limit():
    chunks = [
        {"id": f"c{i}", "modality": "text", "content_or_caption": f"alpha beta c{i}"}
        for i in range(5)
    ]
    out = _run(query="alpha beta", chunks=chunks, k=2)
    assert "top 2 of 5" in out
    assert out.count(". c") == 2


def test_modality_weight_breaks_lexical_tie():
    # Identical content -> equal base Jaccard; modality weight decides order.
    out = _run(query="sales by region", chunks=[
        {"id": "img", "modality": "image", "content_or_caption": "sales by region"},
        {"id": "txt", "modality": "text", "content_or_caption": "sales by region"},
    ])
    lines = out.splitlines()
    assert lines[1].strip().startswith("1. txt")  # text weight 1.0 > image 0.8


def test_custom_weights_override():
    out = _run(query="sales by region",
               weights={"image": 5.0},
               chunks=[
                   {"id": "img", "modality": "image", "content_or_caption": "sales by region"},
                   {"id": "txt", "modality": "text", "content_or_caption": "sales by region"},
               ])
    lines = out.splitlines()
    assert lines[1].strip().startswith("1. img")  # boosted image now wins


def test_zero_overlap_scores_zero():
    out = _run(query="zzz", chunks=[
        {"id": "c1", "modality": "table", "content_or_caption": "totally different words"},
    ])
    assert "c1 [table] score=0" in out


def test_errors():
    t = multimodal_rag()
    assert t.fn({"op": "rank", "query": "", "chunks": [{"id": "a", "modality": "text", "content_or_caption": "x"}]}).startswith("ERROR")
    assert t.fn({"op": "rank", "query": "q", "chunks": []}).startswith("ERROR")
    assert t.fn({"op": "rank", "query": "q", "chunks": [{"id": "a", "modality": "text", "content_or_caption": "x"}], "weights": 5}).startswith("ERROR")
    assert t.fn({"op": "nope", "query": "q", "chunks": [{"id": "a", "modality": "text", "content_or_caption": "x"}]}).startswith("ERROR")
