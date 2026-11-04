"""local_embeddings_cache: content-addressed key + cache stats (no lmdb)."""
from __future__ import annotations

import hashlib
import json

from maverick.tools.local_embeddings_cache import local_embeddings_cache


def _run(**kw):
    return local_embeddings_cache().fn(kw)


def test_key_is_deterministic_sha256():
    k1 = _run(op="key", text="hello world", model="text-embed-3")
    k2 = _run(op="key", text="hello world", model="text-embed-3")
    assert k1 == k2
    assert len(k1) == 64 and all(c in "0123456789abcdef" for c in k1)
    expected = hashlib.sha256(
        json.dumps(["text-embed-3", "hello world"]).encode()).hexdigest()
    assert k1 == expected


def test_key_namespaced_by_model():
    a = _run(op="key", text="same", model="model-a")
    b = _run(op="key", text="same", model="model-b")
    assert a != b  # different model -> different slot, no collision


def test_key_no_boundary_collision_with_nul_in_model():
    # An in-band NUL separator would let two distinct (model, text) pairs
    # collide onto the same slot; the JSON-encoded payload prevents that.
    a = _run(op="key", text="b", model="a\x00")
    b = _run(op="key", text="\x00b", model="a")
    assert a != b


def test_stats_hit_miss_summary():
    out = json.loads(_run(op="stats", entries=[
        {"key": "a", "hits": 5},
        {"key": "b", "hits": 0},
        {"key": "c", "hits": 2},
        {"key": "d", "hits": 0},
    ]))
    assert out["entries"] == 4
    assert out["total_hits"] == 7
    assert out["hit_entries"] == 2
    assert out["miss_entries"] == 2
    assert out["hit_rate"] == 0.5


def test_stats_eviction_candidates_lowest_first():
    out = json.loads(_run(op="stats", evict_k=2, entries=[
        {"key": "hot", "hits": 100},
        {"key": "cold", "hits": 1},
        {"key": "frozen", "hits": 0},
    ]))
    # Lowest hits first; the hot entry is never an eviction candidate.
    assert out["eviction_candidates"] == ["frozen", "cold"]


def test_stats_skips_bad_entries_and_empty():
    out = json.loads(_run(op="stats", entries=[
        {"key": "ok", "hits": 3},
        {"no_key": True},
        "garbage",
        {"key": "", "hits": 9},
    ]))
    assert out["entries"] == 1 and out["total_hits"] == 3
    empty = json.loads(_run(op="stats", entries=[]))
    assert empty["entries"] == 0 and empty["hit_rate"] == 0.0


def test_errors_and_factory_contract():
    t = local_embeddings_cache()
    assert t.fn({"op": "key", "model": "m"}).startswith("ERROR")  # no text
    assert t.fn({"op": "key", "text": "t"}).startswith("ERROR")  # no model
    assert t.fn({"op": "stats"}).startswith("ERROR")  # no entries
    assert t.fn({"op": "stats", "entries": [], "evict_k": -1}).startswith("ERROR")
    assert t.fn({"op": "nope"}).startswith("ERROR")
    assert t.name == "local_embeddings_cache"
    assert t.parallel_safe is True
