"""Local-first embeddings cache.

A content-addressed cache for text embeddings. LMDB is the intended backing
store; this helper is the *pure* logic around it (key derivation + cache
statistics) and deliberately does NOT import lmdb — so the kernel and tests stay
dependency-free and offline. A real backend can map ``key`` -> serialized vector
later without changing this contract.

ops:
  - key(text, model) -> a stable sha256 cache key derived from (model, text), so
    the same text under the same model always hashes to the same slot and
    different models never collide.
  - stats(entries:[{key, hits}]) -> a hit/miss summary plus eviction candidates
    (the lowest-hit entries — what an LRU/LFU sweep would drop first).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from . import Tool

# How many lowest-hit entries to surface as eviction candidates by default.
_DEFAULT_EVICT_K = 3


def _key(args: dict[str, Any]) -> str:
    text = args.get("text")
    model = args.get("model")
    if not isinstance(text, str) or text == "":
        return "ERROR: text is required"
    if not isinstance(model, str) or not model.strip():
        return "ERROR: model is required"
    # Namespace by model so the same text under a different model gets its own
    # slot. JSON-encode both fields so field boundaries are unambiguous — an
    # in-band separator (e.g. an embedded NUL) can't be forged to collide two
    # distinct (model, text) pairs onto the same slot.
    payload = json.dumps([model.strip(), text]).encode()
    return hashlib.sha256(payload).hexdigest()


def _stats(args: dict[str, Any]) -> str:
    entries = args.get("entries")
    if not isinstance(entries, list):
        return "ERROR: entries (array of {key, hits}) is required"
    evict_k = args.get("evict_k", _DEFAULT_EVICT_K)
    try:
        evict_k = int(evict_k)
    except (TypeError, ValueError):
        return "ERROR: evict_k must be an integer"
    if evict_k < 0:
        return "ERROR: evict_k must be >= 0"

    normalized: list[tuple[str, int]] = []
    total_hits = 0
    for e in entries:
        if not isinstance(e, dict):
            continue
        key = e.get("key")
        if not isinstance(key, str) or not key:
            continue
        try:
            hits = int(e.get("hits", 0))
        except (TypeError, ValueError):
            hits = 0
        if hits < 0:
            hits = 0
        normalized.append((key, hits))
        total_hits += hits

    count = len(normalized)
    # A "miss" is an entry that has never been read back (0 hits) — dead weight
    # the cache is holding for nothing.
    misses = sum(1 for _, h in normalized if h == 0)
    hit_entries = count - misses
    hit_rate = round(hit_entries / count, 4) if count else 0.0

    # Eviction candidates: lowest hits first, ties broken by key for a stable,
    # deterministic order.
    ranked = sorted(normalized, key=lambda kh: (kh[1], kh[0]))
    candidates = [k for k, _ in ranked[:evict_k]]

    out = {
        "entries": count,
        "total_hits": total_hits,
        "hit_entries": hit_entries,
        "miss_entries": misses,
        "hit_rate": hit_rate,
        "eviction_candidates": candidates,
    }
    return json.dumps(out, sort_keys=True)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "key":
        return _key(args)
    if op == "stats":
        return _stats(args)
    return f"ERROR: unknown op {op!r} (expected key or stats)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["key", "stats"]},
        "text": {"type": "string", "description": "text to embed, for op=key"},
        "model": {"type": "string", "description": "embedding model id, for op=key"},
        "entries": {
            "type": "array",
            "description": "for op=stats; cached entries, each {key, hits}",
            "items": {
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "hits": {"type": "integer"},
                },
                "required": ["key"],
            },
        },
        "evict_k": {
            "type": "integer",
            "description": "for op=stats; how many lowest-hit entries to flag (default 3)",
        },
    },
    "required": ["op"],
}


def local_embeddings_cache() -> Tool:
    return Tool(
        name="local_embeddings_cache",
        description=(
            "Local-first embeddings cache logic (no lmdb, no network). op=key "
            "{text, model} -> a stable sha256 cache key namespaced by model. "
            "op=stats {entries:[{key, hits}], evict_k?} -> JSON {entries, "
            "total_hits, hit_entries, miss_entries, hit_rate, eviction_candidates} "
            "(lowest-hit entries first). Pure stdlib hashlib; deterministic."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
