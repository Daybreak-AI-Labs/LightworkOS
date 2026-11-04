"""Embeddings tool — first-class semantic similarity.

Lets the agent compute embedding vectors + similarity scores without
spinning up a vector store. Useful for: ranking candidate documents,
deduping pages of search results, finding the closest match from a
small list.

ops:
  - embed(text)                       — single vector (returns first 8 dims + summary)
  - similarity(text_a, text_b)        — cosine in [-1, 1]
  - rank(query, candidates, top_k=5)  — return the top_k closest candidates

Backend: ``fastembed`` (local, CPU, no network). Default model is
``BAAI/bge-small-en-v1.5`` — 384-dim, ~30 MB, fine for English.

Requires::

    python -m pip install -e './packages/maverick-core[embeddings]'
"""
from __future__ import annotations

import logging
import math
import threading
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_EMB_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["embed", "similarity", "rank"]},
        "text": {"type": "string"},
        "text_a": {"type": "string"},
        "text_b": {"type": "string"},
        "query": {"type": "string"},
        "candidates": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Candidate strings to rank against the query.",
        },
        "top_k": {"type": "integer"},
        "model": {"type": "string", "description": "Override embedding model."},
    },
    "required": ["op"],
}


_model_lock = threading.Lock()
_model_cache: dict[str, Any] = {}


def _default_model() -> str:
    """``[models] embed`` (env ``MAVERICK_EMBED_MODEL`` wins), else the default."""
    from ..env_setting import env_or_config

    return (env_or_config("MAVERICK_EMBED_MODEL", "models", "embed") or "").strip() \
        or "BAAI/bge-small-en-v1.5"


def _load_model(name: str):
    with _model_lock:
        if name in _model_cache:
            return _model_cache[name]
        from fastembed import TextEmbedding
        m = TextEmbedding(model_name=name)
        _model_cache[name] = m
        return m


def _embed_one(model, text: str) -> list[float]:
    # fastembed returns a generator of numpy arrays; just take the
    # first and coerce to a plain Python list for downstream math
    # without a numpy dep at the tool layer.
    for vec in model.embed([text]):
        return [float(x) for x in vec]
    return []


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _op_embed(text: str, model_name: str) -> str:
    if not text.strip():
        return "ERROR: embed requires non-empty text"
    model = _load_model(model_name)
    vec = _embed_one(model, text)
    if not vec:
        return "ERROR: embed produced empty vector"
    head = ", ".join(f"{x:.4f}" for x in vec[:8])
    return f"dim={len(vec)}  norm={math.sqrt(sum(x*x for x in vec)):.4f}\n[{head}, ...]"


def _op_similarity(a: str, b: str, model_name: str) -> str:
    if not a.strip() or not b.strip():
        return "ERROR: similarity requires text_a and text_b"
    model = _load_model(model_name)
    va = _embed_one(model, a)
    vb = _embed_one(model, b)
    return f"cosine = {_cosine(va, vb):.4f}"


_MAX_RANK_CANDIDATES = 1000


def _op_rank(query: str, candidates: list[str], top_k: int, model_name: str) -> str:
    if not query.strip():
        return "ERROR: rank requires query"
    candidates = [c for c in (candidates or []) if c and c.strip()]
    if not candidates:
        return "ERROR: rank requires non-empty candidates"
    # Bound the work: each candidate is embedded, so an unbounded model-supplied
    # list (tens of thousands of strings) is a memory / compute DoS. Refuse past
    # a generous cap rather than embed them all.
    if len(candidates) > _MAX_RANK_CANDIDATES:
        return (
            f"ERROR: rank supports at most {_MAX_RANK_CANDIDATES} candidates "
            f"(got {len(candidates)}); narrow the set first"
        )
    model = _load_model(model_name)
    qv = _embed_one(model, query)
    scored: list[tuple[float, int, str]] = []
    for i, c in enumerate(candidates):
        cv = _embed_one(model, c)
        scored.append((_cosine(qv, cv), i, c))
    scored.sort(reverse=True)
    top = scored[: max(1, min(top_k, len(scored)))]
    return "\n".join(
        f"  [{s:.4f}]  #{i}  {c[:80]}" for s, i, c in top
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import fastembed  # noqa: F401
    except ImportError:
        return (
            "ERROR: fastembed not installed. "
            "Run: python -m pip install -e './packages/maverick-core[embeddings]'"
        )
    model_name = (args.get("model") or "").strip() or _default_model()
    try:
        if op == "embed":
            return _op_embed(args.get("text") or "", model_name)
        if op == "similarity":
            return _op_similarity(
                args.get("text_a") or "", args.get("text_b") or "",
                model_name,
            )
        if op == "rank":
            top_k = int(args.get("top_k") or 5)
            return _op_rank(
                args.get("query") or "", args.get("candidates") or [],
                top_k, model_name,
            )
    except Exception as e:
        return f"ERROR: embeddings request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def embeddings() -> Tool:
    return Tool(
        name="embeddings",
        description=(
            "Local CPU embeddings via fastembed. ops: embed (one "
            "string -> dim + head), similarity (two strings -> "
            "cosine), rank (query + candidates -> top_k closest). "
            "Default model BAAI/bge-small-en-v1.5; override with "
            "model arg or MAVERICK_EMBED_MODEL env."
        ),
        input_schema=_EMB_SCHEMA,
        fn=_run,
    )
