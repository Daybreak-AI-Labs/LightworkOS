"""Multi-modal RAG ranker.

Rank a mixed bag of retrieved chunks (text / image-caption / table) against a
query by lexical overlap, with a small per-modality weight so a caller can nudge
the ranking toward (say) tables for a numeric question. Deterministic and
offline: the score is a Jaccard overlap of tokenised query vs chunk content,
scaled by the chunk's modality weight — no embeddings, no model.

ops:
  - rank(query, chunks[, k][, weights])  — chunks: list of
    {id, modality: text|image|table, content_or_caption}.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

_MODALITIES = ("text", "image", "table")
# Default modality weights; text is the baseline, image/table slightly down-
# weighted (a caption / cell dump carries less lexical signal). Overridable.
_DEFAULT_WEIGHTS = {"text": 1.0, "image": 0.8, "table": 0.9}
_TOKEN = re.compile(r"[a-z0-9]+")


def _tokens(s: str) -> set[str]:
    return set(_TOKEN.findall(s.lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _rank(query: str, chunks: list, k: int, weights: dict[str, float]) -> str:
    q_tokens = _tokens(query)
    if not q_tokens:
        return "ERROR: query has no rankable tokens"

    scored: list[tuple[float, int, str, str]] = []
    for idx, c in enumerate(chunks):
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id", "")) or f"chunk{idx}"
        modality = str(c.get("modality", "text")).strip().lower()
        if modality not in _MODALITIES:
            modality = "text"
        content = str(c.get("content_or_caption", ""))
        base = _jaccard(q_tokens, _tokens(content))
        score = round(base * weights.get(modality, 1.0), 4)
        # Stable order: score desc, then original index asc (via -idx in a
        # min-key would invert; keep idx for the tie-break below).
        scored.append((score, idx, cid, modality))

    if not scored:
        return "ERROR: no valid chunks ({id, modality, content_or_caption})"

    scored.sort(key=lambda t: (-t[0], t[1]))
    top = scored[:k]
    lines = [f"top {len(top)} of {len(scored)} chunk(s) for query:"]
    for rank, (score, _idx, cid, modality) in enumerate(top, 1):
        lines.append(f"  {rank}. {cid} [{modality}] score={score:g}")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "rank"):
        return f"ERROR: unknown op {args.get('op')!r}"
    query = args.get("query")
    if not isinstance(query, str) or not query.strip():
        return "ERROR: query (string) is required"
    chunks = args.get("chunks")
    if not isinstance(chunks, list) or not chunks:
        return "ERROR: chunks (non-empty list of {id, modality, content_or_caption}) is required"
    try:
        k = int(args.get("k", 5))
    except (TypeError, ValueError):
        k = 5
    k = max(1, k)

    weights = dict(_DEFAULT_WEIGHTS)
    raw_w = args.get("weights")
    if raw_w is not None:
        if not isinstance(raw_w, dict):
            return "ERROR: weights must be an object of {modality: number}"
        for m, w in raw_w.items():
            try:
                weights[str(m).strip().lower()] = float(w)
            except (TypeError, ValueError):
                return "ERROR: weights values must be numbers"
    return _rank(query, chunks, k, weights)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["rank"]},
        "query": {"type": "string"},
        "chunks": {
            "type": "array",
            "description": "retrieved chunks; each {id, modality, content_or_caption}",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "modality": {"type": "string", "enum": list(_MODALITIES)},
                    "content_or_caption": {"type": "string"},
                },
                "required": ["id", "modality", "content_or_caption"],
            },
        },
        "k": {"type": "integer", "description": "how many top chunks to return (default 5)"},
        "weights": {
            "type": "object",
            "description": "optional per-modality weight overrides {text,image,table}",
        },
    },
    "required": ["query", "chunks"],
}


def multimodal_rag() -> Tool:
    return Tool(
        name="multimodal_rag",
        description=(
            "Rank multi-modal retrieved chunks against a query by lexical "
            "overlap. op=rank with 'query' and 'chunks' (each {id, modality: "
            "text|image|table, content_or_caption}), optional 'k' and per-"
            "modality 'weights'. Score = Jaccard token overlap x modality "
            "weight. Returns top-k {id, modality, score}. Pure lexical, no "
            "embeddings/model."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
