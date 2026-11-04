"""Async compaction scheduler.

Decide which history segments to compact *now* to fit a token budget without
blocking the agent loop. The caller supplies the segments and a budget; this
returns the compaction plan, projected token savings, and the order to compact
in. Deterministic and offline.

Rules:
  - The ``keep_recent`` newest segments are always KEPT (never compacted) — the
    working set the model needs verbatim.
  - Pinned segments are always KEPT regardless of age.
  - Of the remaining (older, unpinned) segments, compact oldest-first until the
    projected total fits ``max_tokens``; the rest are DEFERred for a later pass.
  - Compaction is assumed to shrink a segment to ~``compact_ratio`` of its
    tokens (default 0.2); savings = tokens * (1 - ratio).

ops:
  - plan(segments, budget)  — KEEP/COMPACT/DEFER, savings, compaction order.

Segments: ``[{"tokens", "age_turns", "pinned"?}]`` (age_turns: higher = older).
Budget:   ``{"max_tokens", "keep_recent", "compact_ratio"?}``.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _plan(segments: list, budget: dict) -> str:
    try:
        max_tokens = float(budget.get("max_tokens"))
    except (TypeError, ValueError):
        return "ERROR: budget.max_tokens (number) is required"
    if max_tokens < 0:
        return "ERROR: budget.max_tokens must be >= 0"
    try:
        keep_recent = int(budget.get("keep_recent"))
    except (TypeError, ValueError):
        return "ERROR: budget.keep_recent (integer) is required"
    if keep_recent < 0:
        return "ERROR: budget.keep_recent must be >= 0"

    ratio = budget.get("compact_ratio", 0.2)
    try:
        ratio = float(ratio)
    except (TypeError, ValueError):
        return "ERROR: budget.compact_ratio must be a number"
    if not 0 <= ratio <= 1:
        return "ERROR: budget.compact_ratio must be in [0, 1]"

    parsed: list[tuple[int, float, float, bool]] = []
    for i, s in enumerate(segments):
        if not isinstance(s, dict):
            return "ERROR: each segment must be an object"
        try:
            tokens = float(s.get("tokens"))
            age = float(s.get("age_turns"))
        except (TypeError, ValueError):
            return "ERROR: each segment needs numeric tokens and age_turns"
        if tokens < 0:
            return "ERROR: segment.tokens must be >= 0"
        pinned = bool(s.get("pinned", False))
        parsed.append((i, tokens, age, pinned))

    # Newest = smallest age_turns. The keep_recent newest are protected.
    by_recency = sorted(parsed, key=lambda x: (x[2], x[0]))  # newest first
    protected_idx = {x[0] for x in by_recency[:keep_recent]}

    # Compaction candidates: older-than-recent and unpinned. Oldest first
    # (largest age_turns; ties by original index for stability).
    candidates = [
        x for x in parsed if x[0] not in protected_idx and not x[3]
    ]
    candidates.sort(key=lambda x: (-x[2], x[0]))

    total = sum(t for _, t, _, _ in parsed)
    compact_idx: list[int] = []
    saved = 0.0
    projected = total
    for idx, tokens, _age, _pin in candidates:
        if projected <= max_tokens:
            break
        s = tokens * (1.0 - ratio)
        saved += s
        projected -= s
        compact_idx.append(idx)

    compacted = set(compact_idx)
    n_compact = len(compacted)
    n_keep = len(protected_idx) + sum(
        1 for x in parsed if x[3] and x[0] not in protected_idx
    )
    n_defer = len(parsed) - n_compact - n_keep

    order = ", ".join(str(i) for i in compact_idx) if compact_idx else "(none)"
    fits = "fits" if projected <= max_tokens else "OVER"
    return (
        f"OK total={total:g} -> projected={projected:g} ({fits} max_tokens={max_tokens:g}) "
        f"saved={saved:g}\n"
        f"  KEEP={n_keep} COMPACT={n_compact} DEFER={n_defer}\n"
        f"  compaction_order: [{order}]"
    )


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "plan"):
        return f"ERROR: unknown op {args.get('op')!r}"
    segments = args.get("segments")
    if not isinstance(segments, list):
        return "ERROR: segments (list of {tokens, age_turns, pinned?}) is required"
    budget = args.get("budget")
    if not isinstance(budget, dict):
        return "ERROR: budget ({max_tokens, keep_recent}) is required"
    return _plan(segments, budget)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["plan"]},
        "segments": {
            "type": "array",
            "description": "History segments: {tokens, age_turns, pinned?}",
            "items": {
                "type": "object",
                "properties": {
                    "tokens": {"type": "number"},
                    "age_turns": {"type": "number", "description": "Higher = older"},
                    "pinned": {"type": "boolean"},
                },
                "required": ["tokens", "age_turns"],
            },
        },
        "budget": {
            "type": "object",
            "description": "Compaction budget: {max_tokens, keep_recent, compact_ratio?}",
            "properties": {
                "max_tokens": {"type": "number"},
                "keep_recent": {"type": "integer", "description": "Newest N segments kept verbatim"},
                "compact_ratio": {"type": "number", "description": "Compacted fraction of tokens (default 0.2)"},
            },
            "required": ["max_tokens", "keep_recent"],
        },
    },
    "required": ["segments", "budget"],
}


def async_compaction() -> Tool:
    return Tool(
        name="async_compaction",
        description=(
            "Async history compaction scheduler. op=plan with 'segments' "
            "({tokens, age_turns, pinned?}) and 'budget' ({max_tokens, "
            "keep_recent, compact_ratio?}). Keeps the keep_recent newest and any "
            "pinned segments; compacts older unpinned segments oldest-first until "
            "the projected total fits max_tokens, deferring the rest. Returns "
            "projected token savings and the compaction order. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
