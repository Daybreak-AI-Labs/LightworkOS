"""Smart goal completion.

Given a partial goal the user is typing and a history of past goals, suggest the
most likely completions. Pure lexical ranking — no LLM, no embeddings: a past
goal scores on (1) whether it starts with the partial (prefix bonus) and (2)
how many of the partial's tokens appear in it (token overlap). Deterministic and
offline: the same inputs always yield the same ordering (ties broken by recency
then alphabetically).

ops:
  - suggest(partial, history[, k])  — top-k past goals as completions.

``history`` is a list of past goal strings, most-recent-last (so later entries
win ties). Empty/blank partials return the most recent unique goals.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def _score(partial: str, partial_tokens: set[str], candidate: str) -> float:
    cand_low = candidate.lower()
    cand_tokens = set(_tokens(candidate))
    score = 0.0
    if partial and cand_low.startswith(partial.lower()):
        score += 100.0  # strong prefix match dominates
    if partial_tokens:
        overlap = len(partial_tokens & cand_tokens)
        score += 10.0 * overlap
        # small bonus for every partial token that is a prefix of a cand token
        for pt in partial_tokens:
            if any(ct.startswith(pt) for ct in cand_tokens):
                score += 1.0
    return score


def _suggest(args: dict[str, Any]) -> str:
    partial = str(args.get("partial") or "").strip()
    history = args.get("history")
    if not isinstance(history, list):
        return "ERROR: history must be an array of past goal strings"
    try:
        k = int(args.get("k", 5))
    except (TypeError, ValueError):
        k = 5
    k = max(1, k)

    # De-dup keeping the most recent occurrence; recency = position in history.
    recency: dict[str, int] = {}
    for i, g in enumerate(history):
        if not isinstance(g, str) or not g.strip():
            continue
        recency[g.strip()] = i
    if not recency:
        return "SUGGEST: (no candidates)"

    partial_tokens = set(_tokens(partial))
    scored = []
    for cand, rec in recency.items():
        s = _score(partial, partial_tokens, cand)
        scored.append((s, rec, cand))

    if partial:
        # Drop zero-score candidates: nothing matched the partial at all.
        scored = [t for t in scored if t[0] > 0] or scored

    # Sort: score desc, then recency desc, then alphabetical asc.
    scored.sort(key=lambda t: (-t[0], -t[1], t[2]))
    top = [c for _, _, c in scored[:k]]
    if not top:
        return "SUGGEST: (no candidates)"
    return "SUGGEST:\n" + "\n".join(f"- {c}" for c in top)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "suggest"):
        return f"ERROR: unknown op {args.get('op')!r}"
    if not isinstance(args.get("history"), list):
        return "ERROR: history (array of past goal strings) is required"
    return _suggest(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["suggest"]},
        "partial": {"type": "string", "description": "the partial goal being typed"},
        "history": {
            "type": "array",
            "description": "past goal strings, most-recent-last",
            "items": {"type": "string"},
        },
        "k": {"type": "integer", "description": "number of completions (default 5)"},
    },
    "required": ["history"],
}


def smart_goal_completion() -> Tool:
    return Tool(
        name="smart_goal_completion",
        description=(
            "Suggest goal completions from history. op=suggest with 'partial' "
            "(the goal being typed), 'history' (past goal strings, most-recent-"
            "last), and optional 'k'. Ranks past goals by prefix match then token "
            "overlap (ties broken by recency, then alphabetically). Pure lexical, "
            "deterministic, offline — no LLM."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
