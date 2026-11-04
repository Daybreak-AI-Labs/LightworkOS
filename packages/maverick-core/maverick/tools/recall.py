"""Cross-goal memory recall tool.

Lets the agent ask "have we solved something like this before?" against
the world_model's history. Returns past goals ranked by similarity to
the query text, with their status and final result snippet.

Two scoring backends, chosen automatically:
  1. fastembed (when available)   -> dense cosine similarity
  2. token-Jaccard fallback        -> works without any extra deps

This is the simplest cross-run memory primitive: no continuous-learning
loop, no embedding daemon, no separate vector store. Past goals already
live in the world_model SQLite; we re-rank them on demand and return
the top K. Slow on huge histories (linear scan), but those installs
already have skill_embeddings to cache; we re-use the same model.
"""
from __future__ import annotations

import logging
import math
import re
from pathlib import Path
from typing import Any

from ..world_model import WorldModel, close_world_if_owned
from . import Tool

log = logging.getLogger(__name__)


_RECALL_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "description": "Describe what you're working on; we find similar past goals.",
        },
        "num_results": {
            "type": "integer",
            "description": "Max similar goals to return (default 5, capped at 20).",
        },
        "include_running": {
            "type": "boolean",
            "description": "Include not-yet-finished goals in results (default false).",
        },
    },
    "required": ["query"],
}


_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text or "")}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _goal_text(g) -> str:
    return f"{g.title or ''}\n\n{g.description or ''}".strip()


def _format_match(g, score: float) -> str:
    # Markers keyed on the vocabulary the orchestrator actually writes
    # (active/pending/blocked/done/cancelled) -- the old map keyed on
    # succeeded/failed/in_progress/running (never written) and lacked
    # active/cancelled, so a live goal rendered as "?".
    status_marker = {
        "done": "✓",
        "blocked": "✗", "cancelled": "✗",
        "active": "…",
        "pending": "·",
    }.get((g.status or "").lower(), "?")
    result = (g.result or "")[:240].replace("\n", " ")
    return (
        f"#{g.id} {status_marker} ({score:.2f}) {g.title or '(no title)'}\n"
        f"   status: {g.status}\n"
        f"   result: {result or '(no result captured)'}"
    )


def _rank_with_embeddings(
    query: str,
    goals: list,
) -> list[tuple[float, Any]] | None:
    """Use fastembed if available. Returns None if model can't load."""
    try:
        from ..skill.embeddings import _have_fastembed, embed
        if not _have_fastembed():
            return None
        texts = [_goal_text(g) for g in goals]
        vectors = embed([query] + texts)
        if vectors is None or len(vectors) != len(goals) + 1:
            return None
        qv = vectors[0]
        scored = [(_cosine(qv, vectors[i + 1]), g) for i, g in enumerate(goals)]
        scored.sort(key=lambda p: p[0], reverse=True)
        return scored
    except Exception as e:
        log.debug("embedding-based recall failed (%s); falling back", e)
        return None


def _rank_with_jaccard(query: str, goals: list) -> list[tuple[float, Any]]:
    qt = _tokens(query)
    scored = [(_jaccard(qt, _tokens(_goal_text(g))), g) for g in goals]
    scored.sort(key=lambda p: p[0], reverse=True)
    return scored


def _list_candidate_goals(world: WorldModel, include_running: bool, *, owner: str) -> list:
    """Pull goals that have meaningful text to compare against.

    Routes through the locked, backend-portable ``candidate_goals`` helper
    instead of ``world.conn.execute`` -- the raw path took torn reads, used
    ``dict(row)`` access that returned nothing on the Postgres backend, and
    filtered on ``succeeded``/``failed`` statuses the orchestrator never writes
    (so every failed/``blocked`` past goal was silently missed).
    """
    return world.candidate_goals(include_running, limit=500, owner=owner)


def recall_past_goals(
    query: str,
    *,
    db_path: Path | None = None,
    num_results: int = 5,
    include_running: bool = False,
    world: WorldModel | None = None,
    owner: str | None = None,
) -> list[tuple[float, Any]]:
    """Library entry point. Returns scored matches.

    ``world`` lets callers pass an already-open WorldModel (the tool fn
    does this so we don't re-open the DB on every tool call).
    """
    own_world = False
    if world is None:
        # open_world() honors a configured [world_model] backend, so recall
        # works on a Postgres install instead of always opening empty SQLite.
        from ..world_model import open_world
        world = open_world(db_path)
        own_world = True
    try:
        from ..memory_ownership import current_owner, source_allowed
        owner = current_owner(world=world) if owner is None else owner
        candidates = [goal for goal in _list_candidate_goals(world, include_running, owner=owner)
                      if goal.owner == owner and source_allowed(goal.id, owner, world=world)]
        if not candidates:
            return []
        scored = _rank_with_embeddings(query, candidates)
        if scored is None:
            scored = _rank_with_jaccard(query, candidates)
        scored = [(s, g) for s, g in scored if s > 0.0]
        return scored[:num_results]
    finally:
        if own_world:
            # A no-path open under tenant/client scope returns the canonical
            # process-cached world. Closing it here would poison that cache for
            # every later request; close only non-cached, caller-owned handles.
            close_world_if_owned(world)


def _run_recall(args: dict[str, Any]) -> str:
    query = (args.get("query") or "").strip()
    if not query:
        return "ERROR: query is required"
    num_results = max(1, min(int(args.get("num_results") or 5), 20))
    include_running = bool(args.get("include_running"))
    matches = recall_past_goals(
        query,
        num_results=num_results,
        include_running=include_running,
    )
    if not matches:
        return "no similar past goals found"
    return "\n\n".join(_format_match(g, s) for s, g in matches)


def recall() -> Tool:
    """Factory: builds the recall_past_goals tool."""
    return Tool(
        name="recall_past_goals",
        description=(
            "Search past goals (in the local world_model) for ones similar "
            "to your current task. Returns up to num_results matches with "
            "status and result snippet. Use this BEFORE doing repeated "
            "work the swarm has done before; reuse past plans where you can."
        ),
        input_schema=_RECALL_INPUT_SCHEMA,
        fn=_run_recall,
    )
