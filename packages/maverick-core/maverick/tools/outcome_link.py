"""Tool: link this run to an external business key for later grounding.

When a run acts on a real-world entity -- creates invoice ``INV-42``, opens
ticket ``SUP-91`` -- it can record that key here so that weeks later, when the
system of record reports the *actual* outcome (invoice paid, ticket reopened) to
``/outcomes/by-key``, Lightwork can join it back to the episode that acted and
learn from reality instead of a proxy. This is the run-side half of the
Consequence Engine's grounded loop.

Gated on ``[consequence]`` -- registered only when the operator has turned the
learning loop on, so the default tool surface is unchanged (kernel rule 1).
"""
from __future__ import annotations

import logging
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "key": {
            "type": "string",
            "description": (
                "The external business id this run acted on, ideally namespaced "
                "(e.g. 'invoice:INV-42', 'ticket:SUP-91'). The system of record "
                "reports its outcome against this same key."
            ),
        },
    },
    "required": ["key"],
}


def _thread(world, goal_id: int) -> tuple[int, str] | None:
    """(thread root, owner) of a goal, following ``parent_id`` at most 100
    steps. ``None`` when the goal or an ancestor cannot be read."""
    goal = world.get_goal(int(goal_id))
    if goal is None:
        return None
    owner, root, seen = getattr(goal, "owner", ""), int(goal_id), set()
    while getattr(goal, "parent_id", None) is not None:
        if root in seen or len(seen) >= 100:
            return None
        seen.add(root)
        root = int(goal.parent_id)
        goal = world.get_goal(root)
        if goal is None:
            return None
    return root, owner


def same_thread(world, goal_id: int):
    """A check that a key's holder is in this goal's chat thread or task
    tree (same root goal, same owner): follow-up turns, sub-goals and
    rewind forks. Goals the world cannot read (another tenant) never match."""
    if not hasattr(world, "get_goal"):
        return None
    mine = _thread(world, goal_id)
    if mine is None:
        return None
    return lambda holder: _thread(world, holder) == mine


def _run_factory(world, goal_id: int | None):
    def run(args: dict[str, Any]) -> str:
        # The registry calls every executor as fn(args) with ONE dict payload.
        k = str(args.get("key") or "").strip()
        if not k:
            return "ERROR: remember_outcome_key requires a non-empty 'key'"
        if world is None or goal_id is None:
            return "ERROR: remember_outcome_key requires an active goal"
        try:
            episodes = world.list_episodes(goal_id=goal_id, limit=1)
            if not episodes:
                return "ERROR: no episode to link (the run hasn't started acting yet)"
            from ..consequence import OutcomeKeyOwned, link_outcome_key
            try:
                related = same_thread(world, goal_id)
                linked = link_outcome_key(k[:256], goal_id, episodes[0].id,
                                          **({"same_task": related} if related else {}))
            except OutcomeKeyOwned as exc:
                return f"ERROR: {exc}"
            if not linked:
                return "ERROR: outcome key was not linked; learning is paused or the record could not be saved"
            return (
                f"Linked '{k[:256]}' to this run. A downstream outcome reported "
                "for that key will ground this work in the learning loop."
            )
        except Exception as e:  # pragma: no cover -- linking is best-effort
            log.debug("outcome-link failed for goal %s", goal_id, exc_info=True)
            return f"ERROR: could not link outcome key: {type(e).__name__}: {e}"

    return run


def remember_outcome_key(world, goal_id: int | None) -> Tool:
    """Factory: builds the outcome-link tool bound to (world, goal_id)."""
    return Tool(
        name="remember_outcome_key",
        description=(
            "Link this run to an external business id (invoice/ticket/deal) it "
            "acted on, so the real downstream outcome reported later grounds this "
            "work in the learning loop. Call it once per entity you create or "
            "change, with a namespaced key like 'invoice:INV-42'."
        ),
        input_schema=_SCHEMA,
        fn=_run_factory(world, goal_id),
    )
