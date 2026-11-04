"""Plan-tree minimap.

A compact, one-line-per-node unicode rendering of a goal's subtree — the
at-a-glance companion to ``maverick monitor``'s full plan tree. Each line is
``<indent><status glyph> #<id> <title>``; depth is two-space indentation.
Beyond a depth budget the subtree is collapsed to a single ``▸ +N collapsed``
count line so a deep swarm still fits in a sidebar.

Pure render over Goal rows: it only *reads* the world model via the locked
``get_goal``/``subgoals`` helpers (the same ones the monitor uses) and wires
into nothing — callers (the dashboard minimap endpoint, future TUI panes)
decide where the text goes.
"""
from __future__ import annotations

# Status -> glyph. Keyed on the statuses the orchestrator actually writes
# (pending/active/blocked/done/cancelled), mirroring monitor._STATUS_COLORS.
GLYPHS = {
    "pending": "◌",
    "active": "◐",
    "done": "●",
    "blocked": "⊘",
    "cancelled": "⊗",
}
_DEFAULT_GLYPH = "·"

DEFAULT_DEPTH_BUDGET = 3
_PER_PARENT_CAP = 50    # children fetched per node (matches monitor/plan-tree)
_MAX_LINES = 400        # hard cap so a pathological tree can't flood a pane
_COLLAPSE_COUNT_CAP = 999


def _glyph(status: str | None) -> str:
    return GLYPHS.get((status or "").lower(), _DEFAULT_GLYPH)


def _clip(title: str | None, width: int) -> str:
    t = " ".join((title or "(untitled)").split())
    return t if len(t) <= width else t[: max(1, width - 1)] + "…"


def _count_subtree(world, root_id: int, cap: int = _COLLAPSE_COUNT_CAP) -> int:
    """Bounded count of all descendants of ``root_id`` (capped at ``cap``)."""
    seen = 0
    frontier = [root_id]
    while frontier and seen < cap:
        nid = frontier.pop()
        for child in world.subgoals(nid, limit=_PER_PARENT_CAP):
            seen += 1
            if seen >= cap:
                return seen
            frontier.append(child.id)
    return seen


def render_minimap(
    world,
    goal_id: int,
    *,
    max_depth: int = DEFAULT_DEPTH_BUDGET,
    max_title: int = 60,
) -> str:
    """Render goal ``goal_id``'s subtree as a one-line-per-node minimap.

    ``max_depth`` is the depth budget: nodes deeper than it collapse into a
    ``▸ +N collapsed`` count under their parent. Returns ``""`` for an
    unknown goal (callers decide whether that is a 404).
    """
    root = world.get_goal(goal_id)
    if root is None:
        return ""
    max_depth = max(0, int(max_depth))
    lines: list[str] = []

    def _walk(goal, depth: int) -> None:
        if len(lines) >= _MAX_LINES:
            return
        indent = "  " * depth
        lines.append(f"{indent}{_glyph(goal.status)} #{goal.id} {_clip(goal.title, max_title)}")
        children = world.subgoals(goal.id, limit=_PER_PARENT_CAP)
        if not children:
            return
        if depth >= max_depth:
            hidden = _count_subtree(world, goal.id)
            more = "+" if hidden >= _COLLAPSE_COUNT_CAP else ""
            lines.append(f"{indent}  ▸ +{hidden}{more} collapsed")
            return
        for child in children:
            _walk(child, depth + 1)

    _walk(root, 0)
    if len(lines) >= _MAX_LINES:
        lines.append("… (truncated)")
    return "\n".join(lines)


__all__ = ["GLYPHS", "DEFAULT_DEPTH_BUDGET", "render_minimap"]
