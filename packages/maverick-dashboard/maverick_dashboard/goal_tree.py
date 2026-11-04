"""Goal-forest assembly + layered tree layout, shared by the visual graph
editor (/graph-editor) and the 3D plan tree (/plan-tree-3d).

Everything here is pure / read-only so the layout is unit-testable without a
server: ``layered_layout`` turns ``[{id, parent_id}, ...]`` into
``{id: (depth, row)}``, ``descendant_ids`` answers "would this re-parent make
a cycle", and ``forest_html`` pre-renders the accessible text-tree fallback
(same reason as ``app._render_tree_html``: Jinja macros can't recurse with
dict args).
"""
from __future__ import annotations

import html as _html
from typing import Any

# Pixel spacing applied to (depth, row) by the API so the client JS stays a
# thin renderer (no client-side layout pass).
GAP_X = 220
GAP_Y = 56


def goal_nodes(world, *, owner: str | None = None, limit: int = 300) -> list[dict]:
    """The goal forest as plain dicts (id, parent_id, title, status).

    Bounded, owner-scoped via the world model's existing ``list_goals``
    (oldest first so parents are listed before their children).
    """
    goals = world.list_goals(owner=owner, limit=max(1, min(int(limit), 1000)))
    return [
        {"id": g.id, "parent_id": g.parent_id, "title": g.title or "",
         "status": g.status, "updated_at": g.updated_at}
        for g in goals
    ]


def layered_layout(nodes: list[dict]) -> dict[int, tuple[int, float]]:
    """Layered tree layout for a forest: ``{id: (depth, row)}``.

    Depth is the distance from the node's root; rows are assigned so each
    leaf gets its own lane and an internal node sits at the mean of its
    children's rows. A node whose parent is missing from ``nodes`` (outside
    the fetched window, or another owner's goal) is laid out as a root.
    Deterministic: children keep the input (id) order. Cycle-safe: a node
    re-entered mid-walk is placed as a leaf instead of recursing forever.
    """
    by_id = {n["id"]: n for n in nodes}
    children: dict[int, list[int]] = {}
    roots: list[int] = []
    for n in nodes:
        pid = n.get("parent_id")
        if pid is not None and pid != n["id"] and pid in by_id:
            children.setdefault(pid, []).append(n["id"])
        else:
            roots.append(n["id"])

    pos: dict[int, tuple[int, float]] = {}
    visiting: set[int] = set()
    next_row = 0

    def place(nid: int, depth: int) -> float:
        nonlocal next_row
        if nid in pos:
            return pos[nid][1]
        if nid in visiting:  # cycle in stored parent links: park as a leaf
            row = float(next_row)
            next_row += 1
            pos[nid] = (depth, row)
            return row
        visiting.add(nid)
        kids = children.get(nid, [])
        if kids:
            row = sum(place(k, depth + 1) for k in kids) / len(kids)
        else:
            row = float(next_row)
            next_row += 1
        visiting.discard(nid)
        pos[nid] = (depth, row)
        return row

    for r in roots:
        place(r, 0)
    for n in nodes:  # members of a pure cycle are reachable from no root
        if n["id"] not in pos:
            place(n["id"], 0)
    return pos


def descendant_ids(pairs: list[tuple[int, int | None]], root_id: int) -> set[int]:
    """Every goal id strictly below ``root_id`` given (id, parent_id) pairs.

    Used to refuse re-parenting a goal under its own descendant (a cycle).
    """
    kids: dict[int, list[int]] = {}
    for cid, pid in pairs:
        if pid is not None and pid != cid:
            kids.setdefault(pid, []).append(cid)
    out: set[int] = set()
    stack = [root_id]
    while stack:
        for c in kids.get(stack.pop(), []):
            if c not in out:
                out.add(c)
                stack.append(c)
    return out


def forest_view(nodes: list[dict]) -> dict[str, Any]:
    """The JSON the graph pages consume: laid-out nodes + parent edges."""
    pos = layered_layout(nodes)
    out_nodes = []
    edges: list[list[int]] = []
    by_id = {n["id"]: n for n in nodes}
    for n in nodes:
        depth, row = pos[n["id"]]
        out_nodes.append({
            **n,
            "depth": depth,
            "x": depth * GAP_X,
            "y": round(row * GAP_Y, 1),
        })
        pid = n.get("parent_id")
        if pid is not None and pid != n["id"] and pid in by_id:
            edges.append([pid, n["id"]])
    return {"nodes": out_nodes, "edges": edges, "count": len(out_nodes)}


def forest_html(nodes: list[dict]) -> str:
    """The forest as nested ``<ul>`` HTML — the accessible text fallback."""

    def esc(s: Any) -> str:
        return _html.escape(str(s), quote=True) if s is not None else ""

    def _word(status: Any) -> str:  # "in_progress" -> "In progress"
        text = str(status or "").replace("_", " ").strip()
        return text[:1].upper() + text[1:]

    children: dict[int | None, list[dict]] = {}
    ids = {n["id"] for n in nodes}
    for n in nodes:
        pid = n.get("parent_id")
        key = pid if (pid in ids and pid != n["id"]) else None
        children.setdefault(key, []).append(n)

    def render(n: dict, seen: set[int]) -> str:
        if n["id"] in seen:  # cycle guard
            return ""
        seen = seen | {n["id"]}
        item = (
            f'<a href="/goals/{n["id"]}/plan">'
            f'<span class="badge {esc(n["status"])}">{esc(_word(n["status"]))}</span> '
            f'<span class="title">{esc(n.get("title") or "(untitled)")}</span></a>'
        )
        kids = children.get(n["id"], [])
        if not kids:
            return f"<li>{item}</li>"
        inner = "".join(render(c, seen) for c in kids)
        return f"<li>{item}<ul>{inner}</ul></li>"

    roots = children.get(None, [])
    if not roots:
        return '<p class="muted">No tasks yet.</p>'
    return "<ul>" + "".join(render(r, set()) for r in roots) + "</ul>"


__all__ = [
    "GAP_X", "GAP_Y", "goal_nodes", "layered_layout", "descendant_ids",
    "forest_view", "forest_html",
]
