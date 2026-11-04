"""Session forking: the counterfactual, kept on the Operating Record.

Agent shells let an operator branch an append-only session — "go back three
turns and try it the other way". That is a convenience for whoever is driving
the shell, and the branch that loses is thrown away. The governed version has
to answer a harder question months later, when a reviewer asks *why the agent
did A and not B*: the record has to hold both branches, not only the one that
shipped.

:func:`fork` makes the alternative first-class. It creates a NEW goal, replays
the parent's event trail up to a chosen decision point so the branch opens from
the same visible state, and records the lineage (parent, fork point, who forked
it, why) so a reviewer can read the choice and its alternative side by side
under one root.

**Nothing is re-executed.** A replayed event is a RECORD ROW copied onto the
child's trail — the same text a reviewer already read on the parent. Forking
calls no tool, spends no token, and never touches the sandbox; the child is an
empty run pre-loaded with context, driven from there like any other goal.

Lineage lives in a tenant-scoped JSON sidecar rather than a ``goals`` column.
Released world-model migrations are immutable (see
:mod:`maverick.migration_governance`), and fork provenance is metadata *about*
runs rather than part of one — so it sits beside the world exactly the way
:mod:`maverick.external_agents` keeps its enrollment metadata. A missing or
corrupt sidecar degrades to "no known forks": the runs themselves are still
whole, and a lineage read must never take a review page down.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

log = logging.getLogger("maverick.session_tree")

#: Replay copies the parent's visible trail onto the child, so an enormous
#: parent would otherwise double the world's event rows on every fork. This is
#: also the read window: a fork point past it is refused rather than guessed.
_MAX_REPLAY_EVENTS = 500
#: Page size for the cursor read of a parent's trail (``goal_events`` filters
#: on ``id > since_id``, so paging is a seek, not an offset scan).
_EVENT_PAGE = 200
#: Sidecar ceiling — lineage is metadata, not a growth surface.
_MAX_LINKS = 5000
#: Structural recursion bound for :func:`tree`, independent of the configured
#: ``max_depth`` (which can be lowered after deep forks already exist).
_MAX_TREE_DEPTH = 64
_MAX_LABEL = 200
_MAX_TITLE = 300

#: Replayed rows and the fork marker land as ``status`` events: neutral record
#: text. Copying the parent's original kind would let a replayed row be read as
#: a live tool call or step the child actually performed.
FORK_EVENT_KIND = "status"


class SessionTreeError(Exception):
    """Operator-facing refusal: unknown goal, bad fork point, depth cap, off."""


def enabled() -> bool:
    """``[session_tree] enable`` (on by default — lineage only, no execution)."""
    try:
        from .config import get_session_tree
        return bool(get_session_tree().get("enable", True))
    except Exception:  # pragma: no cover - unreadable config => stay off
        log.warning("session_tree: config unreadable; treating the plane as "
                    "disabled", exc_info=True)
        return False


def _max_depth() -> int:
    try:
        from .config import get_session_tree
        return max(1, int(get_session_tree().get("max_depth", 10)))
    except Exception:  # pragma: no cover - config already warned in enabled()
        return 10


# -- lineage sidecar ----------------------------------------------------------

def registry_path():
    """Fork-lineage sidecar (``session_tree.json``), tenant-scoped, 0600.

    Keyed by child goal id; each value carries the parent, the parent event the
    fork was taken at, when, by whom, and the operator's label for the branch.
    """
    from .paths import data_dir
    return data_dir("session_tree.json")


def _load_links() -> dict[int, dict]:
    """Every fork link, keyed by child goal id. Unreadable => empty + warning."""
    path = registry_path()
    try:
        if not path.exists():
            return {}
        from .file_lock import atomic_read_text
        data = json.loads(atomic_read_text(path) or "{}")
        if not isinstance(data, dict):
            raise ValueError("sidecar root must be an object")
    except (OSError, UnicodeError, ValueError) as e:
        # Losing lineage loses the counterfactual, not the runs -- but it must
        # not pass silently either, so the operator can restore the sidecar.
        log.warning("session_tree: lineage sidecar unreadable (%s); treating "
                    "as empty", e)
        return {}
    links: dict[int, dict] = {}
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        try:
            child = int(key)
            parent = int(value["parent_goal_id"])
        except (KeyError, TypeError, ValueError):
            continue  # a malformed row is dropped, not fatal to the rest
        raw_event = value.get("forked_at_event")
        try:
            at_event = int(raw_event) if raw_event is not None else None
        except (TypeError, ValueError):
            at_event = None  # an unreadable fork point still has a real parent
        links[child] = {
            "parent_goal_id": parent,
            "forked_at_event": at_event,
            "forked_at": float(value.get("forked_at") or 0.0),
            "forked_by": str(value.get("forked_by") or ""),
            "label": str(value.get("label") or "")[:_MAX_LABEL],
        }
    return links


def _save_links(links: dict[int, dict]) -> None:
    from .file_lock import atomic_write_text, ensure_private_directory
    path = registry_path()
    ensure_private_directory(path.parent)
    payload = {str(child): links[child] for child in sorted(links)}
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True),
                      mode=0o600)


def _links_locked():
    from .file_lock import cross_process_lock
    return cross_process_lock(registry_path())


def _ancestors(goal_id: int, links: dict[int, dict]) -> list[int]:
    """Fork ancestors of ``goal_id``, nearest first. Raises on a cycle.

    A cycle cannot arise from :func:`fork` (the child is always a brand-new
    goal id), so one means the sidecar was hand-edited or corrupted; walking it
    would hang. Refusing is the safe reading.
    """
    chain: list[int] = []
    seen = {goal_id}
    node = goal_id
    while True:
        link = links.get(node)
        if link is None:
            return chain
        parent = link["parent_goal_id"]
        if parent in seen:
            raise SessionTreeError(
                f"fork lineage for goal #{goal_id} is cyclic at #{parent}")
        seen.add(parent)
        chain.append(parent)
        node = parent


def _children_index(links: dict[int, dict]) -> dict[int, list[int]]:
    """``{parent_goal_id: [child ids, oldest first]}``."""
    index: dict[int, list[int]] = {}
    for child in sorted(links):
        index.setdefault(links[child]["parent_goal_id"], []).append(child)
    return index


# -- forking ------------------------------------------------------------------

def _trail(world: Any, goal_id: int, limit: int = _MAX_REPLAY_EVENTS) -> list:
    """A goal's events, oldest first, up to ``limit`` (cursor-paged)."""
    out: list = []
    since = 0
    while len(out) < limit:
        page = list(world.goal_events(goal_id, since_id=since,
                                      limit=min(_EVENT_PAGE, limit - len(out))))
        if not page:
            break
        out.extend(page)
        since = page[-1].id
    return out


def fork(goal_id: int, *, at_event: int | None = None, label: str = "",
         forked_by: str = "") -> int:
    """Branch run ``goal_id`` into a new run and return the child's goal id.

    ``at_event`` is the ``goal_events`` **id** of the last parent event to
    carry over (inclusive); ``None`` carries the whole trail. Ids, not offsets:
    ``goal_events.id`` is a global autoincrement with no per-goal sequence
    column, so an offset would silently mean something different on every read.

    Refuses an unknown goal, a fork point that is not on the parent's trail, a
    depth past ``[session_tree] max_depth``, cyclic lineage, and a disabled
    plane. On success the branch holds a replayed copy of the parent's context
    and a marker event naming its origin, and ``SESSION_FORKED`` is audited.
    """
    if not enabled():
        raise SessionTreeError(
            "session forking is off — enable [session_tree] to fork runs")
    try:
        goal_id = int(goal_id)
    except (TypeError, ValueError) as e:
        raise SessionTreeError(f"goal id {goal_id!r} is not an integer") from e

    from .world_model import open_world
    world = open_world()
    parent = world.get_goal(goal_id)
    if parent is None:
        raise SessionTreeError(f"goal #{goal_id} does not exist")

    trail = _trail(world, goal_id)
    if at_event is not None:
        try:
            at_event = int(at_event)
        except (TypeError, ValueError) as e:
            raise SessionTreeError(
                f"fork point {at_event!r} is not an event id") from e
        if at_event not in {e.id for e in trail}:
            raise SessionTreeError(
                f"event #{at_event} is not on goal #{goal_id}'s trail "
                f"(its first {len(trail)} events); a fork point is a "
                f"goal_events id, not an offset")
        trail = [e for e in trail if e.id <= at_event]

    links = _load_links()
    if len(links) >= _MAX_LINKS:
        raise SessionTreeError(
            f"the fork-lineage sidecar is full ({_MAX_LINKS} links); archive "
            f"old run trees before forking again")
    depth = len(_ancestors(goal_id, links)) + 1
    cap = _max_depth()
    if depth > cap:
        raise SessionTreeError(
            f"forking goal #{goal_id} would reach depth {depth}, past the "
            f"[session_tree] max_depth of {cap}")

    label = str(label or "").strip()[:_MAX_LABEL]
    forked_by = str(forked_by or "").strip()[:_MAX_LABEL] or "operator"
    title = f"{(parent.title or '').strip()} — fork of #{goal_id}"[:_MAX_TITLE]
    child_id = world.create_goal(
        title, description=parent.description or "",
        owner=parent.owner or "", domain=parent.domain or "",
        project_id=parent.project_id)

    # Replay is a RECORD COPY, never an execution: each row re-appends the
    # parent's own event text so the branch opens from the state the reviewer
    # already saw. No tool runs, no tokens spent, no sandbox touched.
    for event in trail:
        world.append_event(child_id, event.agent, FORK_EVENT_KIND, event.content)
    origin = f"event #{at_event}" if at_event is not None else "its full trail"
    world.append_event(
        child_id, "session_tree", FORK_EVENT_KIND,
        f"forked from goal #{goal_id} at {origin} by {forked_by}"
        + (f": {label}" if label else ""))

    now = time.time()
    with _links_locked():
        links = _load_links()
        links[child_id] = {
            "parent_goal_id": goal_id,
            "forked_at_event": at_event,
            "forked_at": now,
            "forked_by": forked_by,
            "label": label,
        }
        _save_links(links)

    from .audit import EventKind, audit_event
    audit_event(EventKind.SESSION_FORKED, agent="session_tree",
                goal_id=child_id, parent_goal_id=goal_id, child_goal_id=child_id,
                at_event=at_event, forked_by=forked_by, label=label,
                replayed_events=len(trail))
    return child_id


# -- reading the tree ---------------------------------------------------------

def lineage(goal_id: int) -> dict:
    """Where one run sits in its fork tree.

    ``{goal_id, parent, children, depth, root, label, forked_at_event}`` —
    ``depth`` is 0 for a run that was never forked from, ``root`` is the
    original run the branch descends from (itself, for a root).
    """
    try:
        goal_id = int(goal_id)
    except (TypeError, ValueError) as e:
        raise SessionTreeError(f"goal id {goal_id!r} is not an integer") from e
    links = _load_links()
    link = links.get(goal_id)
    try:
        chain = _ancestors(goal_id, links)
    except SessionTreeError:
        # Corruption, not a run state: report the goal as its own root rather
        # than looping or 500ing the review page.
        log.warning("session_tree: cyclic lineage at goal #%s; reporting it as "
                    "a root", goal_id)
        chain, link = [], None
    return {
        "goal_id": goal_id,
        "parent": link["parent_goal_id"] if link else None,
        "children": _children_index(links).get(goal_id, []),
        "depth": len(chain),
        "root": chain[-1] if chain else goal_id,
        "label": link["label"] if link else "",
        "forked_at_event": link["forked_at_event"] if link else None,
    }


def _node(world: Any, goal_id: int, links: dict[int, dict],
          children: dict[int, list[int]], seen: set[int], depth: int) -> dict | None:
    if goal_id in seen or depth > _MAX_TREE_DEPTH:
        return None  # cyclic/absurd lineage: stop, never recurse forever
    seen.add(goal_id)
    try:
        goal = world.get_goal(goal_id)
    except Exception:  # pragma: no cover - a broken world must not 500 the page
        log.warning("session_tree: goal #%s unreadable; skipping the branch",
                    goal_id, exc_info=True)
        return None
    if goal is None:
        # The run was erased (DSAR, retention) while its lineage row survived.
        # Skip the branch rather than render a ghost node or raise.
        return None
    link = links.get(goal_id) or {}
    kids = []
    for child in children.get(goal_id, []):
        node = _node(world, child, links, children, seen, depth + 1)
        if node is not None:
            kids.append(node)
    return {
        "goal_id": goal_id,
        "title": goal.title or "",
        "status": goal.status,
        "owner": goal.owner or "",
        "label": link.get("label", ""),
        "forked_at_event": link.get("forked_at_event"),
        "forked_at": link.get("forked_at"),
        "forked_by": link.get("forked_by", ""),
        "children": kids,
    }


def tree(root_goal_id: int) -> dict:
    """The nested fork tree under a run, or ``{}`` if that run is gone.

    Each node is ``{goal_id, title, status, owner, label, forked_at_event,
    forked_at, forked_by, children}``. Branches whose goal no longer exists are
    dropped whole — an unreadable parent makes its descendants unreadable too.
    """
    try:
        root_goal_id = int(root_goal_id)
    except (TypeError, ValueError) as e:
        raise SessionTreeError(
            f"goal id {root_goal_id!r} is not an integer") from e
    links = _load_links()
    try:
        from .world_model import open_world
        world = open_world()
    except Exception as e:  # pragma: no cover - no world => nothing to show
        log.warning("session_tree: world unavailable (%s)", e)
        return {}
    return _node(world, root_goal_id, links, _children_index(links), set(), 0) or {}


def roots(limit: int = 50) -> list[dict]:
    """Runs that have been forked, newest fork first.

    ``{goal_id, title, status, owner, forks, last_forked_at}`` per root, where
    ``forks`` counts every branch anywhere beneath it.
    """
    links = _load_links()
    if not links:
        return []
    try:
        from .world_model import open_world
        world = open_world()
    except Exception as e:  # pragma: no cover - no world => nothing to show
        log.warning("session_tree: world unavailable (%s)", e)
        return []
    counts: dict[int, int] = {}
    newest: dict[int, float] = {}
    for child, link in links.items():
        try:
            chain = _ancestors(child, links)
        except SessionTreeError:
            continue  # a cyclic branch is unreadable; the rest still lists
        root = chain[-1] if chain else child
        counts[root] = counts.get(root, 0) + 1
        newest[root] = max(newest.get(root, 0.0), link["forked_at"])
    rows = []
    for root, count in counts.items():
        try:
            goal = world.get_goal(root)
        except Exception:  # pragma: no cover - see _node
            goal = None
        if goal is None:
            continue
        rows.append({"goal_id": root, "title": goal.title or "",
                     "status": goal.status, "owner": goal.owner or "",
                     "forks": count, "last_forked_at": newest.get(root, 0.0)})
    rows.sort(key=lambda r: (-r["last_forked_at"], -r["goal_id"]))
    return rows[:max(1, int(limit))]
