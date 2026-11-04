"""Append-only log of applied flow self-rewrites.

When a proposal from :mod:`.evolve` is actually applied to a flow (a node's kind
swapped), we record the event here with the timestamp and the version it produced.
That timestamp is the boundary the measurement pass (:func:`.evolve.measure`)
splits a node's outcome series around -- outcomes before the apply are the old
behaviour, outcomes at/after it are the new -- which is what lets the loop prove
whether a rewrite actually helped instead of just asserting it.

Append-only NDJSON (the node-outcomes / consequence store shape): 0600,
best-effort, bounded tail. Never raises into a request.
"""
from __future__ import annotations

import time

from ..ndjson_log import append_row, tail_rows

_MAX_ROWS = 50_000


def _path():
    from .store import _flow_dir
    return _flow_dir("evolution.ndjson")


def _current_revision(flow_id: str) -> str:
    from .store import load_flow

    flow = load_flow(flow_id)
    return str(flow.revision or "") if flow is not None else ""


def record_apply(
    flow_id: str,
    node_id: str,
    from_kind: str,
    to_kind: str,
    version: int,
    *,
    source: str = "manual",
    revision: str | None = None,
    before_revision: str | None = None,
    after_revision: str | None = None,
) -> None:
    """Record that ``node_id`` in ``flow_id`` was swapped ``from_kind -> to_kind``,
    producing definition ``version``. ``source`` is ``manual`` (a human applied a
    proposal) or ``auto`` (the sweep did). Best-effort; never raises."""
    generation = str(_current_revision(flow_id) if revision is None else revision)
    if before_revision is None or after_revision is None:
        from .store import definition_cohort

        if before_revision is None:
            before_revision = definition_cohort(generation, max(0, int(version) - 1))
        if after_revision is None:
            after_revision = definition_cohort(generation, int(version))
    append_row(_path(), {
        "ts": time.time(), "flow_id": str(flow_id), "node_id": str(node_id),
        "from_kind": str(from_kind), "to_kind": str(to_kind),
        "version": int(version), "source": str(source),
        "revision": generation,
        # These immutable definition cohorts, not wall-clock position, are the
        # causal comparison boundary. Later unrelated saves cannot rewrite it.
        "before_revision": str(before_revision or ""),
        "after_revision": str(after_revision or ""),
    })


def _rows() -> list[dict]:
    return tail_rows(_path(), _MAX_ROWS)


def history(
    flow_id: str,
    node_id: str | None = None,
    *,
    revision: str | None = None,
) -> list[dict]:
    """Apply events for a flow (optionally one node), newest first."""
    expected_revision = _current_revision(flow_id) if revision is None else str(revision)
    rows = [r for r in _rows() if r.get("flow_id") == flow_id
            and str(r.get("revision") or "") == expected_revision
            and (node_id is None or str(r.get("node_id")) == str(node_id))]
    rows.sort(key=lambda r: r.get("ts") or 0.0, reverse=True)
    return rows


def last_apply(
    flow_id: str, node_id: str, *, revision: str | None = None,
) -> dict | None:
    """The most recent apply event for a node, or ``None`` if it was never
    changed -- i.e. there's no before/after boundary to measure yet."""
    rows = history(flow_id, node_id, revision=revision)
    return rows[0] if rows else None


def improvement_count() -> int:
    """How many flow-node self-rewrites STUCK -- forward applies (a human or the
    autonomous pass enacting a proposal) that the loop did NOT later auto-revert.

    A change the loop measured, found to regress, and undid is not an improvement,
    so it is netted out rather than counted: we tally each rewritten node whose
    latest apply is a forward one, not a revert. An honest "your workflows got
    better and stayed better N times" number -- an inflated one would erode
    the very trust it's meant to build."""
    latest: dict[tuple[str, str, str], dict] = {}
    forward: set[tuple[str, str, str]] = set()
    revisions: dict[str, str] = {}
    for r in _rows():   # append-only chronological tail: last write per node wins
        flow_id = str(r.get("flow_id"))
        revision = str(r.get("revision") or "")
        if flow_id not in revisions:
            revisions[flow_id] = _current_revision(flow_id)
        current = revisions[flow_id]
        if revision != current:
            continue
        key = (flow_id, revision, str(r.get("node_id")))
        latest[key] = r
        if r.get("source") != "auto-revert":
            forward.add(key)
    return sum(1 for key in forward if latest[key].get("source") != "auto-revert")


__all__ = ["record_apply", "history", "last_apply", "improvement_count"]
