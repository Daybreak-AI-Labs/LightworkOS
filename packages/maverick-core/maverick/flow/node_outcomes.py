"""Per-node grounded outcomes for a flow.

Because a flow has structure, an outcome can attach to the *node* that produced
it, not just the whole run. Accumulating ``(flow_id, node_id) -> outcome`` gives
the self-rewrite pass (:mod:`.evolve`) the evidence to say "this agent node's
choice is right 95% of the time -- make it a deterministic rule" or "this action
node fails a third of the time -- let an agent handle the variation". That
per-node signal is the thing a pure flow engine or a pure agent can't produce.

Append-only NDJSON (the consequence-store shape): 0600, best-effort, bounded tail.
"""
from __future__ import annotations

import time
from collections import defaultdict

from ..ndjson_log import append_row, clamp01, tail_rows

_MAX_ROWS = 100_000


def _path():
    from .store import _flow_dir
    return _flow_dir("node-outcomes.ndjson")


def _current_revision(flow_id: str) -> str:
    from .store import load_flow

    flow = load_flow(flow_id)
    return str(flow.revision or "") if flow is not None else ""


def _current_cohort(flow_id: str) -> str:
    from .store import flow_cohort, load_flow

    flow = load_flow(flow_id)
    return flow_cohort(flow) if flow is not None else ""


def record(
    flow_id: str,
    node_id: str,
    kind: str,
    value: float,
    *,
    revision: str | None = None,
    cohort: str | None = None,
) -> None:
    """Append one node outcome. ``value`` in [0, 1]. Best-effort; never raises."""
    append_row(_path(), {
        "ts": time.time(), "flow_id": str(flow_id), "node_id": str(node_id),
        "kind": str(kind), "value": clamp01(value),
        "revision": str(_current_revision(flow_id) if revision is None else revision),
        "cohort": str(_current_cohort(flow_id) if cohort is None else cohort),
    })


def _read_rows() -> list[dict]:
    return tail_rows(_path(), _MAX_ROWS)


def series(
    flow_id: str,
    node_id: str,
    *,
    revision: str | None = None,
    cohort: str | None = None,
) -> list[tuple[float, float]]:
    """Time-ordered ``(ts, value)`` outcomes for one node -- the raw signal the
    measurement pass splits around an applied change to score before vs. after."""
    out: list[tuple[float, float]] = []
    expected_revision = _current_revision(flow_id) if revision is None else str(revision)
    expected_cohort = _current_cohort(flow_id) if cohort is None else str(cohort)
    for r in _read_rows():
        if r.get("flow_id") != flow_id or str(r.get("node_id")) != str(node_id):
            continue
        if str(r.get("revision") or "") != expected_revision:
            continue
        if str(r.get("cohort") or "") != expected_cohort:
            continue
        try:
            out.append((float(r.get("ts") or 0.0), float(r.get("value"))))
        except (TypeError, ValueError):
            continue
    out.sort(key=lambda tv: tv[0])
    return out


def stats(
    flow_id: str,
    *,
    revision: str | None = None,
    cohort: str | None = None,
) -> dict[str, dict]:
    """Per-node aggregate for a flow: ``{node_id: {n, mean, kind}}``."""
    sums: dict[str, float] = defaultdict(float)
    counts: dict[str, int] = defaultdict(int)
    kinds: dict[str, str] = {}
    expected_revision = _current_revision(flow_id) if revision is None else str(revision)
    expected_cohort = _current_cohort(flow_id) if cohort is None else str(cohort)
    for r in _read_rows():
        if r.get("flow_id") != flow_id:
            continue
        if str(r.get("revision") or "") != expected_revision:
            continue
        if str(r.get("cohort") or "") != expected_cohort:
            continue
        nid = str(r.get("node_id"))
        try:
            sums[nid] += float(r.get("value"))
        except (TypeError, ValueError):
            continue
        counts[nid] += 1
        kinds[nid] = str(r.get("kind") or kinds.get(nid, ""))
    return {
        nid: {"n": counts[nid], "mean": sums[nid] / counts[nid], "kind": kinds.get(nid, "")}
        for nid in counts
    }


__all__ = ["record", "series", "stats"]
