"""Per-node tool-usage capture for a flow's agent nodes.

An ``agent`` node runs as a governed goal; that goal calls tools. When such a
node reliably calls exactly ONE tool, run after run, it isn't really exercising
judgement -- it's a deterministic step wearing an agent's clothes, and could be
*hardened* into an ``action`` that calls that tool directly (cheaper, auditable,
no model variance). :mod:`.evolve` already proposes hardening from grounded
success rates, but the blocker was always "which tool?" -- a human had to pick
it. This store answers that from evidence: it records the distinct tools each
agent-node run used, so the proposer can infer the tool the node has been calling
all along.

Sourced from the trajectory store (which knows a goal's tools) at the point an
agent node finishes; only populated when trajectory capture is on. Append-only
NDJSON (the node-outcomes shape): 0600, best-effort, bounded tail, never raises.
"""
from __future__ import annotations

import time
from collections import Counter

from ..ndjson_log import append_row, tail_rows

_MAX_ROWS = 100_000
_DEFAULT_MIN_SUPPORT = 5
_DEFAULT_MIN_FRAC = 0.8


def _path():
    from .store import _flow_dir
    return _flow_dir("node-tools.ndjson")


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
    tools: list[str],
    *,
    revision: str | None = None,
    cohort: str | None = None,
) -> None:
    """Append the distinct ``tools`` one agent-node run used. Best-effort; the
    empty list (a run that called no tool) is still recorded, because it's
    evidence *against* hardening -- it means the node did something other than a
    single tool call."""
    append_row(_path(), {
        "ts": time.time(), "flow_id": str(flow_id), "node_id": str(node_id),
        "tools": [str(t) for t in (tools or [])],
        "revision": str(_current_revision(flow_id) if revision is None else revision),
        "cohort": str(_current_cohort(flow_id) if cohort is None else cohort),
    })


def _rows_for(
    flow_id: str,
    node_id: str,
    *,
    revision: str | None = None,
    cohort: str | None = None,
) -> list[list[str]]:
    out: list[list[str]] = []
    expected_revision = _current_revision(flow_id) if revision is None else str(revision)
    expected_cohort = _current_cohort(flow_id) if cohort is None else str(cohort)
    for r in tail_rows(_path(), _MAX_ROWS):
        if r.get("flow_id") != flow_id or str(r.get("node_id")) != str(node_id):
            continue
        if str(r.get("revision") or "") != expected_revision:
            continue
        if str(r.get("cohort") or "") != expected_cohort:
            continue
        tools = r.get("tools")
        if isinstance(tools, list):
            out.append([str(t) for t in tools])
    return out


def dominant_tool(flow_id: str, node_id: str, *,
                  min_support: int = _DEFAULT_MIN_SUPPORT,
                  min_frac: float = _DEFAULT_MIN_FRAC,
                  revision: str | None = None,
                  cohort: str | None = None) -> str | None:
    """The single tool this agent node has consistently called, or ``None``.

    Conservative on purpose -- an inferred tool can drive an *autonomous* rewrite,
    so a wrong guess would break a flow. Requires at least ``min_support`` recorded
    runs AND that one tool was the node's sole tool call in at least ``min_frac`` of
    ALL those runs (a run that used two tools, or none, counts against it). Returns
    that tool only when both hold. (Only successful node runs are recorded -- see
    execution._capture_node_tools -- so one row is one run, not one retry attempt.)"""
    rows = _rows_for(flow_id, node_id, revision=revision, cohort=cohort)
    if len(rows) < min_support:
        return None
    # Only runs that used EXACTLY one tool are evidence for hardening to it.
    single = [tools[0] for tools in rows if len(tools) == 1]
    if not single:
        return None
    tool, count = Counter(single).most_common(1)[0]
    return tool if count >= min_frac * len(rows) else None


__all__ = ["record", "dominant_tool"]
