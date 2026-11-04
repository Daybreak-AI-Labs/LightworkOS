"""Tool-call inspector.

Aggregate a run's tool-call log into the at-a-glance health view: per-tool call
counts and success rate, total + mean latency, total cost, and which tool is the
slowest / fails the most. Deterministic and offline — pure aggregation over the
supplied log.

ops:
  - summarize(calls)  — calls: list of {tool, ok, ms[, cost]}.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _num(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _summarize(calls: list) -> str:
    stats: dict[str, dict[str, float]] = {}
    total_ms = 0.0
    total_cost = 0.0
    n = 0
    for c in calls:
        if not isinstance(c, dict):
            continue
        name = str(c.get("tool", "")) or "<unknown>"
        ok = c.get("ok") is True
        ms = _num(c.get("ms"))
        cost = _num(c.get("cost"))
        s = stats.setdefault(
            name, {"calls": 0.0, "ok": 0.0, "ms": 0.0, "cost": 0.0}
        )
        s["calls"] += 1
        s["ok"] += 1 if ok else 0
        s["ms"] += ms
        s["cost"] += cost
        total_ms += ms
        total_cost += cost
        n += 1

    if n == 0:
        return "ERROR: no valid tool calls in log"

    # Per-tool table, sorted by call count desc then name for stability.
    rows = sorted(stats.items(), key=lambda kv: (-kv[1]["calls"], kv[0]))
    lines = [
        f"{int(s['calls'])}x {name}: "
        f"{int(s['ok'])}/{int(s['calls'])} ok "
        f"({(s['ok'] / s['calls'] * 100):.0f}%), "
        f"total={s['ms']:g}ms mean={s['ms'] / s['calls']:.1f}ms, "
        f"cost={s['cost']:g}"
        for name, s in rows
    ]

    slowest = max(rows, key=lambda kv: kv[1]["ms"])[0]
    # Most-failed by failure count, tie-broken by name for determinism.
    most_failed = min(
        rows, key=lambda kv: (-(kv[1]["calls"] - kv[1]["ok"]), kv[0])
    )[0]
    failures = int(
        stats[most_failed]["calls"] - stats[most_failed]["ok"]
    )

    overall_ok = sum(s["ok"] for s in stats.values())
    header = (
        f"{n} call(s), {len(stats)} tool(s): "
        f"{(overall_ok / n * 100):.0f}% ok, "
        f"total={total_ms:g}ms mean={total_ms / n:.1f}ms, "
        f"cost={total_cost:g}"
    )
    footer = (
        f"slowest={slowest} ({stats[slowest]['ms']:g}ms); "
        f"most-failed={most_failed} ({failures} fail)"
    )
    return header + "\n" + "\n".join(lines) + "\n" + footer


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "summarize"):
        return f"ERROR: unknown op {args.get('op')!r}"
    calls = args.get("calls")
    if not isinstance(calls, list) or not calls:
        return "ERROR: calls (non-empty list of {tool, ok, ms[, cost]}) is required"
    return _summarize(calls)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["summarize"]},
        "calls": {
            "type": "array",
            "description": "tool-call log; each {tool, ok, ms, cost?}",
            "items": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string"},
                    "ok": {"type": "boolean"},
                    "ms": {"type": "number"},
                    "cost": {"type": "number"},
                },
                "required": ["tool", "ok", "ms"],
            },
        },
    },
    "required": ["calls"],
}


def tool_call_inspector() -> Tool:
    return Tool(
        name="tool_call_inspector",
        description=(
            "Aggregate a tool-call log. op=summarize with 'calls' (each "
            "{tool, ok, ms, cost?}). Returns per-tool counts, success rate, "
            "total+mean latency, total cost, and the slowest / most-failed "
            "tool. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
