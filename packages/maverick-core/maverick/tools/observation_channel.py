"""Multi-agent observation channel.

A shared, time-ordered feed where every agent in a swarm posts what it sees.
``merge`` collapses each agent's observation list into one chronologically
ordered feed plus a per-agent count, so a coordinator gets a single coherent
view. ``since`` filters that feed to observations strictly newer than a
timestamp, for incremental polling. Pure and deterministic.

ops:
  - merge(observations)       — observations: [{agent, ts, text}] -> shared feed.
  - since(observations, ts)   — only observations with ts > the given ts.
"""
from __future__ import annotations

import json
from typing import Any

from . import Tool


def _norm(observations: list[dict]) -> tuple[list[dict], str | None]:
    """Validate + return (sorted feed, error). Ties broken by agent then text
    so the order is fully deterministic regardless of input order."""
    feed: list[dict] = []
    for o in observations:
        if not isinstance(o, dict):
            return [], "each observation must be an object {agent, ts, text}"
        agent = str(o.get("agent", "")).strip()
        if not agent:
            return [], "every observation needs a non-empty agent"
        if "ts" not in o:
            return [], "every observation needs a ts"
        try:
            ts = float(o["ts"])
        except (TypeError, ValueError):
            return [], f"observation ts {o.get('ts')!r} is not a number"
        feed.append({"agent": agent, "ts": ts, "text": str(o.get("text", ""))})
    feed.sort(key=lambda e: (e["ts"], e["agent"], e["text"]))
    return feed, None


def _merge(observations: list[dict]) -> str:
    feed, err = _norm(observations)
    if err:
        return f"ERROR: {err}"
    counts: dict[str, int] = {}
    for e in feed:
        counts[e["agent"]] = counts.get(e["agent"], 0) + 1
    payload = {"feed": feed, "counts": counts}
    return (
        f"{len(feed)} observation(s) from {len(counts)} agent(s)\n"
        + json.dumps(payload, sort_keys=True)
    )


def _since(observations: list[dict], ts: float) -> str:
    feed, err = _norm(observations)
    if err:
        return f"ERROR: {err}"
    newer = [e for e in feed if e["ts"] > ts]
    return f"{len(newer)} observation(s) since {ts}\n" + json.dumps(newer, sort_keys=True)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op not in ("merge", "since"):
        return f"ERROR: unknown op {op!r}"
    observations = args.get("observations")
    if not isinstance(observations, list):
        return "ERROR: observations (list of {agent, ts, text}) is required"
    if op == "merge":
        return _merge(observations)
    if "ts" not in args:
        return "ERROR: ts is required for op=since"
    try:
        ts = float(args["ts"])
    except (TypeError, ValueError):
        return f"ERROR: ts {args.get('ts')!r} is not a number"
    return _since(observations, ts)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["merge", "since"]},
        "observations": {
            "type": "array",
            "description": "Per-agent observations: {agent, ts, text}",
            "items": {"type": "object"},
        },
        "ts": {"type": "number", "description": "Cutoff for op=since (exclusive)"},
    },
    "required": ["op", "observations"],
}


def observation_channel() -> Tool:
    return Tool(
        name="observation_channel",
        description=(
            "Multi-agent observation channel. op=merge with 'observations' "
            "([{agent, ts, text}]) -> one time-ordered shared feed plus "
            "per-agent counts; op=since with 'observations' and 'ts' -> only "
            "observations newer than ts. Pure, deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
