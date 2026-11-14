"""Run-events firehose serializer.

Encode and filter the stream of run events that a WebSocket firehose would push
to dashboards. Pure and offline: this is the *serializer*, not the socket — it
turns an event dict into one JSON line (NDJSON) with a caller-supplied monotonic
sequence number, and filters a batch of events by type / goal. No I/O.

ops:
  - encode(event={type, goal_id, ts, data}, seq) -> a single JSON line for the
    WS firehose, stamped with ``seq``. Validates ``type`` against the known set.
  - filter(events, types?, goal_id?) -> the matching subset (JSON array).

Known event types are validated so a typo'd producer can't poison the stream.
"""
from __future__ import annotations

import json
from typing import Any

from . import Tool

# The events a run can emit on the firehose. Restricting the set means a
# malformed/typo'd producer is rejected at encode time rather than silently
# flowing to every connected dashboard.
_EVENT_TYPES: frozenset[str] = frozenset({
    "goal_started",
    "goal_completed",
    "goal_failed",
    "tool_call",
    "tool_result",
    "subagent_spawned",
    "budget_update",
    "message",
    "heartbeat",
})


def _encode(args: dict[str, Any]) -> str:
    event = args.get("event")
    if not isinstance(event, dict) or not event:
        return "ERROR: event ({type, goal_id, ts, data}) is required"
    etype = event.get("type")
    if not isinstance(etype, str) or not etype.strip():
        return "ERROR: event.type is required"
    etype = etype.strip()
    if etype not in _EVENT_TYPES:
        return f"ERROR: unknown event type {etype!r}"
    if "seq" not in args:
        return "ERROR: seq (a monotonic integer) is required"
    try:
        seq = int(args["seq"])
    except (TypeError, ValueError, OverflowError):
        return "ERROR: seq must be an integer"
    if seq < 0:
        return "ERROR: seq must be >= 0"

    line = {
        "seq": seq,
        "type": etype,
        "goal_id": event.get("goal_id"),
        "ts": event.get("ts"),
        "data": event.get("data", {}),
    }
    # NDJSON: exactly one compact, newline-terminated JSON object per event.
    return json.dumps(line, sort_keys=True) + "\n"


def _filter(args: dict[str, Any]) -> str:
    events = args.get("events")
    if not isinstance(events, list):
        return "ERROR: events (an array) is required"
    types = args.get("types")
    type_set: set[str] | None = None
    if types is not None:
        if not isinstance(types, list):
            return "ERROR: types must be an array of event-type strings"
        type_set = {str(t).strip() for t in types}
    goal_id = args.get("goal_id")
    has_goal_filter = "goal_id" in args and goal_id is not None

    matched: list[dict] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if type_set is not None and str(ev.get("type")) not in type_set:
            continue
        if has_goal_filter and ev.get("goal_id") != goal_id:
            continue
        matched.append(ev)
    return json.dumps(matched, sort_keys=True)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "encode":
        return _encode(args)
    if op == "filter":
        return _filter(args)
    return f"ERROR: unknown op {op!r} (expected encode or filter)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["encode", "filter"]},
        "event": {
            "type": "object",
            "description": "for op=encode; {type, goal_id, ts, data}",
            "properties": {
                "type": {"type": "string"},
                "goal_id": {},
                "ts": {},
                "data": {"type": "object"},
            },
            "required": ["type"],
        },
        "seq": {"type": "integer", "description": "monotonic sequence number for op=encode"},
        "events": {
            "type": "array",
            "description": "for op=filter; the batch of event objects",
            "items": {"type": "object"},
        },
        "types": {
            "type": "array",
            "description": "for op=filter; keep only these event types",
            "items": {"type": "string"},
        },
        "goal_id": {"description": "for op=filter; keep only this goal's events"},
    },
    "required": ["op"],
}


def run_events_firehose() -> Tool:
    return Tool(
        name="run_events_firehose",
        description=(
            "Serializer for the run-events WebSocket firehose (no actual "
            "socket). op=encode {event:{type, goal_id, ts, data}, seq} -> one "
            "NDJSON line stamped with the monotonic seq (type validated against "
            "a known set). op=filter {events, types?, goal_id?} -> the matching "
            "subset as a JSON array. Deterministic; offline; stdlib only."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
