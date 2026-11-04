"""run_events_firehose: WebSocket firehose serializer + filter."""
from __future__ import annotations

import json

from maverick.tools.run_events_firehose import run_events_firehose


def _run(**kw):
    return run_events_firehose().fn(kw)


def test_encode_ndjson_line():
    out = _run(
        op="encode",
        seq=7,
        event={"type": "tool_call", "goal_id": 42, "ts": 1000, "data": {"tool": "shell"}},
    )
    assert out.endswith("\n")
    assert out.count("\n") == 1  # exactly one JSON object per line
    line = json.loads(out)
    assert line == {
        "seq": 7,
        "type": "tool_call",
        "goal_id": 42,
        "ts": 1000,
        "data": {"tool": "shell"},
    }


def test_encode_rejects_unknown_type_and_missing_seq():
    assert _run(op="encode", seq=1, event={"type": "bogus"}).startswith("ERROR")
    assert _run(op="encode", event={"type": "heartbeat"}).startswith("ERROR")  # no seq
    assert _run(op="encode", seq="x", event={"type": "heartbeat"}).startswith("ERROR")


def test_encode_defaults_missing_data():
    line = json.loads(_run(op="encode", seq=0, event={"type": "heartbeat"}))
    assert line["data"] == {}
    assert line["goal_id"] is None and line["ts"] is None


def test_filter_by_type_and_goal():
    events = [
        {"type": "tool_call", "goal_id": 1},
        {"type": "goal_completed", "goal_id": 1},
        {"type": "tool_call", "goal_id": 2},
        {"type": "heartbeat", "goal_id": 2},
    ]
    by_type = json.loads(_run(op="filter", events=events, types=["tool_call"]))
    assert len(by_type) == 2 and all(e["type"] == "tool_call" for e in by_type)

    by_goal = json.loads(_run(op="filter", events=events, goal_id=2))
    assert len(by_goal) == 2 and all(e["goal_id"] == 2 for e in by_goal)

    both = json.loads(_run(op="filter", events=events, types=["tool_call"], goal_id=2))
    assert both == [{"type": "tool_call", "goal_id": 2}]


def test_filter_no_filters_returns_all_and_skips_non_dicts():
    events = [{"type": "heartbeat"}, "garbage", {"type": "message"}]
    out = json.loads(_run(op="filter", events=events))
    assert len(out) == 2  # the string is skipped


def test_errors_and_factory_contract():
    t = run_events_firehose()
    assert t.fn({"op": "encode"}).startswith("ERROR")  # no event
    assert t.fn({"op": "filter"}).startswith("ERROR")  # no events
    assert t.fn({"op": "filter", "events": [], "types": "tool_call"}).startswith("ERROR")
    assert t.fn({"op": "nope"}).startswith("ERROR")
    assert t.name == "run_events_firehose"
    assert t.parallel_safe is True
    assert set(t.input_schema["properties"]["op"]["enum"]) == {"encode", "filter"}
