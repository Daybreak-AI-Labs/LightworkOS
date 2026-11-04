"""observation_channel: shared time-ordered multi-agent feed."""
from __future__ import annotations

import json

from maverick.tools.observation_channel import observation_channel


def _run(**kw):
    return observation_channel().fn(kw)


def _payload(out: str):
    return json.loads(out.split("\n", 1)[1])


def test_merge_orders_by_ts():
    obs = [
        {"agent": "a", "ts": 3, "text": "third"},
        {"agent": "b", "ts": 1, "text": "first"},
        {"agent": "a", "ts": 2, "text": "second"},
    ]
    out = _run(op="merge", observations=obs)
    feed = _payload(out)["feed"]
    assert [e["text"] for e in feed] == ["first", "second", "third"]


def test_merge_per_agent_counts():
    obs = [
        {"agent": "a", "ts": 1, "text": "x"},
        {"agent": "a", "ts": 2, "text": "y"},
        {"agent": "b", "ts": 3, "text": "z"},
    ]
    counts = _payload(_run(op="merge", observations=obs))["counts"]
    assert counts == {"a": 2, "b": 1}


def test_merge_empty():
    out = _run(op="merge", observations=[])
    payload = _payload(out)
    assert payload == {"feed": [], "counts": {}}


def test_since_filters_strictly_newer():
    obs = [
        {"agent": "a", "ts": 1, "text": "old"},
        {"agent": "a", "ts": 2, "text": "edge"},
        {"agent": "b", "ts": 3, "text": "new"},
    ]
    out = _run(op="since", observations=obs, ts=2)
    feed = _payload(out)
    assert [e["text"] for e in feed] == ["new"]  # ts==2 excluded


def test_deterministic_tie_break():
    obs = [
        {"agent": "z", "ts": 1, "text": "b"},
        {"agent": "a", "ts": 1, "text": "a"},
    ]
    feed = _payload(_run(op="merge", observations=obs))["feed"]
    assert [e["agent"] for e in feed] == ["a", "z"]  # same ts -> by agent


def test_errors():
    assert _run(op="merge").startswith("ERROR")  # no observations
    assert _run(op="since", observations=[]).startswith("ERROR")  # no ts
    bad = _run(op="merge", observations=[{"ts": 1, "text": "x"}])
    assert bad.startswith("ERROR") and "agent" in bad
    bad_ts = _run(op="merge", observations=[{"agent": "a", "ts": "soon"}])
    assert bad_ts.startswith("ERROR")
    assert _run(op="nope", observations=[]).startswith("ERROR")
