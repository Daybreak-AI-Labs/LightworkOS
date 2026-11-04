"""streaming_reasoning_trace: ordered, redaction-aware reasoning-trace channel."""
from __future__ import annotations

from maverick.tools.streaming_reasoning_trace import streaming_reasoning_trace


def _fmt(**kw):
    return streaming_reasoning_trace().fn({"op": "format", **kw})


def _sum(**kw):
    return streaming_reasoning_trace().fn({"op": "summarize", **kw})


def test_format_orders_by_timestamp():
    out = _fmt(events=[
        {"phase": "act", "text": "second", "ts": 2},
        {"phase": "plan", "text": "first", "ts": 1},
    ])
    assert out.index("first") < out.index("second")
    assert "plan: first" in out and "act: second" in out


def test_format_redacts_secrets():
    out = _fmt(events=[
        {"phase": "plan", "text": "key is <secret>sk-abc123</secret> done", "ts": 1},
    ])
    assert "sk-abc123" not in out
    assert "[REDACTED]" in out and out.endswith("done")


def test_format_redacts_multiline_and_case_insensitive_tag():
    out = _fmt(events=[
        {"phase": "p", "text": "a <SECRET>line1\nline2</SECRET> b", "ts": 1},
    ])
    assert "line1" not in out and "line2" not in out
    assert "[REDACTED]" in out


def test_summarize_counts_and_duration():
    out = _sum(events=[
        {"phase": "plan", "text": "x", "ts": 10},
        {"phase": "plan", "text": "y", "ts": 12},
        {"phase": "act", "text": "z", "ts": 15},
    ])
    assert "3 event(s)" in out
    assert "duration 5" in out
    assert "act=1" in out and "plan=2" in out


def test_empty_and_errors():
    assert _fmt(events=[]) == "TRACE: (empty)"
    assert _sum(events=[]) == "SUMMARY: 0 event(s)"
    t = streaming_reasoning_trace()
    assert t.fn({"op": "format"}).startswith("ERROR")
    assert t.fn({"op": "nope", "events": []}).startswith("ERROR")


def test_malformed_ts_sorts_last_no_crash():
    out = _fmt(events=[
        {"phase": "a", "text": "good", "ts": 1},
        {"phase": "b", "text": "bad", "ts": "oops"},
    ])
    assert out.index("good") < out.index("bad")
    assert "[?]" in out  # malformed ts rendered as ?


def test_factory_shape():
    t = streaming_reasoning_trace()
    assert t.name == "streaming_reasoning_trace"
    assert t.parallel_safe is True
    assert t.input_schema["required"] == ["events"]
    assert callable(t.fn)
