"""unified_inbox: multi-channel merge, threading, and unread counts."""
from __future__ import annotations

from maverick.tools.unified_inbox import unified_inbox


def _merge(**kw):
    return unified_inbox().fn({"op": "merge", **kw})


def test_time_sorted_across_channels():
    out = _merge(messages=[
        {"channel": "slack", "user": "a", "text": "later", "ts": 30},
        {"channel": "email", "user": "b", "text": "earlier", "ts": 10},
    ])
    assert out.index("earlier") < out.index("later")


def test_threads_grouped_by_channel_user():
    out = _merge(messages=[
        {"channel": "slack", "user": "a", "text": "hi", "ts": 1},
        {"channel": "slack", "user": "a", "text": "again", "ts": 2},
        {"channel": "email", "user": "b", "text": "hey", "ts": 3},
    ])
    assert "2 thread(s)" in out
    assert "thread slack:a (2)" in out
    assert "thread email:b (1)" in out


def test_explicit_thread_key_groups_across_channels():
    out = _merge(messages=[
        {"channel": "slack", "user": "a", "text": "one", "ts": 1, "thread": "T1"},
        {"channel": "email", "user": "b", "text": "two", "ts": 2, "thread": "T1"},
    ])
    assert "1 thread(s)" in out
    assert "thread T1 (2)" in out


def test_unread_counts_per_channel():
    out = _merge(messages=[
        {"channel": "slack", "user": "a", "text": "x", "ts": 1, "unread": True},
        {"channel": "slack", "user": "a", "text": "y", "ts": 2, "unread": True},
        {"channel": "email", "user": "b", "text": "z", "ts": 3, "unread": True},
        {"channel": "email", "user": "b", "text": "read", "ts": 4},
    ])
    assert "unread: email=1, slack=2" in out


def test_empty_and_errors():
    assert _merge(messages=[]) == "INBOX: (empty)"
    t = unified_inbox()
    assert t.fn({"op": "merge"}).startswith("ERROR")
    assert t.fn({"op": "nope", "messages": []}).startswith("ERROR")


def test_factory_shape():
    t = unified_inbox()
    assert t.name == "unified_inbox"
    assert t.parallel_safe is True
    assert t.input_schema["required"] == ["messages"]
