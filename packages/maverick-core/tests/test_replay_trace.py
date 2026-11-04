"""Replayable trace format."""
from __future__ import annotations

import os

import pytest
from maverick.file_lock import private_path_is_restricted
from maverick.replay.trace import TraceWriter, read_trace, replay


def test_write_then_read_roundtrip(tmp_path):
    path = tmp_path / "run.jsonl"
    with TraceWriter(path) as w:
        s1 = w.record("tool_call", name="read_file", args={"path": "a"})
        s2 = w.record("llm_turn", tokens=42)
    assert (s1, s2) == (1, 2)
    events = read_trace(path)
    assert [e["kind"] for e in events] == ["tool_call", "llm_turn"]
    assert events[0]["seq"] == 1
    assert events[0]["args"] == {"path": "a"}
    assert "t" in events[0]


def test_tolerates_corrupt_trailing_line(tmp_path):
    path = tmp_path / "run.jsonl"
    with TraceWriter(path) as w:
        w.record("a")
        w.record("b")
    # simulate a half-written final record (process killed mid-flush)
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 3, "kind": "c", "x":')
    events = read_trace(path)
    assert [e["kind"] for e in events] == ["a", "b"]


def test_non_serialisable_field_coerced(tmp_path):
    path = tmp_path / "run.jsonl"

    class Weird:
        def __str__(self):
            return "weird-obj"

    with TraceWriter(path) as w:
        w.record("x", obj=Weird())
    assert read_trace(path)[0]["obj"] == "weird-obj"


def test_replay_dispatches_in_seq_order(tmp_path):
    path = tmp_path / "run.jsonl"
    with TraceWriter(path) as w:
        w.record("tool", name="one")
        w.record("llm")
        w.record("tool", name="two")
    seen: list[str] = []
    n = replay(path, {
        "tool": lambda e: seen.append(f"tool:{e['name']}"),
        "*": lambda e: seen.append(e["kind"]),
    })
    assert n == 3
    assert seen == ["tool:one", "llm", "tool:two"]


def test_read_missing_file_is_empty(tmp_path):
    assert read_trace(tmp_path / "nope.jsonl") == []


def test_trace_writer_locks_down_trace_permissions(tmp_path):
    old_umask = os.umask(0o022)
    try:
        trace_dir = tmp_path / "traces"
        path = trace_dir / "run.jsonl"
        with TraceWriter(path) as w:
            w.record("observation", content="SECRET_TOKEN=topsecret")
    finally:
        os.umask(old_umask)

    assert private_path_is_restricted(trace_dir, 0o700)
    assert private_path_is_restricted(path, 0o600)
    assert read_trace(path)[0]["content"] == "SECRET_TOKEN=topsecret"


def test_trace_writer_refuses_permissive_caller_parent_without_taking_it_over(tmp_path):
    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    trace_dir.chmod(0o755)
    path = trace_dir / "run.jsonl"
    path.write_text("", encoding="utf-8")
    path.chmod(0o644)

    with pytest.raises(PermissionError, match="parent directory must already be private"):
        TraceWriter(path)

    assert not private_path_is_restricted(trace_dir, 0o700)
    assert path.read_text(encoding="utf-8") == ""
