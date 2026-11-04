"""Compaction quality regression suite.

test_compaction.py covers the mechanical block-level behavior; this guards the
INVARIANTS compaction must hold over a long trajectory -- the ones whose quiet
violation corrupts a run:

  - the goal (first user message) survives verbatim;
  - the last ``keep_recent`` turns survive verbatim;
  - the message COUNT is unchanged, so tool_use/tool_result pairing stays intact
    (a dropped half = orphan tool_use = Anthropic 400 on the next call);
  - old oversized tool outputs are actually shrunk (the point of compaction);
  - the pass is idempotent (compacting a compacted trace is a no-op).

Trajectories are generated (parametrized over length) rather than 20 static
fixtures -- same intent, more thorough, and no fixture files to drift.
"""
from __future__ import annotations

import json

from maverick.compaction import (
    KEEP_RECENT_TURNS,
    MAX_TOOL_OUTPUT_BYTES,
    compact_messages,
)


def _trajectory(n_turns: int, *, big: bool = False) -> list[dict]:
    """A realistic [brief, (assistant tool_use, user tool_result) * n] trace.

    Each turn embeds ``FACT_<i>`` (for survival checks) and a unique tool_use id
    (for pairing checks); ``big`` makes each tool_result exceed the shrink
    threshold so the shrink path is exercised."""
    blob = "X" * (MAX_TOOL_OUTPUT_BYTES * 3) if big else ""
    msgs: list[dict] = [{"role": "user", "content": "GOAL: solve the thing. brief."}]
    for i in range(n_turns):
        tid = f"call_{i}"
        msgs.append({"role": "assistant", "content": [
            {"type": "text", "text": f"step {i}"},
            {"type": "tool_use", "id": tid, "name": "shell", "input": {"cmd": f"echo {i}"}},
        ]})
        msgs.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": tid, "content": f"FACT_{i} {blob}"},
        ]})
    return msgs


def _size(messages) -> int:
    return len(json.dumps(messages))


def _pairs_ok(messages) -> bool:
    """Every assistant tool_use id is answered by a tool_result in the next message."""
    for i, m in enumerate(messages):
        if m.get("role") != "assistant" or not isinstance(m.get("content"), list):
            continue
        ids = {b["id"] for b in m["content"]
               if isinstance(b, dict) and b.get("type") == "tool_use"}
        if not ids:
            continue
        nxt = messages[i + 1] if i + 1 < len(messages) else {}
        answered = {b.get("tool_use_id") for b in (nxt.get("content") or [])
                    if isinstance(b, dict) and b.get("type") == "tool_result"}
        if not ids <= answered:
            return False
    return True


def test_goal_preserved_over_long_trajectory():
    msgs = _trajectory(120)
    assert compact_messages(msgs)[0] == msgs[0]  # the GOAL/brief survives verbatim


def test_recent_turns_preserved_verbatim():
    msgs = _trajectory(120)
    assert compact_messages(msgs, keep_recent=4)[-4:] == msgs[-4:]


def test_message_count_unchanged_and_pairing_intact():
    msgs = _trajectory(120, big=True)
    assert _pairs_ok(msgs)               # the fixture itself is well-formed
    out = compact_messages(msgs)
    assert len(out) == len(msgs)         # shrinks content, never drops a turn
    assert _pairs_ok(out)                # ... so no orphan tool_use -> no API 400


def test_old_oversized_outputs_are_shrunk():
    msgs = _trajectory(120, big=True)
    out = compact_messages(msgs)
    cutoff = len(out) - KEEP_RECENT_TURNS
    for i, m in enumerate(out):
        if i == 0 or i >= cutoff or not isinstance(m.get("content"), list):
            continue
        for b in m["content"]:
            if isinstance(b, dict) and b.get("type") == "tool_result":
                assert len(str(b["content"])) <= MAX_TOOL_OUTPUT_BYTES + 512
    assert _size(out) < _size(msgs) // 2  # dramatically smaller than the raw trace


def test_compaction_is_idempotent():
    msgs = _trajectory(80, big=True)
    once = compact_messages(msgs)
    assert compact_messages(once) == once


def test_recent_facts_and_goal_survive():
    blob = json.dumps(compact_messages(_trajectory(50, big=True), keep_recent=4))
    assert "FACT_49" in blob and "FACT_48" in blob  # kept-recent window, verbatim
    assert "GOAL:" in blob                           # the goal is always present
