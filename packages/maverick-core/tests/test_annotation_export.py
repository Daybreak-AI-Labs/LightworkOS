"""Replay annotation export: markdown + SRT rendering, store read, CLI."""
from __future__ import annotations

import pytest
from maverick import annotation_export as ax
from maverick.world_model import Goal, GoalEvent, WorldModel


def _goal(created_at=1000.0) -> Goal:
    return Goal(id=7, parent_id=None, title="fix the flaky test",
                description=None, status="done", created_at=created_at,
                updated_at=created_at, deadline=None, result=None)


def _events() -> list[GoalEvent]:
    return [
        GoalEvent(id=1, goal_id=7, agent="planner", kind="plan",
                  content="1. reproduce 2. fix", ts=1001.0),
        GoalEvent(id=2, goal_id=7, agent="coder", kind="tool",
                  content="pytest -k flaky", ts=1012.0),
        GoalEvent(id=3, goal_id=7, agent="coder", kind="error",
                  content="AssertionError", ts=1075.0),
    ]


def _notes() -> list[dict]:
    return [
        {"seq": 1, "note": "this is where it diverged", "author": "user:amy", "at": 2000.0},
        {"seq": 2, "note": "root cause", "author": "_anon", "at": 2001.0},
    ]


def test_markdown_has_header_offsets_and_excerpts():
    md = ax.to_markdown(_goal(), _events(), _notes())
    assert md.startswith("# Trace annotations — goal #7: fix the flaky test")
    assert "2 annotation(s) over 3 replay step(s)." in md
    assert "## [00:00:12] step 1 · tool — user:amy" in md
    assert "this is where it diverged" in md
    assert "> pytest -k flaky" in md          # annotated step's excerpt
    assert "## [00:01:15] step 2 · error — _anon" in md


def test_markdown_out_of_range_seq_still_exports():
    md = ax.to_markdown(_goal(), _events(), [{"seq": 99, "note": "late note"}])
    assert "## [00:00:00] step 99 · (no such step) — _anon" in md
    assert "late note" in md


def test_srt_cues_are_numbered_and_timed():
    srt = ax.to_srt(_goal(), _events(), _notes())
    blocks = srt.strip().split("\n\n")
    assert blocks[0].splitlines() == [
        "1", "00:00:12,000 --> 00:00:15,000", "[user:amy] this is where it diverged",
    ]
    assert blocks[1].splitlines()[0] == "2"
    assert "00:01:15,000 --> 00:01:18,000" in blocks[1]


def test_srt_clock_zero_uses_earliest_of_created_and_first_event():
    # Goal row created AFTER its first event (clock skew): offsets clamp >= 0.
    srt = ax.to_srt(_goal(created_at=1005.0), _events(), [{"seq": 0, "note": "n"}])
    assert "00:00:00,000 --> 00:00:03,000" in srt


def test_export_reads_shared_store_and_validates(tmp_path):
    import maverick.ux_store as ux
    ux.reset_shared()
    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("run with notes", "")
    w.append_event(gid, "planner", "plan", "step zero")
    ux.shared().annotate(gid, 0, "kickoff looked wrong", author="user:amy")
    try:
        md = ax.export_annotations(w, gid, "markdown")
        assert "kickoff looked wrong" in md and "step 0" in md
        srt = ax.export_annotations(w, gid, "srt")
        assert srt.splitlines()[0] == "1"
        with pytest.raises(ValueError, match="no such goal"):
            ax.export_annotations(w, 999, "markdown")
        with pytest.raises(ValueError, match="unknown format"):
            ax.export_annotations(w, gid, "vtt")
    finally:
        ux.reset_shared()
        w.close()


def test_export_accepts_injected_annotations(tmp_path):
    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("quiet run", "")
    try:
        out = ax.export_annotations(w, gid, "srt", annotations=[{"seq": 0, "note": "hi"}])
        assert "[_anon] hi" in out
    finally:
        w.close()


def test_cli_prints_markdown_and_handles_unknown_goal(tmp_path, capsys):
    import maverick.ux_store as ux
    ux.reset_shared()
    db = tmp_path / "world.db"
    w = WorldModel(db)
    gid = w.create_goal("cli run", "")
    w.append_event(gid, "coder", "tool", "ls -la")
    ux.shared().annotate(gid, 0, "note via cli")
    w.close()
    try:
        assert ax.main([str(gid), "--db", str(db)]) == 0
        out = capsys.readouterr().out
        assert "note via cli" in out and "cli run" in out
        assert ax.main([str(gid), "--db", str(db), "--format", "srt"]) == 0
        assert "-->" in capsys.readouterr().out
        assert ax.main(["999", "--db", str(db)]) == 2
        assert "no such goal" in capsys.readouterr().out
    finally:
        ux.reset_shared()
