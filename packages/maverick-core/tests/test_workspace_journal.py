"""Workspace mutation journal: pre-image capture at the file-tool chokepoint,
revert/diff, caps, strict mode, and revert-time path hardening.

The journal is opt-in and OFF by default, so the first test pins exactly that
(the whole suite runs with it off — a default-on journal would write to every
test's home). Config is injected by monkeypatching ``_workspace_cfg`` rather
than writing a real config.toml: the unit under test is the journal, not the
config loader.
"""
from __future__ import annotations

import json
import os

import pytest
from maverick import workspace_journal as wj
from maverick.tools import fs
from maverick.tools.fs import write_text_contained


class _SB:
    def __init__(self, workdir):
        self.workdir = str(workdir)


@pytest.fixture(autouse=True)
def _fresh_usage_cache():
    wj._reset_for_tests()
    yield
    wj._reset_for_tests()


@pytest.fixture
def workdir(tmp_path):
    wd = tmp_path / "ws"
    wd.mkdir()
    return wd.resolve()


@pytest.fixture
def journal_on(tmp_path, monkeypatch):
    """Enable the journal with its store under tmp; returns the store root."""
    root = tmp_path / "journal-store"
    monkeypatch.setenv("MAVERICK_WORKSPACE_JOURNAL", "1")
    monkeypatch.setattr(wj, "_workspace_cfg",
                        lambda: {"journal_dir": str(root)})
    return root


def _write(workdir, rel, content):
    sb = _SB(workdir)
    write_text_contained(sb, workdir / rel, content)


# ---- default posture ---------------------------------------------------------

def test_disabled_by_default_records_nothing(workdir, tmp_path, monkeypatch):
    root = tmp_path / "journal-store"
    monkeypatch.setattr(wj, "_workspace_cfg",
                        lambda: {"journal_dir": str(root)})
    monkeypatch.delenv("MAVERICK_WORKSPACE_JOURNAL", raising=False)
    _write(workdir, "a.txt", "hello")
    assert not root.exists()
    assert wj.list_entries("g1") == []


def test_env_zero_beats_config_on(workdir, tmp_path, monkeypatch):
    root = tmp_path / "journal-store"
    monkeypatch.setattr(wj, "_workspace_cfg",
                        lambda: {"journal": True, "journal_dir": str(root)})
    monkeypatch.setenv("MAVERICK_WORKSPACE_JOURNAL", "0")
    _write(workdir, "a.txt", "hello")
    assert not root.exists()


# ---- capture ----------------------------------------------------------------

def test_created_file_journaled_as_not_existed(workdir, journal_on):
    _write(workdir, "new.txt", "fresh")
    entries = wj.list_entries()
    assert len(entries) == 1
    assert entries[0]["existed"] is False
    assert entries[0]["path"] == "new.txt"
    assert entries[0]["blob"] is False


def test_overwrite_captures_prior_bytes(workdir, journal_on):
    (workdir / "a.txt").write_text("original")
    _write(workdir, "a.txt", "changed")
    entries = wj.list_entries()
    assert entries[0]["existed"] is True
    assert entries[0]["blob"] is True
    gdir = wj.goal_dir()
    assert (gdir / f"{entries[0]['seq']:06d}.pre").read_bytes() == b"original"


def test_goal_attribution_from_trace_context(workdir, journal_on, monkeypatch):
    from maverick import logging_config
    tokens = logging_config.set_goal_context(goal_id=77)
    try:
        _write(workdir, "a.txt", "x")
    finally:
        logging_config.reset_goal_context(tokens)
    assert wj.list_entries(77), "write inside a bound goal lands in goal-77"
    assert wj.goal_dir(77).name == "goal-77"


def test_all_editor_paths_share_the_chokepoint(workdir, journal_on):
    # str_replace_editor funnels through write_text_contained too — one entry
    # per mutation with the pre-image, no tool-specific wiring.
    from maverick.tools.str_edit import str_replace_editor
    (workdir / "code.py").write_text("x = 1\n")
    tool = str_replace_editor(_SB(workdir))
    out = tool.fn({"command": "str_replace", "path": "code.py",
                   "old_str": "x = 1", "new_str": "x = 2"})
    assert not out.startswith("ERROR"), out
    entries = wj.list_entries()
    assert len(entries) == 1
    assert entries[0]["pre_sha256"]


# ---- revert -----------------------------------------------------------------

def test_revert_restores_pre_run_state(workdir, journal_on):
    (workdir / "a.txt").write_text("A0")
    _write(workdir, "a.txt", "A1")
    _write(workdir, "a.txt", "A2")     # multi-write: revert must land on A0
    _write(workdir, "made.txt", "new")  # created: revert must delete
    res = wj.revert_goal()
    assert res["reverted"] >= 1 and res["deleted"] == 1
    assert (workdir / "a.txt").read_text() == "A0"
    assert not (workdir / "made.txt").exists()
    # The journal archived itself: a second revert has nothing to replay.
    assert wj.revert_goal()["entries"] == 0


def test_dry_run_touches_nothing(workdir, journal_on):
    (workdir / "a.txt").write_text("keep")
    _write(workdir, "a.txt", "changed")
    res = wj.revert_goal(dry_run=True)
    assert res["dry_run"] is True and res["reverted"] == 1
    assert (workdir / "a.txt").read_text() == "changed"
    assert wj.list_entries(), "dry run must not archive the journal"


def test_revert_refuses_tampered_traversal_path(workdir, journal_on, tmp_path):
    _write(workdir, "a.txt", "x")
    gdir = wj.goal_dir()
    meta = next(gdir.glob("*.json"))
    entry = json.loads(meta.read_text())
    entry["path"] = "../../outside.txt"
    entry["existed"] = False  # would unlink outside the workspace
    meta.write_text(json.dumps(entry))
    outside = workdir.parent / "outside.txt"
    outside.write_text("safe")
    res = wj.revert_goal()
    assert outside.read_text() == "safe"
    assert res["skipped"] == 1


def test_revert_refuses_restore_through_symlink(workdir, journal_on, tmp_path):
    (workdir / "a.txt").write_text("orig")
    _write(workdir, "a.txt", "changed")
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    (workdir / "a.txt").unlink()
    try:
        (workdir / "a.txt").symlink_to(victim)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege is unavailable")
        raise
    res = wj.revert_goal()
    assert victim.read_text() == "untouched"
    assert res["skipped"] == 1


# ---- caps + strict ----------------------------------------------------------

def test_entry_cap_marks_journal_incomplete(workdir, journal_on, monkeypatch):
    monkeypatch.setattr(
        wj, "_workspace_cfg",
        lambda: {"journal_dir": str(journal_on), "journal_max_entries": 1})
    _write(workdir, "a.txt", "1")
    _write(workdir, "b.txt", "2")   # over the cap: not journaled, CAP marker
    assert wj.is_capped()
    assert len(wj.list_entries()) == 1
    with pytest.raises(ValueError, match="incomplete"):
        wj.revert_goal()
    res = wj.revert_goal(partial=True)
    assert res["complete"] is False
    assert not (workdir / "a.txt").exists()


def test_oversized_pre_image_skipped_and_partial_revert(workdir, journal_on,
                                                        monkeypatch):
    monkeypatch.setattr(
        wj, "_workspace_cfg",
        lambda: {"journal_dir": str(journal_on), "journal_max_file_mb": 1})
    big = workdir / "big.bin"
    big.write_bytes(b"x" * (1024 * 1024 + 1))
    _write(workdir, "big.bin", "small now")
    entries = wj.list_entries()
    assert entries[0]["skipped_reason"] == "too_large"
    with pytest.raises(ValueError):
        wj.revert_goal()
    assert wj.revert_goal(partial=True)["skipped"] == 1


def test_strict_mode_refuses_write_when_journal_full(workdir, journal_on,
                                                     monkeypatch):
    monkeypatch.setattr(
        wj, "_workspace_cfg",
        lambda: {"journal_dir": str(journal_on), "journal_max_entries": 1,
                 "journal_strict": True})
    _write(workdir, "a.txt", "1")
    tool = fs.write_file(_SB(workdir))
    out = tool.fn({"path": "b.txt", "content": "2"})
    assert out.startswith("ERROR"), out
    assert "journal" in out
    assert not (workdir / "b.txt").exists(), "strict refusal must precede the write"
    # The guarantee must not lapse after the first cap trip: with the cap
    # marker already on disk, the NEXT write is refused too.
    out2 = tool.fn({"path": "c.txt", "content": "3"})
    assert out2.startswith("ERROR"), out2
    assert not (workdir / "c.txt").exists()


def test_failure_is_open_by_default(workdir, journal_on, monkeypatch):
    # A broken journal store must not block the agent's write (default posture).
    monkeypatch.setattr(wj, "_record_inner",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    tool = fs.write_file(_SB(workdir))
    out = tool.fn({"path": "ok.txt", "content": "fine"})
    assert out.startswith("wrote"), out
    assert (workdir / "ok.txt").read_text() == "fine"


# ---- diff -------------------------------------------------------------------

def test_diff_shows_pre_vs_now(workdir, journal_on):
    (workdir / "a.txt").write_text("old line\n")
    _write(workdir, "a.txt", "new line\n")
    d = wj.diff_goal()
    assert "-old line" in d and "+new line" in d
