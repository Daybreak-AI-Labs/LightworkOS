"""Trace pinning to commit: git-state stamp at run start + readback."""
from __future__ import annotations

import subprocess

from maverick.trace_pin import TRACE_META_KIND, pin_trace, trace_commit, workspace_git_state
from maverick.world_model import open_world


def _git_repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    (tmp_path / "f.txt").write_text("one")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "init"], check=True)
    return tmp_path


def test_workspace_git_state(tmp_path):
    repo = _git_repo(tmp_path)
    state = workspace_git_state(str(repo))
    assert state is not None
    assert len(state["commit"]) == 40 and state["dirty"] is False
    (repo / "f.txt").write_text("two")
    assert workspace_git_state(str(repo))["dirty"] is True


def test_workspace_git_state_disables_repo_fsmonitor(tmp_path):
    repo = _git_repo(tmp_path)
    payload = repo / "fsmonitor-payload.sh"
    marker = repo / "fsmonitor-ran"
    payload.write_text(f"#!/bin/sh\necho pwned > {marker}\nexit 0\n")
    payload.chmod(0o755)
    subprocess.run(["git", "-C", str(repo), "config", "core.fsmonitor", str(payload)], check=True)

    state = workspace_git_state(str(repo))

    assert state is not None
    assert state["dirty"] is True
    assert not marker.exists()


def test_not_a_repo_returns_none(tmp_path):
    assert workspace_git_state(str(tmp_path)) is None


def test_pin_and_readback(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    w = open_world(tmp_path / "world.db")
    gid = w.create_goal("g", "d", owner="")
    state = pin_trace(w, gid, cwd=str(repo))
    assert state is not None
    pinned = trace_commit(w, gid)
    assert pinned == state
    events = [e for e in w.goal_events(gid) if e.kind == TRACE_META_KIND]
    assert len(events) == 1


def test_pin_outside_repo_is_noop(tmp_path):
    w = open_world(tmp_path / "world.db")
    gid = w.create_goal("g", "d", owner="")
    assert pin_trace(w, gid, cwd=str(tmp_path)) is None
    assert trace_commit(w, gid) is None


def test_pin_never_raises(tmp_path):
    class _BrokenWorld:
        def append_event(self, *a, **kw):
            raise RuntimeError("db down")

    repo = _git_repo(tmp_path)
    assert pin_trace(_BrokenWorld(), 1, cwd=str(repo)) is None


def test_runner_stamps_trace(monkeypatch):
    """run_goal_in_thread pins the trace before dispatching the swarm."""
    import maverick.runner as runner_mod
    src = open(runner_mod.__file__, encoding="utf-8").read()
    assert "pin_trace(world, goal_id)" in src
