"""In-process wake-ups after a goal's stored state changes (timing only).

The chat page's event stream re-read the database on a timer that backed off
to two seconds while a model call ran, so a finished answer reached the page
about 1.2 s after it was saved. Writes now wake its watchers, after the commit.
"""
from __future__ import annotations

import sqlite3

import pytest
from maverick import goal_wakeup, world_model


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    path = tmp_path / "w.db"
    wm = world_model.WorldModel(path)
    return wm, path, wm.create_goal("task", "")


def _watch(path, goal_id, wake):
    key = goal_wakeup.world_key(path)
    token = goal_wakeup.watch(key, goal_id, wake)
    return lambda: goal_wakeup.unwatch(key, goal_id, token)


def _committed_events(path, goal_id):
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT COUNT(*) FROM goal_events WHERE goal_id=?", (goal_id,)).fetchone()[0]


def test_each_watched_write_wakes_after_its_commit(world):
    wm, path, gid = world
    seen = []
    stop = _watch(path, gid, lambda: seen.append(_committed_events(path, gid)))
    try:
        wm.append_event(gid, "agent", "plan", "first step")
        assert seen == [1], "woken after the row is visible to another connection"
        assert wm.set_goal_partial_result(gid, "the answer so far")
        wm.set_goal_status(gid, "done", "the answer")
        assert len(seen) == 3
        assert wm.set_goal_partial_result(gid, "too late") is False
        assert len(seen) == 3, "a write that changed nothing wakes nothing"
    finally:
        stop()
    wm.append_event(gid, "agent", "plan", "after")
    assert len(seen) == 3, "a goal no one watches wakes nothing"
    assert (goal_wakeup.world_key(path), gid) not in goal_wakeup._watchers


def test_a_nested_write_wakes_when_the_outer_transaction_commits(world):
    wm, path, gid = world
    seen = []
    stop = _watch(path, gid, lambda: seen.append(1))
    try:
        with wm._writing():
            wm.append_event(gid, "agent", "plan", "one")
            wm.append_event(gid, "agent", "plan", "two")
            assert seen == [], "nothing is committed yet"
        assert seen == [1], "one wake for the transaction"
    finally:
        stop()


def test_a_rolled_back_write_wakes_nothing(world):
    wm, path, gid = world
    seen = []
    stop = _watch(path, gid, lambda: seen.append(1))
    try:
        with pytest.raises(RuntimeError), wm._writing():
            wm.append_event(gid, "agent", "plan", "discarded")
            raise RuntimeError("abandon")
        assert seen == [] and _committed_events(path, gid) == 0
        other = wm.create_goal("another task", "")
        wm.append_event(other, "agent", "plan", "elsewhere")
        assert seen == [], "the discarded change is not announced by the next commit"
        wm.append_event(gid, "agent", "plan", "kept")
        assert seen == [1]
    finally:
        stop()


def test_the_same_id_in_another_world_wakes_nothing(world, tmp_path):
    wm, path, gid = world
    other = world_model.WorldModel(tmp_path / "other.db")
    other_gid = other.create_goal("other task", "")
    assert other_gid == gid
    seen = []
    stop = _watch(path, gid, lambda: seen.append(1))
    try:
        other.append_event(other_gid, "agent", "plan", "elsewhere")
        assert seen == []
    finally:
        stop()


def test_a_failing_watcher_never_fails_the_write(world):
    wm, path, gid = world

    def broken():
        raise RuntimeError("event loop closed")

    stop = _watch(path, gid, broken)
    try:
        event_id = wm.append_event(gid, "agent", "plan", "still saved")
        assert event_id and _committed_events(path, gid) == 1
    finally:
        stop()


def test_a_write_nobody_watches_does_no_wake_up_work(world, monkeypatch):
    wm, path, gid = world
    monkeypatch.setattr(goal_wakeup, "_watchers", {})
    monkeypatch.setattr(goal_wakeup, "world_key", lambda _path: pytest.fail("resolved a path nobody watches"))
    monkeypatch.setattr(goal_wakeup, "notify", lambda *_a: pytest.fail("announced a change nobody watches"))
    wm.append_event(gid, "agent", "plan", "unwatched")
    wm.set_goal_status(gid, "done", "the answer")
    assert _committed_events(path, gid) == 1
