"""Graceful-shutdown drain: in-flight goal accounting + bounded drain."""
from __future__ import annotations

import time

from maverick import runner


def test_inflight_reflects_held_slots():
    assert runner.inflight_goals() == 0
    runner._mark_inflight_started()
    try:
        assert runner.inflight_goals() == 1
    finally:
        runner._mark_inflight_finished()
    assert runner.inflight_goals() == 0


def test_drain_returns_immediately_when_idle():
    t0 = time.monotonic()
    left = runner.drain_inflight(timeout=5.0)
    assert left == 0
    assert time.monotonic() - t0 < 1.0  # didn't wait out the timeout


def test_drain_times_out_with_a_held_slot():
    runner._mark_inflight_started()
    try:
        t0 = time.monotonic()
        left = runner.drain_inflight(timeout=0.3, poll=0.05)
        elapsed = time.monotonic() - t0
        assert left == 1                # slot never freed -> reported still in-flight
        assert 0.25 <= elapsed < 2.0    # waited ~the timeout, then gave up
    finally:
        runner._mark_inflight_finished()


def test_drain_unblocks_when_slot_released(monkeypatch):
    import threading

    runner._mark_inflight_started()

    def _release_soon():
        time.sleep(0.2)
        runner._mark_inflight_finished()

    threading.Thread(target=_release_soon, daemon=True).start()
    left = runner.drain_inflight(timeout=5.0, poll=0.05)
    assert left == 0  # drained once the slot was released, well under the timeout


def test_inflight_accounting_never_goes_negative(caplog):
    assert runner.inflight_goals() == 0
    runner._mark_inflight_finished()
    assert runner.inflight_goals() == 0
    assert "underflow" in caplog.text


def test_shutdown_racing_with_slot_admission_does_not_start_an_orphan_goal(monkeypatch):
    releases = []

    class Lane:
        def acquire(self, *, timeout):
            return True

        def release(self):
            releases.append("principal")

    class Global:
        def acquire(self, *, timeout):
            runner.close_goal_admission()  # drain wins after slots were requested
            return True

        def release(self):
            releases.append("global")

    monkeypatch.setattr(runner, "_principal_semaphore", lambda _principal: Lane())
    monkeypatch.setattr(runner, "_run_semaphore", Global())
    assert runner.run_goal_in_thread(123, acquire_timeout=0) is None
    assert releases == ["global", "principal"]
    assert runner.inflight_goals() == 0 and not runner._accepting_goals
    runner.open_goal_admission()
    assert runner._accepting_goals


def test_a_shutdown_stops_the_runs_it_abandons_at_once(tmp_path, monkeypatch):
    # After the drain runs out, the goals this process still runs are recorded
    # as stopped by the restart right away, instead of showing "Working" until
    # the next process's orphan window (a minute) passes.
    from maverick.stop_reasons import explain_stop
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr("maverick.world_model.open_world", lambda *a, **k: world)
    monkeypatch.setattr("maverick.world_model.close_world_if_owned", lambda w: None)
    running = world.create_goal("running here")
    world.set_goal_status(running, "active")
    queued = world.create_goal("queued here")
    elsewhere = world.create_goal("running in another process")
    world.set_goal_status(elsewhere, "active")
    finished = world.create_goal("finished just now")
    world.set_goal_status(finished, "done", result="all done")
    with runner._submitted_here(running), runner._submitted_here(queued), \
            runner._submitted_here(finished), runner._submitted_here(99, db_path=tmp_path / "other.db"):
        assert runner.stop_runs_interrupted_by_shutdown() == 2
    for goal_id in (running, queued):
        goal = world.get_goal(goal_id)
        assert goal.status == "blocked"
        assert explain_stop(goal.result, status="blocked").kind == "process_restart"
    assert world.get_goal(elsewhere).status == "active"   # not ours: the orphan window decides
    assert world.get_goal(finished).status == "done"
    assert runner.stop_runs_interrupted_by_shutdown() == 0  # nothing held any more


def test_a_world_reclaim_can_be_limited_to_named_goals(tmp_path):
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    mine, other = world.create_goal("mine"), world.create_goal("other")
    for goal_id in (mine, other):
        world.set_goal_status(goal_id, "active")
    assert world.reclaim_orphan_goals(statuses=("active", "pending"), resolved_window_seconds=0,
                                      goal_ids=[mine]) == 1
    assert world.get_goal(mine).status == "blocked" and world.get_goal(other).status == "active"
    assert world.reclaim_orphan_goals(resolved_window_seconds=0, goal_ids=[]) == 0
    assert world.get_goal(other).status == "active"
