"""End-to-end proof of the control/data-plane split (#62 follow-through).

Real QueueDispatcher + SQLite JobQueue + Worker + shared WorldModel; only the
agent execution is stubbed at the LLM boundary."""
from __future__ import annotations

import pytest
from maverick import control_data_plane_e2e as e2e


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))


def test_split_holds_end_to_end(tmp_path):
    ev = e2e.run_e2e(tmp_path)
    assert ev["proof"]["ok"] is True
    # Control plane only enqueued — the goal was still pending after submit.
    assert ev["control_plane"]["submit_returned"] == "queued"
    assert ev["control_plane"]["goal_status_after_enqueue"] == "pending"
    assert ev["control_plane"]["job_kind"] == "run_goal"
    # Data plane claimed it out-of-band and the status flowed back through the
    # shared world DB.
    assert ev["data_plane"]["claimed"] is True
    assert ev["data_plane"]["goal_status_after_run"] == "done"


def test_real_worker_builtin_handler_path(tmp_path, monkeypatch):
    # Prove the worker's REAL builtin "run_goal" handler is what executes —
    # stub only run_goal_in_thread (the LLM boundary), and have it mutate the
    # shared world the way a real run would, so the default (un-registered)
    # execute path is exercised end-to-end.
    from maverick import runner
    from maverick.world_model import WorldModel

    seen = {}

    def fake_run_in_thread(goal_id, **kw):
        seen["goal_id"] = goal_id
        seen["user_id"] = kw.get("user_id")
        w = WorldModel(path=tmp_path / "world.db")
        try:
            w.set_goal_status(int(goal_id), "done", result="real handler")
        finally:
            w.conn.close()
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_thread", fake_run_in_thread)

    # execute=None -> run_e2e registers a handler; to exercise the BUILTIN
    # handler instead, route execution through run_goal_in_thread.
    def via_builtin(world_db, goal_id):
        runner.run_goal_in_thread(goal_id, user_id="e2e")

    ev = e2e.run_e2e(tmp_path, execute=via_builtin)
    assert ev["proof"]["ok"] is True
    assert seen["goal_id"] == ev["goal_id"]
    assert seen["user_id"] == "e2e"


def test_proof_fails_when_worker_never_runs(tmp_path):
    # Negative control: if the data-plane execution is a no-op, the goal never
    # reaches "done" and the proof must report failure (the harness can detect a
    # broken split, not just rubber-stamp).
    ev = e2e.run_e2e(tmp_path, execute=lambda world_db, goal_id: None)
    assert ev["proof"]["ok"] is False
    assert ev["proof"]["status_flowed_through_shared_world"] is False
    # The control-plane half still held: it enqueued and didn't execute.
    assert ev["proof"]["control_plane_did_not_execute"] is True
    assert ev["proof"]["enqueued_exactly_one_job"] is True
