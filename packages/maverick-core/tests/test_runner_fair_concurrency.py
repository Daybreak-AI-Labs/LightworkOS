"""Fair, two-level concurrency: per-user lanes under a global ceiling.

Proves the guarantee behind "multiple people can run the same fleet at once" —
one principal filling its own lane never blocks another principal's run; only a
host-wide ceiling queues anyone.
"""
from __future__ import annotations

import threading
import time

import pytest
from maverick import runner
from maverick.budget import Budget


@pytest.fixture(autouse=True)
def _reset_lanes(monkeypatch):
    # Small per-user lane for a fast, deterministic test; fresh lane registry.
    monkeypatch.setattr(runner, "MAX_CONCURRENT_GOALS_PER_PRINCIPAL", 2)
    monkeypatch.setattr(runner, "_principal_sems", {})
    yield


def test_principal_semaphore_is_per_principal():
    a1 = runner._principal_semaphore("user:alice")
    a2 = runner._principal_semaphore("user:alice")
    b = runner._principal_semaphore("user:bob")
    assert a1 is a2 and a1 is not b
    # None / anon collapse to one shared lane.
    assert runner._principal_semaphore(None) is runner._principal_semaphore("")


def _stub_run(monkeypatch, tmp_path, *, gate: threading.Event, started: dict):
    """Stub run_goal_in_thread's heavy deps; run_goal_sync blocks on ``gate``."""
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    world = WorldModel(db)
    for owner in ("user:alice", "user:alice", "user:alice", "user:bob"):
        world.create_goal("fixture task", owner=owner, execution_principal=owner)
    world.close()

    class _Sandbox:
        def close(self):
            pass

    monkeypatch.setattr("maverick.world_model.open_world", lambda *a, **k: WorldModel(db))
    monkeypatch.setattr("maverick.llm.LLM", lambda *a, **k: object())
    monkeypatch.setattr("maverick.sandbox.build_sandbox", lambda *a, **k: _Sandbox())
    monkeypatch.setattr("maverick.budget.budget_from_config",
                        lambda *a, **k: Budget())
    monkeypatch.setattr("maverick.trace_pin.pin_trace", lambda *a, **k: None)

    def _blocking_run(llm, world, budget, goal_id, **kw):
        started.setdefault(kw.get("user_id"), []).append(goal_id)
        gate.wait(timeout=5.0)
        world.set_goal_status(goal_id, "done")

    monkeypatch.setattr("maverick.orchestrator.run_goal_sync", _blocking_run)


def test_one_user_full_lane_does_not_block_another(monkeypatch, tmp_path):
    gate = threading.Event()
    started: dict = {}
    _stub_run(monkeypatch, tmp_path, gate=gate, started=started)

    threads = []

    def fire(user_id, goal_id):
        thread = threading.Thread(
            target=runner.run_goal_in_thread,
            args=(goal_id,), kwargs={"user_id": user_id}, daemon=True,
        )
        threads.append(thread)
        thread.start()

    # Alice fills her lane (2) and queues a 3rd that must wait on HER lane.
    fire("alice", 1)
    fire("alice", 2)
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and len(started.get("alice", [])) < 2:
            time.sleep(0.02)
        assert len(started.get("alice", [])) == 2
        fire("alice", 3)
        # Bob must start while Alice's admitted workers still hold their lanes.
        fire("bob", 4)
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and "bob" not in started:
            time.sleep(0.02)
        assert started.get("bob") == [4], "Bob waited behind Alice — not fair"
        # Alice has exactly 2 running; her 3rd is parked on her own lane.
        assert len(started.get("alice", [])) == 2
    finally:
        gate.set()  # let every blocked run finish and release its permits
        for thread in threads:
            thread.join(timeout=10)
            assert not thread.is_alive()


# --- run_goal_in_thread must not block forever waiting for a slot ---

def test_runner_refuses_when_no_concurrency_slot(monkeypatch):
    import threading

    import maverick.runner as runner

    drained = threading.BoundedSemaphore(1)
    drained.acquire()  # 0 permits left
    monkeypatch.setattr(runner, "_run_semaphore", drained)
    monkeypatch.setattr(runner, "_ACQUIRE_TIMEOUT", 0.05)
    # Returns None promptly instead of wedging the caller forever.
    assert runner.run_goal_in_thread(999) is None


def test_run_goal_in_thread_acquire_timeout_override(monkeypatch):
    """An explicit acquire_timeout overrides the module default -- the
    knob the job-queue's run_goal/start_goal handlers use so a busy lane
    can't block a shared worker thread for the full 5-minute default."""
    import threading
    import time

    import maverick.runner as runner

    drained = threading.BoundedSemaphore(1)
    drained.acquire()  # 0 permits left
    monkeypatch.setattr(runner, "_principal_semaphore", lambda p: drained)
    # Leave the module default large so a bug that ignores the override
    # would make this test visibly hang/timeout rather than pass by luck.
    monkeypatch.setattr(runner, "_ACQUIRE_TIMEOUT", 30.0)

    t0 = time.monotonic()
    result = runner.run_goal_in_thread(999, acquire_timeout=0.05)
    elapsed = time.monotonic() - t0

    assert result is None
    assert elapsed < 5.0
