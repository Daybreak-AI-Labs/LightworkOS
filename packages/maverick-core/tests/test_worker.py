"""Tests for the job-queue worker (maverick.worker)."""
from __future__ import annotations

import time

# --- the worker must not mark a CRASHED goal as a done job, but must
# also NOT retry a deliberately-stopped ('blocked') goal (budget cap /
# killswitch / awaiting-user) -- retrying re-runs the whole swarm, re-spends
# budget, and defeats the killswitch. run_goal_in_thread returns 'error' for a
# genuine crash (retryable) and 'blocked' for a deliberate stop (terminal). ---

def test_worker_marks_crashed_goal_as_failed_job(tmp_path, monkeypatch):
    import maverick.runner as runner
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    monkeypatch.setattr(runner, "run_goal_in_thread", lambda gid, **k: "error")
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q, retry_after=0.0, max_attempts=1)
    jid = q.enqueue("run_goal", {"goal_id": 1})
    assert w.run_once() is True
    # max_attempts=1 -> the single failure is terminal: 'failed', NOT 'done'.
    assert q.get(jid).status == "failed"


def test_worker_does_not_retry_deliberately_blocked_goal(tmp_path, monkeypatch):
    import maverick.runner as runner
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    # 'blocked' = budget cap / killswitch / awaiting user -- a deliberate stop.
    monkeypatch.setattr(runner, "run_goal_in_thread", lambda gid, **k: "blocked")
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q, retry_after=0.0, max_attempts=5)
    jid = q.enqueue("run_goal", {"goal_id": 1})
    assert w.run_once() is True
    # The job is completed (not requeued) so the swarm is not re-run / re-spent.
    assert q.get(jid).status == "done"


def test_worker_defers_when_goal_could_not_start(tmp_path, monkeypatch):
    """A missing concurrency slot must not be treated like a crashed
    handler. Re-raising through fail() would bump the SAME row toward
    max_attempts and eventually dead-letter a goal that never even started;
    deferring to a fresh job lets the original complete normally."""
    import time

    import maverick.runner as runner
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    # The detailed outcome names a refused concurrency slot explicitly; a bare
    # None now means "outcome unconfirmed" and is never deferred or replayed.
    monkeypatch.setattr(runner, "run_goal_in_thread",
                        lambda gid, **k: runner.GoalRunUnavailable("concurrency_slot"))
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q, retry_after=0.0, max_attempts=5)
    now = time.time()
    jid = q.enqueue("run_goal", {"goal_id": 1})
    w.run_once()
    # The original job completes (not requeued in place)...
    assert q.get(jid).status == "done"
    # ...and a deferred successor carries the retry, with its own bounded
    # defer counter -- not job_queue's attempts/dead-letter mechanism.
    pending = q.list(status="pending", limit=10)
    assert len(pending) == 1
    assert pending[0].payload["goal_id"] == 1
    assert pending[0].payload["_slot_defers"] == 1
    assert pending[0].run_at > now  # scheduled into the future, not immediate


def test_worker_gives_up_after_defer_budget_exhausted(tmp_path, monkeypatch):
    """Once MAVERICK_GOAL_SLOT_MAX_DEFERS deferrals are spent, a persistent
    'no slot' outcome must still surface as a job failure eventually."""
    import maverick.runner as runner
    import maverick.worker as worker_mod
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    monkeypatch.setattr(runner, "run_goal_in_thread",
                        lambda gid, **k: runner.GoalRunUnavailable("concurrency_slot"))
    monkeypatch.setattr(worker_mod, "_MAX_GOAL_SLOT_DEFERS", 2)
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q, retry_after=0.0, max_attempts=5)
    jid = q.enqueue("run_goal", {"goal_id": 1, "_slot_defers": 2})
    w.run_once()
    # Defer budget already spent -> the job stops with a plain reason instead
    # of automatically retrying, and no successor is created.
    job = q.get(jid)
    assert job.status != "pending" and job.status != "done"
    assert "concurrency slot" in (job.last_error or "")
    assert q.list(status="pending", limit=10) == []


def test_worker_never_replays_an_unconfirmed_goal_outcome(tmp_path, monkeypatch):
    import maverick.runner as runner
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    monkeypatch.setattr(runner, "run_goal_in_thread", lambda gid, **k: None)
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q, retry_after=0.0, max_attempts=5)
    jid = q.enqueue("run_goal", {"goal_id": 1})
    w.run_once()
    assert q.get(jid).status not in ("pending", "done")
    assert q.list(status="pending", limit=10) == []


def test_worker_completes_when_goal_done(tmp_path, monkeypatch):
    import maverick.runner as runner
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    monkeypatch.setattr(runner, "run_goal_in_thread", lambda gid, **k: "done")
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q)
    jid = q.enqueue("run_goal", {"goal_id": 1})
    assert w.run_once() is True
    assert q.get(jid).status == "done"


# ---------- Worker daemon ----------

def test_worker_runs_one_job(tmp_path):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    q = JobQueue(db_path=tmp_path / "jobs.db")
    seen: list[int] = []

    def _handler(job):
        seen.append(int(job.payload.get("n", 0)))

    w = Worker(queue=q, idle_sleep=0.0)
    w.register("noop", _handler)

    jid = q.enqueue("noop", {"n": 7})
    assert w.run_once() is True
    assert seen == [7]
    job = q.get(jid)
    assert job.status == "done"


def test_worker_empty_queue_returns_false(tmp_path):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q)
    assert w.run_once() is False


def test_worker_no_handler_terminal(tmp_path):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q)
    jid = q.enqueue("nonexistent", {})
    assert w.run_once() is True
    job = q.get(jid)
    assert job.status == "failed"
    assert "no handler" in job.last_error


def test_worker_handler_exception_reschedules(tmp_path):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q, retry_after=0.0, max_attempts=3)

    def _boom(job):
        raise RuntimeError("kaboom")

    w.register("flaky", _boom)
    jid = q.enqueue("flaky", {})
    w.run_once()  # first attempt fails, reschedules
    job = q.get(jid)
    assert job.status == "pending"
    assert job.attempts == 1
    assert "kaboom" in job.last_error


def test_worker_handler_exception_terminal_after_max(tmp_path):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q, retry_after=0.0, max_attempts=2)

    def _boom(job):
        raise RuntimeError("perma-fail")

    w.register("doomed", _boom)
    jid = q.enqueue("doomed", {})
    for _ in range(5):
        if not w.run_once():
            break
    job = q.get(jid)
    assert job.status == "failed"
    assert "perma-fail" in job.last_error


def test_worker_run_forever_stop_is_clean(tmp_path):
    """run_forever must exit promptly when stop() is called."""
    import threading

    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q, idle_sleep=0.05)

    t = threading.Thread(target=w.run_forever, daemon=True)
    t.start()
    time.sleep(0.1)
    w.stop()
    t.join(timeout=2.0)
    assert not t.is_alive()
