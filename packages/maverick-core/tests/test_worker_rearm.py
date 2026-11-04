"""Durable, idempotent cron re-arm for the job worker.

A recurring CLI schedule (``maverick schedule goal``) carries its cron
expression in ``payload['__cron__']``; the worker enqueues the next occurrence
when it runs the current one. A re-arm that armed exactly once (on
``attempts == 1``) and swallowed any enqueue error would let a single transient
``database is locked`` -- or a crash between claim-commit and re-arm -- silently
and permanently kill the schedule (a ``done`` row with no successor and no
signal). These tests pin the contract: re-arm is retryable across
attempts, idempotent (never a duplicate successor), and surfaces a persistent
failure as a visible ``failed`` row instead of a dropped schedule.
"""
from __future__ import annotations

import sqlite3

CRON = "*/5 * * * *"


def _cron_successors(q, parent_id):
    """Pending cron jobs other than the parent -- i.e. armed successors."""
    return [j for j in q.list(status="pending")
            if j.payload.get("__cron__") and j.id != parent_id]


def test_transient_rearm_failure_is_retried_not_permanently_dead(tmp_path, monkeypatch):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    real = JobQueue._advance_recurrence
    calls = {"n": 0}

    def flaky(queue, connection, row, *, now):
        calls["n"] += 1
        if calls["n"] == 1:
            raise sqlite3.OperationalError("database is locked")
        return real(queue, connection, row, now=now)

    monkeypatch.setattr(JobQueue, "_advance_recurrence", flaky)

    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("noop", {"__cron__": CRON}, run_at=1000.0)
    w = Worker(queue=q, idle_sleep=0.0, retry_after=0.0)
    w.register("noop", lambda job: None)

    # Attempt 1: the re-arm enqueue fails transiently. The job must NOT slip to
    # 'done' with a lost schedule -- it is requeued and no successor exists yet.
    assert w.run_once() is True
    job = q.get(jid)
    assert job.status == "pending"          # requeued, not silently completed
    assert job.attempts == 1
    assert _cron_successors(q, jid) == []   # schedule not yet re-armed...

    # Attempt 2: re-arm now succeeds -> the schedule is alive again.
    assert w.run_once() is True
    assert q.get(jid).status == "done"
    assert len(_cron_successors(q, jid)) == 1  # ...but not permanently lost
    assert calls["n"] == 2


def test_rearm_across_multiple_attempts_makes_no_duplicate_successor(tmp_path):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("boom", {"__cron__": CRON}, run_at=1000.0)

    def _boom(job):
        raise RuntimeError("handler always fails")

    # The handler always fails so the job is re-claimed several times; re-arm
    # runs (or is short-circuited by the durable marker) on each attempt but must
    # arm exactly one successor -- no duplicates from the retryable path.
    w = Worker(queue=q, idle_sleep=0.0, retry_after=0.0, max_attempts=10)
    w.register("boom", _boom)
    for _ in range(3):
        assert w.run_once() is True

    assert q.get(jid).attempts == 3
    assert len(_cron_successors(q, jid)) == 1


def test_persistent_rearm_failure_is_surfaced_as_failed_row(tmp_path, monkeypatch):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    def always_fail(queue, connection, row, *, now):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(JobQueue, "_advance_recurrence", always_fail)

    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("noop", {"__cron__": CRON}, run_at=1000.0)
    w = Worker(queue=q, idle_sleep=0.0, retry_after=0.0, max_attempts=2)
    w.register("noop", lambda job: None)

    assert w.run_once() is True     # attempt 1: re-arm fails -> requeued
    assert q.get(jid).status == "pending"
    assert w.run_once() is True     # attempt 2: hits max_attempts -> dead-letter

    job = q.get(jid)
    assert job.status == "failed"                 # visible, not swallowed
    assert "re-arm" in job.last_error.lower()     # the reason is recorded
    assert _cron_successors(q, jid) == []


def test_rearm_persists_marker_and_strips_it_from_successor(tmp_path):
    # White-box: the durable marker lands on the parent (so a retry short-
    # circuits) and is stripped from the successor (so it can arm its own).
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("noop", {"__cron__": CRON}, run_at=1000.0)
    w = Worker(queue=q, idle_sleep=0.0)
    w.register("noop", lambda job: None)
    assert w.run_once() is True

    parent = q.get(jid)
    assert parent.status == "done"
    assert parent.payload.get("__rearmed__") is True
    successors = _cron_successors(q, jid)
    assert len(successors) == 1
    assert "__rearmed__" not in successors[0].payload


def test_distinct_schedules_sharing_cron_keep_own_successors(tmp_path):
    # Two schedules with the same cron expr but different payloads must NOT
    # dedup each other -- the idempotency guard keys on kind + payload identity.
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    q = JobQueue(db_path=tmp_path / "jobs.db")
    a = q.enqueue("run_goal", {"goal_id": 5, "__cron__": CRON}, run_at=1000.0)
    b = q.enqueue("run_goal", {"goal_id": 6, "__cron__": CRON}, run_at=1000.0)
    w = Worker(queue=q, idle_sleep=0.0)
    w.register("run_goal", lambda job: None)

    assert w.run_once() is True   # runs + re-arms one of them
    assert w.run_once() is True   # runs + re-arms the other

    successors = [j for j in q.list(status="pending")
                  if j.payload.get("__cron__") and j.id not in (a, b)]
    goal_ids = sorted(j.payload["goal_id"] for j in successors)
    assert goal_ids == [5, 6]     # both schedules re-armed independently
