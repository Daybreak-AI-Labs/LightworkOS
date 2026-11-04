"""Tests for the persistent job queue (maverick.job_queue), including attempt
fencing on complete() and fail().
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

from maverick.job_queue import JobQueue


def _q():
    d = tempfile.mkdtemp()
    return JobQueue(db_path=Path(d) / "jobs.db")


def test_stale_complete_does_not_clobber_reclaimed_job():
    q = _q()
    q.enqueue("k", {"x": 1}, run_at=100.0)
    a = q.claim(now=100.0)          # worker A, attempts=1
    assert a is not None
    assert q.reclaim_stale(0, now=100.0) == 1
    b = q.claim(now=100.0)          # worker B re-claims, attempts=2
    assert b is not None
    assert a.attempts != b.attempts
    # A finished late; its fenced completion must be rejected.
    assert q.complete(a.id, expected_attempts=a.attempts) is False
    # B, the current owner, completes successfully.
    assert q.complete(b.id, expected_attempts=b.attempts) is True


def test_stale_fail_does_not_reschedule_reclaimed_job():
    q = _q()
    q.enqueue("k", {}, run_at=100.0)
    a = q.claim(now=100.0)
    assert a is not None
    assert q.reclaim_stale(0, now=100.0) == 1
    b = q.claim(now=100.0)
    assert b is not None
    assert q.fail(a.id, "boom", expected_attempts=a.attempts) is False
    assert q.fail(b.id, "boom", expected_attempts=b.attempts) is True


def test_fence_is_opt_in_unfenced_callers_unaffected():
    q = _q()
    q.enqueue("k", {})
    a = q.claim()
    # No expected_attempts -> legacy behaviour (completes regardless).
    assert q.complete(a.id) is True


# ---------- Job queue ----------

def test_job_queue_enqueue_claim_complete(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("run_goal", {"goal_id": 7})
    assert jid > 0

    job = q.claim()
    assert job is not None
    assert job.kind == "run_goal"
    assert job.payload == {"goal_id": 7}
    assert job.status == "running"
    assert job.attempts == 1

    assert q.complete(jid) is True
    fetched = q.get(jid)
    assert fetched is not None
    assert fetched.status == "done"


def test_job_queue_claim_returns_none_when_empty(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    assert q.claim() is None


def test_job_queue_respects_run_at(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    future = time.time() + 60
    jid = q.enqueue("later", {}, run_at=future)
    # Nothing ready yet.
    assert q.claim() is None
    # Simulate clock moving forward.
    job = q.claim(now=future + 1)
    assert job is not None and job.id == jid


def test_job_queue_fail_reschedules(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("flaky", {})
    job = q.claim()
    assert job is not None

    q.fail(jid, "transient", retry_after=0, max_attempts=3)
    j2 = q.get(jid)
    assert j2.status == "pending"
    assert j2.attempts == 1
    assert "transient" in j2.last_error

    # Re-claim works after the reschedule.
    re = q.claim()
    assert re is not None and re.id == jid
    assert re.attempts == 2


def test_job_queue_fail_terminal_after_max(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("doomed", {})
    # Cycle: claim, fail with retry, claim, fail with retry, ... until max.
    for _ in range(3):
        q.claim()
        q.fail(jid, "boom", retry_after=0, max_attempts=3)
    # Next fail (now 4th attempt) should mark failed.
    q.claim()
    q.fail(jid, "boom-final", retry_after=0, max_attempts=3)
    final = q.get(jid)
    assert final.status == "failed"
    assert "boom-final" in final.last_error


def test_job_queue_list_filters_status(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    a = q.enqueue("a", {})
    b = q.enqueue("b", {})
    q.claim()  # makes one running
    pending = q.list(status="pending")
    pending_ids = {j.id for j in pending}
    # exactly one of {a,b} is still pending
    assert len(pending_ids & {a, b}) == 1


def test_job_queue_purge_removes_done(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("ephemeral", {})
    q.claim()
    q.complete(jid)
    # Backdate the updated_at so purge can see it.
    import sqlite3
    with sqlite3.connect(str(q.db_path)) as c:
        c.execute(
            "UPDATE jobs SET updated_at=? WHERE id=?",
            (time.time() - 365 * 86400, jid),
        )
    deleted = q.purge(older_than_days=30)
    assert deleted == 1
    assert q.get(jid) is None
