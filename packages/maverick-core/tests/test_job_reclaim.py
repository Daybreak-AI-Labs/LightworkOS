"""Stale-job recovery for the persistent JobQueue.

A worker that claims a job and then dies hard (OOM / kill -9 / segfault)
never runs ``complete()`` or ``fail()``, so the row is stranded in
'running' forever -- ``claim()`` only ever picks 'pending' rows. The
``reclaim_stale`` helper (run on worker start) returns such jobs to the
queue, with a poison-pill cap so a job that keeps crashing the process is
eventually failed rather than requeued forever.
"""
from __future__ import annotations


def _running_job(q, *, at: float, attempts_via_claim: int = 1) -> int:
    """Enqueue a job and drive it into 'running' deterministically at time ``at``."""
    jid = q.enqueue("noop", {}, run_at=at)
    job = q.claim(now=at)
    assert job is not None and job.id == jid
    assert job.status == "running" and job.attempts == attempts_via_claim
    return jid


def test_reclaim_stale_requeues_orphaned_running(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = _running_job(q, at=1000.0)

    # Lease of 100s; "now" is 200s after the claim -> well past the lease.
    moved = q.reclaim_stale(100.0, now=1200.0)
    assert moved == 1

    job = q.get(jid)
    assert job.status == "pending"
    assert job.attempts == 1  # preserved, not reset

    # And it is claimable again.
    again = q.claim(now=1300.0)
    assert again is not None and again.id == jid
    assert again.attempts == 2


def test_reclaim_stale_leaves_fresh_running_alone(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = _running_job(q, at=1000.0)

    # Lease of 1000s; only 10s elapsed -> still within lease, untouched.
    moved = q.reclaim_stale(1000.0, now=1010.0)
    assert moved == 0
    assert q.get(jid).status == "running"


def test_reclaim_stale_fails_poison_job_at_max_attempts(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    # One claim -> attempts == 1; with max_attempts=1 it's already spent.
    jid = _running_job(q, at=1000.0)

    moved = q.reclaim_stale(100.0, now=1200.0, max_attempts=1)
    assert moved == 1
    job = q.get(jid)
    assert job.status == "failed"  # terminal, not requeued
    assert "lease expired" in job.last_error


def test_complete_does_not_clobber_self_reclaimed_job(tmp_path):
    """A slow worker's own reclaim_stale requeues its 'running' job to 'pending'
    WITHOUT bumping attempts. A late complete() with the original attempt count
    must NOT flip that requeued (pending) row to 'done' -- it has to be
    re-executed. Fenced on status='running', so the stale completion is a no-op.
    """
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = _running_job(q, at=1000.0)  # running, attempts == 1

    # The worker's periodic reclaim requeues its own long-running job.
    moved = q.reclaim_stale(100.0, now=1200.0)
    assert moved == 1
    assert q.get(jid).status == "pending" and q.get(jid).attempts == 1

    # The slow handler finally returns and completes at the attempt it claimed.
    assert q.complete(jid, expected_attempts=1) is False  # no-op, still pending
    assert q.get(jid).status == "pending"

    # And fail() on the stale lease must not reschedule/kill it either.
    assert q.fail(jid, "late failure", expected_attempts=1) is False
    assert q.get(jid).status == "pending"


def test_worker_reclaims_stale_jobs_on_start(tmp_path):
    """run_forever recovers a prior crash's orphaned job before draining."""
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    q = JobQueue(db_path=tmp_path / "jobs.db")
    # updated_at is set to this ancient timestamp, so against real wall-clock
    # "now" the job is far past any small lease.
    jid = _running_job(q, at=1000.0)

    w = Worker(queue=q, reclaim_lease=1.0, idle_sleep=0.0)
    w.stop()  # ensure the drain loop exits immediately after the reclaim
    w.run_forever()

    assert q.get(jid).status == "pending"


def test_worker_reclaims_peer_orphan_while_running(tmp_path):
    """A live daemon re-runs reclaim periodically, recovering a peer's orphan
    that appeared *after* startup -- not just the one-shot reclaim on start.

    Without the in-loop periodic reclaim, a job orphaned in 'running' by a
    crashed peer after this daemon started would stay stuck forever (claim()
    only picks 'pending' rows), so the no-op handler never runs and the job
    never reaches 'done'.
    """
    import sqlite3
    import threading
    import time

    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    q = JobQueue(db_path=tmp_path / "jobs.db")

    processed = threading.Event()

    w = Worker(queue=q, reclaim_lease=2.0, idle_sleep=0.02)
    w.register("recovered", lambda job: processed.set())

    t = threading.Thread(target=w.run_forever, daemon=True)
    t.start()
    try:
        # Daemon is up and past its startup reclaim. Now simulate a *peer*
        # worker that claimed this job and then hard-crashed: a row stuck in
        # 'running' with an ancient updated_at, well past the lease.
        #
        # We must NOT create it via q.claim() -- the live daemon races the main
        # thread for the same 'pending' row, so the claim is non-deterministic
        # (the flake this test used to hit). Instead: enqueue with a far-future
        # run_at so the daemon's claim() (which filters run_at <= now) never
        # touches the pending row, then stamp it straight into the orphaned
        # 'running' state with a direct write. reclaim_stale ignores run_at and
        # resets it to `now` when it requeues, so the daemon picks it up then.
        jid = q.enqueue("recovered", {}, run_at=1e12)
        con = sqlite3.connect(str(q.db_path))
        try:
            con.execute(
                "UPDATE jobs SET status='running', attempts=1, updated_at=? WHERE id=?",
                (1000.0, jid),
            )
            con.commit()
        finally:
            con.close()
        assert q.get(jid).status == "running"

        # The in-loop periodic reclaim (interval = reclaim_lease/2 = 1s) must
        # requeue it and the daemon must then claim + process it.
        assert processed.wait(timeout=10.0), "peer orphan was never reclaimed"
    finally:
        w.stop()
        t.join(timeout=5.0)

    # Settle: the recovered job ran to completion.
    deadline = time.monotonic() + 5.0
    while q.get(jid).status not in ("done", "failed") and time.monotonic() < deadline:
        time.sleep(0.02)
    assert q.get(jid).status == "done"


def test_heartbeat_extends_lease_and_is_fenced(tmp_path):
    """heartbeat() refreshes updated_at so reclaim_stale never steals a live
    job -- but a stopped heartbeat (crash) still expires, and a stale
    heartbeat can't refresh a row it no longer owns."""
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = _running_job(q, at=1000.0)

    # The live worker heartbeats at t=1150 -> a reclaim at t=1200 (lease 100)
    # no longer sees a stale row.
    assert q.heartbeat(jid, now=1150.0, expected_attempts=1) is True
    assert q.reclaim_stale(100.0, now=1200.0) == 0
    assert q.get(jid).status == "running"

    # ...but without further heartbeats the lease still expires (crash safety).
    assert q.reclaim_stale(100.0, now=1300.0) == 1
    assert q.get(jid).status == "pending"

    # Fenced: the requeued (pending) row is no longer the old owner's to renew.
    assert q.heartbeat(jid, now=1310.0, expected_attempts=1) is False
    assert q.get(jid).status == "pending"

    # A peer re-claims (attempts=2); the old owner's attempt-1 heartbeat no-ops.
    assert q.claim(now=1320.0).id == jid
    assert q.heartbeat(jid, now=1330.0, expected_attempts=1) is False
    assert q.heartbeat(jid, now=1330.0, expected_attempts=2) is True


def test_live_worker_heartbeat_prevents_lease_steal(tmp_path):
    """A handler that outlives reclaim_lease must NOT have its job stolen and
    re-executed. Regression: updated_at was written only at claim (no
    heartbeat), so a peer daemon's periodic reclaim_stale requeued the live
    job and a second swarm drove the same goal concurrently (double spend,
    double side effects)."""
    import threading
    import time

    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    q = JobQueue(db_path=tmp_path / "jobs.db")
    runs: list[int] = []

    def slow_handler(job):
        runs.append(job.attempts)
        time.sleep(2.0)  # several leases long

    # Lease 1.0s -> heartbeat every 0.25s, so updated_at is never > ~0.5s
    # stale while the 2s handler runs.
    w = Worker(queue=q, reclaim_lease=1.0, idle_sleep=0.01)
    w.register("slow", slow_handler)
    jid = q.enqueue("slow", {})

    stolen = []
    peer_stop = threading.Event()

    def peer_reclaims():  # a peer daemon's periodic reclaim, every 0.1s
        while not peer_stop.wait(0.1):
            stolen.append(q.reclaim_stale(1.0, max_attempts=5))

    t = threading.Thread(target=peer_reclaims, daemon=True)
    t.start()
    try:
        assert w.run_once() is True
    finally:
        peer_stop.set()
        t.join(timeout=5.0)

    assert sum(stolen) == 0, "live job's lease was stolen despite heartbeats"
    job = q.get(jid)
    assert job.status == "done"
    assert job.attempts == 1
    assert runs == [1]  # executed exactly once


def test_transient_complete_failure_does_not_re_run_the_handler(tmp_path):
    """Complete() sharing the handler's try/except meant a transient
    terminal-write failure (e.g. sqlite 'database is locked' past
    busy_timeout) was routed through fail() -- requeuing a job whose handler
    had ALREADY run to completion, so the next claim re-ran it. A duplicate
    side effect on the *normal* path, not just the documented at-least-once
    reclaim-path caveat."""
    import sqlite3

    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q, retry_after=0.0)
    runs: list[int] = []
    w.register("side_effect", lambda job: runs.append(job.id))
    jid = q.enqueue("side_effect", {})

    real_complete = q.complete
    calls = {"n": 0}

    def flaky_complete(job_id, *, expected_attempts=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise sqlite3.OperationalError("database is locked")
        return real_complete(job_id, expected_attempts=expected_attempts)

    q.complete = flaky_complete

    assert w.run_once() is True
    assert w.run_once() is False  # nothing left to claim -- not re-queued

    assert runs == [jid]  # handler ran exactly once
    job = q.get(jid)
    assert job.status == "done"
    assert job.attempts == 1


def test_permanently_failing_complete_leaves_job_running_for_reclaim(tmp_path):
    """If complete() keeps failing, the job must be left 'running' (for
    lease reclaim to recover, same as a crashed worker) rather than routed
    through fail() -- which would reschedule it for an immediate, unwarranted
    re-run of a handler that already succeeded."""
    import sqlite3

    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q, retry_after=0.0)
    runs: list[int] = []
    w.register("side_effect", lambda job: runs.append(job.id))
    jid = q.enqueue("side_effect", {})

    def always_fails(job_id, *, expected_attempts=None):
        raise sqlite3.OperationalError("database is locked")

    q.complete = always_fails

    assert w.run_once() is True

    assert runs == [jid]  # handler ran exactly once
    job = q.get(jid)
    assert job.status == "running"  # not 'pending' (would re-run) or 'failed'
    assert job.attempts == 1
