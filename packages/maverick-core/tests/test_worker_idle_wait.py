"""An idle worker sleeps until the next job is due or one is enqueued.

The dashboard's automation pool polled its SQLite queue from three threads
every two seconds while idle: about 90 empty claims a minute, each opening the
database, its write-ahead log and shared-memory file, taking the write lock
and deleting the log again. With the state folder on network storage that was
thousands of metered file operations a minute with nobody using the product.
"""
from __future__ import annotations

import threading
import time

from maverick.job_queue import JobQueue
from maverick.worker import Worker


def test_next_ready_at_is_the_earliest_claimable_job(tmp_path):
    q = JobQueue(db_path=tmp_path / "jobs.db")
    assert q.next_ready_at() is None
    now = time.time()
    q.enqueue("later", {}, run_at=now + 120)
    q.enqueue("sooner", {}, run_at=now + 30)
    assert abs(q.next_ready_at() - (now + 30)) < 1e-3
    job = q.claim(now=now + 31)
    assert job is not None and job.kind == "sooner"
    assert abs(q.next_ready_at() - (now + 120)) < 1e-3


def test_a_write_wakes_a_waiter_and_an_empty_claim_does_not(tmp_path):
    q = JobQueue(db_path=tmp_path / "jobs.db")
    other = JobQueue(db_path=tmp_path / "jobs.db")  # another handle on the same file
    generation = q.work_generation()
    assert q.claim() is None  # an empty claim changes nothing
    assert q.wait_for_work(generation, 0.05) is False
    timer = threading.Timer(0.1, lambda: other.enqueue("k", {}))
    timer.start()
    started = time.monotonic()
    assert q.wait_for_work(generation, 5.0) is True
    assert time.monotonic() - started < 2.0
    timer.join()


def test_an_idle_worker_with_idle_max_claims_far_less_often(tmp_path):
    q = JobQueue(db_path=tmp_path / "jobs.db")
    claims = []
    real_claim = q.claim

    def counting_claim(**kwargs):
        claims.append(time.monotonic())
        return real_claim(**kwargs)

    q.claim = counting_claim  # type: ignore[method-assign]
    ran = []
    worker = Worker(queue=q, idle_sleep=0.05, idle_backoff_start=0.01, idle_max=30.0)
    worker.register("k", lambda job: ran.append(time.monotonic()))
    thread = threading.Thread(target=worker.run_forever, daemon=True)
    thread.start()
    time.sleep(0.6)
    idle_claims = len(claims)
    assert idle_claims <= 3, idle_claims  # idle_sleep alone would poll about 12 times
    enqueued = time.monotonic()
    q.enqueue("k", {})  # an enqueue wakes the worker at once
    deadline = time.monotonic() + 5
    while not ran and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ran and ran[0] - enqueued < 1.0
    q.enqueue("k", {}, run_at=time.time() + 0.3)  # a delayed job runs when due
    deadline = time.monotonic() + 5
    while len(ran) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(ran) == 2
    worker.stop()
    thread.join(timeout=5)
    assert not thread.is_alive(), "stop() wakes an idle worker"


def test_without_idle_max_the_idle_backoff_is_unchanged(tmp_path):
    worker = Worker(queue=JobQueue(db_path=tmp_path / "jobs.db"), idle_sleep=2.0)
    assert worker.idle_max is None
