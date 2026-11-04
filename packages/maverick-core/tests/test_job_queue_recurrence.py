"""Cross-connection occurrence transactions, lease fencing and legacy recovery."""
from __future__ import annotations

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick.job_queue import JobQueue, LeaseLost
from maverick.worker import Worker

CRON = "* * * * *"


def _claimed(tmp_path, payload=None):
    q = JobQueue(tmp_path / "jobs.db")
    jid = q.enqueue("noop", payload or {"__cron__": CRON}, run_at=100)
    return q, q.claim(now=100), jid


def test_reclaimed_attempt_cannot_write_checkpoint_or_arm(tmp_path):
    q, old, jid = _claimed(tmp_path)
    peer = JobQueue(q.db_path)
    assert peer.reclaim_stale(1, now=102) == 1
    # Status alone fences the gap before attempts increments at the next claim.
    assert not q.set_payload(jid, {"stale": True}, expected_attempts=old.attempts)
    with pytest.raises(LeaseLost):
        q.rearm(jid, expected_attempts=old.attempts, now=102)
    current = peer.claim(now=102)
    assert peer.set_payload(jid, {**current.payload, "checkpoint": "current"},
                            expected_attempts=current.attempts)
    assert not q.set_payload(jid, {"checkpoint": "stale"}, expected_attempts=old.attempts)
    with pytest.raises(LeaseLost):
        q.rearm(jid, expected_attempts=old.attempts, now=103)
    assert peer.get(jid).payload["checkpoint"] == "current"
    assert peer.list(status="pending") == []


def test_two_connections_racing_same_occurrence_commit_one_successor(tmp_path):
    q, job, jid = _claimed(tmp_path)
    peer = JobQueue(q.db_path)
    barrier = threading.Barrier(2)

    def advance(queue):
        barrier.wait(timeout=5)
        return queue.rearm(jid, expected_attempts=job.attempts, now=100).successor_id

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = [f.result(timeout=10) for f in
                [pool.submit(advance, q), pool.submit(advance, peer)]]
    assert a == b
    assert [j.id for j in q.list(status="pending")] == [a]
    parent, child = q.get(jid), q.get(a)
    assert parent.recurrence_id == child.recurrence_id
    assert (parent.occurrence, child.occurrence) == (0, 1)
    assert parent.scheduled_at == 100
    assert child.scheduled_at == child.run_at == 120
    assert parent.payload["__rearmed__"] is True
    assert "__rearmed__" not in child.payload


def test_stale_and_new_worker_racing_only_new_owner_advances(tmp_path):
    q, old, jid = _claimed(tmp_path)
    peer = JobQueue(q.db_path)
    peer.reclaim_stale(1, now=102)
    new = peer.claim(now=102)
    barrier = threading.Barrier(2)

    def advance(queue, job):
        barrier.wait(timeout=5)
        try:
            return queue.rearm(jid, expected_attempts=job.attempts, now=103).successor_id
        except LeaseLost:
            return "lease-lost"

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(advance, q, old)
        b = pool.submit(advance, peer, new)
        assert a.result(timeout=10) == "lease-lost"
        assert b.result(timeout=10) == q.get(jid).successor_id
    assert len(q.list(status="pending")) == 1


def test_parent_update_failure_rolls_back_insert_and_reservation(tmp_path):
    q, job, jid = _claimed(tmp_path)
    with sqlite3.connect(q.db_path) as c:
        c.execute("CREATE TRIGGER reject_advance BEFORE UPDATE OF successor_id ON jobs "
                  "BEGIN SELECT RAISE(ABORT, 'injected checkpoint failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match="injected checkpoint"):
        q.rearm(jid, expected_attempts=job.attempts, now=100)
    assert q.list(status="pending") == []
    assert q.get(jid).successor_id is None
    assert "__rearmed__" not in q.get(jid).payload
    with sqlite3.connect(q.db_path) as c:
        c.execute("DROP TRIGGER reject_advance")
    assert q.rearm(jid, expected_attempts=job.attempts, now=100).successor_id
    assert len(q.list(status="pending")) == 1


def test_committed_advance_lost_acknowledgement_is_idempotent(tmp_path, monkeypatch):
    q, job, jid = _claimed(tmp_path)
    real = q.rearm
    calls = 0

    def lose_ack(*args, **kwargs):
        nonlocal calls
        result = real(*args, **kwargs)
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("injected lost acknowledgement")
        return result

    monkeypatch.setattr(q, "rearm", lose_ack)
    worker = Worker(q)
    from maverick.worker import RearmFailed
    with pytest.raises(RearmFailed):
        worker._maybe_rearm(job)
    worker._maybe_rearm(job)
    assert len(q.list(status="pending")) == 1
    assert job.payload["__rearmed__"] is True


def test_identical_independent_schedules_keep_distinct_successors(tmp_path):
    q = JobQueue(tmp_path / "jobs.db")
    ids = [q.enqueue("noop", {"__cron__": CRON}, run_at=100) for _ in range(2)]
    for _ in ids:
        job = q.claim(now=100)
        q.rearm(job.id, expected_attempts=job.attempts, now=100)
        q.complete(job.id, expected_attempts=job.attempts)
    parents = [q.get(jid) for jid in ids]
    assert len({j.recurrence_id for j in parents}) == 2
    assert len({j.successor_id for j in parents}) == 2
    assert len(q.list(status="pending")) == 2


def test_database_unique_occurrence_constraint_is_not_only_application_check(tmp_path):
    q, job, jid = _claimed(tmp_path)
    q.rearm(jid, expected_attempts=job.attempts, now=100)
    with sqlite3.connect(q.db_path) as c, pytest.raises(sqlite3.IntegrityError):
        c.execute("INSERT INTO jobs (kind,payload,run_at,created_at,updated_at,recurrence_id,occurrence) "
                  "VALUES ('noop','{}',120,100,100,?,1)", (job.recurrence_id,))


def test_checkpoint_does_not_change_template_or_erase_armed_state(tmp_path):
    q = JobQueue(tmp_path / "jobs.db")
    jid = q.enqueue("start_goal", {"__cron__": CRON, "text": "original", "tenant": "t"}, run_at=100)
    job = q.claim(now=100)
    assert q.set_payload(jid, {"goal_id": 9, "__rearmed__": True}, expected_attempts=job.attempts)
    # A caller cannot forge a rearm by supplying the old private marker.
    assert "__rearmed__" not in q.get(jid).payload
    parent = q.rearm(jid, expected_attempts=job.attempts, now=100)
    child = q.get(parent.successor_id)
    assert child.payload == {"__cron__": CRON, "text": "original", "tenant": "t"}
    assert q.set_payload(jid, {"goal_id": 10}, expected_attempts=job.attempts)
    assert q.get(jid).payload["__rearmed__"] is True
    assert q.rearm(jid, expected_attempts=job.attempts, now=200).successor_id == child.id


def test_cancelled_or_purged_successor_is_not_recreated_by_parent_retry(tmp_path):
    q, job, jid = _claimed(tmp_path)
    child = q.rearm(jid, expected_attempts=job.attempts, now=100).successor_id
    assert q.cancel(child)
    assert q.rearm(jid, expected_attempts=job.attempts, now=1000).successor_id == child
    assert q.list(status="pending") == []


def test_retry_time_changes_do_not_change_occurrence_identity(tmp_path):
    q, job, jid = _claimed(tmp_path)
    q.fail(jid, "retry", retry_after=0, expected_attempts=job.attempts)
    retry = q.claim()
    assert retry.recurrence_id == job.recurrence_id
    assert retry.occurrence == 0
    assert retry.scheduled_at == 100
    assert retry.run_at != retry.scheduled_at


def test_same_attempt_cannot_checkpoint_or_fail_after_completion(tmp_path):
    q, job, jid = _claimed(tmp_path)
    assert q.complete(jid, expected_attempts=job.attempts)
    assert not q.set_payload(jid, {"late": True}, expected_attempts=job.attempts)
    assert not q.fail(jid, "late failure", expected_attempts=job.attempts)
    assert q.get(jid).status == "done"


def test_timezone_and_execution_identity_survive_advance(tmp_path):
    import datetime as dt
    from zoneinfo import ZoneInfo
    payload = {"__cron__": "0 9 * * *", "__tz__": "America/New_York", "tenant": "t",
               "owner": "o", "channel": "cli", "user_id": "u", "allowed_suites": ["safe"]}
    q, job, jid = _claimed(tmp_path, payload)
    now = dt.datetime(2026, 7, 1, tzinfo=dt.timezone.utc).timestamp()
    child = q.get(q.rearm(jid, expected_attempts=job.attempts, now=now).successor_id)
    assert child.payload == payload
    assert dt.datetime.fromtimestamp(child.run_at, ZoneInfo("America/New_York")).hour == 9


def test_concurrency_deferral_does_not_fork_the_recurring_schedule(tmp_path, monkeypatch):
    q = JobQueue(tmp_path / "jobs.db")
    jid = q.enqueue("run_goal", {"__cron__": "0 0 1 1 *", "goal_id": 42}, run_at=0)
    from maverick.runner import GoalRunUnavailable
    # The worker asks for the detailed outcome: only an explicit slot refusal
    # defers (a bare None is an unconfirmed outcome and stops the job).
    monkeypatch.setattr("maverick.runner.run_goal_in_thread",
                        lambda *a, **kw: GoalRunUnavailable("concurrency_slot"))
    worker = Worker(q)
    assert worker.run_once()
    parent = q.get(jid)
    pending = q.list(status="pending")
    assert parent.status == "done" and len(pending) == 2
    deferred = next(j for j in pending if j.payload.get("_slot_defers"))
    assert deferred.id != parent.successor_id
    assert deferred.payload["__rearmed__"] is True
    continuation = q.claim(now=deferred.run_at)
    assert continuation.id == deferred.id
    worker._maybe_rearm(continuation)
    assert [j.id for j in q.list(status="pending")] == [parent.successor_id]


def _legacy(path, rows):
    with sqlite3.connect(path) as c:
        c.execute("CREATE TABLE jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, "
                  "payload TEXT NOT NULL, run_at REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending', "
                  "attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', "
                  "created_at REAL NOT NULL, updated_at REAL NOT NULL)")
        for payload, attempts, status in rows:
            c.execute("INSERT INTO jobs (kind,payload,run_at,status,attempts,created_at,updated_at) "
                      "VALUES ('noop',?,100,?,?,100,100)", (json.dumps(payload), status, attempts))


def test_legacy_migration_preserves_safe_rows_and_quarantines_ambiguity(tmp_path):
    path = tmp_path / "jobs.db"
    _legacy(path, [({"__cron__": CRON}, 0, "pending"),
                   ({"__cron__": CRON, "__rearmed__": True}, 1, "pending"),
                   ({"__cron__": CRON, "private": "sensitive-body"}, 1, "running")])
    q = JobQueue(path)
    assert q.get(1).status == q.get(2).status == "pending"
    uncertain = q.get(3)
    assert uncertain.status == "failed" and uncertain.recurrence_reconcile_required
    assert "reconciliation required" in uncertain.last_error
    assert "sensitive-body" not in uncertain.last_error
    ids = [q.get(i).recurrence_id for i in (1, 2, 3)]
    assert len(set(ids)) == 3
    reopened = JobQueue(path)
    assert ids == [reopened.get(i).recurrence_id for i in (1, 2, 3)]
    safe = q.claim(now=100)
    assert q.rearm(safe.id, expected_attempts=safe.attempts, now=100).successor_id
    marked = q.claim(now=100)
    assert q.rearm(marked.id, expected_attempts=marked.attempts, now=100).successor_id is None


@pytest.mark.parametrize("link", [True, False])
def test_operator_reconciles_legacy_once_without_replaying_history(tmp_path, link):
    path = tmp_path / "jobs.db"
    _legacy(path, [({"__cron__": CRON}, 1, "running"), ({"__cron__": CRON}, 0, "pending")])
    q = JobQueue(path)
    choice = {"successor_id": 2} if link else {"rearm": True}
    with pytest.raises(ValueError, match="confirm"):
        q.reconcile_recurrence(1, expected_attempts=1, **choice)
    with pytest.raises(ValueError, match="changed"):
        q.reconcile_recurrence(1, expected_attempts=2, confirm=True, **choice)
    first = q.reconcile_recurrence(1, expected_attempts=1, confirm=True, **choice)
    second = q.reconcile_recurrence(1, expected_attempts=1, confirm=True, **choice)
    assert first == second
    parent = q.get(1)
    assert parent.status == "failed" and not parent.recurrence_reconcile_required
    assert "historical execution not replayed" in parent.last_error
    assert len(q.list(status="pending")) == (1 if link else 2)


def test_reconciliation_rejects_different_authority_or_schedule(tmp_path):
    path = tmp_path / "jobs.db"
    _legacy(path, [({"__cron__": CRON, "owner": "a"}, 1, "running"),
                   ({"__cron__": CRON, "owner": "b"}, 0, "pending")])
    q = JobQueue(path)
    with pytest.raises(ValueError, match="template differs"):
        q.reconcile_recurrence(1, expected_attempts=1, successor_id=2, confirm=True)
    assert q.get(1).recurrence_reconcile_required
    assert q.get(1).successor_id is None


def test_unresolved_legacy_occurrence_survives_terminal_purge(tmp_path):
    path = tmp_path / "jobs.db"
    _legacy(path, [({"__cron__": CRON}, 1, "running")])
    q = JobQueue(path)
    assert q.purge(older_than_days=0) == 0
    assert q.get(1).recurrence_reconcile_required


def test_failed_operator_rearm_rolls_back_and_can_retry(tmp_path):
    path = tmp_path / "jobs.db"
    _legacy(path, [({"__cron__": CRON}, 1, "running")])
    q = JobQueue(path)
    with sqlite3.connect(path) as c:
        c.execute("CREATE TRIGGER reject_reconcile BEFORE UPDATE OF recurrence_reconcile_required "
                  "ON jobs BEGIN SELECT RAISE(ABORT, 'injected recovery failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match="injected recovery"):
        q.reconcile_recurrence(1, expected_attempts=1, rearm=True, confirm=True)
    assert q.get(1).recurrence_reconcile_required
    assert q.get(1).successor_id is None
    assert q.list(status="pending") == []
    with sqlite3.connect(path) as c:
        c.execute("DROP TRIGGER reject_reconcile")
    successor = q.reconcile_recurrence(1, expected_attempts=1, rearm=True, confirm=True)
    assert q.get(successor).status == "pending"


def test_stale_goal_checkpoint_stops_before_runner(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")
    q = JobQueue(tmp_path / "jobs.db")
    q.enqueue("start_goal", {"text": "synthetic goal"}, run_at=0)
    job = q.claim(now=0)
    real_checkpoint = q.set_payload

    def lose_lease(job_id, payload, *, expected_attempts):
        q.reclaim_stale(0, now=job.updated_at)
        return real_checkpoint(job_id, payload, expected_attempts=expected_attempts)

    monkeypatch.setattr(q, "set_payload", lose_lease)
    executed = []
    monkeypatch.setattr("maverick.runner.run_goal_in_thread",
                        lambda *a, **kw: executed.append(a))
    with pytest.raises(LeaseLost):
        Worker(q)._handlers["start_goal"](job)
    assert executed == []
    assert "goal_id" not in q.get(job.id).payload


def test_worker_does_not_dispatch_after_lease_is_reclaimed(tmp_path, monkeypatch):
    q = JobQueue(tmp_path / "jobs.db")
    jid = q.enqueue("noop", {"__cron__": CRON}, run_at=0)
    claim = q.claim

    def reclaim_after_claim(**kwargs):
        job = claim(**kwargs)
        q.reclaim_stale(0, now=job.updated_at)
        return job

    monkeypatch.setattr(q, "claim", reclaim_after_claim)
    worker = Worker(q)
    executed = []
    worker.register("noop", lambda job: executed.append(job.id))
    assert worker.run_once()
    assert executed == []
    assert q.get(jid).status == "pending"
    assert len(q.list()) == 1


def test_operator_cli_reconciles_a_parked_schedule(tmp_path, monkeypatch):
    """The recovery API had no operator surface: a parked schedule stayed
    stopped until someone wrote Python. `maverick queue reconcile` is it."""
    from click.testing import CliRunner
    from maverick import job_queue
    from maverick.cli import main

    path = tmp_path / "jobs.db"
    _legacy(path, [({"__cron__": CRON}, 1, "running")])
    real = job_queue.JobQueue
    monkeypatch.setattr(job_queue, "JobQueue", lambda *a, **k: real(path))
    runner = CliRunner()
    listed = runner.invoke(main, ["queue", "failed"])
    assert "maverick queue reconcile" in listed.output
    refused = runner.invoke(main, ["queue", "reconcile", "1", "--expected-attempts", "1", "--rearm"])
    assert refused.exit_code != 0 and "--yes" in refused.output
    stale = runner.invoke(main, ["queue", "reconcile", "1", "--expected-attempts", "9", "--rearm", "--yes"])
    assert stale.exit_code != 0 and "changed" in stale.output
    done = runner.invoke(main, ["queue", "reconcile", "1", "--expected-attempts", "1", "--rearm", "--yes"])
    assert done.exit_code == 0, done.output
    assert not real(path).get(1).recurrence_reconcile_required
    assert len(real(path).list(status="pending")) == 1


def test_cron_rows_inserted_by_an_older_binary_are_backfilled_on_every_start(tmp_path):
    import json
    import sqlite3
    import time

    from maverick.job_queue import JobQueue
    db = tmp_path / "q.db"
    JobQueue(db)                                            # schema already upgraded
    now = time.time() - 5
    with sqlite3.connect(db) as c:                          # a rolled-back binary's insert
        c.execute("INSERT INTO jobs (kind, payload, run_at, created_at, updated_at) VALUES (?,?,?,?,?)",
                  ("run_goal", json.dumps({"goal_id": 1, "__cron__": "*/5 * * * *"}), now, now, now))
    q = JobQueue(db)
    job = q.claim()
    assert job.recurrence_id
    current = q.rearm(job.id, expected_attempts=job.attempts)
    assert current.successor_id and [j.id for j in q.list(status="pending")]

