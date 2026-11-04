"""Wire the cron scheduler + job worker into the CLI.

The scheduler engine (maverick.scheduler) and the worker existed but had no
entry point: nothing imported the scheduler, there was no `maverick worker`
or `maverick schedule` command, and the worker never re-armed recurring
jobs. These tests cover the wiring: JobQueue.cancel, the worker re-arm
(one successor per occurrence), and the three CLI commands.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner

# ---------- JobQueue.cancel ----------

def test_cancel_removes_pending_job(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("noop", {}, run_at=1000.0)
    assert q.cancel(jid) is True
    assert q.get(jid) is None


def test_cancel_running_or_unknown_returns_false(tmp_path):
    from maverick.job_queue import JobQueue
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("noop", {}, run_at=1000.0)
    q.claim(now=1000.0)  # -> running, no longer cancellable
    assert q.cancel(jid) is False
    assert q.cancel(999999) is False


# ---------- worker re-arm ----------

def test_maybe_rearm_once_across_real_claimed_attempts(tmp_path):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    w = Worker(queue=q)
    cron = "*/5 * * * *"

    def _armed():
        return [j for j in q.list(status="pending") if j.payload.get("__cron__")]

    jid = q.enqueue("noop", {"__cron__": cron}, run_at=0)
    first = q.claim(now=0)
    w._maybe_rearm(first)
    assert len(_armed()) == 1

    # A retry (attempts > 1) must NOT enqueue another occurrence.
    assert q.fail(jid, "retry", retry_after=0, expected_attempts=first.attempts)
    retry = q.claim()
    assert retry.attempts == 2
    w._maybe_rearm(retry)
    assert len(_armed()) == 1

    # A non-cron job is never re-armed.
    q.enqueue("noop", {}, run_at=0)
    w._maybe_rearm(q.claim(now=0))
    assert len(_armed()) == 1


def test_worker_run_once_rearms_recurring_job(tmp_path):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    cron = "*/5 * * * *"
    # Past run_at so it's claimable now; carries its cron in the payload.
    jid = q.enqueue("noop", {"__cron__": cron}, run_at=1000.0)

    w = Worker(queue=q, idle_sleep=0.0)
    w.register("noop", lambda job: None)
    assert w.run_once() is True

    assert q.get(jid).status == "done"            # this occurrence ran
    pend = [j for j in q.list(status="pending") if j.payload.get("__cron__")]
    assert len(pend) == 1 and pend[0].id != jid    # next occurrence armed


# ---------- CLI: maverick schedule / worker ----------

def test_cli_registers_worker_and_schedule():
    from maverick.cli import main
    assert "worker" in main.commands
    assert "schedule" in main.commands
    assert set(main.commands["schedule"].commands) >= {"add", "list", "rm"}


def test_schedule_add_list_rm_roundtrip(tmp_path, monkeypatch):
    import re

    from maverick.cli import main
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    r = CliRunner()

    add = r.invoke(main, ["schedule", "add", "*/5 * * * *", "run_goal",
                          "--payload", '{"goal_id": 5}'])
    assert add.exit_code == 0, add.output
    assert "scheduled job" in add.output

    listed = r.invoke(main, ["schedule", "list"])
    assert listed.exit_code == 0
    assert "run_goal" in listed.output and "*/5 * * * *" in listed.output

    jid = re.search(r"scheduled job (\d+)", add.output).group(1)
    rm = r.invoke(main, ["schedule", "rm", jid])
    assert rm.exit_code == 0 and "cancelled" in rm.output

    empty = r.invoke(main, ["schedule", "list"])
    assert "no scheduled jobs" in empty.output


def test_schedule_add_rejects_bad_cron(tmp_path, monkeypatch):
    from maverick.cli import main
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    res = CliRunner().invoke(main, ["schedule", "add", "not a cron", "run_goal"])
    assert res.exit_code == 2
    assert "bad cron" in res.output


def test_schedule_add_warns_unknown_kind_but_still_schedules(tmp_path, monkeypatch):
    # A typo'd kind has no handler; without a warning it would sit in the queue
    # and fail terminally only at worker time (visible only in logs). Warn, but
    # still schedule -- embedders register custom kinds via Worker.register().
    from maverick.cli import main
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    res = CliRunner().invoke(main, ["schedule", "add", "*/5 * * * *", "run_gaol",
                                    "--payload", '{"goal_id": 5}'])
    assert res.exit_code == 0, res.output
    assert "WARNING" in res.output and "run_gaol" in res.output
    assert "scheduled job" in res.output


def test_schedule_add_builtin_kind_does_not_warn(tmp_path, monkeypatch):
    from maverick.cli import main
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    res = CliRunner().invoke(main, ["schedule", "add", "*/5 * * * *", "run_goal",
                                    "--payload", '{"goal_id": 5}'])
    assert res.exit_code == 0, res.output
    assert "WARNING" not in res.output


def test_builtin_job_kinds_matches_worker_handlers(tmp_path):
    # Guard against drift: the advertised constant must equal the handlers the
    # bare worker actually installs.
    from maverick.worker import BUILTIN_JOB_KINDS, Worker
    w = Worker(db_path=tmp_path / "jobs.db")
    assert set(w._handlers) == set(BUILTIN_JOB_KINDS)


def test_worker_command_runs_forever(tmp_path, monkeypatch):
    from maverick.cli import main
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    ran = {"forever": False}

    def _fake_run_forever(self):
        ran["forever"] = True

    monkeypatch.setattr("maverick.worker.Worker.run_forever", _fake_run_forever)
    res = CliRunner().invoke(main, ["worker", "--idle-sleep", "0"])
    assert res.exit_code == 0, res.output
    assert ran["forever"] is True


# ---------- start_goal: recurring autonomous tasks ----------

def test_start_goal_handler_creates_fresh_goal_and_runs_it(tmp_path, monkeypatch):
    # The handler must CREATE a new goal from the prompt (not re-run a fixed id)
    # and hand that fresh id to the runner.
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")
    seen = {}

    def _fake_run(goal_id, *a, **k):
        seen["goal_id"] = goal_id
        seen["run_kwargs"] = k
        return "done"

    monkeypatch.setattr("maverick.runner.run_goal_in_thread", _fake_run)

    import maverick.worker as worker_mod
    from maverick.worker import Worker
    w = Worker(db_path=tmp_path / "jobs.db")
    w.queue.enqueue("start_goal", {
            "title": "Digest",
            "text": "Summarize overnight emails",
            "owner": "user:alice",
            "channel": "api",
            "user_id": "alice",
        }, run_at=0)
    w._handlers["start_goal"](w.queue.claim(now=0))

    from maverick.world_model import open_world
    world = open_world(tmp_path / "world.db")
    try:
        g = world.get_goal(seen["goal_id"])
    finally:
        world.close()
    assert g is not None
    assert g.title == "Digest"
    assert g.description == "Summarize overnight emails"
    assert g.owner == "user:alice"
    assert seen["run_kwargs"] == {
        "channel": "api", "user_id": "alice",
        "acquire_timeout": worker_mod._QUEUE_GOAL_ACQUIRE_TIMEOUT,
        "detailed_outcome": True,  # a slot refusal is told apart from an unknown result
    }


def test_start_goal_records_schedule_provenance(tmp_path, monkeypatch):
    # A scheduled run stamps goal_origins so the dashboard can show the
    # schedule's run history; only when the payload carries a schedule_id.
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(
        "maverick.runner.run_goal_in_thread", lambda goal_id, *a, **k: "done")

    from maverick.worker import Worker
    w = Worker(db_path=tmp_path / "jobs.db")
    w.queue.enqueue("start_goal", {"text": "Summarize emails", "title": "Digest",
                                   "schedule_id": "sched-xyz"}, run_at=0)
    w._handlers["start_goal"](w.queue.claim(now=0))

    from maverick.world_model import open_world
    world = open_world(tmp_path / "world.db")
    try:
        runs = world.goals_for_origin("schedule", "sched-xyz")
    finally:
        world.close()
    assert len(runs) == 1 and runs[0].title == "Digest"


def test_start_goal_without_schedule_id_records_no_origin(tmp_path, monkeypatch):
    # A one-off (non-schedule) start_goal must not leave a provenance row.
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(
        "maverick.runner.run_goal_in_thread", lambda goal_id, *a, **k: "done")
    from maverick.worker import Worker
    w = Worker(db_path=tmp_path / "jobs.db")
    w.queue.enqueue("start_goal", {"text": "one-off"}, run_at=0)
    w._handlers["start_goal"](w.queue.claim(now=0))
    from maverick.world_model import open_world
    world = open_world(tmp_path / "world.db")
    try:
        assert world.goals_for_origin("schedule", "") == []
    finally:
        world.close()


def test_start_goal_idempotent_across_retries(tmp_path, monkeypatch):
    # A transient run failure requeues the job; the retry must REUSE the goal
    # created on the first attempt rather than mint a duplicate goal row each
    # time (a flapping provider would otherwise accumulate orphan goals).
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(
        "maverick.runner.run_goal_in_thread", lambda goal_id, *a, **k: "error"
    )

    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    q.enqueue("start_goal", {"text": "recurring task"}, run_at=0.0)
    w = Worker(queue=q, retry_after=0.0)

    assert w.run_once() is True   # attempt 1: creates goal #1, fails -> requeued
    assert w.run_once() is True   # attempt 2: reuses goal #1, fails -> requeued

    from maverick.world_model import open_world
    world = open_world(tmp_path / "world.db")
    try:
        assert world.get_goal(1) is not None   # the one fresh goal
        assert world.get_goal(2) is None       # no duplicate from the retry
    finally:
        world.close()


def test_start_goal_requires_text(tmp_path):
    from maverick.job_queue import Job
    from maverick.worker import Worker
    w = Worker(db_path=tmp_path / "jobs.db")
    with pytest.raises(ValueError):
        w._handlers["start_goal"](Job(
            id=1, kind="start_goal", payload={"title": "x"},
            run_at=0.0, status="running", attempts=1,
        ))


def test_start_goal_recurs_with_same_prompt(tmp_path, monkeypatch):
    # End-to-end: a cron-armed start_goal runs and re-arms the next occurrence
    # carrying the same prompt -- a true recurring autonomous task.
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(
        "maverick.runner.run_goal_in_thread", lambda goal_id, *a, **k: "done"
    )
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue(
        "start_goal",
        {"text": "Summarize overnight emails", "title": "Digest",
         "__cron__": "*/5 * * * *"},
        run_at=1000.0,
    )
    w = Worker(queue=q, idle_sleep=0.0)
    assert w.run_once() is True
    assert q.get(jid).status == "done"
    nxt = [j for j in q.list(status="pending") if j.payload.get("__cron__")]
    assert len(nxt) == 1 and nxt[0].id != jid
    assert nxt[0].kind == "start_goal"
    assert nxt[0].payload["text"] == "Summarize overnight emails"
    assert nxt[0].payload["title"] == "Digest"


def test_schedule_goal_cli_enqueues_recurring_start_goal(tmp_path, monkeypatch):
    from maverick.cli import main
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")

    res = CliRunner().invoke(main, [
        "schedule", "goal", "0 9 * * 1-5",
        "Summarize my overnight emails", "--title", "Digest",
    ])
    assert res.exit_code == 0, res.output
    assert "scheduled goal job" in res.output

    from maverick.job_queue import JobQueue
    jobs = JobQueue(db_path=tmp_path / "jobs.db").list(status="pending")
    assert len(jobs) == 1
    j = jobs[0]
    assert j.kind == "start_goal"
    assert j.payload["text"] == "Summarize my overnight emails"
    assert j.payload["title"] == "Digest"
    assert j.payload["__cron__"] == "0 9 * * 1-5"
    # It's a normal cron job, so `schedule list` shows it.
    listed = CliRunner().invoke(main, ["schedule", "list"])
    assert "start_goal" in listed.output


def test_schedule_goal_cli_rejects_bad_cron_and_empty_text(tmp_path, monkeypatch):
    from maverick.cli import main
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    bad_cron = CliRunner().invoke(
        main, ["schedule", "goal", "not a cron", "do a thing"]
    )
    assert bad_cron.exit_code == 2 and "bad cron" in bad_cron.output
    empty = CliRunner().invoke(main, ["schedule", "goal", "*/5 * * * *", "   "])
    assert empty.exit_code == 2 and "must not be empty" in empty.output


# ---------- worker drain (one-shot, cron-friendly) ----------

def test_drain_runs_all_ready_jobs_and_returns_count(tmp_path):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    for _ in range(3):
        q.enqueue("noop", {}, run_at=1000.0)  # past run_at -> ready now

    w = Worker(queue=q, idle_sleep=0.0)
    w.register("noop", lambda job: None)
    assert w.drain() == 3
    assert q.claim() is None  # no ready jobs left


def test_claim_ready_cutoff_uses_fresh_heartbeat(tmp_path):
    from maverick.job_queue import JobQueue

    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("noop", {}, run_at=100.0)

    job = q.claim(now=500.0, ready_at=100.0)

    assert job is not None and job.id == jid
    assert job.updated_at == 500.0
    assert q.reclaim_stale(300.0, now=550.0) == 0
    assert q.get(jid).status == "running"


def test_drain_does_not_run_rearmed_future_occurrence(tmp_path):
    # A re-armed cron occurrence has a FUTURE run_at, so it must NOT run in the
    # same drain -- exactly one future occurrence stays pending for next time.
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("noop", {"__cron__": "*/5 * * * *"}, run_at=1000.0)

    w = Worker(queue=q, idle_sleep=0.0)
    w.register("noop", lambda job: None)
    assert w.drain() == 1                          # only the ready occurrence

    assert q.get(jid).status == "done"
    pend = [j for j in q.list(status="pending") if j.payload.get("__cron__")]
    assert len(pend) == 1 and pend[0].id != jid    # next occurrence still armed


def test_drain_snapshots_ready_time_for_slow_recurring_jobs(
    tmp_path, monkeypatch
):
    # ``--once`` must drain the work that was ready when it started, not work
    # that becomes ready while a long handler is still running. Simulate that
    # by making the first cron re-arm due after the drain snapshot (200 > 100)
    # but before the real wall clock used by the old dynamic drain loop.
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    q = JobQueue(db_path=tmp_path / "jobs.db")
    jid = q.enqueue("noop", {"__cron__": "* * * * *"}, run_at=0.0)
    monkeypatch.setattr("maverick.worker.time.time", lambda: 100.0)
    rearmed = {"count": 0}

    def _fake_next_run(expr, *, after=None, tz=""):
        rearmed["count"] += 1
        run_at = 200.0 if rearmed["count"] == 1 else 1_000_000_000_000.0
        return run_at

    monkeypatch.setattr("maverick.scheduler.next_run", _fake_next_run)
    runs = []
    w = Worker(queue=q, idle_sleep=0.0)
    w.register("noop", lambda job: runs.append(job.id))

    assert w.drain() == 1
    assert runs == [jid]
    assert q.get(jid).status == "done"
    pend = [j for j in q.list(status="pending") if j.payload.get("__cron__")]
    assert len(pend) == 1
    assert pend[0].run_at == 200.0


def test_worker_command_once_drains(tmp_path, monkeypatch):
    from maverick.cli import main
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    called = {"drain": False}

    def _fake_drain(self):
        called["drain"] = True
        return 2

    monkeypatch.setattr("maverick.worker.Worker.drain", _fake_drain)
    res = CliRunner().invoke(main, ["worker", "--once"])
    assert res.exit_code == 0, res.output
    assert called["drain"] is True
    assert "drained" in res.output
