"""Boundary regressions for audit custody and approval/schedule lifecycle."""
from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import signing

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_anchor_rollover_serializes_tip_and_refuses_late_append(isolated, monkeypatch):
    from maverick.audit import signing

    audit_dir = isolated / "audit"
    path = audit_dir / "2000-01-01.ndjson"
    signer = signing.AuditSigner(path)
    assert signer.write({"kind": "before_rollover"})
    snapshot = threading.Event()
    append_started = threading.Event()
    release = threading.Event()
    results = []
    errors = []
    original = signing._file_tip_and_count

    def paused_tip(day_file):
        result = original(day_file)
        snapshot.set()
        assert release.wait(5)
        return result

    def anchor():
        try:
            results.append(signing.ensure_anchors(audit_dir))
        except BaseException as exc:
            errors.append(exc)

    def append():
        append_started.set()
        try:
            results.append(signer.write({"kind": "late_rollover"}))
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(signing, "_file_tip_and_count", paused_tip)
    anchoring = threading.Thread(target=anchor)
    anchoring.start()
    assert snapshot.wait(5)
    writing = threading.Thread(target=append)
    writing.start()
    assert append_started.wait(5)
    # A writer that selected yesterday just before midnight cannot cross the
    # tip snapshot/anchor transaction. Releasing the snapshot then closes it.
    writing.join(0.1)
    release.set()
    anchoring.join(5)
    writing.join(5)
    assert not anchoring.is_alive() and not writing.is_alive()
    assert errors == []
    monkeypatch.setattr(signing, "_file_tip_and_count", original)
    assert signing.verify_anchors(audit_dir) == []
    assert len(path.read_text().splitlines()) == 1
    assert sorted(results) == [False, 1]
    assert signer.write({"kind": "before_rollover"}, idempotency_identity=("kind", "before_rollover"))
    from maverick.audit.writer import AuditLog
    assert AuditLog(audit_dir, sign=False)._append_payload(path, {"kind": "unsigned_late"}, None) is False
    assert signing.verify_anchors(audit_dir) == []
    today = audit_dir / f"{datetime.now(timezone.utc):%Y-%m-%d}.ndjson"
    assert signing.AuditSigner(today).write({"kind": "current_day"})


def test_checkpoint_publication_recovers_only_its_stale_stage_link(isolated):
    from maverick.audit import checkpoints, signing

    audit_dir = isolated / "audit"
    checkpoint_dir = isolated / "checkpoints"
    day_file = audit_dir / f"{datetime.now(timezone.utc):%Y-%m-%d}.ndjson"
    signer = signing.AuditSigner(day_file)
    assert signer.write({"kind": "first"})
    target = checkpoints.publish_checkpoint(audit_dir, checkpoint_dir)
    stage = target.with_name(f".{target.name}.0123456789abcdef.stage")
    os.link(target, stage)
    unrelated = target.with_name(f".{target.name}.fedcba9876543210.stage")
    unrelated.write_bytes(target.read_bytes())
    other = target.with_name(f".{target.name}.1111111111111111.stage")
    other.write_text("unrelated evidence")
    alias = target.with_name(f".{target.name}.2222222222222222.stage")
    alias.symlink_to(target)
    assert signer.write({"kind": "second"})
    checkpoints.publish_checkpoint(audit_dir, checkpoint_dir)
    assert not stage.exists()
    assert unrelated.exists() and other.read_text() == "unrelated evidence"
    assert alias.is_symlink()
    assert checkpoints.latest_checkpoint_sequence(checkpoint_dir) == 2
    assert checkpoints.verify_checkpoints(audit_dir, checkpoint_dir) == []


def test_approval_undo_window_starts_when_last_audit_vote_is_delivered(isolated):
    from maverick.world_model import WorldModel

    world = WorldModel(isolated / "world.db")
    aid = world.create_approval("wire-funds", risk="high", approvals_required=2, undoable=True)
    first = world.decide_approval_audited(aid, "approved", decided_by="user:a")
    final = world.decide_approval_audited(aid, "approved", decided_by="user:b")
    delivered = final.created_at + 100
    world.mark_approval_audit_delivered(final.event_id, delivered_at=delivered)
    assert world.get_approval(aid).status == "pending"
    world.mark_approval_audit_delivered(first.event_id, delivered_at=delivered + 60)
    assert world.get_approval(aid).decided_at == delivered + 60
    world.mark_approval_audit_delivered(first.event_id, delivered_at=delivered + 120)
    assert world.get_approval(aid).decided_at == delivered + 60
    world.close()


def test_message_dedup_surfaces_foreign_key_failure(isolated):
    from maverick.world_model import WorldModel

    world = WorldModel(isolated / "world.db")
    with pytest.raises(sqlite3.IntegrityError):
        world.mark_message_processed("sms", "unknown-goal", goal_id=99999)
    assert world.mark_message_processed("sms", "valid") is True
    assert world.mark_message_processed("sms", "valid") is False
    world.close()


@pytest.mark.parametrize("failure", ["rearm", "suspended"])
def test_terminal_rearm_failure_pauses_schedule(isolated, monkeypatch, failure):
    from maverick.job_queue import JobQueue
    from maverick.schedule_definitions import list_definitions
    from maverick.worker import Worker

    payload = {"__cron__": "*/5 * * * *"}
    if failure == "rearm":
        def unavailable(*args, **kwargs):
            raise sqlite3.OperationalError("database is locked")
        monkeypatch.setattr(JobQueue, "_advance_recurrence", unavailable)
    else:
        from maverick.tenant.registry import create_tenant, suspend_tenant
        create_tenant("acme")
        suspend_tenant("acme")
        payload["tenant"] = "acme"
    queue = JobQueue(db_path=isolated / "jobs.db")
    job_id = queue.enqueue("noop", payload, run_at=1000)
    worker = Worker(queue=queue, retry_after=0, max_attempts=2)
    worker.register("noop", lambda job: pytest.fail("unarmed occurrence dispatched"))
    worker.run_once()
    assert list_definitions(queue)[0]["state"] == "active"
    worker.run_once()
    assert queue.get(job_id).status == "failed"
    assert list_definitions(queue)[0]["state"] == "paused"
    assert not queue.list(status="pending")


def _checkpointed_world(path, *, status="blocked"):
    from maverick.budget import Budget
    from maverick.checkpoint import Checkpointer
    from maverick.world_model import WorldModel

    world = WorldModel(path)
    goal_id = world.create_goal("source", owner="user:source")
    ck = Checkpointer(world)
    for step in range(2):
        ck.save(goal_id=goal_id, agent_id="orchestrator-0", episode_id=0,
                step_seq=step, messages=[], budget=Budget(), meta={"role": "orchestrator"})
    world.set_goal_status(goal_id, status)
    return world, goal_id, ck


def test_rewind_refuses_active_goal_and_execution_lease(isolated):
    from maverick.checkpoint import rewind
    from maverick.task_execution_guard import lease

    world, goal_id, ck = _checkpointed_world(isolated / "world.db", status="active")
    assert not rewind(world, goal_id, 0).ok
    assert not rewind(world, goal_id, 0, fork=True).ok
    assert ck.list_steps(goal_id, "orchestrator-0") == [0, 1]
    assert world.get_goal(goal_id).status == "active"
    world.set_goal_status(goal_id, "blocked")
    with lease(world, goal_id):
        assert not rewind(world, goal_id, 0).ok
    world.close()


def test_rewind_fork_preserves_source_owner(isolated):
    from maverick.checkpoint import rewind

    world, goal_id, _ck = _checkpointed_world(isolated / "world.db")
    result = rewind(world, goal_id, 0, fork=True)
    assert result.ok
    assert world.get_goal(result.forked_goal_id).owner == "user:source"
    world.close()


def test_channel_authorization_precedes_any_approval_probe(isolated):
    from maverick.channel_approvals import decide_from_channel

    def forbidden(*args):
        raise PermissionError("unavailable")

    world = SimpleNamespace(get_approval=lambda *args: pytest.fail("approval probed"))
    with pytest.raises(PermissionError, match="unavailable"):
        decide_from_channel(world, 123, "approved", principal="user:other",
                            channel="slack", authorize=forbidden)


@pytest.mark.parametrize("risk", ["high", "critical"])
@pytest.mark.parametrize("write_error", [False, True])
def test_confirmation_evidence_failure_refuses_vote(isolated, monkeypatch, risk, write_error):
    from maverick import audit, channel_approvals

    def failed_audit(*args, **kwargs):
        if write_error:
            raise OSError("audit unavailable")
        return False

    monkeypatch.setattr(channel_approvals, "approval_requires_acknowledgement", lambda: True)
    monkeypatch.setattr(audit, "audit_event", failed_audit)
    approval = SimpleNamespace(id=1, risk=risk, action="wire-funds", detail="")
    with pytest.raises(channel_approvals.ChannelApprovalRefused, match="audit"):
        channel_approvals.require_acknowledgement(
            approval, who="user:a", channel="slack", confirmed=True,
            typed_confirmation="APPROVE",
        )


def test_announcement_owns_world_even_after_callers_world_closes(isolated, monkeypatch):
    from maverick import approval_notify, channel_approvals, world_model

    callbacks = []
    worlds = []
    seen = []

    class World:
        closed = False

        def close(self):
            self.closed = True

    def open_world(path=None):
        assert path == isolated / "selected.db"
        world = World()
        worlds.append(world)
        return world

    def announce(world, approval_id):
        assert not world.closed
        seen.append(approval_id)

    monkeypatch.setattr(approval_notify.threading, "Thread", lambda **kw: SimpleNamespace(
        start=lambda: callbacks.append(kw["target"])))
    monkeypatch.setattr(approval_notify, "install_announcers", lambda: None)
    monkeypatch.setattr(approval_notify, "announcements_configured", lambda: True)
    monkeypatch.setattr(world_model, "open_world", open_world)
    monkeypatch.setattr(channel_approvals, "announce_new_approval", announce)
    caller = World()
    caller.path = isolated / "selected.db"
    approval_notify.approval_created(7, world=caller)
    caller.close()
    callbacks[0]()
    assert seen == [7]
    assert len(worlds) == 1 and worlds[0].closed
