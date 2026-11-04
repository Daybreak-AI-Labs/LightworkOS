"""Schema and quorum invariants for the approval-audit transactional outbox."""
from __future__ import annotations

import json

import pytest


@pytest.mark.parametrize("sign", [False, True])
def test_approval_audit_sink_appends_stable_identity_exactly_once(
    tmp_path,
    sign,
):
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog

    audit_dir = tmp_path / ("signed" if sign else "unsigned")
    log = AuditLog(audit_dir, sign=sign)
    payload = {
        "approval_event_id": "approval-v1-stable-event",
        "approval_id": 7,
        "status": "approved",
        "decided_by": "u:alice",
        "occurred_at": 123.0,
    }
    assert log.record(
        AuditEvent(
            ts=124.0,
            kind=EventKind.APPROVAL_DECISION,
            payload=payload,
        )
    )
    # A post-append delivery-marker failure retries with a fresh transport
    # timestamp but the same transactional identity and logical content.
    assert log.record(
        AuditEvent(
            ts=125.0,
            kind=EventKind.APPROVAL_DECISION,
            payload=payload,
        )
    )

    path = next(audit_dir.glob("*.ndjson"))
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert [
        row["approval_event_id"]
        for row in rows
        if row["kind"] == EventKind.APPROVAL_DECISION
    ] == ["approval-v1-stable-event"]

    conflicting = dict(payload, status="denied")
    assert not log.record(
        AuditEvent(
            ts=126.0,
            kind=EventKind.APPROVAL_DECISION,
            payload=conflicting,
        )
    )
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.parametrize("sign", [False, True])
def test_approval_audit_sink_deduplicates_across_utc_rollover(
    tmp_path,
    monkeypatch,
    sign,
):
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog, _prepare_private_audit_file

    audit_dir = tmp_path / ("signed-rollover" if sign else "rollover")
    first_path = audit_dir / "2026-07-29.ndjson"
    second_path = audit_dir / "2026-07-30.ndjson"
    _prepare_private_audit_file(first_path)
    _prepare_private_audit_file(second_path)
    payload = {
        "approval_event_id": "approval-v1-before-midnight",
        "approval_id": 9,
        "status": "denied",
        "decided_by": "u:bob",
        "occurred_at": 200.0,
    }

    first = AuditLog(audit_dir, sign=sign)
    monkeypatch.setattr(first, "_rotate_if_needed", lambda: first_path)
    assert first.record(
        AuditEvent(
            ts=201.0,
            kind=EventKind.APPROVAL_DECISION,
            payload=payload,
        )
    )

    after_midnight = AuditLog(audit_dir, sign=sign)
    monkeypatch.setattr(
        after_midnight,
        "_rotate_if_needed",
        lambda: second_path,
    )
    assert after_midnight.record(
        AuditEvent(
            ts=202.0,
            kind=EventKind.APPROVAL_DECISION,
            payload=payload,
        )
    )

    rows = [
        json.loads(line)
        for path in (first_path, second_path)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert sum(
        row.get("approval_event_id") == "approval-v1-before-midnight"
        for row in rows
    ) == 1
    assert second_path.read_text(encoding="utf-8") == ""


def test_sqlite_v30_migration_creates_outbox_and_reports_head(tmp_path):
    from maverick.world_model import SCHEMA_VERSION, WorldModel

    world = WorldModel(tmp_path / "world.db")
    assert SCHEMA_VERSION >= 30
    assert world.schema_version == SCHEMA_VERSION
    with world._writing() as conn:
        columns = {
            row[1] for row in conn.execute(
                "PRAGMA table_info(approval_audit_outbox)"
            ).fetchall()
        }
    assert columns == {
        "event_id",
        "approval_id",
        "status",
        "decided_by",
        "final_status",
        "created_at",
        "delivered_at",
    }


def test_postgres_v30_migration_is_additive_tenant_scoped_and_rls_bound():
    from maverick.world_model_backends import postgres

    assert postgres._PG_SCHEMA_VERSION >= 30
    statements = dict(postgres.MIGRATIONS)[30]
    joined = "\n".join(statements)
    assert "CREATE TABLE IF NOT EXISTS approval_audit_outbox" in joined
    assert "tenant_id" in joined
    assert "delivered_at" in joined
    assert "approval_audit_outbox" in postgres._RLS_TABLES
    assert (30, statements) in postgres.pending_migrations(29)


def test_quorum_does_not_become_effective_until_every_vote_is_audited(tmp_path):
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    approval_id = world.create_approval(
        "wire-funds",
        risk="critical",
        approvals_required=2,
    )
    first = world.decide_approval_audited(
        approval_id,
        "approved",
        decided_by="u:alice",
    )
    second = world.decide_approval_audited(
        approval_id,
        "approved",
        decided_by="u:bob",
    )
    assert first.final_status is None
    assert second.final_status == "approved"

    # Even delivery of the quorum-reaching vote cannot skip the older pending
    # audit row.
    assert world.mark_approval_audit_delivered(second.event_id)
    assert world.get_approval(approval_id).status == "pending"
    assert world.approval_state(approval_id)["audit_pending_count"] == 1

    assert world.mark_approval_audit_delivered(first.event_id)
    state = world.approval_state(approval_id)
    assert state["status"] == "approved"
    assert state["effective"] is True
    assert state["audit_pending_count"] == 0


def test_pending_pre_v30_signoff_is_backfilled_before_new_vote_reaches_quorum(
    tmp_path,
):
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    approval_id = world.create_approval(
        "upgraded-quorum",
        risk="critical",
        approvals_required=2,
    )
    # Simulate a signoff written by the pre-v30 immediate path.
    assert world.decide_approval(
        approval_id,
        "approved",
        decided_by="u:legacy",
    )
    assert world.get_approval(approval_id).status == "pending"
    assert world.pending_approval_audit_events(approval_id=approval_id) == []

    current = world.decide_approval_audited(
        approval_id,
        "approved",
        decided_by="u:new",
    )
    queued = world.pending_approval_audit_events(approval_id=approval_id)
    assert len(queued) == 2
    assert {event.decided_by for event in queued} == {"u:legacy", "u:new"}
    assert current.final_status == "approved"

    # The newer quorum vote alone cannot make an unaudited legacy vote
    # authoritative.
    assert world.mark_approval_audit_delivered(current.event_id)
    assert world.get_approval(approval_id).status == "pending"
    legacy = next(event for event in queued if event.decided_by == "u:legacy")
    assert world.mark_approval_audit_delivered(legacy.event_id)
    assert world.get_approval(approval_id).status == "approved"


def test_legacy_decision_api_cannot_bypass_an_active_audit_outbox(tmp_path):
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    single = world.create_approval("single", risk="high")
    single_event = world.decide_approval_audited(
        single,
        "approved",
        decided_by="u:alice",
    )
    assert world.decide_approval(
        single,
        "approved",
        decided_by="u:bypass",
    ) is False
    assert world.get_approval(single).status == "pending"
    assert world.mark_approval_audit_delivered(single_event.event_id)
    assert world.get_approval(single).status == "approved"

    quorum = world.create_approval(
        "quorum",
        risk="critical",
        approvals_required=2,
    )
    first = world.decide_approval_audited(
        quorum,
        "approved",
        decided_by="u:alice",
    )
    assert world.mark_approval_audit_delivered(first.event_id)
    assert world.decide_approval(
        quorum,
        "approved",
        decided_by="u:bypass",
    ) is False
    state = world.approval_state(quorum)
    assert state["status"] == "pending"
    assert state["approved_count"] == 1


def test_a_refused_delivery_commit_tells_no_webhook_subscriber_the_approval_was_decided(tmp_path, monkeypatch):
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    approval_id = world.create_approval("shell", risk="high")
    event = world.decide_approval_audited(approval_id, "approved", decided_by="user:dana")
    told = []
    monkeypatch.setattr(world, "_emit_approval_event", lambda *args, **kwargs: told.append(args))
    calls = []

    def guard():
        calls.append(1)
        if len(calls) == 2:  # the guard that runs just before the commit
            raise PermissionError("authority changed")

    with pytest.raises(PermissionError):
        world.mark_approval_audit_delivered(event.event_id, effect_guard=guard)

    # The transaction rolled back, so the approval is still pending and nobody was told otherwise.
    assert world.get_approval(approval_id).status == "pending"
    assert world.get_approval_audit_event(event.event_id).delivered_at is None
    assert told == []

    assert world.mark_approval_audit_delivered(event.event_id) is True
    assert world.get_approval(approval_id).status == "approved"
    assert [args[:2] for args in told] == [("approval.decided", approval_id)]
