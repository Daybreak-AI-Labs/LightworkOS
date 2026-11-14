"""Tests for audit and world-model erasure: subject-scrubbing, user deletion,
the erase audit event and subgoal cascades.
"""
from __future__ import annotations

# --- privacy: `maverick erase` must append an audit event without subject-derived data ---

def test_erase_emits_non_subject_derived_audit_event(tmp_path, monkeypatch):
    import os

    os.environ.pop("MAVERICK_DB", None)
    import maverick.audit as audit_mod
    from click.testing import CliRunner
    from maverick import cli as cli_mod
    from maverick.world_model import WorldModel

    captured: list = []
    monkeypatch.setattr(
        audit_mod, "record",
        lambda kind, **payload: captured.append((kind, payload)),
    )

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    conv_id = wm.get_or_create_conversation("telegram", "u123").id
    gid = wm.create_goal("hello")
    wm.append_turn(conv_id, "user", "hi there", goal_id=gid)
    wm.close()

    result = CliRunner().invoke(
        cli_mod.main,
        ["--db", str(db), "erase", "--channel", "telegram",
         "--user", "u123", "--yes"],
    )
    assert result.exit_code == 0, result.output

    erase_events = [p for (k, p) in captured if k == "erase"]
    assert erase_events, "no erase audit event emitted"
    ev = erase_events[0]
    assert ev["channel"] == "telegram"
    # Subject is never stored or deterministically derived (Art. 30 without
    # enabling offline dictionary recovery of low-entropy user IDs).
    assert "u123" not in str(ev)
    assert "user_hash" not in ev
    assert isinstance(ev["erasure_id"], str)
    # Receipt v2 uses a full 128-bit random identifier. It remains
    # non-subject-derived while materially reducing collision risk across a
    # deployment-wide immutable receipt set.
    assert len(ev["erasure_id"]) == 32
    int(ev["erasure_id"], 16)


def test_erase_cascades_subgoals_without_fk_abort(tmp_path, monkeypatch):
    """A recursive swarm's subgoal (goals.parent_id) isn't tied to a turn,
    so the turn-derived delete set omitted it; deleting the parent then hit
    the self-FK and rolled the WHOLE erasure back -- a required Art.17
    deletion that silently did nothing. The transitive-closure expansion +
    deferred FK must delete the parent AND every descendant."""
    import os

    os.environ.pop("MAVERICK_DB", None)
    import maverick.audit as audit_mod
    from click.testing import CliRunner
    from maverick import cli as cli_mod
    from maverick.world_model import WorldModel

    monkeypatch.setattr(audit_mod, "record", lambda kind, **payload: None)
    # scrub_user touches the real ~/.maverick/audit dir; neutralize for hermeticity.
    monkeypatch.setattr("maverick.audit.scrub_user", lambda *a, **k: (0, 0))

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    conv_id = wm.get_or_create_conversation("sms", "bob").id
    parent = wm.create_goal("parent goal")
    child = wm.create_goal("child subgoal", parent_id=parent)       # not tied to a turn
    grandchild = wm.create_goal("grandchild", parent_id=child)      # 2 levels deep
    wm.append_turn(conv_id, "user", "do the thing", goal_id=parent)
    wm.close()

    result = CliRunner().invoke(
        cli_mod.main,
        ["--db", str(db), "erase", "--channel", "sms", "--user", "bob", "--yes"],
    )
    assert result.exit_code == 0, result.output

    wm2 = WorldModel(db)
    try:
        remaining = wm2.conn.execute(
            "SELECT id FROM goals WHERE id IN (?, ?, ?)",
            (parent, child, grandchild),
        ).fetchall()
        assert remaining == [], f"parent/subgoals survived erase: {remaining}"
        convs = [c for c in wm2.list_conversations("sms") if c.user_id == "bob"]
        assert convs == [], "conversation survived erase"
    finally:
        wm2.close()


# ---------- audit erase ----------

def test_audit_erase_scrubs_matching(tmp_path):
    from maverick.audit import AuditEvent, AuditLog, EventKind
    from maverick.audit.erase import scrub_user
    audit_dir = tmp_path / "audit"
    al = AuditLog(audit_dir=audit_dir)
    import time as _time
    # 3 events: 2 for the target user, 1 for another.
    al.record(AuditEvent(ts=_time.time(), kind=EventKind.GOAL_START,
                          agent="orch", goal_id=1,
                          payload={"channel": "tg", "user_id": "alice", "title": "t1"}))
    al.record(AuditEvent(ts=_time.time(), kind=EventKind.GOAL_END,
                          agent="orch", goal_id=1,
                          payload={"channel": "tg", "user_id": "alice", "status": "succeeded"}))
    al.record(AuditEvent(ts=_time.time(), kind=EventKind.GOAL_START,
                          agent="orch", goal_id=2,
                          payload={"channel": "tg", "user_id": "bob", "title": "t3"}))

    matched, scanned = scrub_user("tg", "alice", audit_dir=audit_dir)
    assert matched == 2
    assert scanned == 3

    # Re-read the file: alice tombstoned, bob intact.
    rows = al.tail(20)
    target_rows = [r for r in rows if r.get("user_id") in ("alice", "[REDACTED]")]
    bob_rows = [r for r in rows if r.get("user_id") == "bob"]
    assert len(target_rows) == 2
    assert all(r.get("user_id") == "[REDACTED]" for r in target_rows)
    assert len(bob_rows) == 1


def test_audit_erase_delete_user(tmp_path):
    from maverick.audit import AuditEvent, AuditLog, EventKind
    from maverick.audit.erase import delete_user
    audit_dir = tmp_path / "audit"
    al = AuditLog(audit_dir=audit_dir)
    import time as _time
    al.record(AuditEvent(ts=_time.time(), kind=EventKind.GOAL_START,
                          agent="orch", goal_id=1,
                          payload={"channel": "tg", "user_id": "alice"}))
    al.record(AuditEvent(ts=_time.time(), kind=EventKind.GOAL_START,
                          agent="orch", goal_id=2,
                          payload={"channel": "tg", "user_id": "bob"}))

    matched, scanned = delete_user("tg", "alice", audit_dir=audit_dir)
    assert matched == 1
    assert scanned == 1  # only bob's row remains

    rows = al.tail(20)
    assert len(rows) == 1
    assert rows[0]["user_id"] == "bob"


def test_audit_erase_missing_dir_no_crash(tmp_path):
    from maverick.audit.erase import scrub_user
    # Audit dir doesn't exist -> 0, 0; no exception.
    matched, scanned = scrub_user("tg", "alice", audit_dir=tmp_path / "nope")
    assert (matched, scanned) == (0, 0)


def test_audit_erase_logs_only_redacted_subject(tmp_path, caplog):
    import logging
    import time as _time

    from maverick.audit import AuditEvent, AuditLog, EventKind
    from maverick.audit.erase import delete_user, scrub_user

    audit_dir = tmp_path / "audit"
    al = AuditLog(audit_dir=audit_dir)
    secret_user = "alice-secret-123"
    al.record(AuditEvent(ts=_time.time(), kind=EventKind.GOAL_START,
                          agent="orch", goal_id=1,
                          payload={"channel": "tg", "user_id": secret_user}))

    with caplog.at_level(logging.INFO, logger="maverick.audit.erase"):
        scrub_user("tg", secret_user, audit_dir=audit_dir)
        delete_user("tg", secret_user, audit_dir=audit_dir)

    log_output = caplog.text
    assert secret_user not in log_output
    assert "channel=tg" not in log_output
    assert "user_id=" not in log_output
    assert "subject_hash=" in log_output


def test_audit_erase_keeps_non_object_line_instead_of_crashing(tmp_path):
    from maverick.audit import AuditEvent, AuditLog, EventKind
    from maverick.audit.erase import scrub_user

    audit_dir = tmp_path / "audit"
    al = AuditLog(audit_dir=audit_dir, sign=False)
    al.record(AuditEvent(ts=1.0, kind=EventKind.GOAL_START, agent="orch", goal_id=1,
                         payload={"channel": "tg", "user_id": "alice"}))
    (day,) = audit_dir.glob("*.ndjson")
    with open(day, "a", encoding="utf-8") as f:
        f.write("123\n")

    matched, _ = scrub_user("tg", "alice", audit_dir=audit_dir)

    assert matched == 1
    lines = day.read_text().splitlines()
    assert lines[-1] == "123" and "alice" not in day.read_text()
