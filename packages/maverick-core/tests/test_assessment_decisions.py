"""Reviewer decisions + review cadence: the record comes due instead of
dying in a folder, and the follow-up cycle re-opens it."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from maverick.assessment import (
    AssessmentConflict,
    AssessmentSession,
    AssessmentStateError,
    add_followups,
    answer_followup,
    decide_assessment,
    list_saved,
    load_saved,
    save_session,
)


@pytest.fixture(autouse=True)
def _fresh_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))


def _saved() -> AssessmentSession:
    s = AssessmentSession(type="pia", subject="Acme CRM")
    s.record("pia_necessity", "yes")
    save_session(s)
    return s


def test_approve_schedules_the_next_review():
    s = _saved()
    rec = decide_assessment(s.id, "approved", decided_by="dpo",
                            cadence_days=365)
    assert rec["status"] == "approved"
    assert rec["decided_by"] == "dpo"
    assert rec["cadence_days"] == 365
    expected = rec["decided_at"] + 365 * 86400
    assert abs(rec["next_review_at"] - expected) < 1
    row = list_saved()[0]
    assert row["status"] == "approved"
    assert row["review_due"] is False


def test_no_cadence_means_no_re_review_date():
    s = _saved()
    rec = decide_assessment(s.id, "approved", cadence_days=0)
    assert rec["next_review_at"] is None
    rec2 = decide_assessment(s.id, "rejected", cadence_days=365)
    assert rec2["status"] == "rejected"
    assert rec2["next_review_at"] is None  # rejections never come due


def test_review_due_when_the_cadence_elapses(monkeypatch):
    s = _saved()
    decide_assessment(s.id, "approved", cadence_days=30)
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 31 * 86400)
    row = list_saved()[0]
    assert row["review_due"] is True


def test_followup_cycle_reopens_a_decided_record():
    s = _saved()
    decide_assessment(s.id, "approved")
    rec = add_followups(s.id, ["Annual re-attestation: anything changed?"],
                        asked_by="dpo")
    assert rec["status"] == "needs_more"
    fid = rec["followups"][-1]["id"]
    rec = answer_followup(s.id, fid, "No changes to processing.",
                          answered_by="requester")
    assert rec["status"] == "pending_review"
    rec = decide_assessment(s.id, "approved", cadence_days=180)
    assert rec["status"] == "approved"
    assert rec["cadence_days"] == 180


def test_unknown_id_and_bad_decision():
    assert decide_assessment("nope", "approved") is None
    s = _saved()
    with pytest.raises(ValueError):
        decide_assessment(s.id, "maybe")
    # The failed decision left no partial write behind.
    assert load_saved(s.id).get("status", "pending_review") == "pending_review"


def test_cannot_approve_unanswered_required_followups():
    s = _saved()
    pending = add_followups(s.id, ["Provide the countersigned DPA."], asked_by="dpo")
    with pytest.raises(AssessmentStateError, match="unanswered follow-ups"):
        decide_assessment(
            s.id, "approved", decided_by="dpo",
            expected_revision=pending["revision"],
        )
    unchanged = load_saved(s.id)
    assert unchanged["revision"] == pending["revision"]
    assert unchanged["status"] == "needs_more"


def test_concurrent_decisions_have_one_cas_winner():
    s = _saved()
    revision = load_saved(s.id)["revision"]
    barrier = Barrier(2)

    def decide(value: str):
        barrier.wait()
        try:
            return decide_assessment(
                s.id, value, decided_by=f"user:{value}",
                expected_revision=revision,
            )
        except AssessmentConflict as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(decide, ["approved", "rejected"]))
    assert sum(isinstance(value, AssessmentConflict) for value in outcomes) == 1
    assert sum(isinstance(value, dict) for value in outcomes) == 1
    saved = load_saved(s.id)
    assert saved["revision"] == revision + 1
    assert saved["status"] in {"approved", "rejected"}


def test_unknown_followup_answer_is_a_true_noop():
    s = _saved()
    pending = add_followups(s.id, ["Question?"], asked_by="dpo")
    before = load_saved(s.id)
    assert answer_followup(
        s.id, "does-not-exist", "answer", answered_by="respondent",
        expected_revision=pending["revision"],
    ) is None
    after = load_saved(s.id)
    assert after == before


def test_unknown_followup_is_noop_even_if_status_is_inconsistent():
    import maverick.assessment as assessment

    s = _saved()
    pending = add_followups(s.id, ["Question?"], asked_by="dpo")
    followup_id = pending["followups"][0]["id"]
    answered = answer_followup(
        s.id,
        followup_id,
        "Answered",
        answered_by="respondent",
        expected_revision=pending["revision"],
    )
    assessment._rewrite_saved(
        s.id,
        lambda record: record.update(status="needs_more"),
        expected_revision=answered["revision"],
    )
    before = load_saved(s.id)

    assert answer_followup(
        s.id,
        "does-not-exist",
        "answer",
        answered_by="respondent",
        expected_revision=before["revision"],
    ) is None
    assert load_saved(s.id) == before


@pytest.mark.parametrize("revision", [False, "1", 1.5, -1])
def test_persisted_assessment_rejects_non_monotonic_revision(revision):
    import maverick.assessment as assessment

    session = _saved()
    path = assessment._assessment_path(session.id)
    record = assessment._load_saved_raw(session.id)
    record["revision"] = revision
    assessment._write_saved_path_unlocked(path, record)
    corrupt_bytes = path.read_bytes()

    with pytest.raises(AssessmentStateError, match="revision is invalid"):
        load_saved(session.id)
    with pytest.raises(AssessmentStateError, match="revision is invalid"):
        decide_assessment(
            session.id,
            "rejected",
            expected_revision=1,
        )
    assert path.read_bytes() == corrupt_bytes


@pytest.mark.parametrize("outbox", [False, 0, "", {}])
def test_persisted_assessment_rejects_falsey_wrong_shaped_audit_outbox(outbox):
    import maverick.assessment as assessment

    session = _saved()
    path = assessment._assessment_path(session.id)
    record = assessment._load_saved_raw(session.id)
    record["_audit_pending"] = outbox
    assessment._write_saved_path_unlocked(path, record)

    with pytest.raises(AssessmentStateError, match="audit outbox is invalid"):
        load_saved(session.id)


def test_failed_decision_audit_retries_on_exact_read(monkeypatch):
    import maverick.assessment as assessment

    s = _saved()
    attempts = 0

    def fail_once(_receipt):
        nonlocal attempts
        attempts += 1
        return attempts > 1

    monkeypatch.setattr(assessment, "_deliver_audit", fail_once)
    decide_assessment(
        s.id, "approved", decided_by="user:dpo",
        expected_revision=load_saved(s.id)["revision"],
    )
    assert assessment._load_saved_raw(s.id)["_audit_pending"]
    assert load_saved(s.id)["status"] == "approved"
    assert assessment._load_saved_raw(s.id)["_audit_pending"] == []
    assert attempts == 2


def test_full_assessment_audit_outbox_blocks_then_read_recovery(monkeypatch):
    import maverick.assessment as assessment

    s = _saved()
    raw = assessment._load_saved_raw(s.id)
    raw["_audit_pending"] = [
        {
            "event_id": f"event-{i}", "kind": "ASSESSMENT_TEST",
            "actor": "user:dpo", "payload": {}, "created_at": 1.0,
        }
        for i in range(assessment._AUDIT_OUTBOX_LIMIT)
    ]
    path = assessment._assessment_path(s.id)
    assessment._write_saved_path_unlocked(path, raw)
    before = path.read_bytes()
    monkeypatch.setattr(assessment, "_deliver_audit", lambda _receipt: False)
    with pytest.raises(assessment.AssessmentAuditBackpressure):
        decide_assessment(
            s.id, "rejected", decided_by="user:dpo",
            expected_revision=raw["revision"],
        )
    assert path.read_bytes() == before

    monkeypatch.setattr(assessment, "_deliver_audit", lambda _receipt: True)
    assert load_saved(s.id)["revision"] == raw["revision"]
    assert assessment._load_saved_raw(s.id)["_audit_pending"] == []
    recovered = decide_assessment(
        s.id, "rejected", decided_by="user:dpo",
        expected_revision=raw["revision"],
    )
    assert recovered["revision"] == raw["revision"] + 1


# --- assignment: whose desk is this on? -----------------------------------

def test_assign_puts_a_record_on_a_named_desk_and_unassigns():
    from maverick.assessment import assign_assessment
    s = _saved()
    assert list_saved()[0]["assignee"] == ""      # unassigned by default

    rec = assign_assessment(s.id, "A. Novak", assigned_by="dpo")
    assert rec["assignee"] == "A. Novak"
    assert rec["assigned_by"] == "dpo" and rec["assigned_at"] > 0
    assert list_saved()[0]["assignee"] == "A. Novak"

    # Blank returns it to the pool and clears the provenance with it.
    rec = assign_assessment(s.id, "", assigned_by="dpo")
    assert "assignee" not in rec and "assigned_at" not in rec
    assert list_saved()[0]["assignee"] == ""


def test_assign_is_revision_guarded():
    from maverick.assessment import assign_assessment
    s = _saved()
    stale = list_saved()[0]["revision"]
    assign_assessment(s.id, "A. Novak", expected_revision=stale)
    with pytest.raises(AssessmentConflict):
        assign_assessment(s.id, "Someone Else", expected_revision=stale)


def test_assign_does_not_gate_who_may_decide():
    # Routing, not permission: assignment must never become a second, silent
    # approval gate on top of the real one.
    from maverick.assessment import assign_assessment
    s = _saved()
    assign_assessment(s.id, "A. Novak")
    rec = decide_assessment(s.id, "approved", decided_by="someone-else",
                            cadence_days=None)
    assert rec["status"] == "approved" and rec["decided_by"] == "someone-else"
    assert rec["assignee"] == "A. Novak"     # and the owner is untouched


def test_assign_unknown_assessment_returns_none():
    from maverick.assessment import assign_assessment
    assert assign_assessment("no-such-id", "A. Novak") is None
