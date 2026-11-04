"""Custom / edited assessment templates: authoring, overriding a built-in,
scoring parity, and department routing."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from maverick.assessment import (
    AssessmentConflict,
    AssessmentSession,
    _custom_templates_dir,
    delete_custom_template,
    get_template,
    list_templates,
    save_custom_template,
    save_session,
    template_department,
    template_for_saved_record,
    template_state,
)


@pytest.fixture(autouse=True)
def _fresh_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))


def _payload(**over):
    base = {
        "type": "dpia_lite", "title": "DPIA Lite",
        "framework": "GDPR Art. 35 (lightweight)", "department": "privacy",
        "questions": [
            {"text": "Is the processing high risk to data subjects?",
             "risk_answer": "yes", "severity": "high", "section": "Scope"},
            {"text": "Is a defined retention schedule in place?",
             "risk_answer": "no", "severity": "medium",
             "section": "Retention"},
        ],
    }
    base.update(over)
    return base


def test_author_new_template_and_score_with_it():
    tpl = save_custom_template(_payload())
    assert tpl.type == "dpia_lite"
    assert get_template("dpia_lite").title == "DPIA Lite"
    assert "dpia_lite" in {t.type for t in list_templates()}
    assert template_department("dpia_lite") == "privacy"
    # The engine scores a custom questionnaire exactly like a built-in.
    s = AssessmentSession(type="dpia_lite", subject="New analytics tool")
    s.record("dpia_lite_q1", "yes")
    s.record("dpia_lite_q2", "no")
    save_session(s)
    r = s.evaluate()
    assert r.residual_risk == "high"
    assert r.risks_in_scope == 2


def test_override_builtin_and_restore():
    save_custom_template(_payload(
        type="pia", title="PIA (company edition)",
        questions=[{"text": "Company-specific question?",
                    "risk_answer": "no", "severity": "low"}]))
    assert get_template("pia").title == "PIA (company edition)"
    assert len(get_template("pia").questions) == 1
    # One catalog entry per type: the override wins, no duplicate.
    assert [t.type for t in list_templates()].count("pia") == 1
    assert delete_custom_template("pia") is True
    assert get_template("pia").title == "Privacy Impact Assessment"
    assert delete_custom_template("pia") is False  # nothing left to delete


def test_validation_rejects_bad_input():
    for bad in (
        _payload(type="Bad Type!"),
        _payload(title=""),
        _payload(questions=[]),
        _payload(questions=[{"text": "ok?", "severity": "urgent"}]),
        _payload(questions=[{"text": "ok?", "risk_answer": "maybe"}]),
        _payload(department="engineering"),
    ):
        with pytest.raises(ValueError):
            save_custom_template(bad)


def test_finance_department_routing():
    save_custom_template(_payload(
        type="tax_readiness", title="Tax Readiness Check",
        framework="internal tax policy", department="finance"))
    assert template_department("tax_readiness") == "finance"
    assert template_department("sox_control") == "finance"
    assert template_department("pia") == "privacy"


def test_releases_are_immutable_and_stale_publication_is_rejected():
    before = template_state("dpia_lite")
    first = save_custom_template(
        _payload(), expected_revision=before["revision"],
        expected_digest=before["digest"], actor="user:admin",
    )
    release = (_custom_templates_dir() / "releases" / "dpia_lite"
               / f"{first.digest}.json")
    immutable_bytes = release.read_bytes()

    second_payload = _payload(title="DPIA Lite v2")
    second = save_custom_template(
        second_payload, expected_revision=first.revision,
        expected_digest=first.digest, actor="user:admin",
    )
    assert second.revision == first.revision + 1
    assert second.digest != first.digest
    assert release.read_bytes() == immutable_bytes

    with pytest.raises(AssessmentConflict):
        save_custom_template(
            _payload(title="stale overwrite"),
            expected_revision=first.revision,
            expected_digest=first.digest,
            actor="user:stale-admin",
        )
    assert get_template("dpia_lite").title == "DPIA Lite v2"


def test_insert_and_reorder_preserve_existing_question_ids():
    first = save_custom_template(_payload())
    assert [q.id for q in first.questions] == ["dpia_lite_q1", "dpia_lite_q2"]
    q1, q2 = first.questions
    updated = save_custom_template(
        _payload(questions=[
            {"text": "Was a privacy owner assigned?", "risk_answer": "no",
             "severity": "medium"},
            {"id": q2.id, "text": q2.text, "section": q2.section,
             "risk_answer": q2.risk_answer, "severity": q2.severity,
             "guidance": q2.guidance},
            {"id": q1.id, "text": q1.text, "section": q1.section,
             "risk_answer": q1.risk_answer, "severity": q1.severity,
             "guidance": q1.guidance},
        ]),
        expected_revision=first.revision,
        expected_digest=first.digest,
    )
    assert [q.id for q in updated.questions] == [
        "dpia_lite_q3", "dpia_lite_q2", "dpia_lite_q1",
    ]


def test_removed_question_id_is_never_reassigned_to_new_semantics():
    first = save_custom_template(_payload())
    q1, q2 = first.questions
    without_q2 = save_custom_template(
        _payload(questions=[{
            "id": q1.id, "text": q1.text, "section": q1.section,
            "risk_answer": q1.risk_answer, "severity": q1.severity,
            "guidance": q1.guidance,
        }]),
        expected_revision=first.revision,
        expected_digest=first.digest,
    )
    replacement = save_custom_template(
        _payload(questions=[
            {
                "id": q1.id, "text": q1.text, "section": q1.section,
                "risk_answer": q1.risk_answer, "severity": q1.severity,
                "guidance": q1.guidance,
            },
            {
                "text": "Is a privacy owner assigned?",
                "risk_answer": "no",
                "severity": "medium",
            },
        ]),
        expected_revision=without_q2.revision,
        expected_digest=without_q2.digest,
    )

    assert [question.id for question in replacement.questions] == [
        q1.id,
        "dpia_lite_q3",
    ]
    assert q2.id not in {question.id for question in replacement.questions}


def test_retired_question_id_cannot_be_explicitly_reused():
    first = save_custom_template(_payload())
    q1, retired = first.questions
    without_retired = save_custom_template(
        _payload(questions=[{
            "id": q1.id,
            "text": q1.text,
            "section": q1.section,
            "risk_answer": q1.risk_answer,
            "severity": q1.severity,
            "guidance": q1.guidance,
        }]),
        expected_revision=first.revision,
        expected_digest=first.digest,
    )

    with pytest.raises(ValueError, match="belongs to a retired question"):
        save_custom_template(
            _payload(questions=[
                {
                    "id": q1.id,
                    "text": q1.text,
                    "section": q1.section,
                    "risk_answer": q1.risk_answer,
                    "severity": q1.severity,
                    "guidance": q1.guidance,
                },
                {
                    "id": retired.id,
                    "text": "Does an unrelated new control exist?",
                    "risk_answer": "no",
                    "severity": "high",
                },
            ]),
            expected_revision=without_retired.revision,
            expected_digest=without_retired.digest,
        )
    assert get_template("dpia_lite").digest == without_retired.digest


def test_template_description_is_preserved_in_published_release():
    description = "Explain why the governed assessment is required."
    published = save_custom_template(_payload(description=description))

    assert published.description == description
    assert get_template("dpia_lite").description == description


def test_inflight_session_is_pinned_to_exact_release():
    first = save_custom_template(_payload(questions=[{
        "id": "stable_control", "text": "Original high-risk question?",
        "risk_answer": "yes", "severity": "high",
    }]))
    session = AssessmentSession(type="dpia_lite", subject="Acme")
    session.record("stable_control", "yes")

    second = save_custom_template(
        _payload(questions=[{
            "id": "stable_control", "text": "Replacement low-risk question?",
            "risk_answer": "no", "severity": "low",
        }]),
        expected_revision=first.revision, expected_digest=first.digest,
    )
    assert second.digest != first.digest
    result = session.evaluate()
    assert result.risk_rating == "high"
    assert result.findings[0].question == "Original high-risk question?"

    save_session(session)
    from maverick.assessment import load_saved
    saved = load_saved(session.id)
    assert saved["template_digest"] == first.digest
    pinned = template_for_saved_record(saved)
    assert pinned.digest == first.digest
    assert pinned.questions[0].text == "Original high-risk question?"
    assert get_template("dpia_lite").digest == second.digest


def test_concurrent_publications_have_one_cas_winner():
    base = template_state("dpia_lite")
    barrier = Barrier(2)

    def publish(title: str):
        barrier.wait()
        try:
            return save_custom_template(
                _payload(title=title),
                expected_revision=base["revision"],
                expected_digest=base["digest"],
            )
        except AssessmentConflict as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(publish, ["release-a", "release-b"]))
    assert sum(isinstance(value, AssessmentConflict) for value in outcomes) == 1
    assert sum(not isinstance(value, AssessmentConflict) for value in outcomes) == 1
    assert template_state("dpia_lite")["revision"] == base["revision"] + 1


def test_delete_tombstone_prevents_aba_republication():
    first = save_custom_template(_payload())
    assert delete_custom_template(
        "dpia_lite", expected_revision=first.revision,
        expected_digest=first.digest, actor="user:admin",
    )
    tombstone = template_state("dpia_lite")
    assert tombstone == {
        "type": "dpia_lite", "revision": first.revision + 1,
        "digest": "", "custom": False, "builtin": False, "exists": False,
    }
    with pytest.raises(AssessmentConflict):
        save_custom_template(
            _payload(title="stale resurrection"),
            expected_revision=first.revision,
            expected_digest=first.digest,
        )
    republished = save_custom_template(
        _payload(title="governed resurrection"),
        expected_revision=tombstone["revision"],
        expected_digest=tombstone["digest"],
    )
    assert republished.revision == first.revision + 2


def test_failed_template_audit_retries_on_exact_read(monkeypatch):
    import maverick.assessment as assessment

    attempts = 0

    def fail_once(_receipt):
        nonlocal attempts
        attempts += 1
        return attempts > 1

    monkeypatch.setattr(assessment, "_deliver_audit", fail_once)
    published = save_custom_template(_payload(), actor="user:admin")
    assert assessment._load_state_unlocked("dpia_lite")["_audit_pending"]
    assert template_state("dpia_lite")["digest"] == published.digest
    assert assessment._load_state_unlocked("dpia_lite")["_audit_pending"] == []
    assert attempts == 2


def test_full_template_audit_outbox_blocks_then_recovery_makes_room(monkeypatch):
    import maverick.assessment as assessment

    monkeypatch.setattr(assessment, "_deliver_audit", lambda _receipt: False)
    first = save_custom_template(_payload(), actor="user:admin")
    state = assessment._load_state_unlocked("dpia_lite")
    state["_audit_pending"] = [
        {
            "event_id": f"event-{i}", "kind": "QUESTIONNAIRE_TEST",
            "actor": "user:admin", "payload": {}, "created_at": 1.0,
        }
        for i in range(assessment._AUDIT_OUTBOX_LIMIT)
    ]
    assessment._write_state_unlocked("dpia_lite", state)
    before = assessment._state_path("dpia_lite").read_bytes()
    with pytest.raises(assessment.AssessmentAuditBackpressure):
        save_custom_template(
            _payload(title="blocked"), expected_revision=first.revision,
            expected_digest=first.digest, actor="user:admin",
        )
    assert assessment._state_path("dpia_lite").read_bytes() == before

    monkeypatch.setattr(assessment, "_deliver_audit", lambda _receipt: True)
    assert template_state("dpia_lite")["revision"] == first.revision
    assert assessment._load_state_unlocked("dpia_lite")["_audit_pending"] == []
    recovered = save_custom_template(
        _payload(title="recovered"), expected_revision=first.revision,
        expected_digest=first.digest, actor="user:admin",
    )
    assert recovered.revision == first.revision + 1
