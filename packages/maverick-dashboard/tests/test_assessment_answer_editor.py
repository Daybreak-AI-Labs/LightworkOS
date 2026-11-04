"""App intake and answers use the pinned assessment model without approving it."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import api
    from maverick_dashboard.app import app

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    api._world_cache.clear()
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()
    api._world_cache.clear()


def start(client, subject='Acme, "North"', kind="pia"):
    escaped = subject.replace('"', '""')
    response = client.post("/api/v1/assess/bulk-import", json={"csv": f'subject,type\n"{escaped}","{kind}"'})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["created_count"] == 1 and body["error_count"] == 0
    assert body["created"][0]["subject"] == subject
    return body["created"][0]["id"]


def test_complete_questionnaire_scores_answers_but_waits_for_human_review(client):
    identifier = start(client)
    record = client.get(f"/api/v1/assess/sessions/{identifier}").json()
    pinned = record["template_digest"]
    for question in record["question_text"]:
        response = client.put(f"/api/v1/assess/sessions/{identifier}/answers/{question}", json={"answer": "yes", "note": "Confirmed by the respondent", "expected_revision": record["revision"]})
        assert response.status_code == 200, response.text
        record = response.json()
        assert record["template_digest"] == pinned
    assert record["result"]["answered"] == record["result"]["total"]
    assert record["status"] == "pending_review"
    assert "decided_by" not in record
    assert all(value["by"] for value in record["answers"].values())


def test_intake_worklist_does_not_present_unanswered_questions_as_minimal_risk(client):
    import re

    identifier = start(client, subject="Incomplete intake")
    summaries = client.get("/api/v1/assess/sessions").json()["sessions"]
    summary = next(row for row in summaries if row["id"] == identifier)
    assert summary["answered"] == 0 and summary["total"] > 0
    response = client.get("/privacy")
    assert response.status_code == 200
    row = next(row for row in re.findall(r'<tr data-status=.*?</tr>', response.text, re.DOTALL) if identifier in row)
    assert "Incomplete" in row and "resolved" in row
    assert 'badge done">minimal' not in row


@pytest.mark.parametrize("subject", ["Subject", "Vendor", "Name", 'A, B "C"\nD'])
def test_intake_explicit_header_does_not_drop_real_subject_names(client, subject):
    assert start(client, subject)


def test_custom_questionnaire_can_start_and_stays_pinned_after_new_publication(client):
    from maverick.assessment import save_custom_template

    payload = {"type": "custom_intake", "title": "Custom intake", "framework": "Internal", "department": "privacy",
               "questions": [{"id": "control", "text": "Is the control present?", "risk_answer": "no", "severity": "high"}]}
    save_custom_template(payload)
    identifier = start(client, kind="custom_intake")
    save_custom_template({**payload, "questions": [{"id": "replacement", "text": "Has the control changed?", "risk_answer": "yes", "severity": "high"}]})
    response = client.put(f"/api/v1/assess/sessions/{identifier}/answers/control", json={"answer": "no", "expected_revision": 1})
    assert response.status_code == 200, response.text
    assert response.json()["result"]["residual_risk"] == "high"
    assert "control" in response.json()["question_text"]
    assert "replacement" not in response.json()["question_text"]


def test_stale_answer_and_unknown_question_leave_the_record_unchanged(client):
    identifier = start(client)
    url = f"/api/v1/assess/sessions/{identifier}/answers/pia_necessity"
    first = client.put(url, json={"answer": "yes", "expected_revision": 1})
    assert first.status_code == 200
    assert client.put(url, json={"answer": "no", "expected_revision": 1}).status_code == 409
    assert client.put(url.replace("pia_necessity", "invented"), json={"answer": "no", "expected_revision": 2}).status_code == 422
    assert client.put(url, json={"answer": "verified", "expected_revision": 2}).status_code == 422
    record = client.get(f"/api/v1/assess/sessions/{identifier}").json()
    assert record["revision"] == 2 and record["answers"]["pia_necessity"]["answer"] == "yes"


def test_human_edit_retains_previous_source_metadata_without_claiming_it_for_new_answer(client):
    from maverick.assessment import set_assessment_answer_ai_metadata

    identifier = start(client)
    url = f"/api/v1/assess/sessions/{identifier}/answers/pia_necessity"
    assert client.put(url, json={"answer": "yes", "expected_revision": 1}).status_code == 200
    set_assessment_answer_ai_metadata(identifier, "pia_necessity", confidence=0.8, flags=["human_review_required"],
                                      source_kind="document_evidence", source_ref="original-document", source_sha256="a" * 64,
                                      recorded_by="analyst", expected_revision=2)
    response = client.put(url, json={"answer": "unknown", "note": "Evidence could not be confirmed", "expected_revision": 3})
    assert response.status_code == 200, response.text
    record = response.json()
    assert "ai_metadata" not in record["answers"]["pia_necessity"]
    previous = record["answer_history"][-1]["previous_answer"]
    assert previous["ai_metadata"]["source"]["ref"] == "original-document"
    assert previous["answer"] == "yes"
    assert record["status"] == "pending_review"


def test_decided_records_require_reopening_and_followups_still_gate_review(client):
    from maverick.assessment import add_followups, decide_assessment

    identifier = start(client)
    decide_assessment(identifier, "approved", expected_revision=1)
    url = f"/api/v1/assess/sessions/{identifier}"
    assert client.put(url + "/answers/pia_necessity", json={"answer": "yes", "expected_revision": 2}).status_code == 409
    reopened = add_followups(identifier, ["Which evidence confirms this?"], expected_revision=2)
    assert reopened["status"] == "needs_more"
    answered = client.put(url + "/answers/pia_necessity", json={"answer": "yes", "expected_revision": 3}).json()
    assert answered["status"] == "needs_more"
    response = client.put(url + "/followups/fu-1/answer", json={"answer": "The dated inspection report", "expected_revision": 4})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "pending_review"
    assert response.json()["followups"][0]["answered_by"]
    assert client.put(url + "/followups/fu-1/answer", json={"answer": "stale", "expected_revision": 4}).status_code == 409


def test_read_only_callers_cannot_record_answers(client, monkeypatch):
    from maverick_dashboard import api

    identifier = start(client)

    def require(request, permission):
        assert permission == "operate"
        raise HTTPException(status_code=403)

    monkeypatch.setattr(api, "require_permission", require)
    assert client.put(f"/api/v1/assess/sessions/{identifier}/answers/pia_necessity", json={"answer": "yes", "expected_revision": 1}).status_code == 403


def test_followup_decision_between_preflight_and_write_cannot_be_reopened(client, monkeypatch):
    from maverick import assessment

    identifier = start(client)
    assessment.add_followups(identifier, ["Which evidence?"], expected_revision=1)
    assessment.answer_followup(identifier, "fu-1", "Original report", "respondent", expected_revision=2)
    rewrite = assessment._rewrite_saved

    def decision_wins(assessment_id, mutate, **kwargs):
        monkeypatch.setattr(assessment, "_rewrite_saved", rewrite)
        assessment.decide_assessment(identifier, "approved", decided_by="reviewer", expected_revision=3)
        return rewrite(assessment_id, mutate, **kwargs)

    monkeypatch.setattr(assessment, "_rewrite_saved", decision_wins)
    # Predicting the next revision must not bypass the status predicate under lock.
    response = client.put(f"/api/v1/assess/sessions/{identifier}/followups/fu-1/answer", json={"answer": "Changed after approval", "expected_revision": 4})
    assert response.status_code == 409, response.text
    record = assessment.load_saved(identifier)
    assert record["revision"] == 4 and record["status"] == "approved"
    assert record["followups"][0]["answer"] == "Original report"


def test_followup_edits_preserve_previous_reply_and_attribution(client):
    from maverick import assessment

    identifier = start(client)
    assessment.add_followups(identifier, ["Which evidence?"], expected_revision=1)
    first = assessment.answer_followup(identifier, "fu-1", "Original report", "first-respondent", expected_revision=2)
    response = client.put(f"/api/v1/assess/sessions/{identifier}/followups/fu-1/answer", json={"answer": "Corrected report reference", "expected_revision": 3})
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["status"] == "pending_review"
    previous = record["followup_answer_history"][0]["previous_answer"]
    assert previous == {key: first["followups"][0][key] for key in ["answer", "answered_by", "answered_at"]}
    assert record["followups"][0]["answer"] == "Corrected report reference"


def test_saved_answers_cannot_cross_tenant_storage_namespace(client):
    from maverick.assessment import AssessmentSession, answer_saved_question, save_session
    from maverick.paths import tenant_scope

    with tenant_scope(tenant="workspace-a"):
        session = AssessmentSession(type="pia", subject="Private assessment")
        save_session(session)
    with tenant_scope(tenant="workspace-b"):
        assert answer_saved_question(session.id, "pia_necessity", "yes", answered_by="other", expected_revision=1) is None
