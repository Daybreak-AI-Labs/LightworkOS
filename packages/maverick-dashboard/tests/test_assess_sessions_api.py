"""Assessment-session review API: the worklist, the full record the pop-out
renders, and sending follow-up questions back to the respondent.

Mutating /api/v1 requests carry a same-origin Origin (the CSRF contract).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    api._world_cache.clear()


def _saved_session():
    from maverick.assessment import AssessmentSession, save_session
    s = AssessmentSession(type="pia", subject="Acme CRM")
    s.record("pia_necessity", "no", "Marketing collects more than needed.")
    save_session(s)
    return s


def test_sessions_worklist():
    s = _saved_session()
    resp = client.get("/api/v1/assess/sessions")
    assert resp.status_code == 200
    rows = resp.json()["sessions"]
    assert rows[0]["id"] == s.id
    assert rows[0]["status"] == "pending_review"
    assert "open_followups" in rows[0]


def test_get_full_record_for_the_popout():
    s = _saved_session()
    resp = client.get(f"/api/v1/assess/sessions/{s.id}")
    assert resp.status_code == 200
    rec = resp.json()
    assert rec["subject"] == "Acme CRM"
    assert rec["answers"]["pia_necessity"]["answer"] == "no"
    assert rec["result"]["findings"], "the risk answer must yield a finding"
    assert rec["show_all_details"] is True
    assert rec["score_profile"]["scoring_method"] == "transparent_max_severity"
    contribution = next(
        item
        for item in rec["score_profile"]["questions"]
        if item["question_id"] == "pia_necessity"
    )
    assert contribution["contribution_kind"] == "risk_finding"
    assert contribution["contribution_bps"] > 0


def test_lightweight_and_score_profile_projections_are_explicit():
    s = _saved_session()

    summary = client.get(
        f"/api/v1/assess/sessions/{s.id}",
        params={"showAllDetails": "false"},
    )
    assert summary.status_code == 200
    body = summary.json()
    assert body["schema"] == "lightwork.assessment-record-summary.v1"
    assert body["show_all_details"] is False
    assert body["id"] == s.id
    assert "answers" not in body
    assert "score_profile" not in body
    assert body["direct_path"].startswith("/assessments?")

    score = client.get(f"/api/v1/assess/sessions/{s.id}/score-profile")
    assert score.status_code == 200
    profile = score.json()
    assert profile["assessment_id"] == s.id
    assert profile["assessment_revision"] == 1
    assert profile["answered"] == 1
    assert profile["total"] == len(profile["questions"])


def test_ai_answer_metadata_is_cited_persisted_and_does_not_change_answer():
    s = _saved_session()
    source_sha256 = "a" * 64
    response = client.put(
        f"/api/v1/assess/sessions/{s.id}/answers/pia_necessity/ai-metadata",
        json={
            "confidence": 0.73,
            "flags": ["human_review_required", "source_incomplete"],
            "source_kind": "document_evidence",
            "source_ref": "evidence-object-17",
            "source_sha256": source_sha256,
            "expected_revision": 1,
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["answer_changed"] is False
    assert payload["assessment_revision"] == 2
    assert payload["ai_metadata"]["confidence"] == 0.73
    assert payload["ai_metadata"]["source"] == {
        "kind": "document_evidence",
        "ref": "evidence-object-17",
        "sha256": source_sha256,
    }

    record = client.get(f"/api/v1/assess/sessions/{s.id}").json()
    assert record["answers"]["pia_necessity"]["answer"] == "no"
    assert record["answers"]["pia_necessity"]["ai_metadata"] == payload["ai_metadata"]

    stale = client.put(
        f"/api/v1/assess/sessions/{s.id}/answers/pia_necessity/ai-metadata",
        json={
            "confidence": 0.5,
            "flags": [],
            "source_kind": "agent_draft",
            "source_ref": "run-22",
            "source_sha256": "b" * 64,
            "expected_revision": 1,
        },
    )
    assert stale.status_code == 409


def test_get_unknown_record_404():
    assert client.get("/api/v1/assess/sessions/nope").status_code == 404
    # Traversal-shaped ids are refused, not resolved.
    assert client.get("/api/v1/assess/sessions/..%2F..%2Fetc").status_code == 404


def test_post_followups_flips_status_and_validates():
    s = _saved_session()
    current = client.get(f"/api/v1/assess/sessions/{s.id}").json()
    resp = client.post(f"/api/v1/assess/sessions/{s.id}/followups",
                       json={"questions": ["Which sub-processors?",
                                           "DPA countersigned?"],
                             "expected_revision": current["revision"]})
    assert resp.status_code == 200, resp.text
    rec = resp.json()
    assert rec["status"] == "needs_more"
    assert len(rec["followups"]) == 2
    # Validation: empty list 422; unknown id 404.
    assert client.post(f"/api/v1/assess/sessions/{s.id}/followups",
                       json={"questions": [],
                             "expected_revision": rec["revision"]}).status_code == 422
    assert client.post("/api/v1/assess/sessions/nope/followups",
                       json={"questions": ["Q?"],
                             "expected_revision": 0}).status_code == 404


def test_question_comments_are_bound_sorted_paginated_and_strict():
    s = _saved_session()
    current = client.get(f"/api/v1/assess/sessions/{s.id}").json()
    first = client.post(
        f"/api/v1/assess/sessions/{s.id}/comments",
        json={
            "section_id": "Transparency",
            "question_id": "pia_transparency",
            "comment": "Attach the published notice.",
            "expected_revision": current["revision"],
            "idempotency_key": "comment-transparency-1",
        },
    )
    assert first.status_code == 201, first.text
    second = client.post(
        f"/api/v1/assess/sessions/{s.id}/comments",
        json={
            "section_id": "Necessity",
            "question_id": "pia_necessity",
            "comment": "Show the minimization analysis.",
            "expected_revision": first.json()["assessment_revision"],
            "idempotency_key": "comment-necessity-1",
        },
    )
    assert second.status_code == 201, second.text

    page = client.get(
        f"/api/v1/assess/sessions/{s.id}/comments",
        params={"offset": 0, "limit": 1},
    )
    assert page.status_code == 200
    assert page.json()["total"] == 2
    assert page.json()["comments"][0]["question_id"] == "pia_necessity"

    invented = client.post(
        f"/api/v1/assess/sessions/{s.id}/comments",
        json={
            "section_id": "Invented",
            "question_id": "pia_necessity",
            "comment": "misbound",
            "expected_revision": second.json()["assessment_revision"],
            "idempotency_key": "comment-invented-1",
        },
    )
    assert invented.status_code == 409
    spoof = client.post(
        f"/api/v1/assess/sessions/{s.id}/comments",
        json={
            "section_id": "Necessity",
            "question_id": "pia_necessity",
            "comment": "spoof",
            "expected_revision": second.json()["assessment_revision"],
            "idempotency_key": "comment-spoof-1",
            "commented_by": "attacker",
        },
    )
    assert spoof.status_code == 422


def test_question_comment_retry_is_idempotent_and_key_reuse_is_bound():
    s = _saved_session()
    current = client.get(f"/api/v1/assess/sessions/{s.id}").json()
    payload = {
        "section_id": "Necessity",
        "question_id": "pia_necessity",
        "comment": "Show the minimization analysis.",
        "expected_revision": current["revision"],
        "idempotency_key": "comment-retry-1",
    }
    first = client.post(f"/api/v1/assess/sessions/{s.id}/comments", json=payload)
    assert first.status_code == 201, first.text

    # A later write advances the record, then the original stale request is
    # retried exactly. It must return the original comment without a new write.
    later = client.post(
        f"/api/v1/assess/sessions/{s.id}/comments",
        json={
            "section_id": "Transparency",
            "question_id": "pia_transparency",
            "comment": "Attach the notice.",
            "expected_revision": first.json()["assessment_revision"],
            "idempotency_key": "comment-later-1",
        },
    )
    assert later.status_code == 201, later.text
    replay = client.post(f"/api/v1/assess/sessions/{s.id}/comments", json=payload)
    assert replay.status_code == 201, replay.text
    assert replay.json()["comment"] == first.json()["comment"]
    assert replay.json()["assessment_revision"] == later.json()["assessment_revision"]

    conflict = client.post(
        f"/api/v1/assess/sessions/{s.id}/comments",
        json={**payload, "comment": "Different content."},
    )
    assert conflict.status_code == 409
    page = client.get(f"/api/v1/assess/sessions/{s.id}/comments").json()
    assert page["total"] == 2


def test_question_comment_paths_validation_and_revision_pinned_pagination():
    s = _saved_session()
    current = client.get(f"/api/v1/assess/sessions/{s.id}").json()
    payload = {
        "section_id": "Necessity",
        "question_id": "pia_necessity",
        "comment": "Bound note.",
        "expected_revision": current["revision"],
        "idempotency_key": "comment-validation-1",
    }
    created = client.post(f"/api/v1/assess/sessions/{s.id}/comments", json=payload)
    assert created.status_code == 201, created.text
    revision = created.json()["assessment_revision"]
    assert client.get(
        f"/api/v1/assess/sessions/{s.id}/comments",
        params={"expected_revision": revision},
    ).status_code == 200

    advanced = client.post(
        f"/api/v1/assess/sessions/{s.id}/comments",
        json={
            **payload,
            "comment": "Another note.",
            "expected_revision": revision,
            "idempotency_key": "comment-validation-2",
        },
    )
    assert advanced.status_code == 201
    assert client.get(
        f"/api/v1/assess/sessions/{s.id}/comments",
        params={"expected_revision": revision},
    ).status_code == 409

    whitespace = client.post(
        f"/api/v1/assess/sessions/{s.id}/comments",
        json={
            **payload,
            "comment": "   ",
            "expected_revision": advanced.json()["assessment_revision"],
            "idempotency_key": "comment-validation-3",
        },
    )
    assert whitespace.status_code == 422
    alias = f"{s.id}{'x' * 64}"
    assert client.post(f"/api/v1/assess/sessions/{alias}/comments", json=payload).status_code == 404
