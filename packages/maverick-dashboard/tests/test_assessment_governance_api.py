"""Adversarial API coverage for governed questionnaire/assessment writes."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in (
        "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH", "MAVERICK_DASHBOARD_INVITES",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()


def _enable_oidc(monkeypatch) -> None:
    import maverick_dashboard.auth as auth
    import maverick_dashboard.rbac as rbac
    from maverick import oidc

    monkeypatch.setenv("MAVERICK_OIDC_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "1")
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(rbac, "default_role", lambda: "operator")
    monkeypatch.setattr(
        auth,
        "verify_oidc_token",
        lambda token, **_kw: VerifiedPrincipal(
            sub=token,
            issuer="https://issuer.example",
            audience="maverick",
            claims={"sub": token},
        ),
    )


def _as(user: str) -> dict:
    return {"Authorization": f"Bearer {user}", "Origin": "http://127.0.0.1"}


def _template_body(type_: str, title: str, *, headers: dict | None = None) -> dict:
    state = client.get(
        f"/api/v1/assess/template-state/{type_}", headers=headers,
    ).json()
    return {
        "title": title,
        "framework": "Internal governed policy",
        "department": "privacy",
        "questions": [{
            "id": "stable_control",
            "text": "Is the governed control present?",
            "risk_answer": "no",
            "severity": "high",
        }],
        "expected_revision": state["revision"],
        "expected_digest": state["digest"],
    }


def _saved(subject: str = "Acme CRM"):
    from maverick.assessment import AssessmentSession, save_session

    session = AssessmentSession(type="pia", subject=subject)
    session.record("pia_necessity", "yes")
    save_session(session)
    return session


def test_only_admin_can_publish_or_unpublish_and_actor_is_exact(monkeypatch):
    import maverick.assessment as assessment

    _enable_oidc(monkeypatch)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:admin")
    body = _template_body("governed_check", "Governed check", headers=_as("admin"))

    denied = client.put(
        "/api/v1/assess/templates/governed_check",
        headers=_as("operator"), json=body,
    )
    assert denied.status_code == 403
    published = client.put(
        "/api/v1/assess/templates/governed_check",
        headers=_as("admin"), json=body,
    )
    assert published.status_code == 200, published.text
    rec = published.json()
    raw_state = assessment._load_state_unlocked("governed_check")
    assert raw_state["published_by"] == "user:admin"

    stale = client.put(
        "/api/v1/assess/templates/governed_check",
        headers=_as("admin"), json={**body, "title": "stale"},
    )
    assert stale.status_code == 409
    params = {"expected_revision": rec["revision"],
              "expected_digest": rec["digest"]}
    assert client.delete(
        "/api/v1/assess/templates/governed_check",
        headers=_as("operator"), params=params,
    ).status_code == 403
    removed = client.delete(
        "/api/v1/assess/templates/governed_check",
        headers=_as("admin"), params=params,
    )
    assert removed.status_code == 200
    assert assessment._load_state_unlocked("governed_check")[
        "deleted_by"
    ] == "user:admin"


def test_decision_uses_exact_verified_actor_and_stale_revision_conflicts(monkeypatch):
    _enable_oidc(monkeypatch)
    session = _saved()
    current = client.get(
        f"/api/v1/assess/sessions/{session.id}", headers=_as("alice"),
    ).json()
    decided = client.post(
        f"/api/v1/assess/sessions/{session.id}/decide",
        headers=_as("alice"),
        json={"decision": "approved", "cadence_days": 90,
              "expected_revision": current["revision"]},
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["decided_by"] == "user:alice"
    stale = client.post(
        f"/api/v1/assess/sessions/{session.id}/decide",
        headers=_as("bob"),
        json={"decision": "rejected",
              "expected_revision": current["revision"]},
    )
    assert stale.status_code == 409


def test_approval_with_open_followup_fails_closed():
    session = _saved()
    current = client.get(f"/api/v1/assess/sessions/{session.id}").json()
    followup = client.post(
        f"/api/v1/assess/sessions/{session.id}/followups",
        json={"questions": ["Provide the signed DPA."],
              "expected_revision": current["revision"]},
    )
    assert followup.status_code == 200
    denied = client.post(
        f"/api/v1/assess/sessions/{session.id}/decide",
        json={"decision": "approved",
              "expected_revision": followup.json()["revision"]},
    )
    assert denied.status_code == 409
    assert "unanswered follow-ups" in denied.text


def test_corrupt_persisted_revision_is_service_failure_not_conflict():
    from maverick.assessment import (
        _assessment_path,
        _load_saved_raw,
        _write_saved_path_unlocked,
    )

    session = _saved()
    path = _assessment_path(session.id)
    record = _load_saved_raw(session.id)
    record["revision"] = -1
    _write_saved_path_unlocked(path, record)
    response = client.post(
        f"/api/v1/assess/sessions/{session.id}/decide",
        json={"decision": "rejected", "expected_revision": 0},
    )
    assert response.status_code == 503
    assert "revision is invalid" in response.text


def test_legacy_revision_zero_can_followup_and_decide():
    from maverick.assessment import _assessment_path, load_saved
    from maverick.file_lock import atomic_write_text

    followup_session = _saved("Legacy follow-up")
    path = _assessment_path(followup_session.id)
    record = load_saved(followup_session.id)
    for key in ("revision", "template_revision", "template_digest",
                "template_snapshot"):
        record.pop(key, None)
    atomic_write_text(path, json.dumps(record), mode=0o600)
    response = client.post(
        f"/api/v1/assess/sessions/{followup_session.id}/followups",
        json={"questions": ["Legacy question?"], "expected_revision": 0},
    )
    assert response.status_code == 200, response.text
    assert response.json()["revision"] == 1

    decision_session = _saved("Legacy decision")
    path = _assessment_path(decision_session.id)
    record = load_saved(decision_session.id)
    for key in ("revision", "template_revision", "template_digest",
                "template_snapshot"):
        record.pop(key, None)
    atomic_write_text(path, json.dumps(record), mode=0o600)
    response = client.post(
        f"/api/v1/assess/sessions/{decision_session.id}/decide",
        json={"decision": "rejected", "expected_revision": 0},
    )
    assert response.status_code == 200, response.text
    assert response.json()["revision"] == 1


def test_editor_and_review_dialog_carry_governance_identity():
    html = client.get("/privacy").text
    assert "row.dataset.questionId" in html
    assert 'id="tpl-description"' in html
    assert "tpl.description || ''" in html
    assert "description: document.getElementById('tpl-description')" in html
    assert "expected_digest" in html
    assert "expected_revision" in html
    assert 'id="arv-dialog"' in html
    assert 'id="arv-approve"' in html
    assert 'id="arv-status" role="status"' in html
    # Executable stale-response and captured-id behavior is covered by the
    # assessment_mutation_lifecycle DOM suite; render spelling is not a contract.
