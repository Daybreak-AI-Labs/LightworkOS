"""The /compliance page's buttons: protection switches, retention, a person's
data (export / erase), auditor downloads, the AI Act self-check and the
control finder."""
from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import app as app_mod
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

BANNED = re.compile(
    r"MAVERICK_|\[audit\]|\[retention\]|\[privacy\]|\[encryption\]|\[enterprise\]|"
    r"\[compliance\]|maverick (erase|export-user|retention)|~/\.maverick|"
    r"AES-256|export \.md|export \.csv|on-demand"
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    app_mod._world_cache.clear()
    yield
    app_mod._world_cache.clear()


def _as_viewer(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:v", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:v")


def _seed_person():
    world = app_mod._world()
    conv = world.get_or_create_conversation(channel="slack", user_id="U123")
    world.append_turn(conv.id, "user", "hello there")
    return conv


def _retention_review():
    response = client.post("/api/v1/compliance/retention/preview")
    assert response.status_code == 200, response.text
    return {"review_id": response.json()["id"], "confirm_no_holds": True}


def _reviewed_export(monkeypatch):
    """Exercise the native, independent grant before reading channel content."""
    from maverick_dashboard import auth, content_access, rbac

    monkeypatch.setattr(content_access, "enabled", lambda: True)
    actor = ["user:privacy-requester"]
    for name in (actor[0], "user:privacy-reviewer"):
        rbac.set_role(name, "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda _: actor[0])
    body = {"channel": "slack", "user": "U123"}
    assert client.post("/api/v1/compliance/people/export", json=body).status_code == 403
    request = client.post("/api/v1/content-access", json={
        "resource_kind": "subject_data", "resource_id": json.dumps(["slack", "U123"], separators=(",", ":")),
        "purpose": "rights_request", "minutes": 5,
    })
    assert request.status_code == 200, request.text
    row = request.json()
    decision = {"expected_revision": row["revision"], "decision": "approve"}
    endpoint = f"/api/v1/content-access/{row['id']}/decision"
    assert client.post(endpoint, json=decision).status_code == 403
    actor[0] = "user:privacy-reviewer"
    reviewed = client.post(endpoint, json=decision)
    assert reviewed.status_code == 200, reviewed.text
    actor[0] = "user:privacy-requester"
    return body


def test_viewer_cannot_use_any_mutating_button(monkeypatch):
    _as_viewer(monkeypatch)
    assert client.post("/api/v1/compliance/switches/signed_audit").status_code == 403
    assert client.post("/api/v1/compliance/retention", json={"audit_days": 30}).status_code == 403
    assert client.post("/api/v1/compliance/retention/preview").status_code == 403
    assert client.post("/api/v1/compliance/retention/apply", json={
        "review_id": "0" * 32, "confirm_no_holds": True,
    }).status_code == 403
    assert client.get("/api/v1/compliance/people").status_code == 403
    body = {"channel": "slack", "user": "U123"}
    assert client.post("/api/v1/compliance/people/export", json=body).status_code == 403
    assert client.post("/api/v1/compliance/people/erase", json=body).status_code == 403
    assert client.get("/api/v1/compliance/downloads/soc2").status_code == 403


def test_switch_writes_only_a_strengthening_setting(monkeypatch):
    from maverick_dashboard import settings_store

    r = client.post("/api/v1/compliance/switches/signed_audit")
    assert r.status_code == 200, r.text
    assert r.json()["saved"] is True
    assert settings_store.load_overlay()["audit"]["sign"] is True
    assert client.post("/api/v1/compliance/switches/not_a_switch").status_code == 404
    with pytest.raises(ValueError):
        settings_store.set_compliance_settings({("audit", "sign"): False})
    with pytest.raises(ValueError):
        settings_store.set_compliance_settings({("security", "secure_defaults"): True})


def test_retention_periods_save_and_apply(monkeypatch):
    from maverick_dashboard import settings_store

    assert client.post("/api/v1/compliance/retention", json={"audit_days": 0}).status_code == 422
    assert client.post("/api/v1/compliance/retention", json={}).status_code == 422
    r = client.post("/api/v1/compliance/retention", json={"messages_days": 365})
    assert r.status_code == 200, r.text
    assert settings_store.load_overlay()["retention"]["messages_days"] == 365
    fields = client.get("/api/v1/compliance/retention").json()["fields"]
    assert {f["key"]: f["days"] for f in fields}["messages_days"] == 365
    import maverick.audit.retention as retention

    calls = []

    def enforce(**kwargs):
        calls.append(kwargs)
        if kwargs.get("dry_run"):
            # The preview binds the exact eligible records the deletion may remove.
            kwargs["_review_binding"].update(records="reviewed-messages")
        return {"messages": {"deleted": 4}, "marker": {"messages_deleted": 4}}

    monkeypatch.setattr(retention, "enforce", enforce)
    review = _retention_review()
    applied = client.post("/api/v1/compliance/retention/apply", json=review).json()
    assert applied["removed"] == 4 and "4 removals were confirmed" in applied["message"]
    assert calls[0]["dry_run"] is True and not calls[1].get("dry_run")
    assert calls[0]["now"] == calls[1]["now"]  # deletion uses the reviewed cutoff
    assert calls[1]["config"] == {"messages_days": 365}
    assert applied["receipt"]["status"] == "completed"


def test_non_ascii_retention_context_header_is_refused_as_changed_not_a_server_error():
    from maverick_dashboard import settings_store

    stale = {"X-Lightwork-Retention-Context": "contéxt".encode()}
    saved = client.post("/api/v1/compliance/retention", json={"messages_days": 365}, headers=stale)
    assert saved.status_code == 409, saved.text
    assert settings_store.load_overlay().get("retention", {}).get("messages_days") != 365
    assert client.post("/api/v1/compliance/retention/preview", headers=stale).status_code == 409


def test_keep_one_retention_period_preserves_omitted_fields_and_records_change(monkeypatch):
    from maverick import config
    from maverick_dashboard import settings_store

    initial = {"audit_days": 30, "messages_days": 30, "events_days": 30}
    saved = client.post("/api/v1/compliance/retention", json=initial)
    assert saved.status_code == 200, saved.text
    rows = _capture_audit(monkeypatch)
    response = client.post("/api/v1/compliance/retention", json={"audit_days": None, "messages_days": 90})
    assert response.status_code == 200, response.text
    assert response.json()["effective"]["audit_days"] is None
    assert response.json()["effective"]["messages_days"] == 90
    # An explicit Keep is persisted; an omitted field is not a request to clear.
    assert settings_store.load_overlay()["retention"] == {"audit_days": 0, "messages_days": 90, "events_days": 30}
    config.reset_config_cache()
    readback = client.get("/api/v1/compliance/retention")
    assert readback.status_code == 200, readback.text
    periods = {field["key"]: field["days"] for field in readback.json()["fields"]}
    assert periods["audit_days"] is None and periods["messages_days"] == 90 and periods["events_days"] == 30
    changes = [(entry["key"], entry["old"], entry["new"]) for _, entry in rows
               if entry.get("source") == "compliance"]
    assert changes == [("audit_days", 30, 0), ("messages_days", 30, 90)]
    assert all(entry["actor"] for _, entry in rows)


def test_keep_all_retention_periods_survives_reload_and_native_enforcement(monkeypatch, tmp_path):
    from maverick import config
    from maverick.audit.retention import enforce
    from maverick_dashboard.compliance_controls_api import RETENTION_FIELDS

    initial = {key: 30 for key, _ in RETENTION_FIELDS}
    assert client.post("/api/v1/compliance/retention", json=initial).status_code == 200
    world = app_mod._world()
    goal = world.create_goal("Old retained task")
    with world._writing() as connection:
        connection.execute("INSERT INTO goal_events(goal_id,agent,kind,content,ts) VALUES(?,?,?,?,?)",
                           (goal, "fixture", "observation", "Keep this original record", 1.0))
        connection.execute("INSERT INTO episodes(goal_id,started_at,ended_at) VALUES(?,?,?)", (goal, 1.0, 2.0))
    rows = _capture_audit(monkeypatch)
    response = client.post("/api/v1/compliance/retention", json=dict.fromkeys(initial))
    assert response.status_code == 200, response.text
    assert all(value is None for value in response.json()["effective"].values())
    config.reset_config_cache()
    readback = client.get("/api/v1/compliance/retention")
    assert readback.status_code == 200, readback.text
    assert all(field["days"] is None for field in readback.json()["fields"])
    # The actual scheduled enforcement entry point reads the effective config;
    # it must preserve old records after Keep, not just return a friendly label.
    report = enforce(db_path=world.path, audit_dir=tmp_path / "audit", now=2_000_000_000.0)
    assert "events" not in report and "episodes" not in report
    assert len(world.goal_events(goal, limit=10)) == 1
    assert world._read_one("SELECT COUNT(*) FROM episodes WHERE goal_id=?", (goal,))[0] == 1
    changes = {entry["key"]: (entry["old"], entry["new"]) for _, entry in rows
               if entry.get("source") == "compliance"}
    assert changes == dict.fromkeys(initial, (30, 0))


def test_keep_retention_refuses_effective_installation_override(monkeypatch):
    from maverick import config

    assert client.post("/api/v1/compliance/retention", json={"messages_days": 30}).status_code == 200
    # Explicitly model an operator-enforced layer above the UI overlay. Keep the
    # native save/readback route; only that external policy boundary is supplied.
    current = config.load_global_config

    def enforced():
        result = dict(current())
        result["retention"] = {**result.get("retention", {}), "messages_days": 30}
        return result

    monkeypatch.setattr(config, "load_global_config", enforced)
    response = client.post("/api/v1/compliance/retention", json={"messages_days": None})
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["effective"]["messages_days"] == 30
    assert "overridden by installation policy" in response.json()["detail"]["message"]
    readback = client.get("/api/v1/compliance/retention")
    assert next(field for field in readback.json()["fields"] if field["key"] == "messages_days")["days"] == 30


def test_people_list_export_and_erase_are_workspace_scoped(monkeypatch):
    _seed_person()
    people = client.get("/api/v1/compliance/people").json()["people"]
    assert [(p["channel"], p["user"], p["channel_label"]) for p in people] == [
        ("slack", "U123", "Slack")
    ]
    body = _reviewed_export(monkeypatch)
    export = client.post("/api/v1/compliance/people/export", json=body)
    assert export.status_code == 200
    assert "attachment" in export.headers["content-disposition"]
    assert "hello there" in export.text
    assert client.post(
        "/api/v1/compliance/people/export", json={"channel": "../x", "user": "U123"}
    ).status_code == 422
    import maverick.audit as audit
    rows = []
    real_audit_event = audit.audit_event
    audit.audit_event = lambda kind, **kw: rows.append((kind, kw)) or True
    try:
        erased = client.post("/api/v1/compliance/people/erase", json=body)
    finally:
        audit.audit_event = real_audit_event
    assert erased.status_code == 200, erased.text
    assert erased.json()["erased"] is True
    # Who erased is recorded; whose data was erased is not written again.
    assert [kind for kind, _ in rows] == ["erase"]
    assert rows[0][1]["source"] == "dashboard" and rows[0][1]["conversations"] == 1
    assert "U123" not in repr(rows)
    assert client.get("/api/v1/compliance/people").json()["people"] == []
    again = client.post("/api/v1/compliance/people/erase", json=body).json()
    assert again["erased"] is False and "Nothing was found" in again["message"]


def test_erase_without_a_conversation_still_scrubs_what_is_kept_about_the_person():
    world = app_mod._world()
    world.upsert_fact("user:slack:U123:timezone", "Europe/Paris")
    body = client.post("/api/v1/compliance/people/erase",
                       json={"channel": "slack", "user": "U123"}).json()
    assert body["erased"] is True and body["conversations"] == 0
    assert body["clean"] is True and "1 other stored item(s)" in body["message"]
    assert world.get_fact("user:slack:U123:timezone") is None
    again = client.post("/api/v1/compliance/people/erase",
                        json={"channel": "slack", "user": "U123"}).json()
    assert again["erased"] is False and "Nothing was found" in again["message"]


def test_erase_does_not_claim_everything_when_a_clean_up_step_failed(monkeypatch):
    _seed_person()
    import maverick.audit as audit

    def broken_scrub(*args, **kwargs):
        raise OSError("disk")

    monkeypatch.setattr(audit, "scrub_user", broken_scrub)
    body = client.post("/api/v1/compliance/people/erase",
                       json={"channel": "slack", "user": "U123"}).json()
    assert body["erased"] is True and body["clean"] is False
    assert "everything linked" not in body["message"]
    assert "earlier activity records" in body["message"]
    assert body["receipt_id"]


def test_erase_reports_a_refused_erasure_record_as_uncertified(monkeypatch):
    _seed_person()
    import maverick.audit as audit

    def refuse(*args, **kwargs):
        raise audit.AuditRefused("strict audit refused")

    monkeypatch.setattr(audit, "record", refuse)
    response = client.post("/api/v1/compliance/people/erase",
                           json={"channel": "slack", "user": "U123"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["erased"] is True and body["clean"] is False
    assert "the note that this erasure happened" in body["message"]
    assert client.get("/api/v1/compliance/people").json()["people"] == []


def _capture_audit(monkeypatch):
    import maverick.audit as audit

    rows = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **kw: rows.append((str(kind), kw)) or True)
    return rows


def test_protection_and_retention_changes_are_recorded_with_who_made_them(monkeypatch):
    rows = _capture_audit(monkeypatch)
    assert client.post("/api/v1/compliance/switches/anonymous_logs").status_code == 200
    assert client.post("/api/v1/compliance/retention", json={"audit_days": 30}).status_code == 200
    import maverick.audit.retention as retention
    def enforce(**kwargs):
        if kwargs.get("dry_run"):
            kwargs["_review_binding"].update(records="reviewed-audit")
        return {"audit": {"deleted": 0}}
    monkeypatch.setattr(retention, "enforce", enforce)
    response = client.post("/api/v1/compliance/retention/apply", json=_retention_review())
    assert response.status_code == 200, response.text
    assert response.json()["applied"] is True
    changed = [(kw["section"], kw["key"], kw["old"], kw["new"]) for kind, kw in rows
               if kw.get("source") == "compliance" and "section" in kw]
    assert changed == [("privacy", "anonymous", None, True), ("retention", "audit_days", None, 30)]
    assert [kw["actor"] for _, kw in rows]  # every row names who did it
    assert any(kind == "retention_review_accepted" for kind, _ in rows)


def test_a_refused_record_undoes_the_change_and_removes_nothing(monkeypatch):
    import maverick.audit as audit

    _seed_person()
    export_body = _reviewed_export(monkeypatch)
    review = _retention_review()

    def refuse(*args, **kwargs):
        raise audit.AuditRefused("strict audit refused")

    monkeypatch.setattr(audit, "audit_event", refuse)
    saved = client.post("/api/v1/compliance/retention", json={"audit_days": 30})
    assert saved.status_code == 503 and "undone" in saved.json()["detail"]
    assert client.post("/api/v1/compliance/retention", json={"audit_days": 1}).status_code == 422
    from maverick_dashboard import settings_store
    assert (settings_store.load_overlay().get("retention") or {}).get("audit_days") is None
    import maverick.audit.retention as retention
    ran = []
    monkeypatch.setattr(retention, "enforce", lambda **_: ran.append(1) or {})
    assert client.post("/api/v1/compliance/retention/apply", json=review).status_code == 503
    assert ran == []
    exported = client.post("/api/v1/compliance/people/export", json=export_body)
    assert exported.status_code == 503


def test_a_person_data_download_is_recorded_without_the_person(monkeypatch):
    _seed_person()
    body = _reviewed_export(monkeypatch)
    rows = _capture_audit(monkeypatch)
    assert client.post("/api/v1/compliance/people/export",
                       json=body).status_code == 200
    assert [kind for kind, _ in rows] == ["person_data_exported"]
    assert "U123" not in repr(rows)


def test_ai_act_self_check_and_control_finder_are_plain():
    act = client.get("/api/v1/compliance/ai-act").json()
    assert act["banned_uses"] and act["high_risk_uses"]
    assert act["default_level"].startswith("Limited risk")
    found = client.get("/api/v1/compliance/control-finder", params={"q": "vendor has no dpa"}).json()
    assert found["controls"] and found["controls"][0]["references"]
    assert client.get("/api/v1/compliance/control-finder").json() == {"controls": []}


def test_assessment_downloads_reject_typed_references():
    assert client.get("/api/v1/compliance/downloads/oscal", params={"assessment": "../x"}).status_code == 422
    assert client.get("/api/v1/compliance/assessments").status_code == 200


def test_compliance_page_offers_buttons_not_config_keys(monkeypatch):
    import maverick.compliance as compliance
    from maverick.compliance import compliance_report

    real = compliance_report()
    forced = [
        type(c)(c.control, c.regulation, "action_needed" if c.status == "active" else c.status,
                c.detail, framework=c.framework)
        for c in real
    ]
    monkeypatch.setattr(compliance, "compliance_report", lambda: forced)
    body = client.get("/compliance").text
    assert 'data-cmp-switch="signed_audit"' in body
    assert "data-cmp-halt" in body
    assert 'href="#cmp-people"' in body
    assert 'id="cmp-retention-form"' in body
    assert "Download report" in body and "Download spreadsheet" in body
    assert 'id="cmp-erase"' in body and 'id="cmp-export"' in body
    assert not BANNED.search(body), BANNED.search(body)
    for check in real:
        assert check.detail not in body


def test_compliance_template_passes_a11y_audit():
    from pathlib import Path

    from maverick.a11y_audit import audit_file

    template = Path(app_mod.__file__).resolve().parent / "templates" / "compliance.html"
    assert audit_file(template) == []


def test_strict_mode_is_refused_until_sign_in_exists(monkeypatch):
    from maverick_dashboard import settings_store

    r = client.post("/api/v1/compliance/switches/strict_mode")
    assert r.status_code == 409 and "sign-in" in r.json()["detail"]
    assert "enterprise" not in settings_store.load_overlay()


def test_fingerprint_is_computed_on_the_server_and_needs_operate(monkeypatch):
    import hashlib

    data = b"evidence document bytes"
    r = client.post("/api/v1/compliance/fingerprint", content=data,
                    headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 200
    assert r.json() == {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    assert client.post("/api/v1/compliance/fingerprint", content=b"",
                       headers={"Content-Type": "application/octet-stream"}).status_code == 422
    _as_viewer(monkeypatch)
    assert client.post("/api/v1/compliance/fingerprint", content=data,
                       headers={"Content-Type": "application/octet-stream"}).status_code == 403
