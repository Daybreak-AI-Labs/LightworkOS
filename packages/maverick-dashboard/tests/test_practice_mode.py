"""Practice mode in the dashboard: a marker on every screen, practice work kept
apart, live changes refused, and one action back to live."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), tmp_path
    config.reset_config_cache()
    dash_app._world_cache.clear()


def _start(app):
    started = app.post("/api/v1/practice", json={"on": True})
    assert started.status_code == 200, started.text
    assert started.json() == {"on": True, "available": True, "reason": ""}
    assert app.cookies.get("lw_practice") == "1"


def test_the_switch_marks_every_screen_and_back_to_live_removes_it(client):
    app, _tmp = client
    assert app.get("/api/v1/practice").json()["on"] is False
    start_page = app.get("/start").text
    assert "Start practice mode" in start_page and 'id="practice-banner"' not in start_page
    _start(app)
    for path in ("/", "/start", "/chat", "/approvals", "/settings"):
        page = app.get(path)
        assert page.status_code == 200, (path, page.status_code)
        assert 'id="practice-banner"' in page.text and "Back to live" in page.text, path
        assert 'class="is-practice ' in page.text or 'chat-shell is-practice ' in page.text, path
    assert "Start practice mode" not in app.get("/start").text
    state = app.get("/api/v1/practice").json()
    assert {k: state[k] for k in ("on", "available", "reason", "outbox")} == {
        "on": True, "available": True, "reason": "", "outbox": []}
    assert state["spending"] == {"cap": 1.0, "spent_today": 0.0, "real_ai_calls": True}
    assert {"what", "why"} <= set(state["blocked"][0]) and len(state["blocked"]) >= 6
    left = app.post("/api/v1/practice", json={"on": False})
    assert left.status_code == 200 and left.json()["on"] is False
    assert 'id="practice-banner"' not in app.get("/").text


def test_practice_work_never_appears_in_live_work(client):
    app, _tmp = client
    from maverick import practice
    from maverick_dashboard._shared import _world

    live_goal = _world().create_goal("Live: pay the March invoices", "real work")
    with practice.scope():
        practice_goal = _world().create_goal("Practice: pay the March invoices", "practice")
    _start(app)
    practised = {g["title"] for g in app.get("/api/v1/goals").json()}
    app.post("/api/v1/practice", json={"on": False})
    live = {g["title"] for g in app.get("/api/v1/goals").json()}
    assert "Practice: pay the March invoices" in practised and "Live: pay the March invoices" not in practised
    assert "Live: pay the March invoices" in live and "Practice: pay the March invoices" not in live
    assert live_goal and practice_goal


def test_live_changes_are_refused_with_the_reason_until_back_to_live(client):
    app, _tmp = client
    _start(app)
    refused = app.post("/api/v1/agents/proc_po_chaser/override", json={"persona": "Changed"})
    assert refused.status_code == 409 and refused.headers["X-Lightwork-Reason"] == "practice"
    detail = refused.json()["detail"]
    assert detail.startswith("Agents, specialists, skills and workflows are shared with live work")
    assert "Back to live" in detail
    shared = app.post("/api/v1/goals/1/share", json={})
    assert shared.status_code == 409 and "can't be shared" in shared.json()["detail"]
    assert app.post("/api/v1/practice", json={"on": False}).status_code == 200
    live = app.post("/api/v1/agents/proc_po_chaser/override", json={"persona": "Changed"})
    assert live.headers.get("X-Lightwork-Reason") != "practice"  # live rules (e.g. the publish gate) decide now


EXPECTED_IN_PRACTICE = [
    ("POST", "/api/v1/goals"), ("POST", "/api/v1/goals/compose"), ("POST", "/api/v1/goals/5/answer"),
    ("POST", "/api/v1/goals/5/cancel"), ("POST", "/api/v1/goals/5/resume"), ("POST", "/api/v1/goals/5/feedback"),
    ("POST", "/api/v1/goals/5/annotations"), ("POST", "/api/v1/goals/5/attachments"),
    ("POST", "/api/v1/goals/5/share/preview"), ("POST", "/api/v1/approvals/3/approve"),
    ("POST", "/api/v1/approvals/3/deny"), ("POST", "/api/v1/first-outcome/run"), ("POST", "/api/v1/copilot"),
    ("POST", "/api/v1/halt"), ("DELETE", "/api/v1/halt"), ("POST", "/api/v1/pins/5"), ("DELETE", "/api/v1/pins/5"),
    ("POST", "/api/v1/views/mine"), ("PUT", "/api/v1/drafts/composer"),
    ("PUT", "/api/v1/conversations/5/organization"), ("POST", "/api/v1/conversation-inbox/5"),
    ("POST", "/api/v1/voice/transcribe"), ("POST", "/api/v1/notifications/personal/seen"),
    ("POST", "/api/v1/run-tree/5/fork"), ("POST", "/api/v1/agents/proc_po_chaser/publish-check"),
    ("POST", "/api/v1/navigation/pins"), ("POST", "/api/v1/sessions/revoke-all"), ("POST", "/chat/send"),
    ("POST", "/chat/goal/5/reply"), ("POST", "/api/v1/preferences/display"), ("POST", "/api/v1/redact/preview"),
]


@pytest.mark.parametrize(("method", "path"), EXPECTED_IN_PRACTICE)
def test_what_people_do_in_practice_is_not_blocked(method, path):
    from maverick_dashboard import practice_mode

    allowed, why = practice_mode.rule_for(method, path)
    assert allowed, (method, path, why)


@pytest.mark.parametrize(("path", "reason"), [
    ("/api/v1/goals/5/share", "can't be shared"), ("/api/v1/goals/5/share/gist", "can't be shared"),
    ("/api/v1/goals/5/code/sessions", "real commands"), ("/api/v1/task-files/5/restore", "real files"),
    ("/settings/models", "Settings apply"), ("/api/v1/agents/x/override", "Agents, specialists"),
    ("/me/preferences", "Your own settings"), ("/api/v1/connections", "outside systems"),
    ("/api/v1/privacy/requests", "real records"), ("/users/invite", "People and access"),
    ("/api/v1/something-new", "shared with live work"),
])
def test_blocked_changes_say_why(path, reason):
    from maverick_dashboard import practice_mode

    allowed, why = practice_mode.rule_for("POST", path)
    assert not allowed and reason in why, (path, why)
    assert any(row["why"] == why for row in practice_mode.blocked_list()), why


def test_the_marker_says_ai_answers_are_real_and_capped(client):
    app, _tmp = client
    _start(app)
    banner = app.get("/").text
    assert "AI answers still come from the real AI service and cost real money" in banner
    assert "$1.00 a day" in banner and "not your spending limits" in banner


def test_what_practice_held_back_is_listed_for_the_person(client):
    app, _tmp = client
    from maverick import notifications, practice

    with practice.scope():
        notifications.send_email("pat@example.com", "Payment sent", "Body")
    _start(app)
    held = app.get("/api/v1/practice").json()["outbox"]
    assert held and held[0]["kind"] == "email" and "Payment sent" in held[0]["detail"]


def test_practice_cannot_start_when_it_is_turned_off(client):
    app, tmp = client
    from maverick import config

    (tmp / "config.toml").write_text("[practice]\nenable = false\n", encoding="utf-8")
    config.reset_config_cache()
    refused = app.post("/api/v1/practice", json={"on": True})
    assert refused.status_code == 409 and "turned off" in refused.json()["detail"]


def test_a_practice_switch_that_stopped_working_is_never_silent(client):
    app, tmp = client
    from maverick import config

    _start(app)
    (tmp / "config.toml").write_text("[practice]\nenable = false\n", encoding="utf-8")
    config.reset_config_cache()
    page = app.get("/").text
    assert 'id="practice-banner"' in page and "Practice mode stopped" in page and "turned off in Settings" in page
    refused = app.post("/api/v1/goals", json={"title": "Pay the March invoices"})
    assert refused.status_code == 409 and refused.headers["X-Lightwork-Reason"] == "practice"
    assert "turned off in Settings" in refused.json()["detail"] and "Nothing was changed" in refused.json()["detail"]
    assert app.get("/api/v1/practice").json()["reason"] == "Practice mode is turned off in Settings."
    assert app.post("/api/v1/practice", json={"on": False}).status_code == 200
    assert 'id="practice-banner"' not in app.get("/").text


def test_drafts_and_conversation_labels_in_practice_are_kept_apart(client):
    from maverick import practice
    from maverick_dashboard.draft_api import context_for
    from starlette.requests import Request

    request = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})
    live = context_for(request)
    with practice.scope():
        assert context_for(request) != live
    assert context_for(request) == live


def test_get_started_says_why_practice_is_unavailable_here(client, monkeypatch):
    app, _tmp = client
    from maverick import practice

    monkeypatch.setattr(practice, "unavailable_reason", lambda: practice.POSTGRES_REASON)
    page = app.get("/start").text
    assert "Start practice mode" not in page
    assert "Practice mode isn't available here" in page and "separate database server" in page
    refused = app.post("/api/v1/practice", json={"on": True})
    assert refused.status_code == 409 and "separate database server" in refused.json()["detail"]
