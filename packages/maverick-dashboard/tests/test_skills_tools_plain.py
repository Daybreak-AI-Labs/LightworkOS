"""Skills and Tools pages: plain words, pickers instead of typed names, and the
same admin + opt-in gates as the skill API."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app

    dash_app._world_cache.clear()


def _client() -> TestClient:
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def visible_text(html: str) -> str:
    main = html.split('<main id="content"', 1)[-1]
    main = re.sub(r"(?s)<(script|style)\b.*?</\1>", " ", main)
    return re.sub(r"(?s)<[^>]+>", " ", main)


BANNED = ("markdown", "gh:", "HTTP", "registry", "MAVERICK_", "maverick skill",
          "rate-limit", "untrusted code")


def test_skills_page_is_plain_and_uses_a_tool_picker(monkeypatch):
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    html = _client().get("/skills").text
    text = visible_text(html)
    for word in BANNED:
        assert word not in text, word
    # Tools are picked from a checklist, never typed.
    assert 'id="sc-tools"' not in html
    assert 'id="sc-tool-list"' in html and "/api/v1/tools" in html
    assert "mvErrorText" in html and "mvConfirm" in html
    assert "'HTTP '" not in html and "j.detail" not in html
    assert "window.confirm" not in html


def test_skill_forms_say_switched_off_without_the_opt_in(monkeypatch):
    monkeypatch.delenv("MAVERICK_ALLOW_SKILL_INSTALL", raising=False)
    html = _client().get("/skills").text
    assert "switched off on this server" in html
    assert re.search(r'<fieldset class="sk-fieldset"\s+disabled', html)
    # The API gate itself is unchanged.
    r = _client().post("/api/v1/skills/create", json={
        "name": "x", "instructions": "do it", "triggers": ["x"]})
    assert r.status_code == 403


def test_created_skill_shows_with_a_plain_name_and_remove_button(monkeypatch):
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    c = _client()
    r = c.post("/api/v1/skills/create", json={
        "name": "weekly-status-summary", "instructions": "1. Gather updates.",
        "triggers": ["weekly status"], "tools_needed": ["read_file"]})
    assert r.status_code == 201
    html = c.get("/skills").text
    assert "Weekly status summary" in html
    assert 'data-skill-remove="weekly-status-summary"' in html
    assert "Read file" in visible_text(html)
    # The remove button opens a review of the exact saved version first.
    assert c.delete("/api/v1/skills/weekly-status-summary").status_code == 409
    removed = _remove_skill(c, "weekly-status-summary")
    assert removed.status_code == 200 and removed.json()["confirmed"] is True, removed.text
    assert 'data-skill-remove="weekly-status-summary"' not in c.get("/skills").text


def _remove_skill(c, name):
    catalog = c.get("/api/v1/manual-skill-removals").json()
    review = c.post("/api/v1/manual-skill-removals/review", json={"name": name, "context": catalog["context"]})
    assert review.status_code == 200, review.text
    return c.request("DELETE", f"/api/v1/skills/{name}", json={"token": review.json()["token"], "confirmed": True})


def test_a_removal_whose_completion_record_is_pending_stays_unconfirmed(monkeypatch):
    from maverick import audit

    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    c = _client()
    assert c.post("/api/v1/skills/create", json={
        "name": "weekly-status-summary", "instructions": "1. Gather updates.",
        "triggers": ["weekly status"]}).status_code == 201
    original_record = audit.record

    def lose_completion(kind, **payload):
        if payload.get("action") == "skills.manual_remove.completed":
            return False
        return original_record(kind, **payload)

    monkeypatch.setattr(audit, "record", lose_completion)
    removed = _remove_skill(c, "weekly-status-summary")
    assert removed.status_code == 200 and removed.json()["confirmed"] is False


def test_tools_page_is_plain_with_a_page_size_selector():
    html = _client().get("/tools").text
    text = visible_text(html)
    for word in ("registered", "rate-limit", "config file"):
        assert word not in text, word
    assert '<select class="select" id="tool-per-page" name="per_page">' in html
    assert "<code>" not in html.split('<main id="content"', 1)[-1]
