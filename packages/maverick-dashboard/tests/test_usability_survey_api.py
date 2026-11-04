"""The optional ease-of-use survey in the dashboard: off by default, offered once a
quarter, one-click dismissal, answers by role only, and the administrators' results."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard import app as app_mod

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("[analytics]\nusability_survey = true\n")
    for name in ("MAVERICK_DASHBOARD_ADMINS", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app_mod._world_cache.clear()
    config.reset_config_cache()
    yield tmp_path
    app_mod._world_cache.clear()
    config.reset_config_cache()


def _as(monkeypatch, principal, role="operator"):
    from maverick_dashboard import auth, rbac

    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: principal)
    monkeypatch.setattr(auth, "role_for_principal", lambda p: role)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p: role)
    monkeypatch.setattr(rbac, "list_users", lambda: {principal: role})


def _client():
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN, follow_redirects=False)


def _off(tmp_path):
    from maverick import config

    (tmp_path / "config.toml").write_text("")
    config.reset_config_cache()


def test_survey_is_off_by_default_and_the_script_is_not_loaded(isolated, monkeypatch):
    _off(isolated)
    _as(monkeypatch, "user:kim")
    client = _client()
    state = client.get("/api/v1/usability-survey").json()
    assert state["enabled"] is False and state["offer_sus"] is False
    assert client.post("/api/v1/usability-survey/sus", json={"answers": [3] * 10}).status_code == 403
    assert "lightwork-usability-survey.js" not in client.get("/me").text


def test_offered_once_a_quarter_and_one_dismissal_hides_it(isolated, monkeypatch):
    _as(monkeypatch, "user:kim")
    client = _client()
    assert "lightwork-usability-survey.js" in client.get("/me").text
    state = client.get("/api/v1/usability-survey").json()
    assert state["offer_sus"] is True and len(state["sus_items"]) == 10
    assert client.post("/api/v1/usability-survey/dismiss", json={"topic": "sus"}).status_code == 200
    assert client.get("/api/v1/usability-survey").json()["offer_sus"] is False
    refused = client.post("/api/v1/usability-survey/sus", json={"answers": [3] * 10})
    assert refused.status_code == 409


def test_answers_are_saved_by_role_and_validated(isolated, monkeypatch):
    _as(monkeypatch, "user:lee.wong@example.test")
    client = _client()
    saved = client.post("/api/v1/usability-survey/sus", json={"answers": [5, 1] * 5, "role": "approver"})
    assert saved.status_code == 200 and saved.json()["score"] == 100.0
    assert client.post("/api/v1/usability-survey/sus", json={"answers": [3] * 9}).status_code == 422
    assert client.get("/api/v1/usability-survey?task=decide_approval").json()["offer_seq"] is True
    ok = client.post("/api/v1/usability-survey/seq", json={"task": "decide_approval", "rating": 6})
    assert ok.status_code == 200
    assert client.get("/api/v1/usability-survey?task=decide_approval").json()["offer_seq"] is False
    bad = client.post("/api/v1/usability-survey/seq", json={"task": "invite_person", "rating": 9})
    assert bad.status_code == 409
    stored = (isolated / "usability-survey.json").read_text()
    assert "lee" not in stored and "example.test" not in stored
    assert json.loads(stored)["sus"][0]["role"] == "approver"


def test_answers_need_the_same_origin(isolated, monkeypatch):
    from maverick_dashboard.app import app

    _as(monkeypatch, "user:kim")
    foreign = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "https://elsewhere.example"})
    assert foreign.post("/api/v1/usability-survey/sus", json={"answers": [3] * 10}).status_code == 403


def test_results_page_for_administrators_hides_small_groups(isolated, monkeypatch):
    from maverick import usability_survey as survey

    for index in range(5):
        survey.record_sus(f"user:{index}", [4, 2] * 5, role="employee")
    survey.record_sus("user:x", [3] * 10, role="executive")
    _as(monkeypatch, "user:admin", role="admin")
    page = _client().get("/users/usability-survey")
    assert page.status_code == 200
    text = page.text
    assert "Ease-of-use results" in text and "75.0" in text
    assert "Not enough answers yet" in text
    main = text.split("<main", 1)[-1].split("</main>", 1)[0]
    assert "user:" not in main
    assert main.count("btn--primary") <= 1  # one main action per view, in the header


def test_results_page_is_for_administrators_only(isolated, monkeypatch):
    _as(monkeypatch, "user:kim", role="operator")
    assert _client().get("/users/usability-survey").status_code == 403


def test_the_setting_is_in_the_catalog_off_by_default():
    from maverick_dashboard import settings_catalog

    row = next(s for s in settings_catalog.SETTINGS if s.top == "analytics" and s.key == "usability_survey")
    assert row.default is False and row.control == "toggle"


def _measures_on(tmp_path):
    from maverick import config

    (tmp_path / "config.toml").write_text("[analytics]\nusability_survey = true\nusage_measures = true\n")
    config.reset_config_cache()


def test_suggestion_counts_and_first_results_reach_the_results_page(isolated, monkeypatch):
    """Usage research measures: off unless turned on; then pages report
    suggestions, a person's first finished result is noted, and the
    administrators' page shows both without names."""
    from maverick import usage_measures
    from maverick_dashboard._shared import _world

    _as(monkeypatch, "user:kim", role="operator")
    off = _client().post("/api/v1/usage-measures/suggestion",
                         json={"kind": "copilot-question", "item": "How do I invite?", "event": "shown"})
    assert off.status_code == 200 and off.json() == {"recorded": False}
    assert usage_measures.suggestion_report() == []
    _measures_on(isolated)
    app = _client()
    assert 'lightwork-usage-measures.js' in app.get("/start").text  # first seen; the script loads
    for event in ("shown", "dismissed", "shown"):
        r = app.post("/api/v1/usage-measures/suggestion",
                     json={"kind": "copilot-question", "item": "How do I invite?", "event": event})
        assert r.status_code == 200 and r.json() == {"recorded": True}
    assert app.post("/api/v1/usage-measures/suggestion",
                    json={"kind": "Copilot!", "event": "shown"}).status_code == 422
    world = _world()
    gid = world.create_goal("Summarize vendor spend", "", owner="user:kim")
    world.set_goal_status(gid, "done", result="Here is the summary.")
    assert app.get(f"/chat/goal/{gid}").status_code == 200
    first = {row["role"]: row for row in usage_measures.first_session_report()}
    assert first["operator"]["people"] == 1 and first["operator"]["first_session"] == 1
    _as(monkeypatch, "user:admin", role="admin")
    page = _client().get("/users/usability-survey").text
    main = page.split("<main", 1)[-1].split("</main>", 1)[0]
    assert "First result in the first session" in main and "Copilot suggested questions" in main
    assert "Shown again after dismissal" in main and "user:kim" not in main and "How do I invite" not in main
    foreign = TestClient(_client().app, base_url="http://127.0.0.1", headers={"Origin": "https://elsewhere.example"})
    assert foreign.post("/api/v1/usage-measures/suggestion",
                        json={"kind": "copilot-question", "event": "shown"}).status_code == 403
