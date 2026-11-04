"""Dashboard /api/v1/goals/search endpoint (search across runs)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_world(tmp_path, monkeypatch):
    from maverick import world_model
    from maverick_dashboard import app as app_mod
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app_mod._world_cache.clear()
    w = world_model.WorldModel(tmp_path / "world.db")
    w.create_goal("Deploy the billing service", "prod rollout")
    w.create_goal("Write quarterly report", "finance summary")
    yield


def test_search_returns_matching_runs():
    resp = client.get("/api/v1/goals/search", params={"q": "billing"})
    assert resp.status_code == 200
    titles = [g["title"].lower() for g in resp.json()]
    assert any("billing" in t for t in titles)
    assert all("report" not in t for t in titles)


def test_search_empty_query_returns_empty():
    resp = client.get("/api/v1/goals/search", params={"q": "   "})
    assert resp.status_code == 200
    assert resp.json() == []


def test_search_path_not_shadowed_by_goal_id():
    # /goals/search must not be parsed as /goals/{goal_id}
    resp = client.get("/api/v1/goals/search", params={"q": "report"})
    assert resp.status_code == 200
    assert any("report" in g["title"].lower() for g in resp.json())


def test_search_page_refuses_a_non_ascii_context_header_as_changed():
    resp = client.get("/api/v1/goals/search-page", params={"q": "billing"},
                      headers={"X-Lightwork-Task-Search-Context": "contéxt".encode()})
    assert resp.status_code == 409, resp.text


def test_goals_page_renders_search_box():
    resp = client.get("/goals")
    assert resp.status_code == 200
    assert 'id="run-search-q"' in resp.text
    assert "/api/v1/goals/search-page?" in resp.text


def test_tasks_whose_wording_looks_risky_carry_a_plain_label():
    body = client.get("/api/v1/goals/search", params={"q": "billing"}).json()
    assert body[0]["risk_tier"] == "medium" and body[0]["risk_reasons"] == "deletes or deploys"
    quiet = client.get("/api/v1/goals/search", params={"q": "report"}).json()
    assert quiet[0]["risk_tier"] is None
    page = client.get("/goals").text
    assert "Looks medium risk" in page and "its wording mentions: deletes or deploys" in page
