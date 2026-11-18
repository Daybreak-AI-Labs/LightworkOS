"""Today opens at once and loads each work source in its own section.

Live: /today read tasks, decisions, schedules, templates and every published
specialist before sending a byte, and the load balancer gave up after 60 s
(504). The page now renders without any of those reads, and each source
loads from /today/sections/<source> with its own loading and error state.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import api, app, auth, rbac

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:customer")
    config.reset_config_cache()
    api._world_cache.clear()
    rbac.set_role("user:customer", "operator")
    yield TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()
    api._world_cache.clear()


def _forbid(monkeypatch, module, *names):
    def refuse(*_args, **_kwargs):
        raise AssertionError("read while rendering the page")

    for name in names:
        monkeypatch.setattr(module, name, refuse)


def test_today_renders_without_reading_any_work_source(client, monkeypatch):
    from maverick_dashboard import product_operations_task_launch, today_projection

    _forbid(monkeypatch, today_projection, "_tasks", "_decisions", "_schedules", "template_choices", "project")
    # Specialist and model choices are for Chat; Today never shows them.
    _forbid(monkeypatch, product_operations_task_launch, "published_specialists")
    response = client.get("/today")
    assert response.status_code == 200
    page = response.text
    for card, source in (("tasks", "tasks"), ("recent", "tasks"), ("decisions", "decisions"),
                         ("schedules", "schedules"), ("templates", "templates")):
        match = re.search(rf'<section[^>]*id="today-card-{card}"[^>]*>(.*?)</section>', page, re.DOTALL)
        assert match, card
        assert f'data-today-source="{source}"' in match.group(0)
        assert re.search(r'role="status"[^>]*>Loading', match.group(1)), card
    assert 'id="today-decisions-reminder"' in page
    assert "/static/lightwork-today.js" in page


def test_a_source_section_carries_its_cards(client):
    from maverick_dashboard import app

    goal = app._world().create_goal("Quarterly vendor review", owner="user:customer")
    response = client.get("/today/sections/tasks")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "private, no-store"
    fragment = response.text
    assert "<html" not in fragment
    assert re.search(r'<section[^>]*id="today-card-tasks"', fragment)
    assert re.search(r'<section[^>]*id="today-card-recent"', fragment)
    assert f'href="/chat/goal/{goal}"' in fragment and "Quarterly vendor review" in fragment
    assert "data-today-source" not in fragment


def test_decisions_section_carries_the_reminder(client):
    fragment = client.get("/today/sections/decisions").text
    assert re.search(r'id="today-decisions-reminder"', fragment)
    assert re.search(r'<section[^>]*id="today-card-decisions"', fragment)


def test_a_failing_source_shows_its_own_plain_error(client, monkeypatch):
    from maverick_dashboard import today_projection

    def broken(*_args, **_kwargs):
        raise RuntimeError("synthetic: database timeout")

    monkeypatch.setattr(today_projection, "_schedules", broken)
    response = client.get("/today/sections/schedules")
    assert response.status_code == 200
    assert "could not be read" in response.text and "synthetic" not in response.text


def test_unknown_and_unauthorized_sources_are_refused(client):
    from maverick_dashboard import rbac

    assert client.get("/today/sections/everything").status_code == 404
    rbac.set_role("user:customer", "viewer")
    assert client.get("/today/sections/decisions").status_code == 403
