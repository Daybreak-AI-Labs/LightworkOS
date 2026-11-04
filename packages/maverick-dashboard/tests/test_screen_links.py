"""Screens that only Ctrl+K or a typed address could reach are linked from their
natural parent page, and only for people who can open them."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

# (parent page, link target) pairs added so no screen is an orphan.
PARENT_LINKS = (
    ("/audit", "/replay"),
    ("/replay", "/walkthroughs"),
    ("/safety", "/simulate"),
    ("/permissions", "/discovery"),
    ("/agents", "/roles"),
    ("/skills", "/store"),
    ("/settings", "/perf"),
    ("/settings", "/cache"),
    ("/settings", "/embed-demo"),
)


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app._world_cache.clear()
    return TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _as(monkeypatch, role):
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:member", role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:member")


def _task(owner=""):
    from maverick_dashboard import app

    return app._world().create_goal("Quarterly summary", "", owner=owner)


def test_each_orphaned_screen_is_linked_from_its_parent(client):
    for parent, target in PARENT_LINKS:
        page = client.get(parent)
        assert page.status_code == 200, parent
        assert f'href="{target}"' in page.text, (parent, target)
    goal = _task()
    steps = client.get(f"/goals/{goal}/trajectory").text
    assert 'href="/redact"' in steps and f'href="/replay?goal={goal}"' in steps


def test_personal_preferences_link_to_output_styles(client, monkeypatch):
    _as(monkeypatch, "operator")
    assert 'href="/styles"' in client.get("/preferences").text


@pytest.mark.parametrize("role,shown", [
    ("viewer", set()),
    ("operator", {"/redact"}),
    ("auditor", {"/replay"}),
])
def test_task_steps_link_only_screens_the_role_can_open(client, monkeypatch, role, shown):
    _as(monkeypatch, role)
    goal = _task(owner="user:member")
    steps = client.get(f"/goals/{goal}/trajectory")
    assert steps.status_code == 200
    offered = {path for path in ("/redact", "/replay") if f'href="{path}' in steps.text}
    assert offered == shown
    for path in offered:
        assert client.get(path).status_code == 200


def test_hidden_screens_lose_their_parent_links(client, monkeypatch):
    from maverick_dashboard import ui_visibility

    _as(monkeypatch, "operator")
    assert 'href="/store"' in client.get("/skills").text
    ui_visibility.set_visibility("/store", "operator", False)
    assert 'href="/store"' not in client.get("/skills").text
    assert client.get("/store").status_code == 403
