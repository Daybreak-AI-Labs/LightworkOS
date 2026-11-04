"""The sidebar's Approvals badge: how many decisions wait for the person.

The count is read after the page has loaded (see lightwork-ui.js), so it must
match the Approvals page exactly and stay behind the page's own permission.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

COUNT = "/api/v1/approvals/waiting-count"


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app

    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _as(monkeypatch, principal):
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)


def test_waiting_count_matches_the_approvals_page(client, tmp_path):
    from maverick.world_model import WorldModel

    assert client.get(COUNT).json() == {"waiting": 0}
    world = WorldModel(tmp_path / "world.db")
    first = world.create_approval("email.send", risk="medium", scope="Email",
                                  detail="Send the weekly report", provenance="consent")
    world.create_approval("files.delete", risk="high", scope="Files",
                          detail="Delete last year's drafts", provenance="consent")
    response = client.get(COUNT)
    assert response.status_code == 200
    assert response.json() == {"waiting": 2}
    assert response.headers["cache-control"] == "private, no-store"
    assert "2 requests waiting" in client.get("/approvals").text
    assert world.decide_approval(first, "denied", decided_by="operator")
    assert client.get(COUNT).json() == {"waiting": 1}


def test_waiting_count_needs_the_permission_to_decide(client, monkeypatch):
    from maverick_dashboard import rbac

    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:vy", "viewer")
    _as(monkeypatch, "user:vy")
    assert client.get(COUNT).status_code == 403
    # Nobody who cannot decide is offered the badge (or the request behind it).
    assert "data-approvals-badge" not in client.get("/goals").text


@pytest.mark.parametrize("path", ["/goals", "/chat"])
def test_both_shells_carry_an_empty_badge_on_every_approvals_link(client, path):
    body = client.get(path).text
    links = re.findall(r'<a href="/approvals"[^>]*>.*?</a>', body, re.DOTALL)
    # Most used and the Governance group: both get the same hidden badge.
    assert len(links) == 2
    for link in links:
        assert "data-approvals-badge" in link
        assert '<span class="nav-count" hidden></span>' in link
        assert "aria-label" not in link
