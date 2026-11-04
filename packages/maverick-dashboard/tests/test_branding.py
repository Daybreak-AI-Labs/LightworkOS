"""Daybreak Labs branding: the logo is served, stays public (the share view needs
it without a login), and appears on the dashboard chrome + public share page."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    return world_model.WorldModel(tmp_path / "world.db")


def test_logo_is_served_as_jpeg():
    r = client.get("/static/daybreak-logo.jpg")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/jpeg")
    assert len(r.content) > 1000


def test_logo_stays_public_when_a_token_is_set(monkeypatch):
    # With a dashboard token, normal pages require auth -- but the brand image
    # must stay reachable so the (auth-exempt) public share view can load it.
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "secret-token-xyz")
    noauth = TestClient(app, base_url="http://127.0.0.1")  # no bearer header
    assert noauth.get("/goals").status_code == 401          # normal page gated
    assert noauth.get("/static/daybreak-logo.jpg").status_code == 200  # logo public


def test_sidebar_and_favicon_use_the_logo(tmp_path, monkeypatch):
    _world(tmp_path, monkeypatch)
    t = client.get("/goals").text
    assert "/static/daybreak-logo.jpg" in t      # favicon + sidebar both point at it
    assert "brand__plate" in t                   # logo sits on the dark brand plate
    assert "Lightwork by Daybreak Labs" in t      # co-branded footer


def test_share_page_shows_the_logo(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("Forecast", "", domain="finance_cash13w")
    w.set_goal_status(gid, "done", result="ok")
    w.record_signoff(gid, "approved", decided_by="reviewer")
    preview = client.post(f"/api/v1/goals/{gid}/share/preview")
    assert preview.status_code == 200, preview.text
    shared = client.post(f"/api/v1/goals/{gid}/share", json={
        "confirm": True, "source_sha256": preview.json()["source"]["sha256"],
        "lifetime_seconds": 3600, "label": "Branding review",
    })
    assert shared.status_code == 201, shared.text
    token = shared.json()["url"].split("/share/")[1]
    page = TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").text   # anon viewer
    assert "/static/daybreak-logo.jpg" in page
    assert "Daybreak Labs" in page
