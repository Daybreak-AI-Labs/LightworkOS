"""3D plan tree page: WebGL canvas + always-present accessible fallback."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    w = world_model.WorldModel(tmp_path / "world.db")
    g1 = w.create_goal("3d root", "r")
    w.create_goal("3d child", "c", parent_id=g1)
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod
    monkeypatch.setattr(app_mod, "_world", lambda: w)
    monkeypatch.setattr(api_mod, "_world", lambda: w)
    yield TestClient(app_mod.app, base_url="http://127.0.0.1")
    w.close()


def test_page_renders_canvas_and_shares_tree_endpoint(client):
    r = client.get("/plan-tree-3d")
    assert r.status_code == 200
    assert 'id="gl3d"' in r.text
    # vanilla WebGL: no script library, no CDN host
    assert 'getContext("webgl")' in r.text
    assert "cdn.jsdelivr.net" not in r.text
    assert "cytoscape" not in r.text
    # reuses the shared layout endpoint (same data as /graph-editor)
    assert "/api/v1/goal-tree" in r.text


def test_accessible_text_tree_always_present(client):
    r = client.get("/plan-tree-3d")
    # not just a no-WebGL fallback: a <details> for screen readers, with the
    # real tree server-rendered into it
    assert "<details" in r.text
    assert "3d root" in r.text and "3d child" in r.text
    assert "<noscript>" in r.text


def test_webxr_is_feature_detected_and_footnoted(client):
    r = client.get("/plan-tree-3d")
    assert "navigator.xr" in r.text
    assert "isSessionSupported" in r.text
    # the page is honest that VR is untested without hardware
    assert "untested without headset hardware" in r.text
