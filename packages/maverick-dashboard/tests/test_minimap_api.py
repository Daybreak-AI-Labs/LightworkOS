"""GET /api/v1/goals/{id}/minimap — plan-tree minimap text endpoint."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


@pytest.fixture(autouse=True)
def _isolated_world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod
    api_mod._world_cache.clear()
    app_mod._world_cache.clear()
    yield


def _tree():
    from maverick_dashboard.app import _world
    w = _world()
    root = w.create_goal("release", "")
    a = w.create_goal("changelog", "", parent_id=root)
    a1 = w.create_goal("collect PRs", "", parent_id=a)
    w.set_goal_status(root, "active")
    w.set_goal_status(a, "done")
    return root, a, a1


def test_minimap_unknown_goal_404():
    assert client.get("/api/v1/goals/999/minimap").status_code == 404


def test_minimap_returns_plain_text_tree():
    root, a, a1 = _tree()
    r = client.get(f"/api/v1/goals/{root}/minimap")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    lines = r.text.rstrip("\n").splitlines()
    assert lines[0] == f"◐ #{root} release"
    assert lines[1] == f"  ● #{a} changelog"
    assert lines[2] == f"    ◌ #{a1} collect PRs"


def test_minimap_depth_param_collapses():
    root, a, a1 = _tree()
    r = client.get(f"/api/v1/goals/{root}/minimap?depth=1")
    assert "collect PRs" not in r.text
    assert "▸ +1 collapsed" in r.text


def test_minimap_depth_param_is_clamped_not_500():
    root, *_ = _tree()
    assert client.get(f"/api/v1/goals/{root}/minimap?depth=9999").status_code == 200
