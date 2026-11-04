"""Task downloads do their blocking checks off the event loop."""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard.app import app

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


@pytest.mark.parametrize("path", ["/api/v1/goals/7/export.json", "/api/v1/goals/7/handoff.html"])
def test_the_export_source_check_runs_off_the_event_loop(client, monkeypatch, path):
    # Authorization, a fresh configuration and world reads ran inside the async
    # handler, blocking every other request while a large task was checked.
    from maverick_dashboard import goal_export_ops_api as exports

    on_loop = []

    def source(request, goal_id, **kwargs):
        try:
            asyncio.get_running_loop()
            on_loop.append(True)
        except RuntimeError:
            on_loop.append(False)
        raise HTTPException(404, "no such goal")

    monkeypatch.setattr(exports, "_export_source", source)
    assert client.get(path).status_code == 404
    assert on_loop == [False]
