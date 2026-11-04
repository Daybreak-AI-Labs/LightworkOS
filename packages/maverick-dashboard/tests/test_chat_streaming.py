"""Goal events + dashboard bearer auth tests."""
from __future__ import annotations

import os

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


class TestBearerAuth:
    def teardown_method(self):
        os.environ.pop("MAVERICK_DASHBOARD_TOKEN", None)

    def test_no_token_allows_access(self):
        # /livez is the cheap always-200 liveness probe; healthz can be
        # 503 if no LLM key is set, which depends on the test env.
        resp = client.get("/livez")
        assert resp.status_code == 200

    def test_token_blocks_missing_auth(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        resp = client.get("/")
        assert resp.status_code == 401

    def test_token_allows_bearer_header(self, monkeypatch, tmp_path):
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        from maverick import world_model
        monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
        resp = client.get("/", headers={"Authorization": "Bearer s3cr3t"})
        assert resp.status_code == 200

    def test_query_token_no_longer_allowed(self, monkeypatch, tmp_path):
        """Query-token auth was removed (leaked via Referer)."""
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        from maverick import world_model
        monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
        resp = client.get("/?token=s3cr3t")
        assert resp.status_code == 401

    def test_healthz_always_open(self, monkeypatch):
        """healthz/livez must be reachable without auth even when token is set."""
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        # 200 or 503 -- the point is auth-exemption, not the result.
        resp = client.get("/healthz")
        assert resp.status_code in (200, 503)
        # /livez is the always-200 cheap probe.
        resp = client.get("/livez")
        assert resp.status_code == 200

    def test_wrong_token_rejected(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        resp = client.get("/", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 401


class TestGoalEvents:
    def test_events_endpoint_with_real_goal(self, tmp_path, monkeypatch):
        from maverick import world_model
        monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
        w = world_model.WorldModel(tmp_path / "world.db")
        gid = w.create_goal("test", "desc")
        w.append_event(gid, "orchestrator-0", "plan", "thinking about it")
        w.append_event(gid, "researcher-1", "finding", "discovered X")

        resp = client.get(f"/api/goal/{gid}/events")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"
        assert len(data["events"]) == 2
        assert data["events"][0]["kind"] == "plan"
        assert data["events"][1]["kind"] == "finding"
        assert data["next_id"] == data["events"][-1]["id"]

    def test_events_since_filter(self, tmp_path, monkeypatch):
        from maverick import world_model
        monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
        w = world_model.WorldModel(tmp_path / "world.db")
        gid = w.create_goal("test", "desc")
        e1 = w.append_event(gid, "a", "plan", "first")
        w.append_event(gid, "a", "plan", "second")

        resp = client.get(f"/api/goal/{gid}/events?since={e1}")
        data = resp.json()
        assert len(data["events"]) == 1
        assert data["events"][0]["content"] == "second"

    def test_events_for_unknown_goal_404(self):
        resp = client.get("/api/goal/9999999/events")
        assert resp.status_code == 404
