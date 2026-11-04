"""Malformed task-limit configuration answers 503 with the reason, not a 500."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick import world_model


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_BUDGET_DOLLARS", "not-a-number")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")  # pragma: allowlist secret - synthetic
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_create_goal_with_malformed_budget_config_is_503(client):
    resp = client.post("/api/v1/goals", json={"title": "x"})
    assert resp.status_code == 503, resp.text
    assert "task limit configuration is invalid" in resp.json()["detail"]


def test_error_type_is_still_a_value_error():
    from maverick.runner import TaskLimitConfigError
    assert issubclass(TaskLimitConfigError, ValueError)
