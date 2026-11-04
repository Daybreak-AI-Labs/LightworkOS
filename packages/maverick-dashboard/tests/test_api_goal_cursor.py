"""Task cursors retain exact-owner reads and never need authority to their anchor."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick import world_model
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard import api, auth
from maverick_dashboard.app import app


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token, **kwargs: VerifiedPrincipal(
        sub=token, issuer="https://issuer.example", audience="maverick", claims={"sub": token}))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    database = world_model.WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(api, "_world", lambda: database)
    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def client():
    # Like the existing REST tests, do not start service/worker lifespan jobs.
    instance = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1", "Authorization": "Bearer alice"})
    try:
        yield instance
    finally:
        instance.close()


def test_http_cursor_is_current_owner_scoped_even_for_admin(world, monkeypatch, client):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")
    own = [world.create_goal(f"Own {index}", owner="user:root") for index in range(4)]
    world.create_goal("Private employee task", owner="user:alice")
    client.headers["Authorization"] = "Bearer root"
    first = client.get("/api/v1/goals?limit=2")
    assert first.status_code == 200
    assert [goal["id"] for goal in first.json()] == own[2:][::-1]
    assert first.headers["Pagination-Next-Before-Id"] == str(own[2])
    middle = client.get(f"/api/v1/goals?limit=1&before_id={own[3]}")
    assert [goal["id"] for goal in middle.json()] == [own[2]]
    assert middle.headers["Pagination-Has-More"] == "true"
    assert middle.headers["Pagination-Next-Before-Id"] == str(own[2])
    assert "Pagination-Next-Offset" not in middle.headers
    with world._writing() as connection:
        connection.execute("DELETE FROM goals WHERE id=?", (own[2],))
        connection.execute("UPDATE goals SET owner=? WHERE id=?", ("user:alice", own[1]))
    world.create_goal("New own task", owner="user:root")
    last = client.get(f"/api/v1/goals?limit=2&before_id={own[2]}")
    assert last.status_code == 200
    assert [goal["id"] for goal in last.json()] == [own[0]]
    assert last.headers["Pagination-Has-More"] == "false"
    assert "Pagination-Next-Before-Id" not in last.headers
    assert "Pagination-Next-Offset" not in last.headers


@pytest.mark.parametrize("query", ["before_id=0", "before_id=-1", f"before_id={2**63}",
                                  "before_id=invalid", "before_id=5&offset=1", "before_id=5&offset=-1"])
def test_invalid_or_mixed_cursor_refuses_before_world_access(world, monkeypatch, client, query):
    monkeypatch.setattr(api, "_world", lambda: pytest.fail("invalid cursor reached database"))
    assert client.get("/api/v1/goals?" + query).status_code == 422


def test_foreign_or_missing_cursor_is_only_numeric_boundary(world, client):
    allowed = world.create_goal("Own task", owner="user:alice")
    foreign = world.create_goal("Private anchor", owner="user:bob")
    for boundary in (foreign, foreign + 100):
        response = client.get(f"/api/v1/goals?before_id={boundary}")
        assert response.status_code == 200
        assert [goal["id"] for goal in response.json()] == [allowed]
        assert "Private anchor" not in response.text
