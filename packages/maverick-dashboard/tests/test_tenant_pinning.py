"""Per-request tenant pinning.

The world model's tenant scoping (app-layer predicate + Postgres RLS GUC) only
engages when a tenant is pinned; no dashboard request pinned one. The
tenant_pinning middleware pins it from the verified principal when per-user
tenancy is enabled, and is a no-op (single-tenant default) otherwise.
"""

from __future__ import annotations

import maverick_dashboard.auth as auth
import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_world(tmp_path, monkeypatch):
    from maverick import world_model
    from maverick_dashboard import app as app_mod

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    world_model._tenant_worlds.clear()
    app_mod._world_cache.clear()
    yield
    world_model._tenant_worlds.clear()
    app_mod._world_cache.clear()


def _enable_proxy_auth(monkeypatch):
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda host: True)
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)


def test_pins_tenant_from_real_proxy_principal_when_by_user_enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    _enable_proxy_auth(monkeypatch)
    calls = []
    import maverick.paths as paths

    real_set = paths.set_tenant

    def _record(t):
        calls.append(t)
        return real_set(t)

    monkeypatch.setattr(paths, "set_tenant", _record)
    r = client.get("/api/v1/facts", headers={"X-Forwarded-User": "alice"})
    assert r.status_code == 200
    assert calls == ["api:user:alice"]  # pinned after auth, before route world lookup
    # And the pin was reset after the request (no leak).
    assert paths.current_tenant_id() is None


def test_authenticated_route_executes_inside_the_pinned_tenant(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    _enable_proxy_auth(monkeypatch)
    import maverick.paths as paths
    import maverick_dashboard.api as api

    seen = []

    class _World:
        def get_facts(self):
            seen.append(paths.current_tenant_id())
            return {}

    monkeypatch.setattr(api, "_world", lambda: _World())
    r = client.get("/api/v1/facts", headers={"X-Forwarded-User": "alice"})
    assert r.status_code == 200
    assert seen == ["api:user:alice"]
    assert paths.current_tenant_id() is None


def test_no_pin_when_by_user_disabled(monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    _enable_proxy_auth(monkeypatch)
    calls = []
    import maverick.paths as paths

    monkeypatch.setattr(paths, "set_tenant", lambda t: calls.append(t))
    r = client.get("/api/v1/facts", headers={"X-Forwarded-User": "bob"})
    assert r.status_code == 200
    assert calls == []  # single-tenant default: no pinning


def test_no_pin_when_no_principal(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    calls = []
    import maverick.paths as paths

    monkeypatch.setattr(paths, "set_tenant", lambda t: calls.append(t))
    r = client.get("/api/v1/facts")
    assert r.status_code == 200
    assert calls == []  # unauthenticated -> no tenant to pin


def _terminal_goal(world, *, owner: str, event: str) -> int:
    goal_id = world.create_goal("tenant websocket", "isolation", owner=owner)
    world.append_event(goal_id, "coder", "finding", event)
    world.set_goal_status(goal_id, "done", result="ok")
    return goal_id


def _record_tenant_resets(monkeypatch):
    import maverick.paths as paths

    resets = []
    real_reset = paths.reset_tenant

    def _record(token):
        before = paths.current_tenant_id()
        real_reset(token)
        resets.append((before, paths.current_tenant_id()))

    monkeypatch.setattr(paths, "reset_tenant", _record)
    return resets


def test_websocket_uses_principal_tenant_with_colliding_same_owner_goal(
    monkeypatch,
):
    """Owner equality cannot substitute for selecting the correct tenant DB."""
    from maverick.world_model import world_for_tenant

    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    _enable_proxy_auth(monkeypatch)
    alice_world = world_for_tenant("api:user:alice")
    bob_world = world_for_tenant("api:user:bob")
    alice_goal = _terminal_goal(
        alice_world, owner="user:alice", event="ALICE_TENANT_EVENT"
    )
    bob_goal = _terminal_goal(
        bob_world, owner="user:alice", event="BOB_SECRET_SAME_OWNER_EVENT"
    )
    assert alice_goal == bob_goal  # deliberate cross-tenant id collision
    resets = _record_tenant_resets(monkeypatch)

    with client.websocket_connect(
        "ws://127.0.0.1" + f"/ws/v1/runs/{alice_goal}/events",
        headers={
            "Origin": "http://127.0.0.1",
            "X-Forwarded-User": "alice",
        },
    ) as websocket:
        first = websocket.receive_json()
        final = websocket.receive_json()

    assert first["content"] == "ALICE_TENANT_EVENT"
    assert "BOB_SECRET" not in str(first)
    assert final["kind"] == "status" and final["content"] == "done"
    assert resets == [("api:user:alice", None)]


def test_websocket_wrong_tenant_same_owner_is_non_disclosing_and_resets(
    monkeypatch,
):
    from maverick.world_model import world_for_tenant

    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    _enable_proxy_auth(monkeypatch)
    wrong_tenant_goal = _terminal_goal(
        world_for_tenant("api:user:bob"),
        owner="user:alice",
        event="WRONG_TENANT_SECRET",
    )
    resets = _record_tenant_resets(monkeypatch)

    with client.websocket_connect(
        "ws://127.0.0.1" + f"/ws/v1/runs/{wrong_tenant_goal}/events",
        headers={
            "Origin": "http://127.0.0.1",
            "X-Forwarded-User": "alice",
        },
    ) as websocket:
        assert websocket.receive_json() == {"error": "no such goal"}

    assert resets == [("api:user:alice", None)]


def test_websocket_wrong_owner_in_correct_tenant_is_non_disclosing(monkeypatch):
    from maverick.world_model import world_for_tenant

    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    _enable_proxy_auth(monkeypatch)
    wrong_owner_goal = _terminal_goal(
        world_for_tenant("api:user:alice"),
        owner="user:bob",
        event="WRONG_OWNER_SECRET",
    )

    with client.websocket_connect(
        "ws://127.0.0.1" + f"/ws/v1/runs/{wrong_owner_goal}/events",
        headers={
            "Origin": "http://127.0.0.1",
            "X-Forwarded-User": "alice",
        },
    ) as websocket:
        assert websocket.receive_json() == {"error": "no such goal"}
