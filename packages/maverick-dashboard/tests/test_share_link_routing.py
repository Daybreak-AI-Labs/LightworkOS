"""Opaque public-share routing never treats an address as read authority."""
from __future__ import annotations

import hashlib
import json
import secrets
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def share_env(tmp_path, monkeypatch):
    from maverick import world_model
    from maverick_dashboard import app

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "absent.toml"))
    monkeypatch.delenv("MAVERICK_PUBLIC_URL", raising=False)
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app._world_cache.clear()
    return TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _create(client, goal_id):
    preview = client.post(f"/api/v1/goals/{goal_id}/share/preview")
    assert preview.status_code == 200, preview.text
    return client.post(f"/api/v1/goals/{goal_id}/share", json={
        "confirm": True, "source_sha256": preview.json()["source"]["sha256"],
        "lifetime_seconds": 3600, "label": "Read-only answer",
    })


def test_selected_workspace_link_reaches_external_reader_and_revokes(share_env):
    from maverick.paths import current_tenant_id, reset_tenant, set_tenant
    from maverick_dashboard import app

    client = share_env
    default = app._world()
    root_id = default.create_goal("Default answer", "")
    default.set_goal_status(root_id, "done", result="default-only content")
    scope = set_tenant("selected-workspace")
    try:
        world = app._world()
        gid = world.create_goal("Partner answer", "")
        world.set_goal_status(gid, "done", result="selected-workspace content")
        created = _create(client, gid)
        assert created.status_code == 201, created.text
        data = created.json()
    finally:
        reset_tenant(scope)
    token = data["url"].rsplit("/", 1)[1]
    public = TestClient(app.app, base_url="http://127.0.0.1").get(f"/share/{token}")
    assert public.status_code == 200
    assert "selected-workspace content" in public.text
    assert "default-only content" not in public.text
    assert current_tenant_id() is None
    scope = set_tenant("selected-workspace")
    try:
        assert client.post(f"/api/v1/goals/{gid}/share/{data['id']}/revoke").json()["ok"]
    finally:
        reset_tenant(scope)
    assert TestClient(app.app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 404


def test_unknown_and_malformed_tokens_create_no_routing_or_world_files(share_env, monkeypatch):
    from maverick.paths import maverick_home
    from maverick_dashboard import app, share_link_routing

    def must_not_open():
        pytest.fail("an unknown token attempted to create a world")

    monkeypatch.setattr(app, "_world", must_not_open)
    random_token = secrets.token_urlsafe(32)
    assert share_link_routing.resolve(random_token) is None
    new_token = "r1_" + secrets.token_urlsafe(32)
    with pytest.raises(share_link_routing.ShareRouteError):
        share_link_routing.resolve(new_token)
    for token in (random_token, new_token, "bad", "a" * 5000):
        assert share_env.get(f"/share/{token}").status_code == 404
    assert not (maverick_home() / "dashboard-share-routes").exists()
    assert not (maverick_home() / "tenants").exists()


@pytest.mark.parametrize("corrupt", ["invalid_json", "wrong_hash", "duplicate_field"])
def test_corrupt_locator_never_falls_back_to_legacy_store(share_env, monkeypatch, corrupt):
    from maverick.paths import maverick_home
    from maverick_dashboard import app, share_link_routing

    token = secrets.token_urlsafe(32)
    share_link_routing.register(token, expires_at=time.time() + 3600)
    digest = hashlib.sha256(token.encode()).hexdigest()
    path = maverick_home() / "dashboard-share-routes" / f"{digest}.json"
    if corrupt == "invalid_json":
        text = "broken"
    elif corrupt == "duplicate_field":
        text = '{"version":1,"version":1}'
    else:
        record = json.loads(path.read_text())
        record["token_sha256"] = "0" * 64
        text = json.dumps(record)
    path.write_text(text)

    def must_not_open():
        pytest.fail("a corrupt locator fell back to a world")

    monkeypatch.setattr(app, "_world", must_not_open)
    assert share_env.get(f"/share/{token}").status_code == 404


def test_expired_locator_fails_closed_and_is_pruned_on_next_creation(share_env, monkeypatch):
    from maverick.paths import maverick_home
    from maverick_dashboard import share_link_routing

    token = secrets.token_urlsafe(32)
    now = time.time()
    share_link_routing.register(token, expires_at=now + 3600)
    path = maverick_home() / "dashboard-share-routes" / f"{hashlib.sha256(token.encode()).hexdigest()}.json"
    monkeypatch.setattr(share_link_routing.time, "time", lambda: now + 3601)
    assert share_env.get(f"/share/{token}").status_code == 404
    assert path.exists()  # anonymous resolution does not mutate routing storage
    share_link_routing.register(secrets.token_urlsafe(32), expires_at=now + 7200)
    assert not path.exists()


def test_routing_failure_revokes_new_link(share_env, monkeypatch):
    from maverick_dashboard import app, share_link_routing

    world = app._world()
    gid = world.create_goal("Answer", "")
    world.set_goal_status(gid, "done", result="answer")

    def fail(*args, **kwargs):
        raise OSError("synthetic routing persistence failure")

    monkeypatch.setattr(share_link_routing, "register", fail)
    assert _create(share_env, gid).status_code == 503
    links = world.share_links_for_goal(gid)
    assert len(links) == 1 and links[0]["revoked"]


def test_legacy_default_scope_token_remains_usable(share_env):
    from maverick_dashboard import app

    world = app._world()
    gid = world.create_goal("Existing shared answer", "")
    world.set_goal_status(gid, "done", result="legacy answer")
    _, token = world.create_share_link(gid, ttl_seconds=3600)
    assert share_env.get(f"/share/{token}").status_code == 200


def test_missing_selected_world_is_not_recreated(share_env, monkeypatch):
    from maverick.paths import maverick_home, reset_tenant, set_tenant
    from maverick_dashboard import app, share_link_routing

    token = secrets.token_urlsafe(32)
    scope = set_tenant("removed-workspace")
    try:
        share_link_routing.register(token, expires_at=time.time() + 3600)
    finally:
        reset_tenant(scope)

    def must_not_open():
        pytest.fail("public sharing recreated a removed workspace")

    monkeypatch.setattr(app, "_world", must_not_open)
    assert share_env.get(f"/share/{token}").status_code == 404
    assert not (maverick_home() / "tenants").exists()


def test_public_scope_restored_when_store_raises(share_env, monkeypatch):
    from fastapi import HTTPException, Request
    from maverick.paths import current_tenant_id, reset_tenant, set_tenant
    from maverick_dashboard import app, share_link_routing

    token = secrets.token_urlsafe(32)
    target = set_tenant("shared-workspace")
    try:
        share_link_routing.register(token, expires_at=time.time() + 3600)
    finally:
        reset_tenant(target)

    def unavailable(request, share_token):
        assert current_tenant_id() == "shared-workspace"
        raise OSError("synthetic storage error")

    monkeypatch.setattr(app, "_shared_goal_in_scope", unavailable)
    previous = set_tenant("previous-workspace")
    try:
        with pytest.raises(HTTPException) as failure:
            app.shared_goal(Request({"type": "http", "headers": []}), token)
        assert failure.value.status_code == 404
        assert current_tenant_id() == "previous-workspace"
    finally:
        reset_tenant(previous)


def test_postgres_share_resolution_does_not_require_sqlite_file(share_env, monkeypatch):
    from maverick import world_model_backends
    from maverick_dashboard import app

    calls = []

    class ExistingPostgresWorld:
        def resolve_share_link(self, token):
            calls.append(token)
            return None

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.setattr(app, "_world", lambda: ExistingPostgresWorld())
    token = secrets.token_urlsafe(32)
    assert share_env.get(f"/share/{token}").status_code == 404
    assert calls == [token]


@pytest.mark.parametrize("address", [
    "https://user:pass@example.com", "https://example.com?secret=1",
    "https://example.com/#fragment", "http://192.168.1.10", "file:///example",
    "https://bad<host>", "https://example.com/\x00path",
])
def test_invalid_configured_share_address_is_rejected_before_mint(share_env, monkeypatch, address):
    from maverick_dashboard import app, automation_queue

    monkeypatch.setattr(automation_queue, "_public_base_url", lambda: address)
    world = app._world()
    gid = world.create_goal("Answer", "")
    world.set_goal_status(gid, "done", result="answer")
    assert _create(share_env, gid).status_code == 409
    assert world.share_links_for_goal(gid) == []


def test_configured_share_address_and_local_boundary(share_env, monkeypatch):
    from maverick_dashboard import app, share_link_routing

    world = app._world()
    gid = world.create_goal("Answer", "")
    world.set_goal_status(gid, "done", result="answer")
    monkeypatch.setenv("MAVERICK_PUBLIC_URL", "https://lightwork.example.com/app")
    response = _create(share_env, gid)
    assert response.status_code == 201
    assert response.json()["url"].startswith("https://lightwork.example.com/app/share/")
    assert response.json()["local_only"] is False
    monkeypatch.delenv("MAVERICK_PUBLIC_URL")
    assert share_link_routing.share_base_url("http://127.0.0.1:8765/")[1] is True
    assert share_link_routing.share_base_url("http://192.168.1.10:8765/")[1] is True
