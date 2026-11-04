"""Off-loop verification never moves the authoritative request tenant pin."""
from __future__ import annotations

import asyncio
import threading
import time

import httpx
import pytest
from fastapi import HTTPException, Request, WebSocket
from maverick import paths
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard import auth


@pytest.fixture
def identity(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    principal = VerifiedPrincipal("alice", "https://issuer.example", "lightwork", {"iat": time.time()})
    monkeypatch.setattr(auth, "verify_oidc_token", lambda _token: principal)
    return principal


def _connection(websocket=False):
    scope = {"type": "websocket" if websocket else "http", "path": "/metrics", "scheme": "http",
             "headers": [(b"authorization", b"Bearer synthetic"), (b"host", b"127.0.0.1")],
             "query_string": b"", "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 1234)}
    return WebSocket(scope, receive=None, send=None) if websocket else Request(scope)


@pytest.mark.parametrize("path", ["/openapi.json", "/redoc", "/docs", "/docs/oauth2-redirect",
                                  "/static/swagger-ui-5.33.1.css"])
def test_oidc_docs_routes_require_identity(identity, path):
    from fastapi.testclient import TestClient
    from maverick_dashboard.app import app

    client = TestClient(app, base_url="http://127.0.0.1", client=("198.51.100.12", 1234))
    assert client.get(path, follow_redirects=False).status_code in (401, 403, 307)
    assert client.get(path, headers={"Authorization": "Bearer synthetic"}).status_code == 200


def test_authenticated_schema_preserves_mount_root(identity):
    from fastapi.testclient import TestClient
    from maverick_dashboard.app import app

    client = TestClient(app, base_url="http://127.0.0.1", root_path="/lightwork")
    response = client.get("/openapi.json", headers={"Authorization": "Bearer synthetic"})
    assert response.status_code == 200
    assert {server["url"] for server in response.json()["servers"]} >= {"/lightwork"}


def test_blocked_verification_does_not_block_actual_asgi_probe_and_preserves_child_tenant(identity, monkeypatch):
    from maverick_dashboard import api
    from maverick_dashboard.app import app

    entered, release = threading.Event(), threading.Event()
    seen = []

    def verify(_token):
        seen.append(("verify", paths.current_tenant_id(), threading.get_ident()))
        entered.set()
        assert release.wait(3)
        return identity

    class World:
        def get_facts(self):
            seen.append(("route_worker", paths.current_tenant_id(), threading.get_ident()))
            return {}

    monkeypatch.setattr(auth, "verify_oidc_token", verify)
    monkeypatch.setattr(api, "_world", World)

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"Origin": "http://127.0.0.1"}) as client:
            # A served dashboard has built its routes during startup warm-up
            # (app._warm_goal_runtime); FastAPI builds included routes lazily
            # on first match, which this in-process client would otherwise pay
            # inside the timed probe. Warm them the same way first.
            assert (await client.get("/livez")).status_code == 200
            request = asyncio.create_task(client.get("/api/v1/facts", headers={"Authorization": "Bearer synthetic"}))
            try:
                assert await asyncio.to_thread(entered.wait, 1)
                probe = await asyncio.wait_for(client.get("/livez"), 0.5)
                assert probe.status_code == 200 and not request.done()
            finally:
                release.set()
            assert (await request).status_code == 200
        assert seen[0][1] is None and seen[0][2] != loop_thread
        assert seen[-1][0:2] == ("route_worker", "api:user:alice")
        assert paths.current_tenant_id() is None
    asyncio.run(run())


def test_websocket_binding_occurs_in_handler_and_resets_on_exit(identity):
    async def run():
        websocket = _connection(websocket=True)
        dependency = auth.require_websocket_principal_in_context(websocket)
        assert await anext(dependency) is identity
        assert paths.current_tenant_id() == "api:user:alice"
        assert await asyncio.to_thread(paths.current_tenant_id) == "api:user:alice"
        await dependency.aclose()
        assert paths.current_tenant_id() is None
    asyncio.run(run())


def test_cancelled_request_keeps_resolver_admission_until_worker_exits(identity, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr(auth, "_OIDC_VERIFY_SLOTS", 1)
    monkeypatch.setattr(auth, "_OIDC_ADMISSION_SECONDS", 0.01)

    def verify(_token):
        entered.set()
        assert release.wait(3)
        return identity

    monkeypatch.setattr(auth, "verify_oidc_token", verify)

    async def run():
        first = _connection()
        request = asyncio.create_task(auth.require_principal_in_request_context(request=first))
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request
            with pytest.raises(HTTPException) as error:
                await auth.require_principal_in_request_context(request=_connection())
            assert error.value.status_code == 503
            assert not hasattr(first.state, "principal")
        finally:
            release.set()
        limiter = asyncio.get_running_loop()._lightwork_oidc_slots
        await asyncio.wait_for(limiter.acquire(), 1)
        limiter.release()
        assert paths.current_tenant_id() is None
    asyncio.run(run())


def test_revocation_and_workspace_membership_are_rechecked_after_key_verification(identity, monkeypatch):
    from maverick.tenant import registry
    from maverick_dashboard import scim_groups, workspace_tenants

    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "0")
    monkeypatch.setattr(workspace_tenants, "get_selection", lambda _principal: "acme")
    monkeypatch.setattr(registry, "is_active", lambda _tenant: True)
    allowed = [True]
    monkeypatch.setattr(workspace_tenants, "principal_can_select", lambda *_args: allowed[0])
    active = [True]
    monkeypatch.setattr(scim_groups, "active_for_principal", lambda _principal: active[0])

    async def run():
        first = _connection()
        assert await auth.require_principal_in_request_context(request=first) is identity
        assert paths.current_tenant_id() == "acme"
        paths.reset_tenant(first.state.tenant_pin_token)
        allowed[0] = False
        second = _connection()
        await auth.require_principal_in_request_context(request=second)
        assert paths.current_tenant_id() is None
        assert second.state.workspace_tenant_denied == "acme"
        active[0] = False
        with pytest.raises(HTTPException) as error:
            await auth.require_principal_in_request_context(request=_connection())
        assert error.value.status_code == 401
        assert paths.current_tenant_id() is None
    asyncio.run(run())
