"""Reverse-proxy SSO wiring in the dashboard's ``require_principal``.

Hermetic: we monkeypatch the ``maverick.proxy_auth`` seams bound into
``maverick_dashboard.auth`` and drive ``require_principal`` with a fake request,
so the tests exercise the dependency wiring (trusted-peer gate -> principal),
not config/IO.
"""
from __future__ import annotations

from types import SimpleNamespace

import maverick_dashboard.auth as auth
import pytest
from maverick.oidc import OIDCError, VerifiedPrincipal
from starlette.datastructures import Headers


def _req(headers=None, host="127.0.0.1", path="/metrics"):
    return SimpleNamespace(
        headers=Headers(headers or {}),
        cookies={},
        url=SimpleNamespace(path=path),
        client=SimpleNamespace(host=host),
        state=SimpleNamespace(),
    )


def _ws(headers=None, host="127.0.0.1"):
    values = {"Origin": "http://127.0.0.1", "Host": "127.0.0.1"}
    values.update(headers or {})
    return SimpleNamespace(
        headers=Headers(values),
        cookies={},
        client=SimpleNamespace(host=host),
        state=SimpleNamespace(),
    )


def test_trusted_proxy_header_sets_principal(monkeypatch):
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda host: host == "127.0.0.1")
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)  # proxy is the source

    req = _req(headers={"X-Forwarded-User": "alice"}, host="127.0.0.1")
    p = auth.require_principal(req)
    assert p is not None and p.principal == "user:alice"
    assert req.state.principal.principal == "user:alice"


def test_trusted_proxy_rejects_padded_identity_instead_of_trimming(monkeypatch):
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: True)
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)

    req = _req(headers={"X-Forwarded-User": "alice "})

    with pytest.raises(auth.HTTPException) as exc:
        auth.require_principal(req)
    assert exc.value.status_code == 401
    assert not hasattr(req.state, "principal")


def test_untrusted_peer_header_fails_closed(monkeypatch):
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda host: False)
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)

    req = _req(headers={"X-Forwarded-User": "attacker"}, host="10.9.9.9")
    with pytest.raises(auth.HTTPException) as exc:
        auth.require_principal(req)
    assert exc.value.status_code == 401


def test_trusted_peer_without_header_fails_closed_even_without_require_auth(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", raising=False)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda host: True)
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)

    with pytest.raises(auth.HTTPException) as exc:
        auth.require_principal(_req(headers={}, host="127.0.0.1"))
    assert exc.value.status_code == 401


def test_proxy_disabled_is_noop(monkeypatch):
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    req = _req(headers={"X-Forwarded-User": "alice"})
    assert auth.require_principal(req) is None


def test_proxy_can_fall_back_to_valid_oidc_bearer(monkeypatch):
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "_session_principal", lambda _request: None)
    monkeypatch.setattr(
        auth,
        "verify_oidc_token",
        lambda _token: VerifiedPrincipal(
            sub="oidc-user",
            issuer="https://issuer.example",
            audience="lightwork",
            claims={"iat": 1},
        ),
    )
    req = _req(headers={"Authorization": "Bearer oidc-token"})

    principal = auth.require_principal(req)

    assert principal is not None and principal.principal == "user:oidc-user"


def test_proxy_can_fall_back_to_verified_invite_session(monkeypatch):
    principal = VerifiedPrincipal(
        sub="invitee@example.com",
        issuer="invite-session",
        audience="",
        claims={"via": "invite"},
    )
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "_session_principal", lambda _request: None)
    monkeypatch.setattr(auth, "_invite_session_principal", lambda _request: principal)
    req = _req()

    assert auth.require_principal(req) is principal
    assert req.state.principal is principal


def test_proxy_can_fall_back_to_valid_static_dashboard_token(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-token")
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "_session_principal", lambda _request: None)
    monkeypatch.setattr(auth, "_invite_session_principal", lambda _request: None)
    req = _req(headers={"Authorization": "Bearer dashboard-token"})

    assert auth.require_principal(req) is None


def test_proxy_missing_identity_does_not_block_self_authenticated_routes(monkeypatch):
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "_session_principal", lambda _request: None)
    monkeypatch.setattr(auth, "_invite_session_principal", lambda _request: None)

    assert auth.require_principal(_req(path="/webhook/start")) is None


def test_require_auth_proxy_without_header_fails_closed(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "1")
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda host: True)
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)

    try:
        auth.require_principal(_req(headers={}, host="127.0.0.1"))
    except auth.HTTPException as exc:
        assert exc.status_code == 401
    else:  # pragma: no cover - assertion clarity
        raise AssertionError("missing proxy identity header should fail closed")


def test_missing_identity_cannot_inherit_local_permission_bypasses(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: False)
    request = _req()
    goal = SimpleNamespace(owner="")

    checks = (
        lambda: auth.caller_role(request),
        lambda: auth.has_permission(request, "view"),
        lambda: auth.has_global_permission(request, "admin"),
        lambda: auth.caller_suites(request),
        lambda: auth.suite_allowed(request, None),
        lambda: auth.goal_owner_filter(request),
        lambda: auth.can_access_goal(request, goal),
    )
    for check in checks:
        with pytest.raises(auth.HTTPException) as exc:
            check()
        assert exc.value.status_code == 401


def test_genuine_auth_off_local_mode_keeps_legacy_permissions(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: True)
    monkeypatch.setattr("maverick.client.client_binding_enforced", lambda: False)
    request = _req()

    assert auth.has_permission(request, "admin") is True
    assert auth.has_global_permission(request, "admin") is True
    assert auth.caller_suites(request) is None
    assert auth.goal_owner_filter(request) == ""
    assert auth.can_access_goal(request, SimpleNamespace(id=1, owner="user:employee")) is False
    assert auth.can_access_goal(request, SimpleNamespace(id=2, owner="")) is True


def test_verified_static_token_keeps_authenticated_operator_permissions(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-token")
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: False)
    request = _req(headers={"Authorization": "Bearer dashboard-token"})

    assert auth.has_permission(request, "admin") is True
    assert auth.has_global_permission(request, "admin") is True
    assert auth.goal_owner_filter(request) == ""


@pytest.mark.parametrize("mode", ["saml", "invites"])
def test_session_only_auth_modes_reject_anonymous_http_and_websocket(
    monkeypatch, mode,
):
    from maverick_dashboard import invites, saml

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", raising=False)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "_session_principal", lambda _request: None)
    monkeypatch.setattr(auth, "_invite_session_principal", lambda _request: None)
    monkeypatch.setattr(invites, "invites_enabled", lambda: mode == "invites")
    monkeypatch.setattr(saml, "saml_enabled", lambda: mode == "saml")

    assert auth.auth_genuinely_off() is False
    with pytest.raises(auth.HTTPException) as http_exc:
        auth.require_principal(_req())
    assert http_exc.value.status_code == 401

    websocket = _ws()
    with pytest.raises(auth.HTTPException) as ws_exc:
        auth.require_principal(websocket=websocket)
    assert ws_exc.value.status_code == 401
    assert auth.websocket_authorized(websocket) is False


def test_websocket_accepts_valid_trusted_proxy_identity(monkeypatch):
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda host: host == "127.0.0.1")
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    websocket = _ws(headers={"X-Forwarded-User": "alice"})

    principal = auth.require_principal(websocket=websocket)

    assert principal is not None and principal.principal == "user:alice"
    assert auth.websocket_authorized(websocket, principal) is True


def test_websocket_invalid_explicit_bearer_cannot_fall_back_to_session(
    monkeypatch,
):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-operator-token")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(
        auth,
        "_session_principal",
        lambda _request: VerifiedPrincipal(
            sub="ambient-cookie-user",
            issuer="browser-session",
            audience="lightwork",
            claims={"via": "session", "iat": 1},
        ),
    )

    def _reject(_token):
        raise OIDCError("invalid token")

    monkeypatch.setattr(auth, "verify_oidc_token", _reject)
    websocket = _ws(headers={"Authorization": "Bearer invalid-explicit-token"})

    with pytest.raises(auth.HTTPException) as exc:
        auth.require_principal(websocket=websocket)
    assert exc.value.status_code == 401


def test_websocket_static_and_oidc_bearers_compose(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-operator-token")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    principal = VerifiedPrincipal(
        sub="api-client",
        issuer="https://issuer.example",
        audience="lightwork",
        claims={"iat": 1},
    )
    monkeypatch.setattr(auth, "verify_oidc_token", lambda _token: principal)
    monkeypatch.setattr(auth, "_enforce_scim_active", lambda _principal: None)
    monkeypatch.setattr(auth, "_pin_tenant_from_principal", lambda *_args: None)
    websocket = _ws(headers={"Authorization": "Bearer valid-oidc-token"})

    established = auth.require_principal(websocket=websocket)

    assert established is principal
    assert auth.websocket_authorized(websocket, established) is True


@pytest.mark.parametrize(
    ("headers", "trusted"),
    [
        ({}, True),
        ({"X-Forwarded-User": "alice "}, True),
        ({"X-Forwarded-User": "attacker"}, False),
    ],
)
def test_websocket_proxy_rejects_missing_invalid_or_untrusted_identity(
    monkeypatch, headers, trusted,
):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: trusted)
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "_session_principal", lambda _request: None)
    monkeypatch.setattr(auth, "_invite_session_principal", lambda _request: None)
    websocket = _ws(headers=headers)

    with pytest.raises(auth.HTTPException) as exc:
        auth.require_principal(websocket=websocket)
    assert exc.value.status_code == 401
    assert auth.websocket_authorized(websocket) is False


def test_websocket_genuine_auth_off_and_static_token_modes_remain_supported(
    monkeypatch,
):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "_session_principal", lambda _request: None)
    monkeypatch.setattr(auth, "_invite_session_principal", lambda _request: None)
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: True)
    monkeypatch.setattr("maverick.client.client_binding_enforced", lambda: False)
    local = _ws()

    assert auth.require_principal(websocket=local) is None
    assert auth.websocket_authorized(local) is True

    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-token")
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: False)
    token_ws = _ws(headers={"Authorization": "Bearer dashboard-token"})

    assert auth.require_principal(websocket=token_ws) is None
    assert auth.websocket_authorized(token_ws) is True


def test_client_binding_disables_anonymous_permissions_and_websocket(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: True)
    monkeypatch.setattr("maverick.client.client_binding_enforced", lambda: True)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "_session_principal", lambda _request: None)
    monkeypatch.setattr(auth, "_invite_session_principal", lambda _request: None)

    assert auth.anonymous_local_access_allowed() is False
    with pytest.raises(auth.HTTPException) as permission_exc:
        auth.has_permission(_req(), "admin")
    assert permission_exc.value.status_code == 401

    websocket = _ws()
    with pytest.raises(auth.HTTPException) as ws_exc:
        auth.require_principal(websocket=websocket)
    assert ws_exc.value.status_code == 401
    assert auth.websocket_authorized(websocket) is False


def test_client_binding_accepts_explicit_static_operator_token(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-token")
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: True)
    monkeypatch.setattr("maverick.client.client_binding_enforced", lambda: True)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "_session_principal", lambda _request: None)
    monkeypatch.setattr(auth, "_invite_session_principal", lambda _request: None)
    request = _req(headers={"Authorization": "Bearer dashboard-token"})
    websocket = _ws(headers={"Authorization": "Bearer dashboard-token"})

    assert auth.require_principal(request) is None
    assert auth.has_permission(request, "admin") is True
    assert auth.require_principal(websocket=websocket) is None
    assert auth.websocket_authorized(websocket) is True


def test_self_authenticated_webhook_set_matches_middleware_and_is_exact(monkeypatch):
    from maverick_dashboard import app as app_mod
    from maverick_dashboard import voice_receiver_api

    # Exactly the reviewed self-authenticating receivers bypass the middleware:
    # every /webhook/ route, plus the phone receiver, which checks the
    # provider's own current call key (see voice_receiver_api).
    middleware_webhooks = {
        path for path in app_mod._AUTH_EXEMPT
        if path.startswith("/webhook/") or path == voice_receiver_api.RECEIVER_PATH
    }
    assert middleware_webhooks == set(auth.SELF_AUTH_WEBHOOK_PATHS)
    assert set(auth.SELF_AUTH_WEBHOOK_PATHS) - {voice_receiver_api.RECEIVER_PATH} == {
        path for path in app_mod._AUTH_EXEMPT if path.startswith("/webhook/")}
    assert all(auth._self_authenticated_path(path) for path in middleware_webhooks)
    with pytest.raises(auth.HTTPException) as refused:
        voice_receiver_api._current("Bearer not-the-saved-key")
    assert refused.value.status_code in {401, 409}  # off, or the wrong key

    future_path = "/webhook/future-unaudited-route"
    assert auth._self_authenticated_path(future_path) is False
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "_session_principal", lambda _request: None)
    monkeypatch.setattr(auth, "_invite_session_principal", lambda _request: None)

    with pytest.raises(auth.HTTPException) as exc:
        auth.require_principal(_req(path=future_path))
    assert exc.value.status_code == 401


def test_unreadable_dashboard_auth_policy_cannot_enable_local_admin(monkeypatch):
    from maverick_dashboard import invites, saml

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "0")
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setattr(
        "maverick.config.config_source_errors",
        lambda: {"config.toml": "unreadable"},
    )
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(invites, "invites_enabled", lambda: False)
    monkeypatch.setattr(saml, "saml_enabled", lambda: False)

    assert auth._dashboard_require_auth_enabled() is True
    assert auth.auth_genuinely_off() is False
    with pytest.raises(auth.HTTPException) as exc:
        auth.has_permission(_req(), "admin")
    assert exc.value.status_code == 401


@pytest.mark.parametrize(
    "saml_policy",
    [
        {"sp_entity_id": "https://sp.example/saml/metadata"},
        "invalid-non-table-policy",
        None,
    ],
)
def test_incomplete_or_invalid_saml_policy_cannot_enable_local_admin(
    monkeypatch, saml_policy,
):
    from maverick_dashboard import invites, saml

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", raising=False)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {"auth": {"saml": saml_policy}},
    )
    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(invites, "invites_enabled", lambda: False)
    monkeypatch.setattr(saml, "saml_enabled", lambda: False)
    monkeypatch.setattr("maverick.client.client_binding_enforced", lambda: False)

    assert auth._saml_policy_configured() is True
    assert auth.auth_genuinely_off() is False
    with pytest.raises(auth.HTTPException) as exc:
        auth.has_permission(_req(), "admin")
    assert exc.value.status_code == 401
    assert auth.websocket_authorized(_ws()) is False


def test_empty_saml_table_is_not_mistaken_for_an_identity_policy(monkeypatch):
    from maverick_dashboard import invites, saml

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", raising=False)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {"auth": {"saml": {}}},
    )
    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(invites, "invites_enabled", lambda: False)
    monkeypatch.setattr(saml, "saml_enabled", lambda: False)

    assert auth._saml_policy_configured() is False
    assert auth.auth_genuinely_off() is True


def test_auth_off_websocket_rejects_dns_rebinding_host(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: True)
    monkeypatch.setattr("maverick.client.client_binding_enforced", lambda: False)
    websocket = _ws(
        headers={
            "Origin": "http://attacker.example",
            "Host": "attacker.example",
        },
        host="127.0.0.1",
    )

    # The hostile pair is internally same-origin, which demonstrates why the
    # independent request-Host loopback check is load-bearing.
    assert auth._websocket_same_origin(websocket) is True
    assert auth._websocket_loopback_request_host(websocket) is False
    assert auth.websocket_authorized(websocket) is False


@pytest.mark.parametrize(
    "host",
    ["localhost", "localhost:8000", "127.0.0.1:8000", "[::1]:8000", "127.0.0.1"],
)
def test_auth_off_websocket_accepts_explicit_loopback_request_hosts(
    monkeypatch, host,
):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: True)
    monkeypatch.setattr("maverick.client.client_binding_enforced", lambda: False)
    websocket = _ws(headers={"Origin": f"http://{host}", "Host": host})

    assert auth._websocket_loopback_request_host(websocket) is True
    assert auth.websocket_authorized(websocket) is True


def test_testserver_is_not_trusted_as_a_loopback_host(monkeypatch):
    from fastapi.testclient import TestClient
    from maverick_dashboard import app as dashboard

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth, "auth_genuinely_off", lambda: True)
    monkeypatch.setattr("maverick.client.client_binding_enforced", lambda: False)
    assert dashboard._is_loopback_request_host(
        SimpleNamespace(url=SimpleNamespace(hostname="testserver"))
    ) is False
    websocket = _ws(headers={"Origin": "http://testserver", "Host": "testserver"})
    assert auth._websocket_same_origin(websocket) is True
    assert auth._websocket_loopback_request_host(websocket) is False
    assert auth.websocket_authorized(websocket) is False

    with TestClient(dashboard.app, base_url="http://testserver") as client:
        response = client.get("/api/v1/goals", headers={"Origin": "http://testserver"})
        assert response.status_code == 401
        assert response.json()["detail"].startswith("Remote access to this dashboard")


def test_automation_creation_needs_a_durable_owner_when_auth_is_enabled(monkeypatch):
    request = _req()
    monkeypatch.setattr(auth, "caller_principal", lambda _request: None)
    monkeypatch.setattr(auth, "anonymous_local_access_allowed", lambda: False)
    with pytest.raises(auth.HTTPException) as refused:
        auth.require_durable_automation_creator(request)
    assert refused.value.status_code == 409
    assert "named account" in refused.value.detail

    monkeypatch.setattr(auth, "anonymous_local_access_allowed", lambda: True)
    assert auth.require_durable_automation_creator(request) == ""
    monkeypatch.setattr(auth, "anonymous_local_access_allowed", lambda: False)
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:alice")
    assert auth.require_durable_automation_creator(request) == "user:alice"
