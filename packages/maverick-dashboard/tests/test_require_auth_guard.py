"""Guarded require-auth: with [dashboard] require_auth set, the dashboard
refuses to boot when NO auth mechanism (token / OIDC / reverse-proxy) is
configured -- so an operator who asked for auth can't accidentally serve the
loopback control surface unauthenticated. No-op unless explicitly enabled, so a
fresh single-tenant install is never locked out."""
from __future__ import annotations

import maverick_dashboard.app as app_mod
import pytest


def test_no_op_when_require_auth_off(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    app_mod._assert_dashboard_auth_configured()  # must not raise


def test_refuses_boot_when_required_but_no_auth(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: False)
    monkeypatch.setattr("maverick.proxy_auth.proxy_auth_enabled", lambda: False)
    monkeypatch.setattr("maverick_dashboard.invites.invites_enabled", lambda: False)
    monkeypatch.setattr("maverick_dashboard.saml.saml_enabled", lambda: False)
    with pytest.raises(RuntimeError, match="require_auth is set"):
        app_mod._assert_dashboard_auth_configured()


def test_satisfied_by_dashboard_token(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "tok")  # pragma: allowlist secret
    app_mod._assert_dashboard_auth_configured()  # token configured -> ok


def test_satisfied_by_oidc(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: True)
    app_mod._assert_dashboard_auth_configured()  # OIDC configured -> ok


def test_satisfied_by_complete_saml_session_auth(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: False)
    monkeypatch.setattr("maverick.proxy_auth.proxy_auth_enabled", lambda: False)
    monkeypatch.setattr("maverick_dashboard.invites.invites_enabled", lambda: False)
    monkeypatch.setattr("maverick_dashboard.saml.saml_enabled", lambda: True)
    monkeypatch.setattr(
        "maverick_dashboard.saml._session_secret",
        lambda: "configured-session-secret",  # pragma: allowlist secret
    )

    app_mod._assert_dashboard_auth_configured()


def test_incomplete_saml_without_session_secret_does_not_satisfy_guard(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: False)
    monkeypatch.setattr("maverick.proxy_auth.proxy_auth_enabled", lambda: False)
    monkeypatch.setattr("maverick_dashboard.invites.invites_enabled", lambda: False)
    monkeypatch.setattr("maverick_dashboard.saml.saml_enabled", lambda: True)
    monkeypatch.setattr("maverick_dashboard.saml._session_secret", str)

    with pytest.raises(RuntimeError, match="require_auth is set"):
        app_mod._assert_dashboard_auth_configured()


def test_unreadable_require_auth_policy_blocks_startup(monkeypatch):
    def _unreadable(*_args, **_kwargs):
        raise OSError("configuration unavailable")

    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "0")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr("maverick.config.load_config", _unreadable)
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: False)
    monkeypatch.setattr("maverick.proxy_auth.proxy_auth_enabled", lambda: False)
    monkeypatch.setattr("maverick_dashboard.invites.invites_enabled", lambda: False)
    monkeypatch.setattr("maverick_dashboard.saml.saml_enabled", lambda: False)

    assert app_mod._require_auth_enabled() is True
    with pytest.raises(RuntimeError, match="require_auth is set"):
        app_mod._assert_dashboard_auth_configured()
