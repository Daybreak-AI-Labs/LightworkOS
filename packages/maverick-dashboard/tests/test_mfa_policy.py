"""Second-factor policy: what proves a second factor, and step-up freshness."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from maverick import config
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard import mfa_policy, step_up


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_MFA_REQUIRE", "MAVERICK_MFA_STEP_UP_MINUTES"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _write_config(tmp_path, text: str) -> None:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(text, encoding="utf-8")
    config.reset_config_cache()


# ---- policy defaults and knobs ------------------------------------------------


def test_policy_is_off_by_default():
    assert mfa_policy.require_mfa() is False
    assert mfa_policy.step_up_seconds() == 15 * 60
    p = mfa_policy.policy()
    assert "otp" in p["amr_values"] and "pwd" not in p["amr_values"]
    assert p["acr_values"] == []
    assert "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken" in p["saml_authn_contexts"]


def test_env_and_config_turn_it_on(tmp_path, monkeypatch):
    _write_config(tmp_path, "[auth.mfa]\nrequire = true\nstep_up_minutes = 5\n"
                            "amr_values = [\"custom\"]\nacr_values = [\"urn:x:mfa\"]\n")
    assert mfa_policy.require_mfa() is True
    assert mfa_policy.step_up_seconds() == 300
    assert mfa_policy.policy()["amr_values"] == ["custom"]
    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "0")
    assert mfa_policy.require_mfa() is False
    monkeypatch.setenv("MAVERICK_MFA_STEP_UP_MINUTES", "2")
    assert mfa_policy.step_up_seconds() == 120


def test_malformed_require_fails_closed(tmp_path):
    _write_config(tmp_path, "[auth.mfa]\nrequire = \"yes\"\nstep_up_minutes = 0\n")
    assert mfa_policy.require_mfa() is True
    # A nonsense freshness falls back to the documented default.
    assert mfa_policy.step_up_seconds() == 15 * 60


def test_require_stays_on_when_the_source_breaks_during_the_load(tmp_path, monkeypatch):
    # The check before the load sees a clean file; the file breaks just before
    # the load reads it. Falling back to "off" here would drop the second factor.
    _write_config(tmp_path, "[auth.mfa]\nrequire = false\n")
    assert mfa_policy.require_mfa() is False
    real_get = config.get_auth_mfa

    def get_after_the_file_breaks():
        (tmp_path / "home" / "config.toml").write_text("[auth.mfa\n", encoding="utf-8")
        return real_get()

    monkeypatch.setattr(config, "get_auth_mfa", get_after_the_file_breaks)
    assert mfa_policy.require_mfa() is True


# ---- what proves a second factor ------------------------------------------------


@pytest.mark.parametrize("claims, expected", [
    ({"amr": ["pwd", "mfa"]}, True),
    ({"amr": ["pwd", "otp"]}, True),
    ({"amr": "hwk"}, True),
    ({"amr": ["pwd"]}, False),
    ({"amr": ["pin", "kba"]}, False),
    ({}, False),
    ({"amr": None}, False),
    ({"acr": "urn:x:mfa"}, False),  # not configured
])
def test_amr_values_prove_mfa(claims, expected):
    assert mfa_policy.claims_prove_mfa(claims) is expected


def test_configured_acr_value_proves_mfa(tmp_path):
    _write_config(tmp_path, "[auth.mfa]\nacr_values = [\"urn:x:mfa\", \"phr\"]\n")
    assert mfa_policy.claims_prove_mfa({"acr": "phr", "amr": ["pwd"]}) is True
    assert mfa_policy.claims_prove_mfa({"acr": "urn:x:other"}) is False


def test_admin_can_extend_amr_values(tmp_path):
    _write_config(tmp_path, "[auth.mfa]\namr_values = [\"mfa\", \"corp-push\"]\n")
    assert mfa_policy.claims_prove_mfa({"amr": ["corp-push"]}) is True
    assert mfa_policy.claims_prove_mfa({"amr": ["otp"]}) is False


def test_saml_context():
    assert mfa_policy.saml_context_proves_mfa(
        "http://schemas.microsoft.com/claims/multipleauthn") is True
    assert mfa_policy.saml_context_proves_mfa(
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport") is False
    assert mfa_policy.saml_context_proves_mfa("") is False


def test_principal_mfa_from_session_and_bearer_and_proxy():
    session = VerifiedPrincipal(sub="a", issuer="oidc-session", audience="",
                                claims={"via": "session", "mfa": True, "mfa_at": 100.0})
    assert mfa_policy.principal_mfa(session) == (True, 100.0)
    no = VerifiedPrincipal(sub="a", issuer="oidc-session", audience="",
                           claims={"via": "session", "mfa": False})
    assert mfa_policy.principal_mfa(no) == (False, None)
    bearer = VerifiedPrincipal(sub="a", issuer="i", audience="x",
                               claims={"amr": ["otp"], "auth_time": 42, "iat": 50})
    assert mfa_policy.principal_mfa(bearer) == (True, 42.0)
    proxy = VerifiedPrincipal(sub="a", issuer="proxy", audience="", claims={"via": "proxy"})
    assert mfa_policy.principal_mfa(proxy) == (False, None)


def test_enforce_session_policy(tmp_path):
    no = VerifiedPrincipal(sub="a", issuer="oidc-session", audience="",
                           claims={"via": "session", "mfa": False})
    mfa_policy.enforce_session_policy(no)  # off: nothing happens
    _write_config(tmp_path, "[auth.mfa]\nrequire = true\n")
    with pytest.raises(mfa_policy.HTTPException) as exc:
        mfa_policy.enforce_session_policy(no)
    assert exc.value.status_code == 403
    assert exc.value.detail == mfa_policy.MFA_MISSING_MESSAGE
    yes = VerifiedPrincipal(sub="a", issuer="oidc-session", audience="",
                            claims={"via": "session", "mfa": True, "mfa_at": time.time()})
    mfa_policy.enforce_session_policy(yes)
    mfa_policy.enforce_session_policy(None)


def test_fresh_enough():
    assert mfa_policy.fresh_enough(1000.0, now=1000.0 + 14 * 60)
    assert not mfa_policy.fresh_enough(1000.0, now=1000.0 + 16 * 60)
    assert not mfa_policy.fresh_enough(None)
    assert not mfa_policy.fresh_enough(2000.0, now=1000.0)  # from the future


# ---- step-up -----------------------------------------------------------------


def _request(principal):
    return SimpleNamespace(state=SimpleNamespace(principal=principal),
                           url=SimpleNamespace(path="/users/set", query=""),
                           method="POST", headers={})


def test_step_up_is_a_no_op_without_named_sign_in(tmp_path):
    _write_config(tmp_path, "[auth.mfa]\nrequire = true\n")
    step_up.require_recent_mfa(_request(None), "change_role")


def test_step_up_is_a_no_op_while_second_factor_not_required():
    stale = VerifiedPrincipal(sub="a", issuer="oidc-session", audience="",
                              claims={"via": "session", "mfa": False})
    step_up.require_recent_mfa(_request(stale), "change_role")


def test_step_up_fresh_stale_and_missing(tmp_path):
    _write_config(tmp_path, "[auth.mfa]\nrequire = true\nstep_up_minutes = 10\n")
    now = time.time()
    fresh = VerifiedPrincipal(sub="a", issuer="oidc-session", audience="",
                              claims={"via": "session", "mfa": True, "mfa_at": now - 60})
    step_up.require_recent_mfa(_request(fresh), "clear_emergency_stop")
    stale = VerifiedPrincipal(sub="a", issuer="oidc-session", audience="",
                              claims={"via": "session", "mfa": True, "mfa_at": now - 11 * 60})
    with pytest.raises(step_up.StepUpRequired) as exc:
        step_up.require_recent_mfa(_request(stale), "clear_emergency_stop")
    assert exc.value.status_code == 403
    assert exc.value.detail == step_up.STEP_UP_MESSAGE
    assert exc.value.reauthenticate.startswith("/auth/logout")  # no browser login set up
    assert exc.value.headers["X-Reauthenticate"] == exc.value.reauthenticate
    missing = VerifiedPrincipal(sub="a", issuer="oidc-session", audience="",
                                claims={"via": "session", "mfa": False})
    with pytest.raises(step_up.StepUpRequired):
        step_up.require_recent_mfa(_request(missing), "rotate_keys")


def test_step_up_only_knows_the_documented_operations():
    with pytest.raises(ValueError):
        step_up.require_recent_mfa(_request(None), "make_coffee")
    assert set(step_up.SENSITIVE_OPERATIONS) == {
        "change_role", "remove_spending_limit", "clear_emergency_stop", "rotate_keys",
        "change_auth_settings", "delete_workspace", "restore_workspace", "revoke_sessions",
        "reset_passphrase",
    }


def test_reauthenticate_url_prefers_the_browser_login(monkeypatch):
    monkeypatch.setenv("MAVERICK_OIDC_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_ID", "c")
    monkeypatch.setenv("MAVERICK_OIDC_SESSION_SECRET", "s")
    # Browser login is on only when fully configured (maverick.oidc.login_enabled).
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_SECRET", "x")  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_OIDC_REDIRECT_URI", "http://127.0.0.1/auth/callback")
    monkeypatch.setenv("MAVERICK_OIDC_AUDIENCE", "c")
    url = step_up.reauthenticate_url(
        SimpleNamespace(url=SimpleNamespace(path="/users", query="a=1"), method="GET"))
    assert url == "/auth/login?fresh=1&return_to=%2Fusers%3Fa%3D1"


def test_reauthenticate_url_asks_saml_for_a_fresh_sign_in(monkeypatch):
    # Without fresh=1 the SAML login reused the IdP session, the assertion kept
    # its old AuthnInstant and step-up refused again: a loop.
    import maverick.oidc as oidc
    from maverick_dashboard import saml

    monkeypatch.setattr(oidc, "login_enabled", lambda: False)
    monkeypatch.setattr(saml, "saml_enabled", lambda: True)
    url = step_up.reauthenticate_url(
        SimpleNamespace(url=SimpleNamespace(path="/users", query=""), method="GET"))
    assert url == "/saml/login?fresh=1&return_to=%2Fusers"


def test_required_second_factor_does_not_refuse_api_keys(monkeypatch):
    # A key cannot present a second factor; it was issued from a checked sign-in.
    from types import SimpleNamespace

    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "1")
    key = SimpleNamespace(claims={"via": "api_key"}, issuer="lightwork")
    mfa_policy.enforce_session_policy(key)
    browser = SimpleNamespace(claims={"via": "session"}, issuer="lightwork")
    with pytest.raises(Exception) as refused:
        mfa_policy.enforce_session_policy(browser)
    assert getattr(refused.value, "status_code", None) == 403
