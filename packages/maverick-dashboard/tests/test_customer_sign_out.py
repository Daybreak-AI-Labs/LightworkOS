"""Customer sign-out uses the real enrollment, cookie and revocation stores."""
from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient
from maverick import client as client_binding
from maverick import config, world_model
from maverick.web_session import sign_session
from maverick_dashboard import invites, rbac, saml, session_revocation
from maverick_dashboard.app import app

ORIGIN = "http://127.0.0.1:8765"
EMAIL = "owner@example.test"
PASSWORD = "Synthetic customer sign out phrase"  # pragma: allowlist secret -- disposable test passphrase


@pytest.fixture
def customer(monkeypatch, tmp_path):
    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    config_path = tmp_path / "config.toml"
    config_path.write_text('[client]\nid="customer-sign-out"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    client_binding.reset_client_cache()
    client = TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 50001),
                        headers={"Origin": ORIGIN})
    yield client
    client.close()
    config.reset_config_cache()
    client_binding.reset_client_cache()


def enroll(customer):
    response = customer.post("/auth/local-owner", data={"email": EMAIL,
        "password": PASSWORD, "confirm": "yes"}, follow_redirects=False)
    assert response.status_code == 303, response.text
    assert "mvk_session" in customer.cookies


def test_first_owner_can_find_sign_out_and_return_to_sign_in(customer):
    enroll(customer)
    page = customer.get("/start")
    assert page.status_code == 200
    assert 'href="/auth/logout"' in page.text
    confirmation = customer.get("/auth/logout", follow_redirects=False)
    assert confirmation.status_code == 200 and "mvk_session" in customer.cookies
    response = customer.post("/auth/logout", follow_redirects=False)
    assert response.status_code == 303
    assert "mvk_session" not in customer.cookies
    denied = customer.get("/goals", headers={"Accept": "text/html"}, follow_redirects=False)
    assert denied.status_code in {302, 303}
    assert denied.headers["location"].startswith("/auth/local-login")
    signed_in = customer.post("/auth/local-login", data={"email": EMAIL,
        "password": PASSWORD}, follow_redirects=False)
    assert signed_in.status_code == 303
    assert customer.get("/start").status_code == 200


@pytest.mark.parametrize("mode", ["owner", "invite", "saml"])
@pytest.mark.parametrize("all_sessions", [False, True])
def test_each_browser_session_type_can_sign_out(customer, monkeypatch, mode, all_sessions):
    if mode == "owner":
        enroll(customer)
    elif mode == "invite":
        monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
        rbac.set_role("user:" + EMAIL, "viewer")
        customer.cookies.set("mvk_session", invites.mint_local_session(EMAIL),
                             domain="127.0.0.1", path="/")
    else:
        monkeypatch.setattr(saml, "saml_enabled", lambda: True)
        monkeypatch.setenv("MAVERICK_OIDC_SESSION_SECRET", "synthetic-saml-sign-out-secret")
        rbac.set_role("user:" + EMAIL, "viewer")
        customer.cookies.set("mvk_session", saml.mint_session_cookie(EMAIL),
                             domain="127.0.0.1", path="/")
    assert 'href="/auth/logout"' in customer.get("/start").text
    response = customer.post("/auth/logout" + ("?all=1" if all_sessions else ""),
                            follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert "mvk_session" not in customer.cookies
    assert bool(session_revocation.revocation_epoch(EMAIL)) is all_sessions


@pytest.mark.parametrize("cookie", ["valid", "tampered", "expired"])
def test_local_global_sign_out_requires_same_origin_and_verified_cookie(customer, cookie):
    enroll(customer)
    if cookie == "tampered":
        customer.cookies.set("mvk_session", "invalid-cookie", domain="127.0.0.1", path="/")
    elif cookie == "expired":
        raw = sign_session({"sub": EMAIL, "iat": int(time.time()) - 60,
                            "exp": int(time.time()) - 1}, invites.local_session_secret())
        customer.cookies.set("mvk_session", raw, domain="127.0.0.1", path="/")
    response = customer.post("/auth/logout?all=1", follow_redirects=False,
                            headers={"Origin": "https://elsewhere.example.test",
                                     "Referer": "https://elsewhere.example.test/"} if cookie == "valid" else {})
    assert response.status_code == (403 if cookie == "valid" else 303)
    if cookie == "valid":
        assert "mvk_session" in customer.cookies
    assert session_revocation.revocation_epoch(EMAIL) == 0


def test_local_global_sign_out_can_revoke_again_after_prior_revocation(customer):
    enroll(customer)
    session_revocation.revoke_principal(EMAIL, at=time.time() - 5)
    before = session_revocation.revocation_epoch(EMAIL)
    response = customer.post("/auth/logout?all=1", follow_redirects=False)
    assert response.status_code == 303
    assert session_revocation.revocation_epoch(EMAIL) > before


@pytest.mark.parametrize("path", [
    "/api/v1/consent/global-opt-out/configurations",
    "/api/v1/consent/global-opt-out/integrity",
    "/api/v1/consent/global-opt-out/configurations/GOO-C" + "0" * 48,
    "/api/v1/consent/delivery/destination-adapters/integrity",
    "/api/v1/consent/delivery/destination-adapters/example/ambiguous",
])
def test_first_owner_gets_configuration_guidance_for_disabled_consent(customer, path):
    enroll(customer)
    response = customer.get(path)
    assert response.status_code == 403, response.text
    assert "consent" in response.text.lower()
    assert "internal server error" not in response.text


@pytest.mark.parametrize("operation", ["purge", "retry-audit"])
def test_disabled_opt_out_maintenance_is_refused_before_mutation(customer, operation):
    enroll(customer)
    response = customer.post("/api/v1/consent/global-opt-out/maintenance/" + operation,
                             json={"limit": 1})
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "global_opt_out_disabled"
