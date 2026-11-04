"""SAML 2.0 SP browser SSO.

Hermetic: no pysaml2 and no real assertion. The library calls (``_client`` /
``verify_acs_response`` / ``login_redirect_url`` / ``sp_metadata_xml``) are
isolated and monkeypatched, so the routing, NameID->principal mapping, session
minting, relay-state safety and fail-closed gating are all exercised without a
live IdP. (A real Okta/Entra round-trip still needs certifying separately.)
"""

from __future__ import annotations

import json
import math
import sys
import time
import types

import maverick_dashboard.saml as saml_mod
import pytest
from fastapi.testclient import TestClient
from maverick.web_session import sign_session, verify_session
from maverick_dashboard.app import app

SECRET = "saml-unit-session-secret"  # pragma: allowlist secret

ENABLED_CFG = {
    "sp_entity_id": "https://us.example.com/saml/metadata",
    "acs_url": "https://us.example.com/saml/acs",
    "idp_metadata_url": "https://idp.example.com/metadata",
}


def _client() -> TestClient:
    return TestClient(
        app,
        base_url="https://127.0.0.1",
        headers={"Origin": "https://127.0.0.1"},
    )


def _arm_saml_tx(
    client: TestClient,
    *,
    request_id: str = "req-unit-1",
    state: str = "relay-unit-1",
    return_to: str = "/",
    jti: str = "tx-unit-1",
    fresh: bool = False,
) -> str:
    """Install the signed, browser-bound transaction an IdP POST must answer."""
    payload = {
        "request_id": request_id,
        "state": state,
        "return_to": return_to,
        "jti": jti,
        "exp": int(time.time()) + saml_mod._TX_TTL,
    }
    if fresh:
        payload["fresh"] = True  # started from the step-up link
    raw = sign_session(payload, SECRET)
    client.cookies.set(saml_mod.TX_COOKIE, raw, path="/saml")
    return state


@pytest.fixture
def _enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(saml_mod, "_auth_saml_cfg", lambda: dict(ENABLED_CFG))
    monkeypatch.setattr(saml_mod, "_session_secret", lambda: SECRET)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))


# --- gating -----------------------------------------------------------------


def test_enabled_requires_full_config(monkeypatch):
    monkeypatch.setattr(saml_mod, "_auth_saml_cfg", dict)
    assert saml_mod.saml_enabled() is False
    monkeypatch.setattr(
        saml_mod, "_auth_saml_cfg", lambda: {"sp_entity_id": "x"}
    )  # missing acs + idp
    assert saml_mod.saml_enabled() is False
    monkeypatch.setattr(saml_mod, "_auth_saml_cfg", lambda: dict(ENABLED_CFG))
    assert saml_mod.saml_enabled() is True


def test_pysaml_config_disables_unsolicited_responses(monkeypatch):
    fake = types.ModuleType("saml2")
    fake.BINDING_HTTP_POST = "post"
    fake.BINDING_HTTP_REDIRECT = "redirect"
    monkeypatch.setitem(sys.modules, "saml2", fake)
    cfg = saml_mod.SamlConfig(**ENABLED_CFG)

    # Without an installed signature backend, no client configuration exists.
    monkeypatch.setattr(saml_mod, "runtime_readiness", lambda: {
        "ready": False, "backend": "", "message": "not installed"})
    with pytest.raises(saml_mod.SamlUnavailable):
        saml_mod._pysaml2_config(cfg)

    monkeypatch.setattr(saml_mod, "runtime_readiness", lambda: {
        "ready": True, "backend": "XMLSecurity", "message": "installed"})
    conf = saml_mod._pysaml2_config(cfg)

    assert conf["service"]["sp"]["allow_unsolicited"] is False
    assert conf["crypto_backend"] == "XMLSecurity"


@pytest.mark.parametrize(
    "assertions_signed, response_signed", [(True, False), (False, True)]
)
def test_at_least_one_signature_is_always_required(
    monkeypatch, assertions_signed, response_signed
):
    # Signed assertions are the default. With that switched off, the response
    # signature must carry the requirement, or an unsigned assertion is accepted.
    fake = types.ModuleType("saml2")
    fake.BINDING_HTTP_POST = "post"
    fake.BINDING_HTTP_REDIRECT = "redirect"
    monkeypatch.setitem(sys.modules, "saml2", fake)
    monkeypatch.setattr(saml_mod, "runtime_readiness", lambda: {
        "ready": True, "backend": "XMLSecurity", "message": "installed"})
    cfg = saml_mod.SamlConfig(**ENABLED_CFG, want_assertions_signed=assertions_signed)

    sp = saml_mod._pysaml2_config(cfg)["service"]["sp"]

    assert sp["want_assertions_signed"] is assertions_signed
    assert sp["want_response_signed"] is response_signed
    assert sp["want_assertions_signed"] or sp["want_response_signed"]


def test_routes_404_when_disabled(monkeypatch):
    monkeypatch.setattr(saml_mod, "_auth_saml_cfg", dict)
    c = _client()
    assert c.get("/saml/metadata").status_code == 404
    assert c.get("/saml/login", follow_redirects=False).status_code == 404
    assert c.post("/saml/acs", data={"SAMLResponse": "x"}).status_code == 404


# --- mapping + session ------------------------------------------------------


class _FakeNID:
    text = "alice@example.com"


class _FakeResp:
    name_id = _FakeNID()

    def get_identity(self):
        return {"email": ["alice@example.com"], "groups": ["admins"]}

    def get_subject(self):
        return _FakeNID()


def test_extract_identity_maps_nameid_and_attrs():
    ident = saml_mod.extract_identity(_FakeResp())
    assert ident.name_id == "alice@example.com"
    assert ident.principal == "user:alice@example.com"
    assert ident.attributes["groups"] == ["admins"]


@pytest.mark.parametrize("name_id", [" alice", "alice ", "alice\n", "x" * 252])
def test_extract_identity_rejects_invalid_nameid_without_canonicalizing(name_id):
    class _NID:
        text = name_id

    class _Response(_FakeResp):
        name_id = _NID()

    with pytest.raises(saml_mod.SamlUnavailable, match="no NameID"):
        saml_mod.extract_identity(_Response())


def test_extract_identity_accepts_full_principal_length_boundary():
    subject = "x" * 251

    class _NID:
        text = subject

    class _Response(_FakeResp):
        name_id = _NID()

    assert len(saml_mod.extract_identity(_Response()).principal) == 256


def test_extract_identity_requires_nameid():
    class _NoNID:
        name_id = None

        def get_subject(self):
            raise RuntimeError("no subject")

    with pytest.raises(saml_mod.SamlUnavailable):
        saml_mod.extract_identity(_NoNID())


def test_extract_identity_rejects_none():
    with pytest.raises(saml_mod.SamlUnavailable):
        saml_mod.extract_identity(None)


def test_extract_identity_reads_authn_context_and_instant():
    class _Response(_FakeResp):
        def authn_info(self):
            return [("urn:x:ac:otp", [], "2026-10-08T10:15:30Z")]

    ident = saml_mod.extract_identity(_Response())
    assert ident.authn_context == "urn:x:ac:otp"
    assert ident.authn_instant == 1791454530.0
    # No (or an unreadable) AuthnInstant is "unknown", never "just now".
    assert saml_mod.extract_identity(_FakeResp()).authn_instant == 0.0

    class _Garbled(_FakeResp):
        def authn_info(self):
            return [("urn:x:ac:otp", [], "yesterday")]

    assert saml_mod.extract_identity(_Garbled()).authn_instant == 0.0


def test_verify_acs_response_passes_outstanding_request_id(monkeypatch):
    fake = types.ModuleType("saml2")
    fake.BINDING_HTTP_POST = "post"
    monkeypatch.setitem(sys.modules, "saml2", fake)
    monkeypatch.setattr(saml_mod, "_auth_saml_cfg", lambda: dict(ENABLED_CFG))
    seen = {}

    class _Client:
        # ``client_scope`` builds the native client from the resolved config.
        config = types.SimpleNamespace(crypto_backend="xmlsec1")

        def __init__(self, cfg):
            seen["cfg"] = cfg

        def parse_authn_request_response(self, response, binding, *, outstanding):
            seen.update(
                response=response, binding=binding, outstanding=dict(outstanding)
            )
            parsed = _FakeResp()
            parsed.in_response_to = "request-123"
            return parsed

    monkeypatch.setattr(saml_mod, "_client", _Client)
    identity = saml_mod.verify_acs_response("signed", request_id="request-123")

    assert identity.name_id == "alice@example.com"
    assert seen.pop("cfg").idp_metadata_url == ENABLED_CFG["idp_metadata_url"]
    assert seen == {
        "response": "signed",
        "binding": "post",
        "outstanding": {"request-123": ""},
    }


def test_verify_acs_response_rejects_wrong_in_response_to(monkeypatch):
    fake = types.ModuleType("saml2")
    fake.BINDING_HTTP_POST = "post"
    monkeypatch.setitem(sys.modules, "saml2", fake)
    monkeypatch.setattr(saml_mod, "_auth_saml_cfg", lambda: dict(ENABLED_CFG))

    class _Client:
        config = types.SimpleNamespace(crypto_backend="xmlsec1")

        def __init__(self, cfg):
            pass

        def parse_authn_request_response(self, response, binding, *, outstanding):
            parsed = _FakeResp()
            parsed.in_response_to = "attacker-request"
            return parsed

    monkeypatch.setattr(saml_mod, "_client", _Client)

    with pytest.raises(ValueError, match="did not match"):
        saml_mod.verify_acs_response("signed", request_id="request-123")


def test_mint_session_roundtrips_through_shared_verifier():
    cookie = saml_mod.mint_session_cookie("bob@example.com", secret=SECRET)
    payload = verify_session(cookie, SECRET)
    assert payload and payload["sub"] == "bob@example.com" and payload["exp"] > 0
    assert isinstance(payload["iat"], int) and payload["iat"] > 0


def test_mint_session_after_revocation_has_fresh_iat(monkeypatch, tmp_path):
    from maverick_dashboard import session_revocation as sr

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    sr.revoke_principal("bob@example.com", at=999.0)
    monkeypatch.setattr(saml_mod.time, "time", lambda: 1000.0)

    cookie = saml_mod.mint_session_cookie("bob@example.com", secret=SECRET)
    payload = verify_session(cookie, SECRET, now=1000.0)

    assert payload
    assert payload["iat"] == 1000
    assert payload["exp"] == 1000 + saml_mod._SESSION_TTL
    assert sr.is_revoked(payload["sub"], payload["iat"]) is False


def test_mint_session_requires_secret():
    with pytest.raises(saml_mod.SamlUnavailable):
        saml_mod.mint_session_cookie("bob", secret="")


def test_saml_only_session_reaches_protected_route_and_anonymous_is_denied(
    _enabled, monkeypatch,
):
    """SAML is a complete dashboard auth mode even when OIDC login is off."""
    from maverick_dashboard import auth, oidc_login

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", raising=False)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(oidc_login, "login_enabled", lambda: False)
    monkeypatch.setattr(
        oidc_login,
        "load_oidc_config",
        lambda: types.SimpleNamespace(session_secret=SECRET),
    )

    anonymous = _client()
    assert anonymous.get("/api/v1/providers").status_code == 401

    authenticated = _client()
    authenticated.cookies.set(
        "mvk_session",
        saml_mod.mint_session_cookie("alice@example.com", secret=SECRET),
    )
    # The raw inventory is global-admin-only; a valid default-viewer session is
    # authenticated (403 rather than 401) and can still reach the redacted page.
    assert authenticated.get("/api/v1/providers").status_code == 403
    assert authenticated.get("/providers").status_code == 200
    assert authenticated.post("/api/v1/goals", json={"title": "work"}).status_code == 403
    assert authenticated.post("/api/v1/approvals/1/approve").status_code == 403


# --- ACS --------------------------------------------------------------------


def test_acs_verifies_sets_session_and_redirects(_enabled, monkeypatch):
    seen = {}

    def _verify(response, *, request_id):
        seen["response"] = response
        seen["request_id"] = request_id
        return saml_mod.SamlIdentity(
            name_id="opaque-name-id", attributes={"mail": ["alice@example.com"]},
            assertion_id="assertion-login-1"
        )

    monkeypatch.setattr(
        saml_mod,
        "verify_acs_response",
        _verify,
    )
    client = _client()
    state = _arm_saml_tx(client, request_id="req-login-1", return_to="/goals")
    res = client.post(
        "/saml/acs",
        data={"SAMLResponse": "signed", "RelayState": state},
        follow_redirects=False,
    )
    assert res.status_code == 303
    assert res.headers["location"] == "/goals"
    assert seen == {"response": "signed", "request_id": "req-login-1"}
    cookie = res.cookies.get("mvk_session")
    assert cookie
    payload = verify_session(cookie, SECRET)
    assert payload["sub"] == "opaque-name-id"
    assert payload["idp_email"] == "alice@example.com"
    # SAML sign-ins carry no permission address: the assertion offers no proof that an email is verified.
    assert "verified_email" not in payload


_MFA_CONTEXT = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"


def _acs_with(monkeypatch, *, n=1, fresh=False, **identity_fields):
    monkeypatch.setattr(
        saml_mod,
        "verify_acs_response",
        lambda r, *, request_id: saml_mod.SamlIdentity(
            name_id="opaque-name-id", assertion_id=f"assertion-mfa-{n}",
            authn_context=_MFA_CONTEXT, **identity_fields),
    )
    client = _client()
    state = _arm_saml_tx(client, request_id="req-mfa-1", return_to="/goals",
                         jti=f"tx-mfa-{n}", fresh=fresh)
    res = client.post("/saml/acs", data={"SAMLResponse": "signed", "RelayState": state},
                      follow_redirects=False)
    assert res.status_code == 303
    return verify_session(res.cookies.get("mvk_session"), SECRET)


def test_acs_dates_the_second_factor_by_the_assertions_authn_instant(_enabled, monkeypatch):
    # An IdP that reuses its own SSO session returns a TimeSyncToken context for
    # an authentication from hours ago; the ACS's own clock must not re-date it.
    old = float(int(time.time()) - 6 * 3600)
    payload = _acs_with(monkeypatch, authn_instant=old)
    assert payload["mfa"] is True and payload["mfa_at"] == old


def test_acs_without_a_usable_authn_instant_dates_the_second_factor_now(_enabled, monkeypatch):
    for n, instant in enumerate((0.0, time.time() + 3600)):  # unknown, or past any skew
        payload = _acs_with(monkeypatch, n=n, authn_instant=instant)
        assert payload["mfa"] is True and payload["mfa_at"] == payload["iat"]


def test_step_up_acs_counts_the_second_factor_only_for_a_recent_authn_instant(_enabled, monkeypatch):
    # The step-up link asked for ForceAuthn. An IdP that ignored it and reused
    # its session asserts an old (or no) AuthnInstant: that is no fresh second
    # factor, so step-up must not pass on it. A real re-authentication does.
    now = int(time.time())
    assert _acs_with(monkeypatch, n=11, fresh=True, authn_instant=float(now - 6 * 3600))["mfa"] is False
    assert _acs_with(monkeypatch, n=12, fresh=True, authn_instant=0.0)["mfa"] is False
    recent = float(now - 30)
    payload = _acs_with(monkeypatch, n=13, fresh=True, authn_instant=recent)
    assert payload["mfa"] is True and payload["mfa_at"] == recent


def test_step_up_acs_refuses_a_reused_idp_session_when_a_second_factor_is_required(_enabled, monkeypatch):
    from maverick_dashboard import mfa_policy

    monkeypatch.setattr(mfa_policy, "require_mfa", lambda: True)
    monkeypatch.setattr(
        saml_mod,
        "verify_acs_response",
        lambda r, *, request_id: saml_mod.SamlIdentity(
            name_id="opaque-name-id", assertion_id="assertion-stale-step-up",
            authn_context=_MFA_CONTEXT, authn_instant=float(int(time.time()) - 6 * 3600)),
    )
    client = _client()
    state = _arm_saml_tx(client, jti="tx-stale-step-up", fresh=True)
    res = client.post("/saml/acs", data={"SAMLResponse": "signed", "RelayState": state},
                      follow_redirects=False)
    assert res.status_code == 403
    assert res.cookies.get("mvk_session") is None


def test_acs_rejects_replayed_assertion(_enabled, monkeypatch, tmp_path):
    # A captured, still-valid SAMLResponse must be single-use: the first POST
    # mints a session, an identical replay is refused (401) before minting.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(
        saml_mod,
        "verify_acs_response",
        lambda r, *, request_id: saml_mod.SamlIdentity(
            name_id="alice@example.com",
            assertion_id="assertion-abc",
            expires_at=time.time() + 300,
        ),
    )
    client = _client()
    state = _arm_saml_tx(client, jti="tx-assertion-replay-1")
    first = client.post(
        "/saml/acs",
        data={"SAMLResponse": "signed", "RelayState": state},
        follow_redirects=False,
    )
    assert first.status_code == 303 and first.cookies.get("mvk_session")
    # Model a captured browser transaction as well as a captured assertion.
    state = _arm_saml_tx(client, jti="tx-assertion-replay-2")
    replay = client.post(
        "/saml/acs",
        data={"SAMLResponse": "signed", "RelayState": state},
        follow_redirects=False,
    )
    assert replay.status_code == 401
    assert "already used" in replay.text
    assert replay.cookies.get("mvk_session") is None


def test_acs_rejects_replayed_browser_transaction(_enabled, monkeypatch):
    calls = 0

    def _verify(response, *, request_id):
        nonlocal calls
        calls += 1
        return saml_mod.SamlIdentity(
            name_id="alice@example.com", assertion_id=f"assertion-tx-{calls}"
        )

    monkeypatch.setattr(saml_mod, "verify_acs_response", _verify)
    client = _client()
    state = _arm_saml_tx(client, jti="captured-transaction")
    first = client.post(
        "/saml/acs",
        data={"SAMLResponse": "signed-1", "RelayState": state},
        follow_redirects=False,
    )
    assert first.status_code == 303

    state = _arm_saml_tx(client, jti="captured-transaction")
    replay = client.post(
        "/saml/acs",
        data={"SAMLResponse": "signed-2", "RelayState": state},
        follow_redirects=False,
    )
    assert replay.status_code == 401
    assert "transaction already used" in replay.text


def test_acs_replay_store_failure_fails_closed(_enabled, monkeypatch, tmp_path):
    # If single-use can't be proven (store unreadable), refuse the login rather
    # than risk accepting a replay.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick_dashboard import saml_replay
    monkeypatch.setattr(
        saml_mod,
        "verify_acs_response",
        lambda r, *, request_id: saml_mod.SamlIdentity(
            name_id="a", assertion_id="assertion-xyz", expires_at=0.0
        ),
    )

    def _boom(*a, **k):
        raise saml_replay.ReplayStoreError("unreadable")

    monkeypatch.setattr(saml_replay, "consume", _boom)
    client = _client()
    state = _arm_saml_tx(client)
    res = client.post(
        "/saml/acs",
        data={"SAMLResponse": "signed", "RelayState": state},
        follow_redirects=False,
    )
    assert res.status_code == 503
    assert res.cookies.get("mvk_session") is None


def test_replay_store_consume_is_first_writer_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    import time

    from maverick_dashboard import saml_replay
    future = time.time() + 300
    assert saml_replay.consume("aid-1", future) is True     # first use accepted
    assert saml_replay.consume("aid-1", future) is False    # replay refused
    assert saml_replay.consume("aid-2", future) is True     # a different id is fine
    assert saml_replay.consume("", future) is False         # no id -> fail closed
    # An already-expired assertion still records (pruned later) and is single-use.
    assert saml_replay.consume("aid-3", time.time() - 10) is True
    assert saml_replay.consume("aid-3", time.time() - 10) is False


@pytest.mark.parametrize(
    "corrupt",
    [
        "[]",
        "null",
        '"not-an-object"',
        '{"aid": "tomorrow"}',
        '{"aid": true}',
        '{"aid": null}',
        '{"": 123}',
        '{" padded ": 123}',
        '{"aid": 0}',
        '{"aid": -1}',
        '{"aid": NaN}',
        '{"aid": Infinity}',
        '{"aid": -Infinity}',
        '{"aid": 123, "aid": 456}',
    ],
)
def test_replay_store_rejects_corrupt_existing_state(
    monkeypatch, tmp_path, corrupt
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick_dashboard import saml_replay

    path = tmp_path / "saml-consumed-assertions.json"
    path.write_text(corrupt, encoding="utf-8")

    with pytest.raises(saml_replay.ReplayStoreError, match="replay store corrupt"):
        saml_replay.consume("new-assertion", time.time() + 300)

    # A corrupt store must not be reset or overwritten: doing so would forget
    # every prior assertion and reopen their replay window.
    assert path.read_text(encoding="utf-8") == corrupt


@pytest.mark.parametrize("expires_at", [math.nan, math.inf, -math.inf, "Infinity"])
def test_replay_store_nonfinite_new_expiry_uses_bounded_fallback(
    monkeypatch, tmp_path, expires_at
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick_dashboard import saml_replay

    before = time.time()
    assert saml_replay.consume("aid-nonfinite", expires_at) is True

    stored = json.loads(
        (tmp_path / "saml-consumed-assertions.json").read_text(encoding="utf-8"),
        parse_constant=lambda value: pytest.fail(f"non-finite JSON: {value}"),
    )
    assert math.isfinite(stored["aid-nonfinite"])
    assert before + saml_replay._FALLBACK_TTL_SECONDS <= stored["aid-nonfinite"]
    assert stored["aid-nonfinite"] <= time.time() + saml_replay._FALLBACK_TTL_SECONDS


def test_acs_missing_response_is_400(_enabled):
    client = _client()
    state = _arm_saml_tx(client)
    res = client.post(
        "/saml/acs", data={"RelayState": state}, follow_redirects=False
    )
    assert res.status_code == 400


def test_acs_verification_failure_is_401(_enabled, monkeypatch):
    def _boom(_r, *, request_id):
        raise ValueError("bad signature")

    monkeypatch.setattr(saml_mod, "verify_acs_response", _boom)
    client = _client()
    state = _arm_saml_tx(client)
    res = client.post(
        "/saml/acs",
        data={"SAMLResponse": "tampered", "RelayState": state},
        follow_redirects=False,
    )
    assert res.status_code == 401
    assert "did not verify" in res.text


def test_acs_blocks_open_redirect_in_signed_transaction(_enabled, monkeypatch):
    monkeypatch.setattr(
        saml_mod,
        "verify_acs_response",
        lambda r, *, request_id: saml_mod.SamlIdentity(
            name_id="a", assertion_id="assertion-open-redirect"
        ),
    )
    client = _client()
    state = _arm_saml_tx(client, return_to="https://evil.example/")
    res = client.post(
        "/saml/acs",
        data={"SAMLResponse": "x", "RelayState": state},
        follow_redirects=False,
    )
    assert res.status_code == 303
    assert res.headers["location"] == "/"  # external relay rejected -> default


def test_acs_503_without_pysaml2(_enabled, monkeypatch):
    def _boom(_r, *, request_id):
        raise saml_mod.SamlUnavailable("needs pysaml2")

    monkeypatch.setattr(saml_mod, "verify_acs_response", _boom)
    client = _client()
    state = _arm_saml_tx(client)
    res = client.post(
        "/saml/acs",
        data={"SAMLResponse": "x", "RelayState": state},
        follow_redirects=False,
    )
    assert res.status_code == 503


def test_acs_rejects_missing_browser_transaction_before_verification(
    _enabled, monkeypatch
):
    def _should_not_verify(*args, **kwargs):
        raise AssertionError("unsolicited assertion reached verification")

    monkeypatch.setattr(saml_mod, "verify_acs_response", _should_not_verify)
    res = _client().post(
        "/saml/acs",
        data={"SAMLResponse": "signed", "RelayState": "attacker-state"},
        follow_redirects=False,
    )
    assert res.status_code == 401
    assert res.cookies.get("mvk_session") is None


def test_acs_rejects_relay_state_mismatch_before_verification(_enabled, monkeypatch):
    def _should_not_verify(*args, **kwargs):
        raise AssertionError("mismatched RelayState reached verification")

    monkeypatch.setattr(saml_mod, "verify_acs_response", _should_not_verify)
    client = _client()
    _arm_saml_tx(client, state="expected-state")
    res = client.post(
        "/saml/acs",
        data={"SAMLResponse": "signed", "RelayState": "attacker-state"},
        follow_redirects=False,
    )
    assert res.status_code == 401


def test_acs_rejects_non_ascii_relay_state_as_a_mismatch_not_a_server_error(
    _enabled, monkeypatch
):
    def _should_not_verify(*args, **kwargs):
        raise AssertionError("non-ASCII RelayState reached verification")

    monkeypatch.setattr(saml_mod, "verify_acs_response", _should_not_verify)
    client = _client()
    _arm_saml_tx(client, state="expected-state")
    res = client.post(
        "/saml/acs",
        data={"SAMLResponse": "signed", "RelayState": "expected-st\u00e4te"},
        follow_redirects=False,
    )
    assert res.status_code == 401


def test_acs_rejects_assertion_without_replay_id(_enabled, monkeypatch):
    monkeypatch.setattr(
        saml_mod,
        "verify_acs_response",
        lambda r, *, request_id: saml_mod.SamlIdentity(name_id="alice@example.com"),
    )
    client = _client()
    state = _arm_saml_tx(client)
    res = client.post(
        "/saml/acs",
        data={"SAMLResponse": "signed", "RelayState": state},
        follow_redirects=False,
    )
    assert res.status_code == 401
    assert res.cookies.get("mvk_session") is None


# --- login + metadata -------------------------------------------------------


def test_login_redirects_to_idp(_enabled, monkeypatch):
    seen = {}

    def _prepare(cfg=None, relay_state="/", force_authn=False):
        seen["relay_state"] = relay_state
        seen["force_authn"] = force_authn
        return "req-login-42", "https://idp.example.com/sso?x=1"

    monkeypatch.setattr(
        saml_mod,
        "prepare_login_redirect",
        _prepare,
    )
    client = _client()
    res = client.get("/saml/login?return_to=/goals", follow_redirects=False)
    assert res.status_code == 303
    assert res.headers["location"].startswith("https://idp.example.com/sso")
    raw_tx = res.cookies.get(saml_mod.TX_COOKIE)
    tx = verify_session(raw_tx, SECRET)
    assert tx["request_id"] == "req-login-42"
    assert tx["return_to"] == "/goals"
    assert tx["state"] == seen["relay_state"]
    assert seen["force_authn"] is False and "fresh" not in tx
    set_cookie = res.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "samesite=none" in set_cookie
    assert "secure" in set_cookie


def test_step_up_login_asks_the_idp_for_a_fresh_authentication(_enabled, monkeypatch):
    seen = {}

    def _prepare(cfg=None, relay_state="/", force_authn=False):
        seen["force_authn"] = force_authn
        return "req-fresh-1", "https://idp.example.com/sso?x=1"

    monkeypatch.setattr(saml_mod, "prepare_login_redirect", _prepare)
    res = _client().get("/saml/login?fresh=1&return_to=/users", follow_redirects=False)
    assert res.status_code == 303
    assert seen["force_authn"] is True
    tx = verify_session(res.cookies.get(saml_mod.TX_COOKIE), SECRET)
    assert tx["fresh"] is True and tx["return_to"] == "/users"


def test_force_authn_reaches_the_real_authn_request(tmp_path):
    pytest.importorskip("saml2")
    if not saml_mod.runtime_readiness()["ready"]:
        pytest.skip("no SAML XML security backend installed")
    import base64
    import zlib
    from urllib.parse import parse_qs, urlsplit

    metadata = tmp_path / "idp.xml"
    metadata.write_text(
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        'entityID="https://idp.example.com/metadata"><md:IDPSSODescriptor '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        'Location="https://idp.example.com/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>',
        encoding="utf-8")
    cfg = saml_mod.SamlConfig(enabled=True, sp_entity_id=ENABLED_CFG["sp_entity_id"],
                              acs_url=ENABLED_CFG["acs_url"], idp_metadata_file=str(metadata))
    client = saml_mod._client(cfg)

    def request_xml(force_authn):
        _request_id, url = saml_mod.prepare_login_redirect(client, cfg, relay_state="s",
                                                           force_authn=force_authn)
        raw = parse_qs(urlsplit(url).query)["SAMLRequest"][0]
        return zlib.decompress(base64.b64decode(raw), -15).decode("utf-8")

    assert 'ForceAuthn="true"' in request_xml(True)
    assert "ForceAuthn" not in request_xml(False)


def test_metadata_503_without_pysaml2(_enabled, monkeypatch):
    def _boom(*a, **k):
        raise saml_mod.SamlUnavailable("needs pysaml2")

    monkeypatch.setattr(saml_mod, "sp_metadata_xml", _boom)
    assert _client().get("/saml/metadata").status_code == 503


def test_acs_rejects_oversized_body_before_form_parse(_enabled, monkeypatch):
    def _should_not_verify(*args, **kwargs):
        raise AssertionError("oversized ACS body reached SAML verification")

    monkeypatch.setattr(saml_mod, "verify_acs_response", _should_not_verify)
    client = _client()
    state = _arm_saml_tx(client)
    res = client.post(
        "/saml/acs",
        data={"SAMLResponse": "x", "RelayState": state + ("a" * (1024 * 1024))},
        follow_redirects=False,
    )
    assert res.status_code == 413


def test_acs_rejects_oversized_saml_response_before_verification(_enabled, monkeypatch):
    def _should_not_verify(*args, **kwargs):
        raise AssertionError("oversized SAMLResponse reached SAML verification")

    monkeypatch.setattr(saml_mod, "verify_acs_response", _should_not_verify)
    client = _client()
    state = _arm_saml_tx(client)
    res = client.post(
        "/saml/acs",
        data={"SAMLResponse": "x" * (768 * 1024 + 1), "RelayState": state},
        follow_redirects=False,
    )
    assert res.status_code == 413


# --- SCIM deprovision reach (persistent NameID) -----------------------------


def test_acs_records_persistent_nameid_for_scim_revocation(_enabled, monkeypatch, tmp_path):
    """A persistent/transient NameID matches no SCIM attribute, so SCIM
    deprovision can only reach the live SAML session if the ACS recorded the
    NameID against the user's email/UPN in the subject directory. Without that
    recording, ``subs_for([email])`` is empty and the session survives."""
    from maverick_dashboard import subject_directory as sd

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))

    name_id = "_persistent-okta-abc123"  # not an email; absent from SCIM attrs
    monkeypatch.setattr(
        saml_mod,
        "verify_acs_response",
        lambda r, *, request_id: saml_mod.SamlIdentity(
            name_id=name_id,
            attributes={"email": ["alice@example.com"]},
            assertion_id="assertion-scim-1",
        ),
    )

    client = _client()
    state = _arm_saml_tx(client)
    res = client.post(
        "/saml/acs",
        data={"SAMLResponse": "signed", "RelayState": state},
        follow_redirects=False,
    )
    assert res.status_code == 303

    # SCIM deprovision looks the sub up by the user's stable identifiers; the
    # persistent NameID must now be reachable via the email attribute.
    assert name_id in sd.subs_for(["alice@example.com"])
    assert name_id in sd.subs_for([name_id])


@pytest.mark.parametrize(
    "object_id_attr",
    (
        "oid",
        "http://schemas.microsoft.com/identity/claims/objectidentifier",
    ),
)
def test_verified_saml_object_id_bridges_nameid_to_scim_group_role(
    _enabled, monkeypatch, object_id_attr,
):
    """A signed immutable SAML object ID can use the existing non-forgeable
    externalId bridge. Email/UPN remains unavailable to group-role matching."""
    from maverick_dashboard import scim, scim_groups

    name_id = "_persistent-saml-nameid"
    object_id = "entra-object-id-1"
    saml_mod._record_session_subject(
        saml_mod.SamlIdentity(
            name_id=name_id,
            attributes={object_id_attr: [object_id]},
        )
    )
    monkeypatch.setattr(
        scim,
        "_load",
        lambda: {
            "scim-user-1": {
                "id": "scim-user-1",
                "externalId": object_id,
                "active": True,
            }
        },
    )
    monkeypatch.setattr(
        scim,
        "_load_effective_groups",
        lambda: {
            "scim-group-1": {
                "displayName": "Finance Team",
                "members": ["scim-user-1"],
            }
        },
    )
    monkeypatch.setattr(
        scim_groups,
        "_config_table",
        lambda key: {"Finance Team": "operator"} if key == "group_roles" else {},
    )

    principal = f"user:{name_id}"
    assert scim_groups.group_names_for_principal(principal) == frozenset(
        {"Finance Team"}
    )
    assert scim_groups.role_for_principal(principal) == "operator"


def test_record_session_subject_skips_when_no_email_attr(_enabled, monkeypatch, tmp_path):
    """With no email/UPN attribute the NameID is still recorded under itself
    (covers an email-format NameID that IS the SCIM identifier)."""
    from maverick_dashboard import subject_directory as sd

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))

    ident = saml_mod.SamlIdentity(name_id="bob@example.com", attributes={})
    saml_mod._record_session_subject(ident)
    assert "bob@example.com" in sd.subs_for(["bob@example.com"])
