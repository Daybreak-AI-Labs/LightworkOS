"""Company sign-in recovery and review: the owner's authenticator code, then a recovery proof."""
from __future__ import annotations

import json
import re
import time

import pytest
from fastapi.testclient import TestClient

PASSPHRASE = "a long local owner fixture phrase"  # pragma: allowlist secret - test fixture passphrase
WRONG = "an incorrect long fixture phrase"  # pragma: allowlist secret - deliberately wrong test passphrase
EMAIL = "owner@example.com"
ORIGIN = "http://127.0.0.1:8765"
OPERATION = "a" * 32
CONTEXT = "b" * 64
GATE = "authenticator app"  # the first-step refusal names the owner's app

COMPANY = "/auth/company-signin-recovery"
SAML = "/auth/company-saml-recovery"
RECOVERY_STEPS = [
    (COMPANY + "/lookup", {}),
    (COMPANY + "/original", {"operation": OPERATION}),
    (COMPANY + "/review", {"operation": OPERATION}),
    (SAML + "/lookup", {}),
    (SAML + "/original", {"operation": OPERATION}),
    (SAML + "/review", {"operation": OPERATION}),
]


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    import os

    from maverick_dashboard import local_passphrases
    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.config.load_global_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.config.config_source_errors", lambda **k: [])
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr("maverick.audit.audit_event", lambda *a, **k: True)
    local_passphrases.reset_attempt_limit()
    yield
    local_passphrases.reset_attempt_limit()


@pytest.fixture
def clock(monkeypatch):
    from maverick_dashboard import local_owner_second_factor as second
    state = {"offset": 0.0}
    monkeypatch.setattr(second, "_now", lambda: time.time() + state["offset"])

    class Clock:
        def advance(self, seconds):
            state["offset"] += seconds

        def now(self):
            return time.time() + state["offset"]

    return Clock()


@pytest.fixture
def events(monkeypatch):
    recorded = []
    monkeypatch.setattr("maverick.audit.audit_event", lambda kind, **kw: recorded.append((kind, kw)) or True)
    return recorded


def current_code(secret_text, clock, offset_steps=0):
    from maverick_dashboard import owner_totp
    key = owner_totp.decode_secret(secret_text)
    return owner_totp.totp(key, clock.now() + offset_steps * owner_totp.STEP_SECONDS)


def enrolled_owner_with_codes(clock):
    """An owner who has enrolled an authenticator app. Returns its secret and its recovery codes."""
    from maverick_dashboard import local_owner, owner_totp
    from maverick_dashboard import local_owner_second_factor as second
    from starlette.requests import Request
    scope = {"type": "http", "method": "POST", "scheme": "http", "path": "/auth/local-owner",
             "query_string": b"", "server": ("127.0.0.1", 8765), "client": ("127.0.0.1", 1234),
             "headers": [(b"host", b"127.0.0.1:8765"), (b"origin", ORIGIN.encode())]}
    local_owner.enroll(Request(scope), email=EMAIL, password=PASSPHRASE, confirm=True)
    secret, _uri = second.start_setup(PASSPHRASE)
    codes = second.confirm_setup(current_code(secret, clock))
    clock.advance(owner_totp.STEP_SECONDS)
    return secret, codes


@pytest.fixture
def owner(clock):
    """An owner who has enrolled an authenticator app. Returns its secret."""
    secret, _codes = enrolled_owner_with_codes(clock)
    return secret


def client(*, raise_server_exceptions=True):
    from maverick_dashboard.app import app
    return TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 53210), headers={"Origin": ORIGIN},
                      follow_redirects=False, raise_server_exceptions=raise_server_exceptions)


def record():
    from maverick_dashboard import local_owner
    return json.loads(local_owner.path().read_text())


def proof_cookies(response):
    return [value for value in response.headers.get_list("set-cookie") if value.startswith("mvk_owner_recovery_proof=")]


def proof_token(response):
    match = re.search(r"mvk_owner_recovery_proof=([^;]+)", " ".join(proof_cookies(response)))
    assert match, "no recovery proof cookie was sent"
    return match.group(1)


def body(path, **fields):
    base = {"email": EMAIL, "password": PASSPHRASE}
    base.update(fields)
    return base


def sealed_recovery(protocol=None):
    """A sealed recovery review, as the restricted apply step receives it."""
    from maverick_dashboard import company_signin_migration as migration
    from maverick_dashboard import local_owner
    value = {"purpose": migration.PURPOSE, "kind": "recovery", "operation": OPERATION, "nonce": "c" * 32,
             "actor": "user:" + EMAIL, "owner_claim": migration._claim_binding(local_owner._read()),
             "migration": "CSM-" + OPERATION, "migration_revision": 1, "material": "d" * 64,
             "before_choice": {"present": False, "value": None, "reset": False}, "before_revision": "e" * 64,
             "expires": time.time() + 600}
    if protocol:
        value["protocol"] = protocol
    return migration._seal(value)


@pytest.mark.parametrize("path, extra", RECOVERY_STEPS)
def test_a_recovery_step_refuses_the_passphrase_alone_for_an_enrolled_owner(owner, path, extra, events):
    from maverick_dashboard import local_owner
    with client() as web:
        refused = web.post(path, json=body(path, **extra))
    assert refused.status_code == 401
    assert GATE in refused.json()["detail"] and "recovery code" in refused.json()["detail"]
    assert proof_cookies(refused) == []
    assert local_owner._read()["failures"] == 0
    assert not [kw for kind, kw in events if kw.get("verb", "").startswith("owner_recovery_proof")]


@pytest.mark.parametrize("protocol", ["company", "saml"])
def test_the_apply_step_refuses_the_passphrase_alone_for_an_enrolled_owner(owner, protocol):
    path = (COMPANY if protocol == "company" else SAML) + "/apply"
    token = sealed_recovery("saml" if protocol == "saml" else None)
    with client() as web:
        refused = web.post(path, json=body(path, token=token, confirmed=True))
    assert refused.status_code == 401
    assert GATE in refused.json()["detail"]


@pytest.mark.parametrize("prefix", [COMPANY, SAML])
def test_a_current_code_passes_the_lookup_and_sets_a_proof_for_that_flow_only(owner, clock, prefix):
    with client() as web:
        step = web.post(prefix + "/lookup", json=body(prefix, code=current_code(owner, clock)))
    assert step.status_code == 200, step.text
    cookie = " ".join(proof_cookies(step))
    assert "HttpOnly" in cookie and "samesite=strict" in cookie.lower() and "Max-Age=600" in cookie
    assert f"Path={prefix}" in cookie
    assert EMAIL not in proof_cookies(step)[0]
    assert "flow_proofs" in record() and len(record()["flow_proofs"]) == 1


@pytest.mark.parametrize("prefix", [COMPANY, SAML])
def test_a_later_step_of_the_same_flow_takes_the_proof_and_still_checks_the_passphrase(owner, clock, prefix, events):
    with client() as web:
        assert web.post(prefix + "/lookup", json=body(prefix, code=current_code(owner, clock))).status_code == 200
        # The browser sends the proof back on its flow's path, so no code is asked again.
        later = web.post(prefix + "/original", json=body(prefix, operation=OPERATION))
        assert later.status_code == 200, later.text
        wrong = web.post(prefix + "/original", json=body(prefix, operation=OPERATION, password=WRONG))
        assert wrong.status_code == 401
    used = [kw for kind, kw in events if kw.get("verb") == "owner_recovery_proof_used"]
    assert len(used) == 1 and used[0]["actor"] == "user:" + EMAIL


def test_a_proof_from_one_flow_is_refused_by_another_flow(owner, clock):
    with client() as web:
        step = web.post(COMPANY + "/lookup", json=body(COMPANY, code=current_code(owner, clock)))
        token = proof_token(step)
        other = web.post(SAML + "/original", json=body(SAML, operation=OPERATION),
                         headers={"cookie": f"mvk_owner_recovery_proof={token}"})
        same = web.post(COMPANY + "/original", json=body(COMPANY, operation=OPERATION),
                        headers={"cookie": f"mvk_owner_recovery_proof={token}"})
    assert other.status_code == 401 and GATE in other.json()["detail"]
    assert same.status_code == 200


def test_an_expired_proof_is_refused(owner, clock):
    from maverick_dashboard import local_owner_second_factor as second
    with client() as web:
        web.post(COMPANY + "/lookup", json=body(COMPANY, code=current_code(owner, clock)))
        clock.advance(second.PROOF_SECONDS + 1)
        late = web.post(COMPANY + "/original", json=body(COMPANY, operation=OPERATION))
    assert late.status_code == 401 and GATE in late.json()["detail"]


def test_cancelling_a_flow_spends_its_proof(owner, clock, events):
    with client() as web:
        step = web.post(SAML + "/lookup", json=body(SAML, code=current_code(owner, clock)))
        token = proof_token(step)
        cancelled = web.post(SAML + "/cancel")
        assert cancelled.status_code == 200
        assert any("Max-Age=0" in value or "1970" in value for value in proof_cookies(cancelled))
        spent = web.post(SAML + "/original", json=body(SAML, operation=OPERATION),
                         headers={"cookie": f"mvk_owner_recovery_proof={token}"})
    assert spent.status_code == 401
    assert "flow_proofs" not in record()
    ended = [kw for kind, kw in events if kw.get("verb") == "owner_recovery_proof_ended"]
    assert len(ended) == 1 and ended[0]["actor"] == "user:" + EMAIL
    assert token not in json.dumps(events, default=str)


def test_a_cancel_spends_only_the_proof_its_own_browser_holds(owner, clock):
    """A cancel from a browser without the flow's proof changes nothing, so no local process can end a step."""
    with client() as holder:
        token = proof_token(holder.post(SAML + "/lookup", json=body(SAML, code=current_code(owner, clock))))
    with client() as stranger:
        refused = stranger.post(SAML + "/cancel")
        wrong_flow = stranger.post(COMPANY + "/cancel", headers={"cookie": f"mvk_owner_recovery_proof={token}"})
        wrong_token = stranger.post(SAML + "/cancel", headers={"cookie": "mvk_owner_recovery_proof=not-the-proof"})
    assert refused.status_code == wrong_flow.status_code == wrong_token.status_code == 200
    assert len(record()["flow_proofs"]) == 1
    with client() as holder_again:
        still = holder_again.post(SAML + "/original", json=body(SAML, operation=OPERATION),
                                  headers={"cookie": f"mvk_owner_recovery_proof={token}"})
    assert still.status_code == 200, still.text


def test_a_wrong_code_counts_toward_the_owner_lock_on_the_route(owner):
    with client() as web:
        for _ in range(5):
            assert web.post(COMPANY + "/lookup", json=body(COMPANY, code="000000")).status_code == 401
        locked = web.post(COMPANY + "/lookup", json=body(COMPANY, code="000000"))
    assert locked.status_code == 429


@pytest.mark.parametrize("prefix", [COMPANY, SAML])
def test_an_unenrolled_owner_is_not_asked_for_a_code(prefix):
    from maverick_dashboard import local_owner
    from starlette.requests import Request
    scope = {"type": "http", "method": "POST", "scheme": "http", "path": "/auth/local-owner",
             "query_string": b"", "server": ("127.0.0.1", 8765), "client": ("127.0.0.1", 1234),
             "headers": [(b"host", b"127.0.0.1:8765"), (b"origin", ORIGIN.encode())]}
    local_owner.enroll(Request(scope), email=EMAIL, password=PASSPHRASE, confirm=True)
    with client() as web:
        step = web.post(prefix + "/lookup", json=body(prefix))
    assert step.status_code == 200, step.text
    assert proof_cookies(step) == [] and "flow_proofs" not in record()


@pytest.mark.parametrize("prefix, api", [
    ("/api/v1/settings/sign-in-migration", "company"),
    ("/api/v1/settings/single-sign-on", "saml"),
])
def test_the_activation_review_takes_a_code_and_keeps_the_proof_even_when_refused(owner, clock, monkeypatch,
                                                                                 prefix, api):
    from maverick_dashboard import company_saml_setup, company_signin_migration, local_owner
    module = company_signin_migration if api == "company" else company_saml_setup
    # The owner-session and managed-policy checks have their own tests; this isolates the second factor.
    monkeypatch.setattr(module, "authority", lambda request, expected=None, **k: (CONTEXT, local_owner._read()))
    review = prefix + ("/review" if api == "company" else "/activation-review")
    payload = {"check": "no-such-check", "context": CONTEXT, "password": PASSPHRASE}
    from maverick_dashboard import local_passphrases
    with client() as web:
        # The owner signs in on this computer first, with a code, as the activation pages require.
        local_passphrases.reset_attempt_limit()
        assert web.post("/auth/local-login", data={"email": EMAIL, "password": PASSPHRASE}).status_code == 200
        local_passphrases.reset_attempt_limit()
        assert web.post("/auth/owner-second-factor", data={"code": current_code(owner, clock)}).status_code == 303
        clock.advance(30)
        refused = web.post(review, json=payload)
        assert refused.status_code == 401 and GATE in refused.json()["detail"]
        assert proof_cookies(refused) == []
        # With a code the step passes the second factor. Its own check then refuses an unknown choice,
        # and the proof the code issued still reaches the browser.
        passed = web.post(review, json={**payload, "code": current_code(owner, clock)})
    assert passed.status_code == 404
    assert f"Path={prefix}" in " ".join(proof_cookies(passed))


def test_a_completed_step_spends_the_flow_proof_through_the_helper(clock, owner):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_mfa_routes as routes
    from starlette.requests import Request
    from starlette.responses import Response
    step = Request({"type": "http", "method": "POST", "scheme": "http", "path": COMPANY + "/lookup",
                    "query_string": b"", "server": ("127.0.0.1", 8765), "client": ("127.0.0.1", 1234),
                    "headers": [(b"host", b"127.0.0.1:8765"), (b"origin", ORIGIN.encode())]})
    local_owner.verify_recovery(step, email=EMAIL, password=PASSPHRASE, flow="company-signin-recovery",
                                code=current_code(owner, clock))
    assert "flow_proofs" in record()
    done = routes.passphrase_step(step, lambda: {"done": True}, headers={}, completes="company-signin-recovery")
    assert "flow_proofs" not in record()
    assert isinstance(done, Response) and "mvk_owner_recovery_proof=" in " ".join(done.headers.getlist("set-cookie"))


def test_the_restricted_recovery_pages_ask_for_the_owner_code():
    with client() as web:
        company = web.get(COMPANY)
        saml = web.get(SAML)
    assert company.status_code == 200 and 'id="company-migration-code"' in company.text
    assert saml.status_code == 200 and "data-saml-code" in saml.text
    assert "<script>" not in company.text and "onclick=" not in company.text


@pytest.mark.parametrize("path", [COMPANY + "/lookup", SAML + "/lookup"])
def test_a_rejected_owner_code_or_passphrase_is_not_echoed_in_the_validation_error(path):
    """A 422 names the field, never the rejected value: the code and the passphrase are both secrets."""
    marker = "CODEMARK" * 5  # longer than the 32-character code field
    short_phrase = "SHORTPHRASE"  # shorter than the 14-character passphrase minimum
    with client() as web:
        too_long = web.post(path, json={"email": EMAIL, "password": PASSPHRASE, "code": marker})
        no_passphrase = web.post(path, json={"email": EMAIL, "code": marker})
        too_short = web.post(path, json={"email": EMAIL, "password": short_phrase, "code": "123456"})
    for refused in (too_long, no_passphrase, too_short):
        assert refused.status_code == 422, refused.text
        assert "CODEMARK" not in refused.text and short_phrase not in refused.text and "123456" not in refused.text


def test_a_refusal_after_the_code_keeps_the_proof_and_gets_the_app_wide_answer(owner, clock, monkeypatch):
    """A restricted step refused after its code still hands the proof to the browser, and its refusal
    carries the same fields as every other route: the re-authentication link and no-store."""
    from maverick_dashboard import company_signin_migration as migration
    from maverick_dashboard.step_up import StepUpRequired

    def refuse(*args, **kwargs):
        raise StepUpRequired("/auth/local-login?return_to=%2Fsettings")

    monkeypatch.setattr(migration, "_records", refuse)
    with client() as web:
        refused = web.post(COMPANY + "/lookup", json=body(COMPANY, code=current_code(owner, clock)))
    assert refused.status_code == 403
    assert refused.json()["reauthenticate"] == "/auth/local-login?return_to=%2Fsettings"
    assert refused.headers["x-reauthenticate"] == "/auth/local-login?return_to=%2Fsettings"
    assert "no-store" in refused.headers["cache-control"]
    assert proof_cookies(refused) and f"Path={COMPANY}" in proof_cookies(refused)[0]


def test_a_recovery_code_passes_the_lookup_once_and_is_refused_after_that(clock, events):
    _secret, codes = enrolled_owner_with_codes(clock)
    with client() as web:
        first = web.post(COMPANY + "/lookup", json=body(COMPANY, code=codes[0]))
        assert first.status_code == 200, first.text
        assert proof_cookies(first)
    with client() as another_browser:
        spent = another_browser.post(COMPANY + "/lookup", json=body(COMPANY, code=codes[0]))
    assert spent.status_code == 401 and proof_cookies(spent) == []
    assert len(record()["recovery"]) == 9 and record()["failures"] == 1
    used = [kw for kind, kw in events if kw.get("verb") == "owner_recovery_code_used"]
    assert len(used) == 1 and codes[0] not in json.dumps(events, default=str)


@pytest.mark.parametrize("prefix, module, route", [
    (COMPANY, "company_signin_migration", "/apply"),
    (SAML, "company_saml_setup", "/apply"),
])
def test_a_completed_recovery_spends_the_proof_and_clears_its_cookie(clock, monkeypatch, prefix, module, route):
    import importlib
    native = importlib.import_module("maverick_dashboard." + module)
    monkeypatch.setattr(native, "recover", lambda request, token, email, password, code="": {
        "confirmed": True, "message": "Restored."})
    secret = enrolled_owner_with_codes(clock)[0]
    with client() as web:
        assert web.post(prefix + "/lookup", json=body(prefix, code=current_code(secret, clock))).status_code == 200
        assert "flow_proofs" in record()
        done = web.post(prefix + route, json=body(prefix, token="a" * 40, confirmed=True))
    assert done.status_code == 200, done.text
    assert "flow_proofs" not in record()
    cleared = " ".join(proof_cookies(done))
    assert f"Path={prefix}" in cleared and ("Max-Age=0" in cleared or "1970" in cleared)


@pytest.mark.parametrize("prefix, module, review, activate", [
    ("/api/v1/settings/sign-in-migration", "company_signin_migration", "/review", "/activate"),
    ("/api/v1/settings/single-sign-on", "company_saml_setup", "/activation-review", "/activate"),
])
def test_a_completed_activation_spends_the_proof_and_clears_its_cookie(owner, clock, monkeypatch, prefix, module,
                                                                       review, activate):
    import importlib

    from maverick_dashboard import local_owner, local_passphrases
    native = importlib.import_module("maverick_dashboard." + module)
    monkeypatch.setattr(native, "authority", lambda request, expected=None, **k: (CONTEXT, local_owner._read()))
    monkeypatch.setattr(native, "activate", lambda request, token: {"confirmed": True, "message": "Activated."})
    payload = {"check": "no-such-check", "context": CONTEXT, "password": PASSPHRASE}
    with client() as web:
        local_passphrases.reset_attempt_limit()
        assert web.post("/auth/local-login", data={"email": EMAIL, "password": PASSPHRASE}).status_code == 200
        local_passphrases.reset_attempt_limit()
        assert web.post("/auth/owner-second-factor", data={"code": current_code(owner, clock)}).status_code == 303
        clock.advance(30)
        web.post(prefix + review, json={**payload, "code": current_code(owner, clock)})
        assert "flow_proofs" in record()
        done = web.post(prefix + activate, json={"token": "a" * 40, "confirmed": True})
    assert done.status_code == 200, done.text
    assert "flow_proofs" not in record()
    assert f"Path={prefix}" in " ".join(proof_cookies(done))


@pytest.mark.parametrize("prefix, review", [
    ("/api/v1/settings/sign-in-migration", "/review"),
    ("/api/v1/settings/single-sign-on", "/activation-review"),
])
def test_a_signed_in_owner_review_that_is_rejected_does_not_echo_the_code(owner, clock, prefix, review):
    from maverick_dashboard import local_passphrases
    short_phrase = "SHORTPHRASE"  # shorter than the 14-character passphrase minimum
    with client() as web:
        local_passphrases.reset_attempt_limit()
        assert web.post("/auth/local-login", data={"email": EMAIL, "password": PASSPHRASE}).status_code == 200
        local_passphrases.reset_attempt_limit()
        assert web.post("/auth/owner-second-factor", data={"code": current_code(owner, clock)}).status_code == 303
        clock.advance(30)
        # No review context is sent, so the whole body is reported as missing: it holds both secrets.
        refused = web.post(prefix + review, json={"check": "no-such-check", "password": short_phrase,
                                                  "code": "CODEMARK" * 5})
    assert refused.status_code == 422, refused.text
    assert "CODEMARK" not in refused.text and "SHORTPHRASE" not in refused.text
