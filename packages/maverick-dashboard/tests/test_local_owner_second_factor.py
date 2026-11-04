"""The owner's authenticator app: set-up, the second sign-in step, disabling and recovery codes."""
from __future__ import annotations

import json
import logging
import re
import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

PASSPHRASE = "a long local owner fixture phrase"  # pragma: allowlist secret - test fixture passphrase
WRONG = "an incorrect long fixture phrase"  # pragma: allowlist secret - deliberately wrong test passphrase
EMAIL = "owner@example.com"
ORIGIN = "http://127.0.0.1:8765"
FLOW = "company-signin-recovery"  # a restricted flow (local_owner_second_factor.FLOW_PATHS)


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
    """Second-step time, moved forward by the test. Starts at the real time."""
    from maverick_dashboard import local_owner_second_factor as second
    state = {"offset": 0.0}
    monkeypatch.setattr(second, "_now", lambda: time.time() + state["offset"])

    class Clock:
        def advance(self, seconds):
            state["offset"] += seconds

        def now(self):
            return time.time() + state["offset"]

    return Clock()


def request(*, origin=ORIGIN, extra=()):
    return Request({"type": "http", "method": "POST", "scheme": "http", "path": "/auth/local-login",
                    "query_string": b"", "server": ("127.0.0.1", 8765), "client": ("127.0.0.1", 1234),
                    "headers": [(b"host", b"127.0.0.1:8765"), (b"origin", origin.encode()), *extra]})


def session_request(token):
    base = request()
    scope = dict(base.scope)
    scope["headers"] = [*scope["headers"], (b"cookie", f"mvk_session={token}".encode())]
    return Request(scope)


def enroll_owner():
    from maverick_dashboard import local_owner
    return local_owner.enroll(request(), email=EMAIL, password=PASSPHRASE, confirm=True)


def set_mode(monkeypatch, mode):
    cfg = {"auth": {"local_owner": {"totp": mode}}} if mode is not None else {}
    monkeypatch.setattr("maverick.config.load_global_config", lambda *a, **k: cfg)


def current_code(secret_text, clock, offset_steps=0):
    from maverick_dashboard import owner_totp
    key = owner_totp.decode_secret(secret_text)
    return owner_totp.totp(key, clock.now() + offset_steps * owner_totp.STEP_SECONDS)


def turn_on(clock):
    """Enroll the owner through the signed-in set-up path. Returns (secret_text, recovery_codes)."""
    from maverick_dashboard import local_owner_second_factor as second
    secret, _uri = second.start_setup(PASSPHRASE)
    codes = second.confirm_setup(current_code(secret, clock))
    clock.advance(30)  # a new step, so the next code is not a replay of the setup code
    return secret, codes


def row():
    from maverick_dashboard import local_owner
    return json.loads(local_owner.path().read_text())


def test_an_owner_table_does_not_switch_local_sign_in_off():
    from maverick_dashboard import local_owner
    assert local_owner.sign_in_available_for({"auth": {"local_owner": {"totp": "required"}}}, bootstrap=True) is True
    assert local_owner.sign_in_available_for({"auth": {"mfa": {"require": True}}}) is False


def test_without_an_authenticator_app_sign_in_is_unchanged(monkeypatch):
    from maverick_dashboard import local_owner
    enroll_owner()
    result = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    assert isinstance(result, str) and result


def test_set_up_needs_the_passphrase_and_a_valid_code(clock):
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    with pytest.raises(HTTPException) as wrong_passphrase:
        second.start_setup(WRONG)
    assert wrong_passphrase.value.status_code == 401
    assert "totp_setup" not in row()
    secret, uri = second.start_setup(PASSPHRASE)
    assert uri.startswith("otpauth://totp/Lightwork:owner@example.com?") and f"secret={secret}" in uri
    assert "totp" not in row()  # nothing is on until a code is accepted
    wrong_code = "000000" if current_code(secret, clock) != "000000" else "111111"
    with pytest.raises(HTTPException) as refused:
        second.confirm_setup(wrong_code)
    assert refused.value.status_code == 401
    assert "totp" not in row()
    codes = second.confirm_setup(current_code(secret, clock))
    assert len(codes) == 10 and len(set(codes)) == 10
    assert "totp" in row() and len(row()["recovery"]) == 10
    with pytest.raises(HTTPException) as again:
        second.start_setup(PASSPHRASE)
    assert again.value.status_code == 409


def test_the_secret_and_recovery_codes_are_never_stored_in_plain_text(clock):
    from maverick.crypto_at_rest import is_sealed_str
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    secret, codes = turn_on(clock)
    stored = local_owner.path().read_text()
    assert secret not in stored and secret.replace(" ", "") not in stored
    assert all(code not in stored for code in codes)
    assert is_sealed_str(row()["totp"])
    assert second.status(row())["unused_recovery"] == 10


def test_sign_in_asks_for_a_code_and_the_session_records_a_second_factor(clock):
    from maverick_dashboard import invites, local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    secret, _codes = turn_on(clock)
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    assert isinstance(challenge, second.Challenge) and challenge.purpose == "sign_in"
    assert challenge.secret == "" and challenge.uri == ""
    with pytest.raises(HTTPException) as wrong:
        second.complete(request(), token=challenge.token, code="000000")
    assert wrong.value.status_code == 401
    finished = second.complete(request(), token=challenge.token, code=current_code(secret, clock))
    principal = invites.local_session_principal(session_request(finished.session))
    assert principal.principal == "user:" + EMAIL
    assert principal.claims["mfa"] is True and principal.claims["mfa_at"] is not None
    # The pending token is spent.
    with pytest.raises(HTTPException):
        second.complete(request(), token=challenge.token, code=current_code(secret, clock, 1))


def test_a_code_cannot_open_two_sign_ins(clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    secret, _codes = turn_on(clock)
    first = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    second.complete(request(), token=first.token, code=current_code(secret, clock))
    again = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    with pytest.raises(HTTPException) as replay:
        second.complete(request(), token=again.token, code=current_code(secret, clock))
    assert replay.value.status_code == 401
    # The next time step is accepted.
    clock.advance(30)
    second.complete(request(), token=again.token, code=current_code(secret, clock))


def test_a_second_step_token_expires_after_five_minutes(clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    secret, _codes = turn_on(clock)
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    clock.advance(second.PENDING_SECONDS + 1)
    with pytest.raises(HTTPException) as expired:
        second.complete(request(), token=challenge.token, code=current_code(secret, clock))
    assert expired.value.status_code == 401
    assert second.challenge_for(challenge.token) is None


def test_a_second_step_token_takes_five_codes_and_is_then_discarded(clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    turn_on(clock)
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    for _ in range(5):
        with pytest.raises(HTTPException) as bad:
            second.complete(request(), token=challenge.token, code="000000")
        assert bad.value.status_code == 401
    assert second.challenge_for(challenge.token) is None


def test_wrong_codes_from_many_sign_ins_share_the_passphrase_lock(clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    secret, _codes = turn_on(clock)
    for _ in range(5):
        challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
        with pytest.raises(HTTPException):
            second.complete(request(), token=challenge.token, code="000000")
    # Five wrong codes lock the owner, even with a fresh correct passphrase.
    with pytest.raises(HTTPException) as locked:
        local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    assert locked.value.status_code == 429


def test_a_recovery_code_opens_one_sign_in_and_is_audited(monkeypatch, clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    events = []
    monkeypatch.setattr("maverick.audit.audit_event", lambda kind, **kw: events.append((kind, kw)) or True)
    enroll_owner()
    _secret, codes = turn_on(clock)
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    second.complete(request(), token=challenge.token, code=codes[2].lower())
    assert len(row()["recovery"]) == 9
    used = [kw for kind, kw in events if kw.get("verb") == "owner_recovery_code_used"]
    assert len(used) == 1 and used[0]["actor"] == "user:" + EMAIL and codes[2] not in json.dumps(used[0])
    again = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    with pytest.raises(HTTPException):
        second.complete(request(), token=again.token, code=codes[2])


def test_a_refused_audit_stops_a_recovery_code_sign_in(monkeypatch, clock):
    from maverick.audit import AuditRefused
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    _secret, codes = turn_on(clock)
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)

    def refuse(*a, **k):
        raise AuditRefused("log unavailable")

    monkeypatch.setattr("maverick.audit.audit_event", refuse)
    with pytest.raises(HTTPException) as stopped:
        second.complete(request(), token=challenge.token, code=codes[0])
    assert stopped.value.status_code == 503
    assert len(row()["recovery"]) == 10


def test_turning_off_needs_the_passphrase_and_a_current_code(clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    secret, codes = turn_on(clock)
    with pytest.raises(HTTPException) as no_passphrase:
        second.disable(password=WRONG, code=current_code(secret, clock))
    assert no_passphrase.value.status_code == 401
    with pytest.raises(HTTPException) as no_code:
        second.disable(password=PASSPHRASE, code="000000")
    assert no_code.value.status_code == 401
    assert "totp" in row()
    second.disable(password=PASSPHRASE, code=codes[5])  # a recovery code is enough
    assert "totp" not in row() and "recovery" not in row()
    result = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    assert isinstance(result, str)


def test_required_mode_does_not_allow_turning_off(monkeypatch, clock):
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    secret, _codes = turn_on(clock)
    set_mode(monkeypatch, "required")
    with pytest.raises(HTTPException) as refused:
        second.disable(password=PASSPHRASE, code=current_code(secret, clock, 1))
    assert refused.value.status_code == 409
    assert "totp" in row()


def test_new_recovery_codes_replace_the_old_ones(clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    secret, old_codes = turn_on(clock)
    with pytest.raises(HTTPException):
        second.regenerate(code="000000")
    fresh = second.regenerate(code=current_code(secret, clock))
    assert len(fresh) == 10 and not set(fresh) & set(old_codes)
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    with pytest.raises(HTTPException):
        second.complete(request(), token=challenge.token, code=old_codes[0])
    second.complete(request(), token=challenge.token, code=fresh[0])


def test_off_hides_set_up_but_an_enrolled_owner_is_still_asked(monkeypatch, clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    set_mode(monkeypatch, "off")
    with pytest.raises(HTTPException) as hidden:
        second.start_setup(PASSPHRASE)
    assert hidden.value.status_code == 409
    set_mode(monkeypatch, None)
    turn_on(clock)  # enrolled while the option was offered
    set_mode(monkeypatch, "off")
    assert isinstance(local_owner.login(request(), email=EMAIL, password=PASSPHRASE), second.Challenge)


def test_required_mode_forces_set_up_before_any_session(monkeypatch, clock):
    from maverick_dashboard import invites, local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    set_mode(monkeypatch, "required")
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    assert isinstance(challenge, second.Challenge) and challenge.purpose == "enroll"
    assert challenge.secret and challenge.uri.startswith("otpauth://totp/")
    assert "totp" not in row() and "totp_setup" in row()
    finished = second.complete(request(), token=challenge.token,
                               code=current_code(challenge.secret, clock))
    assert len(finished.recovery_codes) == 10
    principal = invites.local_session_principal(session_request(finished.session))
    assert principal.claims["mfa"] is True
    assert "totp" in row()


def test_a_wrong_code_during_forced_set_up_shows_the_same_key_again(monkeypatch, clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    set_mode(monkeypatch, "required")
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    again = second.challenge_for(challenge.token)
    assert again is not None and again.secret == challenge.secret and again.purpose == "enroll"
    assert "totp" not in row()


def test_nothing_secret_is_logged(caplog, clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    caplog.set_level(logging.DEBUG)
    enroll_owner()
    secret, codes = turn_on(clock)
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    with pytest.raises(HTTPException):
        second.complete(request(), token=challenge.token, code="000000")
    second.complete(request(), token=challenge.token, code=current_code(secret, clock))
    text = caplog.text + "".join(r.getMessage() for r in caplog.records)
    assert secret.replace(" ", "") not in text and challenge.token not in text
    assert all(code not in text for code in codes)


def test_the_owner_form_asks_for_a_code_and_sets_the_session_cookie(clock):
    from maverick_dashboard import local_passphrases
    from maverick_dashboard.app import app
    enroll_owner()
    secret, _codes = turn_on(clock)
    local_passphrases.reset_attempt_limit()
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 53210),
                    headers={"Origin": ORIGIN}, follow_redirects=False) as client:
        step = client.post("/auth/local-login", data={"email": EMAIL, "password": PASSPHRASE})
        assert step.status_code == 200, step.text
        assert "Enter your code" in step.text
        assert "mvk_session=" not in step.headers.get("set-cookie", "")
        assert "mvk_owner_second_factor=" in step.headers.get("set-cookie", "")
        local_passphrases.reset_attempt_limit()
        done = client.post("/auth/owner-second-factor", data={"code": current_code(secret, clock)})
        assert done.status_code == 303, done.text
        assert done.headers["location"] == "/start"
        assert "mvk_session=" in done.headers["set-cookie"]
        assert client.get("/api/v1/features/modules").status_code == 200


def test_the_account_page_turns_the_app_on_and_shows_codes_once(clock):
    from maverick_dashboard import local_owner_second_factor as second
    from maverick_dashboard import local_passphrases
    from maverick_dashboard.app import app
    enroll_owner()
    local_passphrases.reset_attempt_limit()
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 53211),
                    headers={"Origin": ORIGIN}, follow_redirects=False) as client:
        response = client.post("/auth/local-login", data={"email": EMAIL, "password": PASSPHRASE})
        assert response.status_code == 303 and "mvk_session=" in response.headers["set-cookie"]
        local_passphrases.reset_attempt_limit()
        page = client.get("/account/owner-authenticator")
        assert page.status_code == 200 and "Set up an authenticator app" in page.text
        setup = client.post("/account/owner-authenticator/setup", data={"password": PASSPHRASE})
        assert setup.status_code == 200, setup.text
        secret = re.search(r"<code>([A-Z2-7 ]+)</code>", setup.text).group(1).replace(" ", "")
        assert second.status(row())["enrolled"] is False
        confirmed = client.post("/account/owner-authenticator/confirm",
                                data={"code": current_code(secret, clock)})
        assert confirmed.status_code == 200, confirmed.text
        codes = re.findall(r"<li><code>([A-Z0-9]{4}-[A-Z0-9]{4})</code></li>", confirmed.text)
        assert len(codes) == 10
        assert "Save these recovery codes" in confirmed.text
        clock.advance(30)
        status = client.get("/account/owner-authenticator")
        assert "The authenticator app is <strong>on</strong>" in status.text
        refused = client.post("/account/owner-authenticator/disable",
                              data={"password": WRONG, "code": codes[0]})
        assert refused.status_code == 401


def test_the_account_page_refuses_a_visitor_who_is_not_signed_in():
    from maverick_dashboard.app import app
    enroll_owner()
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 53212),
                    headers={"Origin": ORIGIN}, follow_redirects=False) as client:
        response = client.get("/account/owner-authenticator")
        assert response.status_code == 401
        assert response.json() == {"detail": "authenticated identity required"}
        assert "otpauth://" not in response.text and "<code>" not in response.text


def test_a_form_with_extra_fields_is_refused(clock):
    from maverick_dashboard import local_passphrases
    from maverick_dashboard.app import app
    enroll_owner()
    local_passphrases.reset_attempt_limit()
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 53213),
                    headers={"Origin": ORIGIN}, follow_redirects=False) as client:
        client.post("/auth/local-login", data={"email": EMAIL, "password": PASSPHRASE})
        local_passphrases.reset_attempt_limit()
        bad = client.post("/auth/owner-second-factor", data={"code": "000000", "extra": "x"})
        assert bad.status_code == 422


def test_off_refuses_changes_but_still_asks_an_enrolled_owner_for_a_code(monkeypatch, clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    secret, codes = turn_on(clock)
    set_mode(monkeypatch, "off")
    with pytest.raises(HTTPException) as no_disable:
        second.disable(password=PASSPHRASE, code=codes[0])
    assert no_disable.value.status_code == 409
    with pytest.raises(HTTPException) as no_new_codes:
        second.regenerate(code=current_code(secret, clock, 1))
    assert no_new_codes.value.status_code == 409
    assert isinstance(local_owner.login(request(), email=EMAIL, password=PASSPHRASE), second.Challenge)
    assert "totp" in row() and len(row()["recovery"]) == 10


def test_a_passphrase_only_recovery_check_does_not_reset_the_code_lock(clock):
    """R1: the restricted recovery check must not clear the wrong-code count of an enrolled owner."""
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    turn_on(clock)
    for _ in range(4):
        challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
        with pytest.raises(HTTPException):
            second.complete(request(), token=challenge.token, code="000000")
    assert row()["failures"] == 4
    with pytest.raises(HTTPException) as passphrase_only:
        local_owner.verify_recovery(request(), email=EMAIL, password=PASSPHRASE, flow=FLOW)
    assert passphrase_only.value.status_code == 401
    assert row()["failures"] == 4 and row()["locked_until"] == 0
    # The sign-in path keeps the count too: a correct passphrase gives a code challenge and no reset.
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    assert isinstance(challenge, second.Challenge) and challenge.purpose == "sign_in"
    assert row()["failures"] == 4 and row()["locked_until"] == 0
    with pytest.raises(HTTPException) as fifth:
        second.complete(request(), token=challenge.token, code="000000")
    assert fifth.value.status_code == 401
    assert row()["failures"] == 5
    # The restricted recovery check is refused while the lock holds, as sign-in is.
    with pytest.raises(HTTPException) as locked:
        local_owner.verify_recovery(request(), email=EMAIL, password=PASSPHRASE, flow=FLOW, code="000000")
    assert locked.value.status_code == 429
    with pytest.raises(HTTPException) as still_locked:
        local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    assert still_locked.value.status_code == 429


def test_required_mode_gives_no_session_at_first_owner_setup(monkeypatch, clock):
    """R3: the first owner's set-up under required mode ends in the set-up step, not a session."""
    from maverick_dashboard import invites, local_owner
    from maverick_dashboard import local_owner_second_factor as second
    set_mode(monkeypatch, "required")
    result = local_owner.enroll(request(), email=EMAIL, password=PASSPHRASE, confirm=True)
    assert isinstance(result, second.Challenge) and result.purpose == "enroll"
    assert result.secret and result.uri.startswith("otpauth://totp/")
    assert "totp" not in row() and "totp_setup" in row()
    finished = second.complete(request(), token=result.token, code=current_code(result.secret, clock))
    assert len(finished.recovery_codes) == 10
    principal = invites.local_session_principal(session_request(finished.session))
    assert principal.principal == "user:" + EMAIL and principal.claims["mfa"] is True


def test_required_first_owner_form_asks_for_set_up_and_sets_no_session_cookie(monkeypatch):
    from maverick_dashboard import local_passphrases
    from maverick_dashboard.app import app
    set_mode(monkeypatch, "required")
    local_passphrases.reset_attempt_limit()
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 53214),
                    headers={"Origin": ORIGIN}, follow_redirects=False) as client:
        response = client.post("/auth/local-owner", data={"email": EMAIL, "password": PASSPHRASE,
                                                          "password2": PASSPHRASE, "confirm": "yes"})
        assert response.status_code == 200, response.text
        assert "Set up your authenticator app" in response.text and "Nothing is turned on yet" in response.text
        assert "mvk_session=" not in response.headers.get("set-cookie", "")
        assert "mvk_owner_second_factor=" in response.headers.get("set-cookie", "")
        assert client.get("/api/v1/features/modules").status_code in {401, 403}


def test_a_second_step_begun_before_managed_sign_in_is_refused_and_spends_nothing(monkeypatch, clock):
    """R6: the second step runs the managed sign-in policy again, as the passphrase step does."""
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    secret, _codes = turn_on(clock)
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "managed-sign-in-set-after-the-challenge")  # pragma: allowlist secret - fixture token
    with pytest.raises(HTTPException) as refused:
        second.complete(request(), token=challenge.token, code=current_code(secret, clock))
    assert refused.value.status_code == 409
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN")
    finished = second.complete(request(), token=challenge.token, code=current_code(secret, clock))
    assert finished.session


def test_a_second_step_begun_before_the_owner_was_deprovisioned_is_refused(monkeypatch, clock):
    from fastapi import HTTPException as Refusal
    from maverick_dashboard import auth, local_owner
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    secret, _codes = turn_on(clock)
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)

    def deprovisioned(principal):
        raise Refusal(status_code=401, detail="invalid identity")

    monkeypatch.setattr(auth, "_enforce_scim_active", deprovisioned)
    with pytest.raises(HTTPException) as refused:
        second.complete(request(), token=challenge.token, code=current_code(secret, clock))
    assert refused.value.status_code == 401
    assert "totp" in row() and len(row()["recovery"]) == 10


def test_a_set_up_whose_session_cannot_be_made_stores_no_secret_and_no_codes(monkeypatch, clock):
    """R7: the authenticator app and recovery codes are committed only when a session can be shown."""
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    events = []
    monkeypatch.setattr("maverick.audit.audit_event", lambda kind, **kw: events.append((kind, kw)) or True)
    enroll_owner()
    set_mode(monkeypatch, "required")
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    real_finish = local_owner._finish

    def no_session(*args, **kwargs):
        raise RuntimeError("session store unavailable")

    monkeypatch.setattr(local_owner, "_finish", no_session)
    with pytest.raises(RuntimeError):
        second.complete(request(), token=challenge.token, code=current_code(challenge.secret, clock))
    stored = row()
    assert "totp" not in stored and "recovery" not in stored and "totp_setup" in stored
    assert not [kw for kind, kw in events if kw.get("verb") == "owner_authenticator_enabled"]
    monkeypatch.setattr(local_owner, "_finish", real_finish)
    finished = second.complete(request(), token=challenge.token, code=current_code(challenge.secret, clock))
    assert len(finished.recovery_codes) == 10


def test_a_refused_audit_for_set_up_ends_the_session_it_made_and_stores_nothing(monkeypatch, clock):
    from maverick.audit import AuditRefused
    from maverick_dashboard import local_owner, session_registry
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    set_mode(monkeypatch, "required")
    challenge = local_owner.login(request(), email=EMAIL, password=PASSPHRASE)
    before = len(session_registry.list_for("user:" + EMAIL))

    def refuse(*a, **k):
        raise AuditRefused("log unavailable")

    monkeypatch.setattr("maverick.audit.audit_event", refuse)
    with pytest.raises(HTTPException) as stopped:
        second.complete(request(), token=challenge.token, code=current_code(challenge.secret, clock))
    assert stopped.value.status_code == 503
    assert "totp" not in row() and "recovery" not in row()
    assert len(session_registry.list_for("user:" + EMAIL)) == before


def test_the_second_step_returns_the_owner_to_the_page_they_asked_for(clock):
    """R8: a safe return address from the passphrase step survives the second step."""
    from maverick_dashboard import local_passphrases
    from maverick_dashboard.app import app
    enroll_owner()
    secret, _codes = turn_on(clock)
    local_passphrases.reset_attempt_limit()
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 53215),
                    headers={"Origin": ORIGIN}, follow_redirects=False) as client:
        step = client.post("/auth/local-login?return_to=%2Fchat", data={"email": EMAIL, "password": PASSPHRASE})
        assert step.status_code == 200, step.text
        assert 'action="/auth/owner-second-factor?return_to=%2Fchat"' in step.text
        local_passphrases.reset_attempt_limit()
        done = client.post("/auth/owner-second-factor?return_to=%2Fchat", data={"code": current_code(secret, clock)})
        assert done.status_code == 303, done.text
        assert done.headers["location"] == "/chat"


def test_the_second_step_never_returns_the_owner_off_site_or_to_a_sign_in_page(clock):
    from maverick_dashboard import local_passphrases
    from maverick_dashboard.app import app
    enroll_owner()
    secret, _codes = turn_on(clock)
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 53216),
                    headers={"Origin": ORIGIN}, follow_redirects=False) as client:
        for unsafe in ("%2F%2Fevil.example", "%2Fauth%2Flogout", "https%3A%2F%2Fevil.example"):
            local_passphrases.reset_attempt_limit()
            step = client.post(f"/auth/local-login?return_to={unsafe}", data={"email": EMAIL, "password": PASSPHRASE})
            assert step.status_code == 200, step.text
            assert 'action="/auth/owner-second-factor"' in step.text
            local_passphrases.reset_attempt_limit()
            done = client.post("/auth/owner-second-factor", data={"code": current_code(secret, clock)})
            assert done.status_code == 303, done.text
            assert done.headers["location"] == "/start"
            clock.advance(30)
            client.cookies.clear()


def test_the_owners_account_page_links_to_the_authenticator_app(monkeypatch):
    """R5: the owner reaches set-up from the account page, and off hides the link."""
    from maverick_dashboard import local_passphrases
    from maverick_dashboard.app import app
    enroll_owner()
    local_passphrases.reset_attempt_limit()
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 53217),
                    headers={"Origin": ORIGIN}, follow_redirects=False) as client:
        assert client.post("/auth/local-login", data={"email": EMAIL, "password": PASSPHRASE}).status_code == 303
        page = client.get("/account")
        assert page.status_code == 200, page.text
        assert 'href="/account/owner-authenticator"' in page.text
        set_mode(monkeypatch, "off")
        hidden = client.get("/account")
        assert hidden.status_code == 200
        assert 'href="/account/owner-authenticator"' not in hidden.text


def test_a_colleague_is_not_offered_the_owner_authenticator_link():
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import local_owner_mfa_routes
    enroll_owner()
    owner_request = request()
    owner_request.state.principal = VerifiedPrincipal(sub=EMAIL, issuer="invite-session", audience="", claims={"via": "invite"})
    colleague_request = request()
    colleague_request.state.principal = VerifiedPrincipal(sub="colleague@example.com", issuer="invite-session",
                                                          audience="", claims={"via": "invite"})
    assert local_owner_mfa_routes.owner_link_visible(owner_request) is True
    assert local_owner_mfa_routes.owner_link_visible(colleague_request) is False
    assert local_owner_mfa_routes.owner_link_visible(request()) is False


def proof_request(token, *, flow_cookie=None):
    """A request that presents a recovery proof cookie, as the browser sends it on its flow's path."""
    base = request()
    scope = dict(base.scope)
    scope["headers"] = [*scope["headers"], (b"cookie", f"mvk_owner_recovery_proof={token}".encode())]
    return Request(scope)


def capture_audit(monkeypatch):
    events = []
    monkeypatch.setattr("maverick.audit.audit_event", lambda kind, **kw: events.append((kind, kw)) or True)
    return events


def test_a_passphrase_alone_is_refused_for_an_enrolled_owner_and_counts_nothing(clock):
    from maverick_dashboard import local_owner
    enroll_owner()
    turn_on(clock)
    with pytest.raises(HTTPException) as refused:
        local_owner.verify_recovery(request(), email=EMAIL, password=PASSPHRASE, flow=FLOW)
    assert refused.value.status_code == 401
    assert "authenticator app" in refused.value.detail and "recovery code" in refused.value.detail
    assert row()["failures"] == 0 and "flow_proofs" not in row()


def test_a_current_code_passes_the_step_and_issues_a_proof_kept_only_as_a_digest(monkeypatch, clock):
    import hashlib

    from maverick_dashboard import local_owner
    events = capture_audit(monkeypatch)
    enroll_owner()
    secret, _codes = turn_on(clock)
    step = request()
    local_owner.verify_recovery(step, email=EMAIL, password=PASSPHRASE, flow=FLOW, code=current_code(secret, clock))
    flow, token = step.state.owner_recovery_proof
    assert flow == FLOW and len(token) >= 40
    stored = row()
    key = hashlib.sha256(f"{FLOW}\n{EMAIL}\n{token}".encode()).hexdigest()
    assert list(stored["flow_proofs"]) == [key]
    assert stored["flow_proofs"][key]["flow"] == FLOW
    assert 0 < stored["flow_proofs"][key]["expires"] - clock.now() <= 600
    assert token not in local_owner.path().read_text()
    issued = [kw for kind, kw in events if kw.get("verb") == "owner_recovery_proof_issued"]
    assert len(issued) == 1 and issued[0]["actor"] == "user:" + EMAIL
    assert token not in json.dumps(issued[0]) and secret not in json.dumps(issued[0])


def test_a_recovery_code_passes_the_step_and_is_spent_and_audited(monkeypatch, clock):
    from maverick_dashboard import local_owner
    events = capture_audit(monkeypatch)
    enroll_owner()
    _secret, codes = turn_on(clock)
    step = request()
    local_owner.verify_recovery(step, email=EMAIL, password=PASSPHRASE, flow=FLOW, code=codes[4].lower())
    assert len(row()["recovery"]) == 9
    used = [kw for kind, kw in events if kw.get("verb") == "owner_recovery_code_used"]
    assert len(used) == 1 and codes[4] not in json.dumps(events, default=str)
    with pytest.raises(HTTPException):
        local_owner.verify_recovery(request(), email=EMAIL, password=PASSPHRASE, flow=FLOW, code=codes[4])


def test_a_later_step_of_the_same_flow_accepts_the_proof_without_a_code(monkeypatch, clock):
    from maverick_dashboard import local_owner
    events = capture_audit(monkeypatch)
    enroll_owner()
    secret, _codes = turn_on(clock)
    first = request()
    local_owner.verify_recovery(first, email=EMAIL, password=PASSPHRASE, flow=FLOW, code=current_code(secret, clock))
    _flow, token = first.state.owner_recovery_proof
    clock.advance(30)
    later = proof_request(token)
    local_owner.verify_recovery(later, email=EMAIL, password=PASSPHRASE, flow=FLOW, code="")
    # The passphrase is still checked, and the proof is not spent by a later step.
    with pytest.raises(HTTPException) as wrong:
        local_owner.verify_recovery(proof_request(token), email=EMAIL, password=WRONG, flow=FLOW)
    assert wrong.value.status_code == 401
    local_owner.verify_recovery(proof_request(token), email=EMAIL, password=PASSPHRASE, flow=FLOW)
    used = [kw for kind, kw in events if kw.get("verb") == "owner_recovery_proof_used"]
    assert len(used) == 2 and used[0]["actor"] == "user:" + EMAIL
    assert token not in json.dumps(events, default=str)


def test_a_proof_never_works_for_another_flow(clock):
    from maverick_dashboard import local_owner
    enroll_owner()
    secret, _codes = turn_on(clock)
    first = request()
    local_owner.verify_recovery(first, email=EMAIL, password=PASSPHRASE, flow=FLOW, code=current_code(secret, clock))
    _flow, token = first.state.owner_recovery_proof
    for other in ("company-saml-recovery", "company-saml-activation", "company-signin-activation"):
        with pytest.raises(HTTPException) as refused:
            local_owner.verify_recovery(proof_request(token), email=EMAIL, password=PASSPHRASE, flow=other)
        assert refused.value.status_code == 401
    # The proof still works for its own flow.
    local_owner.verify_recovery(proof_request(token), email=EMAIL, password=PASSPHRASE, flow=FLOW)


def test_an_expired_proof_is_refused_and_a_closed_flow_spends_its_proof(clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    from starlette.responses import Response
    enroll_owner()
    secret, _codes = turn_on(clock)
    first = request()
    local_owner.verify_recovery(first, email=EMAIL, password=PASSPHRASE, flow=FLOW, code=current_code(secret, clock))
    _flow, token = first.state.owner_recovery_proof
    clock.advance(second.PROOF_SECONDS + 1)
    with pytest.raises(HTTPException) as expired:
        local_owner.verify_recovery(proof_request(token), email=EMAIL, password=PASSPHRASE, flow=FLOW)
    assert expired.value.status_code == 401
    # A fresh code issues a new proof; closing the flow spends it at once.
    again = request()
    local_owner.verify_recovery(again, email=EMAIL, password=PASSPHRASE, flow=FLOW,
                                code=current_code(secret, clock, 1))
    _flow, live = again.state.owner_recovery_proof
    assert list(row()["flow_proofs"].values())[0]["expires"] > clock.now()
    response = Response()
    second.close_flow(response, flow=FLOW)
    assert "flow_proofs" not in row()
    assert f"Path={second.FLOW_PATHS[FLOW]}" in response.headers["set-cookie"]
    with pytest.raises(HTTPException):
        local_owner.verify_recovery(proof_request(live), email=EMAIL, password=PASSPHRASE, flow=FLOW)


def test_a_new_proof_replaces_the_earlier_one_for_the_same_flow(clock):
    from maverick_dashboard import local_owner
    enroll_owner()
    secret, _codes = turn_on(clock)
    first = request()
    local_owner.verify_recovery(first, email=EMAIL, password=PASSPHRASE, flow=FLOW, code=current_code(secret, clock))
    _flow, old = first.state.owner_recovery_proof
    clock.advance(30)
    second_step = request()
    local_owner.verify_recovery(second_step, email=EMAIL, password=PASSPHRASE, flow=FLOW,
                                code=current_code(secret, clock))
    assert len(row()["flow_proofs"]) == 1
    with pytest.raises(HTTPException):
        local_owner.verify_recovery(proof_request(old), email=EMAIL, password=PASSPHRASE, flow=FLOW)


def test_wrong_codes_count_toward_the_lock_and_a_correct_passphrase_does_not_clear_it(clock):
    from maverick_dashboard import local_owner
    enroll_owner()
    turn_on(clock)
    for _ in range(4):
        with pytest.raises(HTTPException) as bad:
            local_owner.verify_recovery(request(), email=EMAIL, password=PASSPHRASE, flow=FLOW, code="000000")
        assert bad.value.status_code == 401
    assert row()["failures"] == 4
    with pytest.raises(HTTPException) as fifth:
        local_owner.verify_recovery(request(), email=EMAIL, password=PASSPHRASE, flow=FLOW, code="000000")
    assert fifth.value.status_code == 401 and row()["failures"] == 5 and row()["locked_until"] > clock.now()
    with pytest.raises(HTTPException) as locked:
        local_owner.verify_recovery(request(), email=EMAIL, password=PASSPHRASE, flow=FLOW, code="000000")
    assert locked.value.status_code == 429


def test_an_unenrolled_owner_passes_the_step_on_the_passphrase_alone_as_before(clock):
    from maverick_dashboard import local_owner
    enroll_owner()
    step = request()
    local_owner.verify_recovery(step, email=EMAIL, password=PASSPHRASE, flow=FLOW)
    assert not hasattr(step.state, "owner_recovery_proof")
    assert "flow_proofs" not in row() and "totp" not in row()


def test_turning_the_app_off_leaves_recovery_proofs_alone(monkeypatch, clock):
    """Turning the app off changes only the app: a recovery proof is spent by its flow, not by this."""
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    capture_audit(monkeypatch)
    enroll_owner()
    secret, _codes = turn_on(clock)
    step = request()
    local_owner.verify_recovery(step, email=EMAIL, password=PASSPHRASE, flow=FLOW, code=current_code(secret, clock))
    clock.advance(30)
    second.disable(password=PASSPHRASE, code=current_code(secret, clock))
    assert "totp" not in row() and len(row()["flow_proofs"]) == 1


def test_a_malformed_proof_record_makes_owner_authority_unavailable(clock):
    from maverick_dashboard import local_owner
    enroll_owner()
    turn_on(clock)
    stored = row()
    stored["flow_proofs"] = {"not-a-digest": {"flow": FLOW, "expires": 1.0}}
    local_owner.path().write_text(json.dumps(stored))
    with pytest.raises(HTTPException) as unavailable:
        local_owner.verify_recovery(request(), email=EMAIL, password=PASSPHRASE, flow=FLOW)
    assert unavailable.value.status_code == 503


def test_the_operator_reset_needs_the_owners_email_and_clears_everything_second_factor(monkeypatch, clock):
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    events = capture_audit(monkeypatch)
    enroll_owner()
    secret, codes = turn_on(clock)
    step = request()
    local_owner.verify_recovery(step, email=EMAIL, password=PASSPHRASE, flow=FLOW, code=current_code(secret, clock))
    before = row()
    with pytest.raises(ValueError):
        second.reset_by_operator(confirm_email="someone@example.com", actor="os:posix:1000")
    assert row() == before and not [e for e in events if e[1].get("verb") == "owner_authenticator_reset"]
    assert second.reset_by_operator(confirm_email=" OWNER@example.com ", actor="os:posix:1000") is True
    stored = row()
    for key in ("totp", "totp_step", "totp_setup", "recovery", "second_factor", "flow_proofs"):
        assert key not in stored
    assert stored["status"] == "ready" and stored["email"] == EMAIL
    reset = [kw for kind, kw in events if kw.get("verb") == "owner_authenticator_reset"]
    assert len(reset) == 1 and reset[0]["actor"] == "os:posix:1000"
    assert secret not in json.dumps(events, default=str) and codes[0] not in json.dumps(events, default=str)
    assert second.reset_by_operator(confirm_email=EMAIL, actor="os:posix:1000") is False


def test_a_refused_audit_stops_the_operator_reset(monkeypatch, clock):
    from maverick.audit import AuditRefused
    from maverick_dashboard import local_owner_second_factor as second
    enroll_owner()
    turn_on(clock)
    before = row()

    def refuse(*a, **k):
        raise AuditRefused("log unavailable")

    monkeypatch.setattr("maverick.audit.audit_event", refuse)
    with pytest.raises(HTTPException) as stopped:
        second.reset_by_operator(confirm_email=EMAIL, actor="os:posix:1000")
    assert stopped.value.status_code == 503
    assert row() == before


def test_ending_a_flow_is_recorded_without_its_token_and_a_refused_log_does_not_keep_the_proof(monkeypatch, clock):
    from maverick.audit import AuditRefused
    from maverick_dashboard import local_owner
    from maverick_dashboard import local_owner_second_factor as second
    from starlette.responses import Response
    events = capture_audit(monkeypatch)
    enroll_owner()
    secret, _codes = turn_on(clock)
    first = request()
    local_owner.verify_recovery(first, email=EMAIL, password=PASSPHRASE, flow=FLOW, code=current_code(secret, clock))
    _flow, token = first.state.owner_recovery_proof
    second.close_flow(Response(), flow=FLOW, presented=token)
    ended = [kw for kind, kw in events if kw.get("verb") == "owner_recovery_proof_ended"]
    assert len(ended) == 1 and ended[0]["actor"] == "user:" + EMAIL
    assert ended[0]["detail"] == f"recovery flow {FLOW}" and "flow_proofs" not in row()
    assert token not in json.dumps(events, default=str)
    # Nothing is recorded when there is nothing to end.
    second.close_flow(Response(), flow=FLOW)
    assert len([kw for kind, kw in events if kw.get("verb") == "owner_recovery_proof_ended"]) == 1
    # A refused activity log is logged, not raised: the proof is still spent.
    clock.advance(30)
    again = request()
    local_owner.verify_recovery(again, email=EMAIL, password=PASSPHRASE, flow=FLOW, code=current_code(secret, clock))
    _flow, live = again.state.owner_recovery_proof

    def refuse(*a, **k):
        raise AuditRefused("log unavailable")

    monkeypatch.setattr("maverick.audit.audit_event", refuse)
    response = Response()
    second.close_flow(response, flow=FLOW)
    assert "flow_proofs" not in row()
    assert f"Path={second.FLOW_PATHS[FLOW]}" in response.headers["set-cookie"]
    with pytest.raises(HTTPException):
        local_owner.verify_recovery(proof_request(live), email=EMAIL, password=PASSPHRASE, flow=FLOW)
