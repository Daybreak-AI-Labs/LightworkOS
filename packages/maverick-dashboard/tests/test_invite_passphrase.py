"""Invited colleagues can sign back in.

Accepting an invitation used to create a session but no passphrase, so a
colleague who signed out was locked out: the link says "already used" and the
sign-in page rejected their email. Now, when invitations sign people in
locally (no SSO), accepting sets a passphrase with the owner's rules (14 to
1,024 characters), hashing (scrypt with a per-account salt) and lockout (five
wrong tries, then a one-minute wait); the colleague signs in again from any
computer; the owner's own sign-in still works only on the computer running
Lightwork. With SSO the company account signs people in and no passphrase is
asked for.
"""
from __future__ import annotations

import json
import os
import re
import time

import pytest
from fastapi.testclient import TestClient

LOCAL = "http://127.0.0.1:8765"
REMOTE = "https://lightwork.example"  # remote access runs over TLS (Secure cookies)
OWNER = "owner@example.test"
OWNER_PASS = "Synthetic owner passphrase for invites"  # pragma: allowlist secret
COLLEAGUE = "sam@example.test"
GOOD = "harbor violet tram ledger"  # pragma: allowlist secret - synthetic fixture passphrase
OTHER = "a different synthetic passphrase"  # pragma: allowlist secret - synthetic fixture passphrase


@pytest.fixture
def workspace(monkeypatch, tmp_path):
    from maverick import client as client_binding
    from maverick import config, world_model

    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    config_path = tmp_path / "config.toml"
    config_path.write_text('[client]\nid="invite-passphrase"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    client_binding.reset_client_cache()
    from maverick_dashboard import local_passphrases
    from maverick_dashboard.app import app

    local_passphrases.reset_attempt_limit()  # each test starts with a fresh per-address window
    owner = TestClient(app, base_url=LOCAL, client=("127.0.0.1", 50001),
                       headers={"Origin": LOCAL}, follow_redirects=False)
    claimed = owner.post("/auth/local-owner", data={
        "email": OWNER, "password": OWNER_PASS, "password2": OWNER_PASS, "confirm": "yes"})
    assert claimed.status_code == 303, claimed.text
    yield owner
    owner.close()
    local_passphrases.reset_attempt_limit()
    config.reset_config_cache()
    client_binding.reset_client_cache()


def _remote():
    """A colleague's browser on another computer."""
    from maverick_dashboard.app import app

    return TestClient(app, base_url=REMOTE, client=("192.0.2.40", 50002),
                      headers={"Origin": REMOTE}, follow_redirects=False)


def _invite(owner, email=COLLEAGUE, role="operator") -> str:
    made = owner.post("/users/invite", data={"email": email, "role": role})
    assert made.status_code == 200, made.text
    return re.search(r"/auth/invite/(inv_[A-Za-z0-9_-]+)", made.text)[0]


def _accept(browser, link, password=GOOD, password2=None):
    return browser.post(link, data={"password": password,
                                    "password2": password if password2 is None else password2})


def _sign_in(browser, email=COLLEAGUE, password=GOOD):
    return browser.post("/auth/local-login", data={"email": email, "password": password})


def test_invite_page_is_branded_names_the_role_plainly_and_asks_for_a_passphrase(workspace):
    link = _invite(workspace)
    page = _remote().get(link)
    assert page.status_code == 200
    html = page.text
    assert "/static/lightwork.css" in html and "daybreak-logo" in html
    assert "You&#39;re invited" in html or "You're invited" in html
    assert "Operator" in html and "run work and approve actions" in html
    assert "<code>operator</code>" not in html
    assert re.search(r'<input[^>]*name="password"[^>]*autocomplete="new-password"', html)
    assert re.search(r'<input[^>]*name="password2"', html)
    # Password managers save the right account name with the new passphrase.
    assert re.search(rf'<input[^>]*autocomplete="username"[^>]*value="{re.escape(COLLEAGUE)}"', html)
    assert "Accept invitation" in html


def test_accept_set_passphrase_sign_out_and_sign_back_in_from_another_computer(workspace, tmp_path):
    from maverick.file_lock import private_path_is_restricted
    from maverick_dashboard import invites, rbac

    link = _invite(workspace)
    colleague = _remote()
    accepted = _accept(colleague, link)
    assert accepted.status_code == 303, accepted.text
    assert "mvk_session" in colleague.cookies
    assert rbac.get_stored_role("user:" + COLLEAGUE) == "operator"
    assert invites.peek_invite(link.rsplit("/", 1)[1]) is None
    store = tmp_path / "dashboard-passphrases.json"
    assert store.exists() and GOOD not in store.read_text(encoding="utf-8")
    assert private_path_is_restricted(store)
    assert colleague.get("/api/v1/features/modules").status_code == 200
    # Sign out, then come back the next day.
    assert colleague.post("/auth/logout", follow_redirects=False).status_code == 303
    assert "mvk_session" not in colleague.cookies
    denied = colleague.get("/goals", headers={"Accept": "text/html"})
    assert denied.status_code in {302, 303} and denied.headers["location"].startswith("/auth/local-login")
    form = colleague.get("/auth/local-login")
    assert form.status_code == 200 and 'name="email"' in form.text
    signed_in = _sign_in(colleague)
    assert signed_in.status_code == 303, signed_in.text
    assert "mvk_session" in colleague.cookies
    assert colleague.get("/api/v1/features/modules").status_code == 200


def test_a_bad_passphrase_at_acceptance_keeps_the_invitation_usable(workspace):
    from maverick_dashboard import invites

    link = _invite(workspace)
    token = link.rsplit("/", 1)[1]
    colleague = _remote()
    for password, password2 in (("", ""), ("too short 13c", "too short 13c"), (GOOD, GOOD + " typo")):
        refused = _accept(colleague, link, password, password2)
        assert refused.status_code == 422, (password, refused.text)
        assert "mvk_session" not in colleague.cookies
        assert invites.peek_invite(token) is not None
    assert "14" in _accept(colleague, link, "short", "short").text
    assert "do not match" in _accept(colleague, link, GOOD, OTHER).text
    assert _accept(colleague, link).status_code == 303


def test_a_used_link_is_refused_and_cannot_replace_the_passphrase(workspace):
    link = _invite(workspace)
    assert _accept(_remote(), link).status_code == 303
    again = _accept(_remote(), link, OTHER)
    assert again.status_code == 410
    assert "Ask your administrator to send a new one" in again.text
    assert _sign_in(_remote(), password=OTHER).status_code == 401
    assert _sign_in(_remote(), password=GOOD).status_code == 303


def test_wrong_passphrases_lock_the_account_like_the_owner_and_never_reveal_who_exists(workspace):
    link = _invite(workspace)
    assert _accept(_remote(), link).status_code == 303
    browser = _remote()
    unknown = _sign_in(browser, email="nobody@example.test", password=OTHER)
    wrong = _sign_in(browser, password=OTHER)
    assert unknown.status_code == wrong.status_code == 401
    text = lambda page: re.sub(r"\s+", " ", page.text)  # noqa: E731
    assert "The email or passphrase was not accepted." in text(wrong)
    assert "ask your administrator for an invitation" in text(wrong)
    assert "An invitation cannot replace a passphrase you already have" in text(wrong)
    assert text(unknown).count("not accepted") == text(wrong).count("not accepted")
    for _ in range(4):
        assert _sign_in(browser, password=OTHER).status_code == 401
    locked = _sign_in(browser, password=GOOD)
    assert locked.status_code == 429
    assert "mvk_session" not in browser.cookies


def test_a_removed_colleague_cannot_sign_back_in(workspace):
    from maverick_dashboard import rbac

    link = _invite(workspace)
    assert _accept(_remote(), link).status_code == 303
    rbac.remove_user("user:" + COLLEAGUE)
    refused = _sign_in(_remote())
    assert refused.status_code == 403
    assert "give your account access again" in refused.text


def test_workspace_invitation_keeps_its_workspace_role_for_sign_in(workspace):
    from maverick.tenant import registry
    from maverick_dashboard import invites, rbac

    registry.create_tenant("client-a")
    _inv, token = invites.create_invite("client-admin@example.test", "admin",
                                        created_by="user:" + OWNER, tenant="client-a")
    assert _accept(_remote(), f"/auth/invite/{token}").status_code == 303
    assert rbac.get_stored_role("user:client-admin@example.test") is None
    assert rbac.get_tenant_role("client-a", "user:client-admin@example.test") == "admin"
    assert _sign_in(_remote(), email="client-admin@example.test").status_code == 303


def test_the_owner_still_signs_in_only_on_this_computer(workspace):
    assert _sign_in(_remote(), email=OWNER, password=OWNER_PASS).status_code == 401
    local = workspace
    local.cookies.clear()
    assert _sign_in(local, email=OWNER, password=OWNER_PASS).status_code == 303


def test_sign_in_post_needs_this_sites_origin(workspace):
    from maverick_dashboard.app import app

    link = _invite(workspace)
    assert _accept(_remote(), link).status_code == 303
    for headers in ({}, {"Origin": "https://attacker.example"}):
        hostile = TestClient(app, base_url=REMOTE, client=("192.0.2.41", 50003),
                             headers=headers, follow_redirects=False)
        response = _sign_in(hostile)
        assert response.status_code in {400, 403}, headers
        assert "mvk_session" not in hostile.cookies


def test_sign_in_page_offers_a_new_invite_to_people_without_a_passphrase(workspace):
    page = re.sub(r"\s+", " ", _remote().get("/auth/local-login").text)
    assert "No passphrase yet? Ask your administrator for an invitation" in page
    assert "An invitation cannot replace a passphrase you already have" in page
    assert "Forgotten it? Ask the installation owner to reset it." in page
    assert "/static/lightwork.css" in page


def test_a_corrupt_passphrase_store_fails_closed(workspace, tmp_path):
    link = _invite(workspace)
    assert _accept(_remote(), link).status_code == 303
    store = tmp_path / "dashboard-passphrases.json"
    store.write_text("not json", encoding="utf-8")
    response = _sign_in(_remote())
    assert response.status_code == 503
    # Nothing is reset or overwritten: the file is left for an administrator.
    assert store.read_text(encoding="utf-8") == "not json"


def test_with_sso_the_invitation_signs_in_with_the_company_account_and_asks_no_passphrase(
        workspace, monkeypatch, tmp_path):
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import invite_routes, invites, rbac

    link = _invite(workspace, email="sso.person@example.test")
    monkeypatch.setattr("maverick.oidc.login_enabled", lambda: True)
    assert not invites.local_login_mode()
    page = _remote().get(link)
    assert page.status_code == 200
    assert "company account" in page.text and 'name="password"' not in page.text
    assert "no Lightwork passphrase" in page.text
    signed_in = VerifiedPrincipal(
        sub="sso.person@example.test", issuer="oidc-session", audience="",
        claims={"idp_email": "sso.person@example.test"},
    )
    monkeypatch.setattr(invite_routes, "_session_principal", lambda request: signed_in)
    accepted = _remote().post(link)
    assert accepted.status_code == 303, accepted.text
    assert rbac.get_stored_role("user:sso.person@example.test") == "operator"
    assert not (tmp_path / "dashboard-passphrases.json").exists()


def test_parallel_wrong_guesses_get_at_most_five_checks_before_the_lock(workspace, monkeypatch, tmp_path):
    """The slow hash runs outside the store lock, and each attempt is reserved
    first, so guesses racing in parallel still stop at five per lock window."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from fastapi import HTTPException
    from maverick_dashboard import local_owner, local_passphrases
    from starlette.requests import Request

    assert _accept(_remote(), _invite(workspace)).status_code == 303
    salt = json.loads((tmp_path / "dashboard-passphrases.json").read_text())["accounts"][COLLEAGUE]["salt"]
    real, checks, under_lock = local_owner._password, [], []

    def slow_hash(password, value):
        # No sign-in holds the store lock while it hashes, so one slow guess
        # never queues every other sign-in (and its server thread) behind it.
        under_lock.append(local_passphrases._LOCK._is_owned())
        if value == salt:
            checks.append(value)
            time.sleep(0.2)  # the guesses overlap while each one hashes
        return real(password, value)

    monkeypatch.setattr(local_owner, "_password", slow_hash)
    request = Request({"type": "http", "method": "POST", "path": "/auth/local-login",
                       "headers": [], "client": ("192.0.2.40", 50002)})
    start = threading.Barrier(12)

    def guess(_):
        start.wait()
        try:
            local_passphrases.login(request, email=COLLEAGUE, password=OTHER)
        except HTTPException as exc:
            return exc.status_code
        return 200

    with ThreadPoolExecutor(max_workers=12) as pool:
        codes = list(pool.map(guess, range(12)))
    assert len(checks) == 5
    assert sorted(codes) == [401] * 5 + [429] * 7
    with pytest.raises(HTTPException) as locked:  # even the right passphrase waits now
        local_passphrases.login(request, email=COLLEAGUE, password=GOOD)
    assert locked.value.status_code == 429
    assert len(checks) == 5
    with pytest.raises(HTTPException) as unknown:  # an unknown email hashes outside the lock too
        local_passphrases.login(request, email="nobody@example.test", password=OTHER)
    assert unknown.value.status_code == 401
    assert under_lock and not any(under_lock)


def test_the_address_limit_answers_before_any_passphrase_check(workspace, monkeypatch):
    from maverick_dashboard import local_owner
    from maverick_dashboard.app import app

    real, calls = local_owner._password, []
    monkeypatch.setattr(local_owner, "_password", lambda password, salt: calls.append(salt) or real(password, salt))
    browser = _remote()
    for attempt in range(10):
        assert _sign_in(browser, email=f"nobody{attempt}@example.test", password=OTHER).status_code == 401
    assert len(calls) == 10
    limited = _sign_in(browser, email="nobody@example.test", password=OTHER)
    assert limited.status_code == 429
    assert "Too many sign-in attempts. Wait a minute and try again." in limited.text
    assert len(calls) == 10  # refused before any hashing
    neighbour = TestClient(app, base_url=REMOTE, client=("192.0.2.77", 50009),
                           headers={"Origin": REMOTE}, follow_redirects=False)
    assert _sign_in(neighbour, email="nobody@example.test", password=OTHER).status_code == 401


def test_a_correct_sign_in_works_once_the_lock_expires(workspace, monkeypatch):
    from types import SimpleNamespace

    from maverick_dashboard import local_passphrases

    assert _accept(_remote(), _invite(workspace)).status_code == 303
    browser = _remote()
    for _ in range(5):
        assert _sign_in(browser, password=OTHER).status_code == 401
    assert _sign_in(browser, password=GOOD).status_code == 429
    later = time.time() + 61
    monkeypatch.setattr(local_passphrases, "time", SimpleNamespace(time=lambda: later))
    assert _sign_in(browser, password=GOOD).status_code == 303
    # The success clears the count: one more wrong try is not a lockout.
    assert _sign_in(_remote(), password=OTHER).status_code == 401


def test_the_owners_sign_in_on_this_computer_keeps_its_own_lockout(workspace, tmp_path):
    local = workspace
    local.cookies.clear()
    for _ in range(5):
        assert _sign_in(local, email=OWNER, password=OTHER).status_code == 401
    assert _sign_in(local, email=OWNER, password=OWNER_PASS).status_code == 429
    assert not (tmp_path / "dashboard-passphrases.json").exists()


# -- an invitation never takes over an account that can already sign in -------

def _audits(monkeypatch):
    rows = []
    import maverick.audit as audit

    real = audit.audit_event

    def record(kind, **fields):
        rows.append({"kind": kind, **fields})
        return real(kind, **fields)

    monkeypatch.setattr(audit, "audit_event", record)
    return rows


def _passphrase_row(tmp_path, email=COLLEAGUE):
    data = json.loads((tmp_path / "dashboard-passphrases.json").read_text(encoding="utf-8"))
    return dict(data["accounts"][email])


def test_an_invitation_for_an_existing_colleague_is_refused_and_changes_nothing(workspace, tmp_path, monkeypatch):
    from maverick_dashboard import invites

    assert _accept(_remote(), _invite(workspace)).status_code == 303
    before = _passphrase_row(tmp_path)
    pending = len(invites.list_invites())
    audits = _audits(monkeypatch)

    refused = workspace.post("/users/invite", data={"email": COLLEAGUE.upper(), "role": "viewer"})
    assert refused.status_code == 409
    assert "already has a sign-in" in refused.text and "/auth/invite/inv_" not in refused.text
    assert len(invites.list_invites()) == pending
    assert any(row.get("action") == "invite_refused" and row.get("reason") == "existing_local_account"
               for row in audits)
    assert _passphrase_row(tmp_path) == before
    assert _sign_in(_remote(), password=GOOD).status_code == 303


def test_the_owner_cannot_be_invited_to_get_a_remote_passphrase(workspace, tmp_path):
    refused = workspace.post("/users/invite", data={"email": OWNER, "role": "viewer"})
    assert refused.status_code == 409
    assert not (tmp_path / "dashboard-passphrases.json").exists()
    assert _sign_in(_remote(), email=OWNER, password=OTHER).status_code == 401


def test_a_link_issued_before_the_account_existed_cannot_replace_its_passphrase(workspace, tmp_path, monkeypatch):
    """The attack: a second link for the same person, redeemed by whoever holds it."""
    from maverick_dashboard import invites, rbac

    first = _invite(workspace)
    second = _invite(workspace, role="viewer")  # issued while no account existed yet
    assert _accept(_remote(), first).status_code == 303
    before = _passphrase_row(tmp_path)
    audits = _audits(monkeypatch)

    attacker = _remote()
    refused = _accept(attacker, second, OTHER)
    assert refused.status_code == 409
    assert "already has a sign-in" in refused.text
    assert "mvk_session" not in attacker.cookies                         # no session minted
    assert _passphrase_row(tmp_path) == before                           # credential unchanged
    assert invites.peek_invite(second.rsplit("/", 1)[1]) is not None     # link not used up
    assert rbac.get_stored_role("user:" + COLLEAGUE) == "operator"       # role not changed
    assert any(row.get("action") == "invite_acceptance_refused"
               and row.get("reason") == "existing_local_account" for row in audits)
    assert _sign_in(_remote(), password=OTHER).status_code == 401
    assert _sign_in(_remote(), password=GOOD).status_code == 303


def test_new_colleagues_can_still_be_invited(workspace):
    from maverick_dashboard import invites

    assert invites.existing_local_account("new@example.test") is False
    link = _invite(workspace, email="new@example.test")
    newcomer = _remote()
    assert _accept(newcomer, link).status_code == 303
    assert "mvk_session" in newcomer.cookies
    assert invites.existing_local_account("new@example.test") is True


# -- the installation owner resets a forgotten passphrase ----------------------

def _reset(client, email=COLLEAGUE, confirm="reset"):
    return client.post("/users/passphrase-reset", data={"email": email, "confirm": confirm})


def _reset_link(response) -> str:
    assert response.status_code == 200, response.text
    match = re.search(r'id="passphrase-reset-link"[^>]*value="[^"]*(/auth/invite/reset/pwr_[A-Za-z0-9_-]+)"',
                      response.text)
    assert match, response.text[:2000]
    return match[1]


def _later(monkeypatch, seconds=2):
    """Sign-ins after a reset are issued after its revocation epoch (whole seconds)."""
    from maverick_dashboard import oidc_login

    now = int(time.time()) + seconds
    monkeypatch.setattr(oidc_login, "_now", lambda: now)


def _colleague_with_session(owner):
    assert _accept(_remote(), _invite(owner)).status_code == 303
    browser = _remote()
    assert _sign_in(browser).status_code == 303
    assert browser.get("/api/v1/features/modules").status_code == 200
    return browser


def test_the_owner_resets_a_forgotten_passphrase_end_to_end(workspace, tmp_path, monkeypatch):
    from maverick_dashboard import rbac, session_registry

    signed_in = _colleague_with_session(workspace)
    page = workspace.get("/users")
    assert 'action="/users/passphrase-reset"' in page.text and 'data-users-ok="Reset passphrase"' in page.text
    assert f"Reset the passphrase for {COLLEAGUE}?" in page.text
    audits = _audits(monkeypatch)

    reset = _reset(workspace)
    link = _reset_link(reset)
    assert f"Passphrase reset for {COLLEAGUE}." in reset.text
    assert "no-store" in reset.headers["cache-control"]
    store = tmp_path / "dashboard-passphrase-resets.json"
    assert link.rsplit("/", 1)[1] not in store.read_text(encoding="utf-8")  # only a hash is kept
    # The old passphrase and every live session stop working at once.
    assert _sign_in(_remote(), password=GOOD).status_code == 401
    assert signed_in.get("/api/v1/features/modules").status_code == 401
    assert session_registry.list_for("user:" + COLLEAGUE) == []
    assert rbac.get_stored_role("user:" + COLLEAGUE) == "operator"  # access is not changed
    issued = [row for row in audits if row.get("action") == "passphrase_reset_issued"]
    assert len(issued) == 1
    assert issued[0]["actor"] == "user:" + OWNER and issued[0]["principal"] == "user:" + COLLEAGUE

    browser = _remote()
    opened = browser.get(link)
    assert opened.status_code == 200
    text = re.sub(r"\s+", " ", opened.text)
    assert f"reset by the installation owner ({OWNER})" in text
    assert re.search(r'<input[^>]*name="password"[^>]*autocomplete="new-password"', opened.text)
    done = _accept(browser, link, OTHER)
    assert done.status_code == 200, done.text
    assert "New passphrase saved" in done.text
    assert "mvk_session" not in browser.cookies  # the link signs no one in
    assert any(row.get("action") == "passphrase_reset_completed" and row.get("reset_by") == "user:" + OWNER
               for row in audits)
    assert _passphrase_row(tmp_path)["tenant"] == ""

    _later(monkeypatch)
    assert _sign_in(_remote(), password=GOOD).status_code == 401
    returned = _remote()
    assert _sign_in(returned, password=OTHER).status_code == 303
    assert returned.get("/api/v1/features/modules").status_code == 200
    assert rbac.get_stored_role("user:" + COLLEAGUE) == "operator"


def test_a_reset_link_works_once(workspace, tmp_path):
    assert _accept(_remote(), _invite(workspace)).status_code == 303
    link = _reset_link(_reset(workspace))
    assert _accept(_remote(), link, OTHER).status_code == 200
    saved = _passphrase_row(tmp_path)
    again = _accept(_remote(), link, GOOD + " again")
    assert again.status_code == 410
    assert "invalid, expired or already used" in again.text
    assert _remote().get(link).status_code == 410
    assert _passphrase_row(tmp_path) == saved


def test_an_expired_reset_link_is_refused_and_the_owner_can_reset_again(workspace, tmp_path, monkeypatch):
    from types import SimpleNamespace

    from maverick_dashboard import passphrase_resets

    assert _accept(_remote(), _invite(workspace)).status_code == 303
    link = _reset_link(_reset(workspace))
    later = time.time() + passphrase_resets.RESET_TTL_SECONDS + 1
    monkeypatch.setattr(passphrase_resets, "time", SimpleNamespace(time=lambda: later))
    assert _remote().get(link).status_code == 410
    assert _accept(_remote(), link, OTHER).status_code == 410
    accounts = json.loads((tmp_path / "dashboard-passphrases.json").read_text(encoding="utf-8"))["accounts"]
    assert COLLEAGUE not in accounts
    # The person is still listed, so the owner can send a new link.
    page = re.sub(r"\s+", " ", workspace.get("/users").text)
    assert "Waiting to choose a passphrase" in page
    fresh = _reset_link(_reset(workspace))
    assert _accept(_remote(), fresh, OTHER).status_code == 200
    assert _accept(_remote(), link, GOOD).status_code == 410  # the old link stays dead


@pytest.mark.parametrize("change", ["role", "workspace", "departments"])
def test_a_reset_link_is_refused_after_the_account_changes(workspace, tmp_path, monkeypatch, change):
    from maverick.tenant import registry
    from maverick_dashboard import rbac, suite_grants

    assert _accept(_remote(), _invite(workspace)).status_code == 303
    link = _reset_link(_reset(workspace))
    audits = _audits(monkeypatch)
    principal = "user:" + COLLEAGUE
    if change == "role":
        rbac.set_role(principal, "admin")
    elif change == "workspace":
        registry.create_tenant("client-a")
        rbac.set_tenant_role("client-a", principal, "admin")
    else:
        suite_grants.set_suites(principal, [sorted(suite_grants.known_suites())[0]])
    refused = _accept(_remote(), link, OTHER)
    assert refused.status_code == 409
    assert "changed after the reset" in refused.text and "no passphrase was saved" in refused.text
    accounts = json.loads((tmp_path / "dashboard-passphrases.json").read_text(encoding="utf-8"))["accounts"]
    assert COLLEAGUE not in accounts  # no passphrase was saved
    assert any(row.get("action") == "passphrase_reset_refused" and row.get("reason") == "account_changed"
               for row in audits)
    # The link is used up: changing the access back does not revive it.
    if change == "role":
        rbac.set_role(principal, "operator")
    elif change == "workspace":
        rbac.remove_tenant_role("client-a", principal)
    assert _accept(_remote(), link, OTHER).status_code == 410


def test_a_reset_the_activity_log_refuses_changes_nothing(workspace, tmp_path, monkeypatch):
    import maverick.audit as audit
    from maverick.audit import AuditRefused
    from maverick_dashboard import passphrase_resets

    signed_in = _colleague_with_session(workspace)
    before = _passphrase_row(tmp_path)
    real = audit.audit_event

    def refuse(kind, **fields):
        if fields.get("action") == "passphrase_reset_issued":
            raise AuditRefused("custody unavailable")
        return real(kind, **fields)

    monkeypatch.setattr(audit, "audit_event", refuse)
    refused = _reset(workspace)
    assert refused.status_code == 503 and "activity log refused" in refused.text
    # The refusal is true: the person is not locked out and no link exists.
    assert _passphrase_row(tmp_path) == before
    assert not (tmp_path / "dashboard-passphrase-resets.json").exists()
    assert not passphrase_resets.pending_for(COLLEAGUE)
    assert signed_in.get("/api/v1/features/modules").status_code == 200
    assert _sign_in(_remote(), password=GOOD).status_code == 303

    monkeypatch.setattr(audit, "audit_event", real)         # the log recovers
    assert _reset_link(_reset(workspace))
    assert _sign_in(_remote(), password=GOOD).status_code == 401


# -- authority the identity provider's groups confer is part of the account ----

_SCIM_TOKEN = "scim-secret-token-xyz"  # pragma: allowlist secret


def _idp(monkeypatch, *, roles=None, suites=None):
    """The identity provider as its own caller (no browser session), with a
    group -> role / department mapping."""
    from maverick_dashboard import scim_groups
    from maverick_dashboard.app import app

    monkeypatch.setenv("MAVERICK_SCIM_TOKEN", _SCIM_TOKEN)
    tables = {"group_roles": roles or {}, "group_suites": suites or {}}
    monkeypatch.setattr(scim_groups, "_config_table", lambda key: tables.get(key, {}))
    idp = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    headers = {"Authorization": f"Bearer {_SCIM_TOKEN}"}

    def push(email, group):
        user = idp.post("/scim/v2/Users", headers=headers, json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": email,
            "externalId": email, "emails": [{"value": email, "primary": True}], "active": True})
        assert user.status_code == 201, user.text
        made = idp.post("/scim/v2/Groups", headers=headers, json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": group,
            "members": [{"value": user.json()["id"]}]})
        assert made.status_code == 201, made.text

    return push


def _workspace_member_only(owner):
    """Sam signs in with a passphrase and holds a workspace membership, no installation role."""
    from maverick.tenant import registry
    from maverick_dashboard import auth, rbac

    assert _accept(_remote(), _invite(owner)).status_code == 303
    principal = "user:" + COLLEAGUE
    registry.create_tenant("acme")
    rbac.set_tenant_role("acme", principal, "viewer")
    rbac.remove_user(principal)
    assert auth.global_role_for_principal(principal) is None
    return principal


def test_a_reset_link_is_refused_after_the_idp_gives_the_person_a_group_role(workspace, tmp_path, monkeypatch):
    from maverick_dashboard import auth

    principal = _workspace_member_only(workspace)
    link = _reset_link(_reset(workspace))
    audits = _audits(monkeypatch)
    _idp(monkeypatch, roles={"Admins": "admin"})(COLLEAGUE, "Admins")   # the IdP promotes them
    assert auth.global_role_for_principal(principal) == "admin"

    refused = _accept(_remote(), link, OTHER)
    assert refused.status_code == 409
    assert "changed after the reset" in refused.text and "no passphrase was saved" in refused.text
    accounts = json.loads((tmp_path / "dashboard-passphrases.json").read_text(encoding="utf-8"))["accounts"]
    assert COLLEAGUE not in accounts
    assert any(row.get("action") == "passphrase_reset_refused" and row.get("reason") == "account_changed"
               for row in audits)
    assert _accept(_remote(), link, OTHER).status_code == 410            # used up


def test_a_reset_link_is_refused_after_the_idp_gives_the_person_group_departments(workspace, tmp_path, monkeypatch):
    from maverick_dashboard import suite_grants

    _workspace_member_only(workspace)
    link = _reset_link(_reset(workspace))
    suite = sorted(suite_grants.known_suites())[0]
    _idp(monkeypatch, suites={"Finance": [suite]})(COLLEAGUE, "Finance")
    assert suite_grants.granted_suites("user:" + COLLEAGUE) == frozenset({suite})

    assert _accept(_remote(), link, OTHER).status_code == 409
    accounts = json.loads((tmp_path / "dashboard-passphrases.json").read_text(encoding="utf-8"))["accounts"]
    assert COLLEAGUE not in accounts


def test_a_reset_link_still_works_when_the_idp_changes_someone_else(workspace, tmp_path, monkeypatch):
    _workspace_member_only(workspace)
    link = _reset_link(_reset(workspace))
    _idp(monkeypatch, roles={"Admins": "admin"})("someone.else@example.test", "Admins")
    assert _accept(_remote(), link, OTHER).status_code == 200
    accounts = json.loads((tmp_path / "dashboard-passphrases.json").read_text(encoding="utf-8"))["accounts"]
    assert COLLEAGUE in accounts


def test_the_owner_cannot_be_reset_this_way(workspace, tmp_path):
    refused = _reset(workspace, email=OWNER)
    assert refused.status_code == 403
    assert "installation owner's passphrase cannot be reset" in refused.text
    assert not (tmp_path / "dashboard-passphrase-resets.json").exists()
    local = workspace
    local.cookies.clear()
    assert _sign_in(local, email=OWNER, password=OWNER_PASS).status_code == 303


def test_an_admin_role_holder_who_is_not_the_owner_cannot_reset(workspace, tmp_path):
    assert _accept(_remote(), _invite(workspace)).status_code == 303
    assert _accept(_remote(), _invite(workspace, email="boss@example.test", role="admin")).status_code == 303
    boss = _remote()
    assert _sign_in(boss, email="boss@example.test").status_code == 303
    page = boss.get("/users")
    assert page.status_code == 200 and 'action="/users/passphrase-reset"' not in page.text
    before = _passphrase_row(tmp_path)
    refused = _reset(boss)
    assert refused.status_code == 403
    assert _passphrase_row(tmp_path) == before
    assert not (tmp_path / "dashboard-passphrase-resets.json").exists()


def test_an_installation_administrator_who_is_not_the_owner_cannot_reset(workspace, tmp_path, monkeypatch):
    """Only the owner resets. Being named in configuration is not enough: the list
    is editable in Settings by anyone holding the Admin role."""
    assert _accept(_remote(), _invite(workspace)).status_code == 303
    assert _accept(_remote(), _invite(workspace, email="ia@example.test", role="admin")).status_code == 303
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:ia@example.test")
    installer = _remote()
    assert _sign_in(installer, email="ia@example.test").status_code == 303
    assert 'action="/users/passphrase-reset"' not in installer.get("/users").text
    before = _passphrase_row(tmp_path)
    refused = _reset(installer)
    assert refused.status_code == 403
    assert _passphrase_row(tmp_path) == before
    assert not (tmp_path / "dashboard-passphrase-resets.json").exists()
    # The owner may reset a colleague and an installation administrator alike.
    opened = re.sub(r"\s+", " ", _remote().get(_reset_link(_reset(workspace))).text)
    assert "reset by the installation owner (" + OWNER in opened
    assert _reset_link(_reset(workspace, email="ia@example.test"))


def test_an_admin_role_holder_cannot_make_themselves_an_administrator_to_reset(workspace, tmp_path):
    """An Admin-role holder can save [dashboard] admins, but that must not give
    them the power to choose a colleague's next passphrase."""
    from test_support.settings_pages import save_catalog

    assert _accept(_remote(), _invite(workspace)).status_code == 303
    assert _accept(_remote(), _invite(workspace, email="boss@example.test", role="admin")).status_code == 303
    boss = _remote()
    assert _sign_in(boss, email="boss@example.test").status_code == 303
    assert _reset(boss).status_code == 403
    saved = save_catalog(boss, "/api/v1/settings/catalog", json={"changes": [
        {"id": "dashboard.admins", "value": ["user:boss@example.test"]}], "confirm": True})
    assert saved.status_code == 200, saved.text
    before = _passphrase_row(tmp_path)
    assert _reset(boss).status_code == 403
    assert 'action="/users/passphrase-reset"' not in boss.get("/users").text
    assert _passphrase_row(tmp_path) == before
    # So the refusal an invitation shows must not send people to an administrator for a link.
    from maverick_dashboard import local_passphrases
    assert "administrator can send" not in local_passphrases.ACCOUNT_EXISTS
    assert not (tmp_path / "dashboard-passphrase-resets.json").exists()
    assert _sign_in(_remote(), password=GOOD).status_code == 303  # the colleague is untouched


def test_an_over_long_email_is_refused_and_cannot_make_the_invite_store_unreadable(workspace):
    from maverick_dashboard import invites

    refused = workspace.post("/users/invite", data={"email": "a" * 400 + "@example.test", "role": "viewer"})
    assert 400 <= refused.status_code < 500, refused.text
    assert invites.list_invites() == []
    assert workspace.post("/users/invite", data={"email": "fine@example.test", "role": "viewer"}).status_code == 200


def test_a_reset_needs_confirmation_this_site_and_a_recent_second_factor(workspace, tmp_path, monkeypatch):
    from maverick_dashboard import step_up
    from maverick_dashboard.app import app

    assert _accept(_remote(), _invite(workspace)).status_code == 303
    before = _passphrase_row(tmp_path)
    assert _reset(workspace, confirm="").status_code == 422
    hostile = TestClient(app, base_url=LOCAL, client=("127.0.0.1", 50001),
                         headers={"Origin": "https://attacker.example"}, follow_redirects=False)
    hostile.cookies.update(workspace.cookies)
    assert _reset(hostile).status_code == 403
    monkeypatch.setattr(step_up, "applies", lambda request: True)
    stepped = _reset(workspace)
    assert stepped.status_code == 403
    assert step_up.STEP_UP_MESSAGE in stepped.text
    assert _passphrase_row(tmp_path) == before
    assert _sign_in(_remote(), password=GOOD).status_code == 303


def test_a_reset_link_only_saves_from_its_own_page(workspace, tmp_path):
    assert _accept(_remote(), _invite(workspace)).status_code == 303
    link = _reset_link(_reset(workspace))
    from maverick_dashboard.app import app

    for headers in ({}, {"Origin": "https://attacker.example"}):
        hostile = TestClient(app, base_url=REMOTE, client=("192.0.2.41", 50003),
                             headers=headers, follow_redirects=False)
        assert _accept(hostile, link, OTHER).status_code == 400
    assert _accept(_remote(), link, OTHER).status_code == 200  # still usable from its page


def test_a_person_waiting_for_a_new_passphrase_cannot_be_invited(workspace):
    from maverick_dashboard import invites, rbac

    assert _accept(_remote(), _invite(workspace)).status_code == 303
    _reset_link(_reset(workspace))
    rbac.remove_user("user:" + COLLEAGUE)
    assert invites.existing_local_account(COLLEAGUE) is True
    assert workspace.post("/users/invite", data={"email": COLLEAGUE, "role": "viewer"}).status_code == 409


# -- a person with access but no passphrase gets a first link ------------------
#
# An invitation never replaces what already exists, so a role assigned on the
# Users page, a workspace membership or a place in [dashboard] admins can be
# neither invited nor reset. The owner and installation administrators give them
# a first link by the same route, with the same checks.

PRE = "preassigned@example.test"


def test_a_role_holder_with_no_passphrase_gets_a_first_link_from_the_owner(workspace, tmp_path, monkeypatch):
    from maverick_dashboard import rbac

    rbac.set_role("user:" + PRE, "operator")
    assert workspace.post("/users/invite", data={"email": PRE, "role": "viewer"}).status_code == 409
    page = re.sub(r"\s+", " ", workspace.get("/users").text)
    assert PRE in page and "Has access but no passphrase yet" in page
    assert f"Create a sign-in link for {PRE}?" in page and 'data-users-ok="Create link"' in page
    audits = _audits(monkeypatch)

    made = _reset(workspace, email=PRE)
    link = _reset_link(made)
    text = re.sub(r"\s+", " ", made.text)
    assert f"Sign-in link for {PRE}" in text and "They have access but no passphrase yet" in text
    issued = [row for row in audits if row.get("action") == "passphrase_reset_issued"]
    assert len(issued) == 1 and issued[0]["email"] == PRE
    assert issued[0]["passphrase_removed"] is False and issued[0]["first_passphrase"] is True

    opened = re.sub(r"\s+", " ", _remote().get(link).text)
    assert "Choose a passphrase" in opened and "so you can choose a passphrase" in opened
    assert "was reset" not in opened and "old passphrase" not in opened
    assert _accept(_remote(), link, GOOD).status_code == 200
    assert rbac.get_stored_role("user:" + PRE) == "operator"               # access is unchanged
    _later(monkeypatch)                                                    # after the link's revocation epoch
    browser = _remote()
    assert _sign_in(browser, email=PRE).status_code == 303
    assert browser.get("/api/v1/features/modules").status_code == 200
    assert _accept(_remote(), link, OTHER).status_code == 410              # works once
    assert any(row.get("action") == "passphrase_reset_completed" and row.get("email") == PRE for row in audits)
    after = re.sub(r"\s+", " ", workspace.get("/users").text)
    assert f"Reset the passphrase for {PRE}?" in after                      # now an ordinary account
    assert f"Create a sign-in link for {PRE}?" not in after


def test_a_workspace_member_with_no_passphrase_signs_in_after_a_first_link(workspace, tmp_path):
    from maverick.tenant import registry
    from maverick_dashboard import rbac

    registry.create_tenant("acme")
    rbac.set_tenant_role("acme", "user:member@example.test", "viewer")
    link = _reset_link(_reset(workspace, email="member@example.test"))
    assert _accept(_remote(), link, GOOD).status_code == 200
    assert _passphrase_row(tmp_path, "member@example.test")["tenant"] == "acme"
    assert rbac.get_stored_role("user:member@example.test") is None
    assert _sign_in(_remote(), email="member@example.test").status_code == 303


def test_a_configured_admin_with_no_passphrase_gets_a_first_link_only_from_the_owner(
        workspace, tmp_path, monkeypatch):
    assert _accept(_remote(), _invite(workspace, email="ia@example.test", role="admin")).status_code == 303
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:ia@example.test,user:cto@example.test")
    installer = _remote()
    assert _sign_in(installer, email="ia@example.test").status_code == 303
    page = installer.get("/users").text
    assert 'name="email" value="cto@example.test"' not in page
    refused = _reset(installer, email="cto@example.test")
    assert refused.status_code == 403
    assert not (tmp_path / "dashboard-passphrase-resets.json").exists()

    link = _reset_link(_reset(workspace, email="cto@example.test"))
    assert _accept(_remote(), link, GOOD).status_code == 200
    assert _sign_in(_remote(), email="cto@example.test").status_code == 303


def test_a_person_with_no_access_and_no_passphrase_gets_nothing(workspace, tmp_path):
    for email in ("stranger@example.test", "not-an-email", ""):
        refused = _reset(workspace, email=email)
        assert refused.status_code in (404, 422), refused.text
    refused = _reset(workspace, email="stranger@example.test")
    assert refused.status_code == 404 and "no passphrase and no access" in refused.text
    assert not (tmp_path / "dashboard-passphrase-resets.json").exists()
    assert not (tmp_path / "dashboard-passphrases.json").exists()


def test_a_first_link_needs_the_same_authority_confirmation_and_second_factor(workspace, tmp_path, monkeypatch):
    from maverick_dashboard import rbac, step_up

    rbac.set_role("user:" + PRE, "operator")
    assert _accept(_remote(), _invite(workspace, email="boss@example.test", role="admin")).status_code == 303
    boss = _remote()
    assert _sign_in(boss, email="boss@example.test").status_code == 303
    assert _reset(boss, email=PRE).status_code == 403                      # an Admin-role holder is not enough
    assert _reset(workspace, email=PRE, confirm="").status_code == 422
    monkeypatch.setattr(step_up, "applies", lambda request: True)
    stepped = _reset(workspace, email=PRE)
    assert stepped.status_code == 403 and step_up.STEP_UP_MESSAGE in stepped.text
    assert not (tmp_path / "dashboard-passphrase-resets.json").exists()


def test_a_first_link_is_refused_after_the_account_changes(workspace, tmp_path):
    from maverick_dashboard import rbac

    rbac.set_role("user:" + PRE, "operator")
    link = _reset_link(_reset(workspace, email=PRE))
    rbac.set_role("user:" + PRE, "admin")
    refused = _accept(_remote(), link, GOOD)
    assert refused.status_code == 409 and "changed after the reset" in refused.text
    assert not (tmp_path / "dashboard-passphrases.json").exists()


def test_a_first_link_that_expired_can_be_replaced(workspace, tmp_path, monkeypatch):
    from types import SimpleNamespace

    from maverick_dashboard import passphrase_resets, rbac

    rbac.set_role("user:" + PRE, "operator")
    link = _reset_link(_reset(workspace, email=PRE))
    later = time.time() + passphrase_resets.RESET_TTL_SECONDS + 1
    monkeypatch.setattr(passphrase_resets, "time", SimpleNamespace(time=lambda: later))
    assert _accept(_remote(), link, GOOD).status_code == 410
    page = re.sub(r"\s+", " ", workspace.get("/users").text)
    assert "Waiting to choose a passphrase" in page
    again = _reset(workspace, email=PRE)
    fresh = _reset_link(again)
    assert "Sign-in link for" in again.text                                 # still a first link
    assert _accept(_remote(), fresh, GOOD).status_code == 200
    assert _sign_in(_remote(), email=PRE).status_code == 303


def test_the_pages_that_followed_a_failed_acceptance_no_longer_ask_for_a_replacement_invitation(
        workspace, monkeypatch):
    """The passphrase is already saved when the access save fails, and a
    replacement invitation for that email is refused, so the copy must not send
    people to one."""
    from maverick_dashboard import invite_routes

    def broken(principal, inv):
        raise RuntimeError("the role list could not be saved")

    monkeypatch.setattr(invite_routes, "_bind_role", broken)
    page = _accept(_remote(), _invite(workspace))
    assert page.status_code == 503
    text = re.sub(r"\s+", " ", page.text)
    assert "Users page" in text and "passphrase you chose" in text
    assert "new invitation link" not in text and "replacement invitation" not in text


def test_an_unknown_email_is_locked_after_five_tries_exactly_like_a_real_account(workspace):
    """If only real accounts ever answered 429, six wrong tries would reveal
    which emails have an account."""
    assert _accept(_remote(), _invite(workspace)).status_code == 303
    browser = _remote()
    for _ in range(5):
        assert _sign_in(browser, email="nobody@example.test", password=OTHER).status_code == 401
    assert _sign_in(browser, email="nobody@example.test", password=OTHER).status_code == 429
    assert _sign_in(browser, email="someone.else@example.test", password=OTHER).status_code == 401
    from maverick_dashboard import local_passphrases
    local_passphrases._ATTEMPTS.reset()                                     # the per-address window is a separate limit
    for _ in range(5):
        assert _sign_in(browser, password=OTHER).status_code == 401
    assert _sign_in(browser, password=OTHER).status_code == 429             # the real account answers the same way


def test_a_workspace_name_at_the_longest_allowed_length_still_lets_everyone_sign_in(workspace, tmp_path):
    from maverick.paths import MAX_TENANT_SEGMENT_LENGTH
    from maverick_dashboard import local_passphrases
    prepared = local_passphrases.prepare(COLLEAGUE, GOOD)
    local_passphrases.store(prepared, tenant="w" * MAX_TENANT_SEGMENT_LENGTH)
    assert local_passphrases.has_account(COLLEAGUE) is True                  # the store reads back what it wrote
    other = local_passphrases.prepare("pat@example.test", GOOD)
    with pytest.raises(Exception) as refused:
        local_passphrases.store(other, tenant="w" * (MAX_TENANT_SEGMENT_LENGTH + 1))
    assert getattr(refused.value, "status_code", None) == 422
    assert local_passphrases.has_account("pat@example.test") is False
    assert local_passphrases.has_account(COLLEAGUE) is True                  # the refusal left the store readable


def test_a_reset_record_for_a_long_workspace_id_reads_back():
    # A reset copies its workspace id from a passphrase row or a membership,
    # which allow MAX_TENANT_SEGMENT_LENGTH; the reset store must read back
    # what it wrote, or every later reset and invitation check fails.
    from maverick.paths import MAX_TENANT_SEGMENT_LENGTH
    from maverick_dashboard import passphrase_resets

    row = {"email": "ana@corp.example", "tenant": "w" * MAX_TENANT_SEGMENT_LENGTH, "binding": "b" * 64,
           "created_by": "user:owner@corp.example", "created_at": 1.0, "expires_at": 2.0,
           "used_at": None, "outcome": "", "first": True}
    assert passphrase_resets._valid("a" * 64, row)
    assert not passphrase_resets._valid("a" * 64, {**row, "tenant": "w" * (MAX_TENANT_SEGMENT_LENGTH + 1)})
