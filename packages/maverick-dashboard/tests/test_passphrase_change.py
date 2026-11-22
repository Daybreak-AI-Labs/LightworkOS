"""People who sign in with a passphrase can change it themselves.

Before, a signed-in person could not change their own passphrase: only the
installation owner could reset a colleague's, and nobody could change the
owner's. ``/account/passphrase`` checks the current passphrase with the same
rules, hashing and lockout as sign-in (and the owner's authenticator code when
the owner has one), saves the new one, ends every other browser session and
keeps this browser signed in.
"""
from __future__ import annotations

import json
import os
import re

import pytest
from fastapi.testclient import TestClient

LOCAL = "http://127.0.0.1:8765"
REMOTE = "https://lightwork.example"
OWNER = "owner@example.test"
OWNER_PASS = "Synthetic owner passphrase for changes"  # pragma: allowlist secret
COLLEAGUE = "sam@example.test"
GOOD = "harbor violet tram ledger"  # pragma: allowlist secret - synthetic fixture passphrase
NEW = "copper lantern meadow quartz"  # pragma: allowlist secret - synthetic fixture passphrase
PAGE = "/account/passphrase"


@pytest.fixture
def workspace(monkeypatch, tmp_path):
    from maverick import client as client_binding
    from maverick import config, world_model

    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    config_path = tmp_path / "config.toml"
    config_path.write_text('[client]\nid="passphrase-change"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    client_binding.reset_client_cache()
    from maverick_dashboard import local_passphrases
    from maverick_dashboard.app import app

    local_passphrases.reset_attempt_limit()
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


def _remote(port=50002):
    from maverick_dashboard.app import app

    return TestClient(app, base_url=REMOTE, client=("192.0.2.40", port),
                      headers={"Origin": REMOTE}, follow_redirects=False)


def _colleague(owner):
    made = owner.post("/users/invite", data={"email": COLLEAGUE, "role": "operator"})
    assert made.status_code == 200, made.text
    link = re.search(r"/auth/invite/(inv_[A-Za-z0-9_-]+)", made.text)[0]
    browser = _remote()
    assert browser.post(link, data={"password": GOOD, "password2": GOOD}).status_code == 303
    return browser


def _sign_in(browser, email=COLLEAGUE, password=GOOD):
    return browser.post("/auth/local-login", data={"email": email, "password": password})


def _change(browser, current=GOOD, new=NEW, again=None, code=None):
    data = {"current": current, "password": new, "password2": new if again is None else again}
    if code is not None:
        data["code"] = code
    return browser.post(PAGE, data=data)


def _audits(monkeypatch):
    rows = []
    import maverick.audit as audit

    real = audit.audit_event

    def record(kind, **fields):
        rows.append({"kind": kind, **fields})
        return real(kind, **fields)

    monkeypatch.setattr(audit, "audit_event", record)
    return rows


def _later(monkeypatch, seconds=2):
    import time

    from maverick_dashboard import oidc_login
    now = int(time.time()) + seconds
    monkeypatch.setattr(oidc_login, "_now", lambda: now)


def test_the_page_asks_for_the_current_and_new_passphrase(workspace):
    browser = _colleague(workspace)
    page = browser.get(PAGE)
    assert page.status_code == 200, page.text
    html = page.text
    assert re.search(r'<input[^>]*name="current"[^>]*autocomplete="current-password"', html)
    assert re.search(r'<input[^>]*name="password"[^>]*autocomplete="new-password"', html)
    assert re.search(r'<input[^>]*name="password2"', html)
    assert "no-store" in page.headers["cache-control"]
    # The account page offers it to people who sign in with a passphrase.
    assert f'href="{PAGE}"' in browser.get("/account").text


def test_a_colleague_changes_their_passphrase_and_other_browsers_sign_out(workspace, tmp_path, monkeypatch):
    browser = _colleague(workspace)
    elsewhere = _remote(port=50003)
    assert _sign_in(elsewhere).status_code == 303
    assert elsewhere.get("/api/v1/features/modules").status_code == 200
    audits = _audits(monkeypatch)
    _later(monkeypatch)

    changed = _change(browser)
    assert changed.status_code == 303, changed.text
    assert changed.headers["location"] == PAGE + "?changed=1"
    assert "mvk_session" in changed.cookies
    assert "no-store" in changed.headers["cache-control"]
    # This browser stays signed in; the other one is signed out.
    assert browser.get("/api/v1/features/modules").status_code == 200
    assert elsewhere.get("/api/v1/features/modules").status_code == 401
    done = browser.get(PAGE + "?changed=1")
    assert "Your passphrase was changed" in done.text
    # Only the new passphrase signs in; neither is stored in the clear.
    store = (tmp_path / "dashboard-passphrases.json").read_text(encoding="utf-8")
    assert GOOD not in store and NEW not in store
    assert _sign_in(_remote(port=50004)).status_code == 401
    assert _sign_in(_remote(port=50005), password=NEW).status_code == 303
    rows = [row for row in audits if row.get("action") == "passphrase_changed"]
    assert len(rows) == 1 and rows[0]["principal"] == "user:" + COLLEAGUE
    assert GOOD not in json.dumps(rows) and NEW not in json.dumps(rows)


@pytest.mark.parametrize("fields, status, words", [
    ({"current": "not the passphrase at all"}, 401, "current passphrase was not accepted"),
    ({"again": "a different confirmation phrase"}, 422, "do not match"),
    ({"new": "too short", "again": "too short"}, 422, "14"),
    ({"new": GOOD, "again": GOOD}, 422, "different"),
])
def test_a_refused_change_keeps_the_old_passphrase(workspace, tmp_path, fields, status, words):
    browser = _colleague(workspace)
    before = (tmp_path / "dashboard-passphrases.json").read_text(encoding="utf-8")
    refused = _change(browser, **fields)
    assert refused.status_code == status, refused.text
    assert words in refused.text
    after = json.loads((tmp_path / "dashboard-passphrases.json").read_text(encoding="utf-8"))
    assert after["accounts"][COLLEAGUE]["password_hash"] == json.loads(before)["accounts"][COLLEAGUE]["password_hash"]
    assert browser.get("/api/v1/features/modules").status_code == 200


def test_wrong_current_passphrases_lock_like_sign_in(workspace):
    browser = _colleague(workspace)
    for _ in range(5):
        assert _change(browser, current="wrong but long enough phrase").status_code == 401
    locked = _change(browser)
    assert locked.status_code == 429 and locked.headers.get("retry-after") == "60"


def test_a_change_from_another_site_is_refused(workspace):
    browser = _colleague(workspace)
    refused = browser.post(PAGE, data={"current": GOOD, "password": NEW, "password2": NEW},
                           headers={"Origin": "https://evil.example"})
    assert refused.status_code == 403


def test_the_owner_changes_their_passphrase_on_this_computer(workspace, monkeypatch):
    _later(monkeypatch)
    changed = _change(workspace, current=OWNER_PASS)
    assert changed.status_code == 303, changed.text
    assert workspace.get("/api/v1/features/modules").status_code == 200
    from maverick_dashboard.app import app

    fresh = TestClient(app, base_url=LOCAL, client=("127.0.0.1", 50009),
                       headers={"Origin": LOCAL}, follow_redirects=False)
    assert _sign_in(fresh, email=OWNER, password=OWNER_PASS).status_code == 401
    assert _sign_in(fresh, email=OWNER, password=NEW).status_code == 303


def test_copilot_explains_the_change_and_only_opens_the_page():
    from maverick_dashboard import copilot_tasks

    task = copilot_tasks.match("/account", "how do I change my password")
    assert task is not None and task.href == PAGE
    reply = copilot_tasks.reply(task)
    assert "Nothing was changed" in reply["warning"]


def _workspace_selected(monkeypatch, tenant="tenant-a"):
    """Bind every signed-in request to a selected workspace, as a real installation does."""
    from maverick.tenant import registry
    from maverick_dashboard import auth, workspace_tenants

    # No fixed client floor from here on: the person's own selection decides.
    monkeypatch.setattr("maverick.client.client_id", lambda *a, **k: None)
    monkeypatch.setattr("maverick.paths.tenant_by_user_enabled", lambda: False)
    monkeypatch.setattr(workspace_tenants, "get_selection", lambda name: tenant)
    monkeypatch.setattr(workspace_tenants, "principal_can_select", lambda name, chosen: True)
    monkeypatch.setattr(registry, "is_active", lambda chosen: True)
    monkeypatch.setattr(auth, "_enforce_workspace_policies", lambda *_args: None)


def test_with_a_workspace_selected_the_form_names_it_and_the_change_works(workspace, monkeypatch):
    # A selected workspace is the normal state after setup. The form must send
    # the workspace it was rendered under, or the stale-tab check refuses it.
    browser = _colleague(workspace)
    _workspace_selected(monkeypatch)
    page = browser.get(PAGE)
    visible = " ".join(re.sub(r"<[^>]+>", " ", page.text.split("<body", 1)[-1]).split())
    assert re.search(r'<input type="hidden" name="_expected_tenant" value="tenant-a">', page.text), visible[:600]
    stale = browser.post(PAGE, data={"current": GOOD, "password": NEW, "password2": NEW})
    assert stale.status_code == 409  # without the field: refused, nothing changed
    changed = browser.post(PAGE, data={"current": GOOD, "password": NEW, "password2": NEW,
                                       "_expected_tenant": "tenant-a"})
    assert changed.status_code == 303, changed.text


def test_with_a_workspace_selected_the_owner_authenticator_form_reaches_its_route(workspace, monkeypatch):
    # The authenticator page had the same gap: every form was refused as stale.
    _workspace_selected(monkeypatch)
    page = workspace.get("/account/owner-authenticator")
    assert page.status_code == 200, page.text
    assert 'name="_expected_tenant" value="tenant-a"' in page.text
    refused = workspace.post("/account/owner-authenticator/setup",
                             data={"password": "not the owner passphrase at all", "_expected_tenant": "tenant-a"})  # pragma: allowlist secret - synthetic wrong passphrase
    assert refused.status_code == 401, refused.text  # the passphrase check ran, not the stale-tab refusal


# Pages without the shared page script, whose forms a signed-in person can
# submit and whose handlers accept the workspace field. Each must name the
# workspace its page was rendered under, or the stale-tab check refuses it.
_STANDALONE_SIGNED_IN_FORMS = ("account_passphrase.html", "owner_authenticator.html", "owner_second_factor.html",
                               "auth_logout.html", "unsubscribe.html", "rights_verify.html")


@pytest.mark.parametrize("name", _STANDALONE_SIGNED_IN_FORMS)
def test_standalone_forms_name_their_workspace(name):
    from pathlib import Path

    page = (Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates" / name).read_text(encoding="utf-8")
    assert "lightwork-ui.js" not in page  # otherwise the shared script adds it
    forms = re.findall(r"<form\b[^>]*method=\"post\"[^>]*>.*?</form>", page, re.DOTALL)
    assert forms
    for form in forms:
        assert 'name="_expected_tenant"' in form and "workspace_expected_tenant" in form, form[:200]


def test_signing_out_works_with_a_workspace_selected(workspace, monkeypatch):
    browser = _colleague(workspace)
    _workspace_selected(monkeypatch)
    page = browser.get("/auth/logout")
    assert 'name="_expected_tenant" value="tenant-a"' in page.text
    out = browser.post("/auth/logout", data={"_expected_tenant": "tenant-a"})
    assert out.status_code == 303, out.text
    assert browser.get("/api/v1/features/modules").status_code == 401
