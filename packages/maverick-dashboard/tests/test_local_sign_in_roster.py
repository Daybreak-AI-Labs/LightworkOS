"""Local sign-in and a role list that failed to save, or went missing.

A first roster write that fails must not strand a fresh install, and a lost
roster must not lock out the administrators set up in configuration: they are
always administrators, so they must be able to sign in and start a new list.
"""
from __future__ import annotations

import errno
import json
import os
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

LOCAL = "http://127.0.0.1:8765"
REMOTE = "https://lightwork.example"
OWNER = "owner@example.test"
OWNER_PASS = "Synthetic owner passphrase for roster tests"  # pragma: allowlist secret
COLLEAGUE = "sam@example.test"
GOOD = "harbor violet tram ledger"  # pragma: allowlist secret - synthetic fixture passphrase


@pytest.fixture
def home(monkeypatch, tmp_path):
    """A fresh installation: invitations sign people in locally, nobody has claimed it."""
    from maverick import client as client_binding
    from maverick import config, world_model

    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    config_path = tmp_path / "config.toml"
    config_path.write_text('[client]\nid="roster-sign-in"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    client_binding.reset_client_cache()
    from maverick_dashboard import local_passphrases

    local_passphrases.reset_attempt_limit()
    yield tmp_path
    local_passphrases.reset_attempt_limit()
    config.reset_config_cache()
    client_binding.reset_client_cache()


def _on_this_computer():
    from maverick_dashboard.app import app

    return TestClient(app, base_url=LOCAL, client=("127.0.0.1", 50001),
                      headers={"Origin": LOCAL}, follow_redirects=False)


def _elsewhere():
    from maverick_dashboard.app import app

    return TestClient(app, base_url=REMOTE, client=("192.0.2.40", 50002),
                      headers={"Origin": REMOTE}, follow_redirects=False)


def _claim(owner):
    return owner.post("/auth/local-owner", data={
        "email": OWNER, "password": OWNER_PASS, "password2": OWNER_PASS, "confirm": "yes"})


def _break_writes_of(monkeypatch, name):
    """Make every write of ``name`` fail until ``fault["armed"] = False``."""
    from maverick import file_lock

    real = file_lock.atomic_write_text
    fault = {"armed": True, "failed": 0}

    def flaky(path, *args, **kwargs):
        if fault["armed"] and Path(path).name == name:
            fault["failed"] += 1
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(file_lock, "atomic_write_text", flaky)
    return fault


def test_owner_setup_survives_a_failed_first_roster_write(home, monkeypatch):
    from maverick_dashboard import local_owner, rbac

    fault = _break_writes_of(monkeypatch, "dashboard-users.json")
    owner = _on_this_computer()
    first = _claim(owner)
    assert first.status_code == 503, first.text
    assert fault["failed"] == 1
    assert json.loads((home / "dashboard-owner.json").read_text(encoding="utf-8"))["status"] == "pending"
    assert not (home / "dashboard-users.json").exists()
    assert not (home / "dashboard-users.json.present").exists()

    fault["armed"] = False
    again = owner.post("/auth/local-login", data={"email": OWNER, "password": OWNER_PASS})
    assert again.status_code == 303, again.text
    assert rbac.get_stored_role("user:" + OWNER) == "admin"
    assert local_owner._read()["status"] == "ready"
    assert owner.get("/users", headers={"Accept": "text/html"}).status_code == 200


def _sign_in(browser, email, password):
    return browser.post("/auth/local-login", data={"email": email, "password": password})


def _invite_and_accept(owner, email=COLLEAGUE, role="operator"):
    made = owner.post("/users/invite", data={"email": email, "role": role})
    assert made.status_code == 200, made.text
    link = re.search(r"/auth/invite/(inv_[A-Za-z0-9_-]+)", made.text)[0]
    colleague = _elsewhere()
    accepted = colleague.post(link, data={"password": GOOD, "password2": GOOD})
    assert accepted.status_code == 303, accepted.text
    return colleague


def _lose_the_roster(home):
    (home / "dashboard-users.json").unlink()
    assert (home / "dashboard-users.json.present").exists()


def test_a_configured_admin_who_is_the_owner_signs_in_with_the_roster_lost_and_starts_a_new_one(home, monkeypatch):
    from maverick_dashboard import rbac

    owner = _on_this_computer()
    assert _claim(owner).status_code == 303
    _lose_the_roster(home)

    # Without a configured administrator nobody can sign in, and the page says what to do.
    refused = _sign_in(_on_this_computer(), OWNER, OWNER_PASS)
    assert refused.status_code == 503
    for needle in ("role list is missing", "[dashboard] admins", "MAVERICK_DASHBOARD_ADMINS", "backup"):
        assert needle in refused.text, needle
    assert "mvk_session" not in refused.cookies

    # Naming the owner in configuration is the file-level recovery.
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:" + OWNER)
    browser = _on_this_computer()
    signed_in = _sign_in(browser, OWNER, OWNER_PASS)
    assert signed_in.status_code == 303, signed_in.text
    assert "mvk_session" in browser.cookies
    page = browser.get("/users", headers={"Accept": "text/html"})
    assert page.status_code == 503 and 'action="/users/roster/reset"' in page.text
    done = browser.post("/users/roster/reset", data={"confirm": "reset"})
    assert done.status_code == 303, done.text
    assert rbac.list_users() == {}
    assert browser.get("/users", headers={"Accept": "text/html"}).status_code == 200


def test_a_wrong_passphrase_is_still_refused_with_the_roster_lost(home, monkeypatch):
    owner = _on_this_computer()
    assert _claim(owner).status_code == 303
    _lose_the_roster(home)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:" + OWNER)
    refused = _sign_in(_on_this_computer(), OWNER, "not the owner passphrase")
    assert refused.status_code == 401 and "mvk_session" not in refused.cookies


def test_a_configured_admin_colleague_signs_in_with_the_roster_lost_and_others_do_not(home, monkeypatch):
    from maverick_dashboard import rbac

    owner = _on_this_computer()
    assert _claim(owner).status_code == 303
    _invite_and_accept(owner)
    _lose_the_roster(home)

    refused = _sign_in(_elsewhere(), COLLEAGUE, GOOD)
    assert refused.status_code == 503 and "role list is missing" in refused.text
    assert "mvk_session" not in refused.cookies

    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:" + COLLEAGUE)
    browser = _elsewhere()
    signed_in = _sign_in(browser, COLLEAGUE, GOOD)
    assert signed_in.status_code == 303, signed_in.text
    page = browser.get("/users", headers={"Accept": "text/html"})
    assert page.status_code == 503 and 'action="/users/roster/reset"' in page.text
    assert browser.post("/users/roster/reset", data={"confirm": "reset"}).status_code == 303
    assert rbac.list_users() == {}
    # The owner still has no stored role and is not a configured administrator.
    gone = _sign_in(_on_this_computer(), OWNER, OWNER_PASS)
    assert gone.status_code == 403 and "no longer has an assigned role" in gone.text


def test_a_pending_owner_claim_with_a_lost_roster_finishes_for_a_configured_admin(home, monkeypatch):
    """The state an older build could leave after one failed first roster write."""
    from maverick_dashboard import local_owner, rbac

    fault = _break_writes_of(monkeypatch, "dashboard-users.json")
    assert _claim(_on_this_computer()).status_code == 503
    fault["armed"] = False
    rbac._record_roster(rbac.store_path())  # the marker an older build left behind
    assert not rbac.store_path().exists()

    refused = _sign_in(_on_this_computer(), OWNER, OWNER_PASS)
    assert refused.status_code == 503 and "role list is missing" in refused.text
    assert local_owner._read()["status"] == "pending"

    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:" + OWNER)
    browser = _on_this_computer()
    assert _sign_in(browser, OWNER, OWNER_PASS).status_code == 303
    assert local_owner._read()["status"] == "ready"
    assert browser.post("/users/roster/reset", data={"confirm": "reset"}).status_code == 303
    assert rbac.list_users() == {}
