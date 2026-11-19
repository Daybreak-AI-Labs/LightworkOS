"""The name and verified email a sign-in reports, so people read as people.

Live: approvals, settings history and the Activity log named the installation
administrator only as "Google account", because nothing kept the name the
identity provider reported. The account record keeps only the verified email
and display name, follows the at-rest encryption setting, is in My data's
export and is removed by My data's reviewed deletion and the company
directory's account deletion.
"""
from __future__ import annotations

import json
import os
import stat
from types import SimpleNamespace

import pytest

GOOGLE = "user:google-oauth2|104857600123456789"


@pytest.fixture
def profiles(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_REMEMBER_ACCOUNT_NAMES", raising=False)
    from maverick_dashboard import account_profiles

    return account_profiles


def test_sign_in_keeps_only_a_verified_email_and_the_display_name(profiles):
    profiles.record_sign_in(GOOGLE, {"sub": "x", "email": "Dana@Northwind.example", "email_verified": True,
                                     "name": "Dana Lee", "picture": "https://x/p.png", "locale": "en"})
    assert profiles.get(GOOGLE) == {"email": "dana@northwind.example", "name": "Dana Lee", "at": profiles.get(GOOGLE)["at"]}
    profiles.record_sign_in(GOOGLE, {"email": "other@northwind.example", "name": "Dana Lee"})  # not verified
    assert profiles.get(GOOGLE)["email"] == ""
    profiles.record_sign_in(GOOGLE, {"given_name": "Dana", "family_name": "Lee‮"})
    assert profiles.get(GOOGLE)["name"] == "Dana Lee"
    profiles.record_sign_in(GOOGLE, {"sub": "x"})  # nothing to keep: the record goes
    assert profiles.get(GOOGLE) is None


def test_the_record_is_private_and_sealed_when_encryption_at_rest_is_on(profiles, monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    profiles.record_sign_in(GOOGLE, {"email": "dana@northwind.example", "email_verified": True, "name": "Dana Lee"})
    path = profiles._path()
    assert b"dana@northwind.example" not in path.read_bytes()
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert profiles.names() == {GOOGLE: "Dana Lee"}
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    profiles.record_sign_in(GOOGLE, {"email": "dana@northwind.example", "email_verified": True})
    assert b"dana@northwind.example" in path.read_bytes()
    assert profiles.names() == {GOOGLE: "dana@northwind.example"}


def test_the_setting_turns_recording_and_naming_off(profiles, monkeypatch):
    profiles.record_sign_in(GOOGLE, {"email": "dana@northwind.example", "email_verified": True})
    monkeypatch.setenv("MAVERICK_REMEMBER_ACCOUNT_NAMES", "0")
    assert profiles.names() == {}
    profiles.record_sign_in("user:someone-else", {"email": "x@northwind.example", "email_verified": True})
    monkeypatch.delenv("MAVERICK_REMEMBER_ACCOUNT_NAMES")
    assert profiles.get("user:someone-else") is None
    assert profiles.get(GOOGLE)["email"] == "dana@northwind.example"  # kept until erased


def test_oidc_sign_in_records_the_account(profiles, monkeypatch):
    from maverick_dashboard import oidc_login

    seen = []
    monkeypatch.setattr(profiles, "record_sign_in", lambda principal, claims: seen.append((principal, claims)))
    oidc_login._remember_account(SimpleNamespace(sub="google-oauth2|1", claims={"name": "Dana Lee"}))
    assert seen == [("user:google-oauth2|1", {"name": "Dana Lee"})]


def test_people_read_as_their_recorded_name(profiles, monkeypatch):
    from maverick_dashboard import invites, scim
    from maverick_dashboard.person_names import labeler

    monkeypatch.setattr(invites, "list_invites", list)
    monkeypatch.setattr(scim, "_load", dict)
    assert labeler()(GOOGLE) == "Google account"
    profiles.record_sign_in(GOOGLE, {"email": "dana@northwind.example", "email_verified": True, "name": "Dana Lee"})
    assert labeler()(GOOGLE) == "Dana Lee"


def test_my_data_export_includes_the_account_record(profiles, monkeypatch):
    from urllib.parse import parse_qs, urlsplit

    from maverick_dashboard import personal_data_exports as service

    profiles.record_sign_in(GOOGLE, {"email": "dana@northwind.example", "email_verified": True, "name": "Dana Lee"})
    monkeypatch.setattr(service.native, "_actor", lambda request: GOOGLE)
    monkeypatch.setattr(service, "context_for", lambda request: "a" * 64)
    monkeypatch.setattr(service.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + value)
    monkeypatch.setattr(service.crypto_at_rest, "unseal_from_str", lambda value: value.removeprefix("sealed:"))
    monkeypatch.setattr(service.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setattr(service, "audit_event", lambda *a, **kw: True)
    token = parse_qs(urlsplit(service.link(None, store="account_name")["href"]).query)["token"][0]
    bundle = json.loads(service.download(None, token).body)
    assert bundle["store"] == "account_name"
    assert bundle["record"]["email"] == "dana@northwind.example" and bundle["record"]["name"] == "Dana Lee"


def test_my_data_reviewed_deletion_erases_the_account_record(profiles):
    from maverick_dashboard import personal_data_requests as deletion

    profiles.record_sign_in(GOOGLE, {"email": "dana@northwind.example", "email_verified": True, "name": "Dana Lee"})
    assert "account_name" in deletion.KINDS
    target = {"store": "account_name", "state": "requested", **deletion._preview_owned_account("account_name", GOOGLE)}
    assert target["count"] == 1
    result = deletion._erase_target(None, {"owner": GOOGLE, "channel": "dashboard", "user_id": "x"}, target)
    assert result["state"] == "purged" and result["removed"] == 1
    assert profiles.get(GOOGLE) is None


def test_deleting_the_company_directory_account_erases_its_record(profiles, monkeypatch):
    from maverick_dashboard import scim, subject_directory

    profiles.record_sign_in(GOOGLE, {"email": "dana@northwind.example", "email_verified": True})
    profiles.record_sign_in("user:keep", {"email": "keep@northwind.example", "email_verified": True})
    monkeypatch.setattr(scim, "_revoke_user_sessions", lambda rec: None)
    monkeypatch.setattr(subject_directory, "retire", lambda identifiers, **_: None)
    monkeypatch.setattr(subject_directory, "subs_for", lambda identifiers: {GOOGLE.removeprefix("user:")}
                        if "ext-1" in identifiers else set())
    from maverick.tenant import registry
    monkeypatch.setattr(registry, "delete_tenant", lambda uid: None)
    scim._delete_tenant("a" * 32, {"id": "a" * 32, "externalId": "ext-1", "userName": "dana", "email": ""})
    assert profiles.get(GOOGLE) is None and profiles.get("user:keep") is not None
