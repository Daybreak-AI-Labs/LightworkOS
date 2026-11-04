"""Operator registration separation over real tenant-sealed local stores."""
from __future__ import annotations

import hashlib
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from maverick import config, connections
from maverick import connection_oauth as oauth
from maverick.paths import tenant_scope

OPERATOR = "user:operator"
CUSTOMER = "user:customer"
RETURN = "https://lightwork.example/connections"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    import os
    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    config.config_path().write_text("[connections]\nenable=true\n[oauth]\nvault=true\n")
    monkeypatch.setattr(oauth, "_post_token", lambda *a: pytest.fail("Unexpected provider request"))
    monkeypatch.setattr(oauth, "_provider_identity", lambda provider, token, **_identity_inputs: {
        "provider": provider, "subject": "fixture-account", "display_name": "Fixture Account",
        "email": "fixture@example.test", "email_verified": True, "hosted_domain": "example.test",
    })
    with tenant_scope(tenant="tenant-a"):
        yield
    config.reset_config_cache()


def registration(actor=OPERATOR, *, shared=True, revision=""):
    save = oauth.save_workspace_application if shared else oauth.save_application
    return save(actor, provider="google", client_id="synthetic-client", client_secret="synthetic-app-secret", expected_revision=revision)[0]


def begin(actor=CUSTOMER):
    return oauth.begin(actor, profile="google-drive", name="drive", redirect_uri=RETURN, context="synthetic-context")


def finish(start, monkeypatch, actor=CUSTOMER):
    calls = []
    def token(provider, payload):
        calls.append((provider, payload))
        return {"access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "expires_in": 3600}
    monkeypatch.setattr(oauth, "_post_token", token)
    saved = oauth.finish(actor, state=start["state"], code="synthetic-code", context="synthetic-context", redirect_uri=RETURN)
    return saved, calls


def test_shared_registration_binds_customer_consent_and_private_credential(monkeypatch):
    app = registration()
    available = oauth.available_applications(CUSTOMER)
    assert available == [{"provider": "google", "configured": True, "registration_scope": "workspace"}]
    assert "client" not in str(available) and "secret" not in str(available)
    started = begin()
    query = parse_qs(urlsplit(started["authorize_url"]).query)
    assert query["client_id"] == ["synthetic-client"]
    pending = oauth._load()["consents"][hashlib.sha256(started["state"].encode()).hexdigest()]
    assert pending["application_key"] != oauth._app_key(OPERATOR, "google")
    saved, calls = finish(started, monkeypatch)
    raw = connections.get_connection("drive")
    assert raw["owner"] == CUSTOMER
    assert raw["oauth"]["application_key"] == pending["application_key"]
    assert raw["oauth"]["application_revision"] == app["revision"]
    assert len(calls) == 1
    assert saved["oauth"]["renewal_state"] == "ready"
    for secret in ("synthetic-app-secret", "synthetic-refresh", "synthetic-access"):
        assert secret not in str(saved)
        assert secret.encode() not in oauth._path().read_bytes()
        assert secret.encode() not in connections._path().read_bytes()


@pytest.mark.parametrize("phase", ["consent", "unexpired", "expired"])
def test_shared_rotation_denies_before_any_provider_request_and_status_is_current(monkeypatch, phase):
    app = registration()
    started = begin()
    if phase != "consent":
        finish(started, monkeypatch)
        if phase == "expired":
            rows = connections._load()
            rows["drive"]["oauth"]["expires_at"] = time.time() - 1
            connections._save(rows)
    registration("user:second-operator", revision=app["revision"])
    monkeypatch.setattr(oauth, "_post_token", lambda *a: pytest.fail("Rotated registration used"))
    before = connections._path().read_bytes() if connections._path().exists() else None
    with pytest.raises(connections.ConnectionVersionConflict):
        if phase == "consent":
            oauth.finish(CUSTOMER, state=started["state"], code="synthetic-code", context="synthetic-context", redirect_uri=RETURN)
        else:
            oauth.renew(connections.get_connection("drive"), actor=CUSTOMER)
    if phase != "consent":
        assert connections._path().read_bytes() == before
        status = connections.list_connections(owner=CUSTOMER)[0]["oauth"]
        assert status["renewal_state"] == "reconnect_required"
        assert status["available"] is False
        assert "Reconnect" in status["recovery_action"]


def test_legacy_registration_never_becomes_other_accounts_fallback():
    registration(shared=False)
    assert oauth.available_applications(CUSTOMER) == []
    with pytest.raises(ValueError, match="administrator"):
        begin()
    with tenant_scope(tenant="tenant-b"):
        assert oauth.available_applications(OPERATOR) == []


@pytest.mark.parametrize("old_record", [False, True])
def test_legacy_binding_stays_owner_specific_after_shared_registration_added(monkeypatch, old_record):
    legacy = registration(CUSTOMER, shared=False)
    started = begin()
    if old_record:
        store = oauth._load()
        for row in store["consents"].values():
            row.pop("application_key", None)
        oauth._save(store)
    registration()
    finish(started, monkeypatch)
    rows = connections._load()
    assert rows["drive"]["oauth"]["application_revision"] == legacy["revision"]
    if old_record:
        rows["drive"]["oauth"].pop("application_key", None)
        connections._save(rows)
    monkeypatch.setattr(oauth, "_post_token", lambda *a: pytest.fail("Unexpired legacy token refreshed"))
    assert oauth.renew(connections.get_connection("drive"), actor=CUSTOMER)["owner"] == CUSTOMER
    registration(CUSTOMER, shared=False, revision=legacy["revision"])
    with pytest.raises(connections.ConnectionVersionConflict):
        oauth.renew(connections.get_connection("drive"), actor=CUSTOMER)


def test_public_status_fails_closed_on_unreadable_registration(monkeypatch):
    registration()
    finish(begin(), monkeypatch)
    oauth._path().write_bytes(b"synthetic-corruption")
    status = connections.list_connections(owner=CUSTOMER)[0]["oauth"]
    assert status["available"] is False and status["renewal_state"] == "unavailable"
    assert "synthetic-corruption" not in str(status)


def test_shared_renewal_uses_pinned_operator_registration_without_changing_review_revision(monkeypatch):
    registration(CUSTOMER, shared=False)
    registration()
    saved, _ = finish(begin(), monkeypatch)
    rows = connections._load()
    assert rows["drive"]["oauth"]["application_key"] == oauth._workspace_app_key("google")
    rows["drive"]["oauth"]["expires_at"] = time.time() - 1
    connections._save(rows)
    calls = []
    def refreshed(provider, payload):
        calls.append(payload)
        return {"access_token": "synthetic-renewed-access", "expires_in": 3600}
    monkeypatch.setattr(oauth, "_post_token", refreshed)
    with connections.bind_principal(CUSTOMER):
        result = connections.resolve_named("drive", expected_revision=saved["revision"], connector="gdrive", origin="https://www.googleapis.com")
    assert result["revision"] == saved["revision"] and result["token"] == "synthetic-renewed-access"
    assert len(calls) == 1 and calls[0]["client_id"] == "synthetic-client"
    assert calls[0]["grant_type"] == "refresh_token"


@pytest.mark.parametrize("change", ["shared_removed", "other_owners_legacy_key"])
def test_pinned_registration_cannot_fallback_or_borrow_another_owners_matching_revision(monkeypatch, change):
    registration(CUSTOMER, shared=False)
    registration()
    finish(begin(), monkeypatch)
    store = oauth._load()
    if change == "shared_removed":
        del store["applications"][oauth._workspace_app_key("google")]
    else:
        foreign_key = oauth._app_key(OPERATOR, "google")
        shared = dict(store["applications"][oauth._workspace_app_key("google")])
        shared["scope"] = "owner"
        store["applications"][foreign_key] = shared
        rows = connections._load()
        rows["drive"]["oauth"]["application_key"] = foreign_key
        connections._save(rows)
    oauth._save(store)
    monkeypatch.setattr(oauth, "_post_token", lambda *a: pytest.fail("Invalid binding used"))
    with pytest.raises(connections.ConnectionVersionConflict):
        oauth.renew(connections.get_connection("drive"), actor=CUSTOMER)
    assert connections.list_connections(owner=CUSTOMER)[0]["oauth"]["available"] is False


def test_shared_registration_rotation_blocks_pinned_jira_adapter_before_http_effect(monkeypatch):
    import httpx
    from maverick.governed_operations import ServiceContext
    from maverick.tools import _ssrf
    from maverick.vendor_onboarding_adapters import JiraTickets

    application = oauth.save_workspace_application(OPERATOR, provider="atlassian", client_id="synthetic-jira-client", client_secret="synthetic-jira-secret", expected_revision="")[0]
    started = oauth.begin(CUSTOMER, profile="jira-cloud", name="jira", redirect_uri=RETURN,
        context="synthetic-context", site_url="https://customer.atlassian.net")
    monkeypatch.setattr(oauth, "_jira_sites", lambda _: [{"id": "f13718a7-c4a3-49ac-8db9-20f1da1a3af9", "url": "https://customer.atlassian.net", "scopes": ["read:jira-work", "write:jira-work"]}])
    saved, _ = finish(started, monkeypatch)
    calls = []
    def response(request):
        calls.append(request)
        return httpx.Response(201, json={"key": "VEND-1"})
    monkeypatch.setattr(_ssrf, "safe_client", lambda *a, **k: httpx.Client(transport=httpx.MockTransport(response)))
    ctx = ServiceContext("tenant-a", CUSTOMER, "vendor-team", CUSTOMER, "jira", human=True)
    jira = JiraTickets()
    assert jira.authority_version(ctx) == saved["revision"]
    body = {"project": "VEND", "summary": "Synthetic vendor", "description": "Synthetic evidence", "marker": "lightwork-vop-" + "1" * 32}
    assert jira.create(ctx, body, "VOP-" + "1" * 32, expected_credential_version=saved["revision"])["key"] == "VEND-1"
    oauth.save_workspace_application(OPERATOR, provider="atlassian", client_id="synthetic-rotated-client", client_secret=None, expected_revision=application["revision"])
    monkeypatch.setattr(oauth, "_post_token", lambda *a: pytest.fail("Rotated registration refreshed"))
    with pytest.raises(connections.ConnectionVersionConflict, match="registration changed"):
        jira.create(ctx, body, "VOP-" + "1" * 32, expected_credential_version=saved["revision"])
    assert len(calls) == 1
