"""Synthetic provider boundary over real sealed, named credential stores."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event, current_thread
from urllib.parse import parse_qs, urlsplit

import pytest
from maverick import config, connections
from maverick import connection_oauth as oauth
from maverick.paths import tenant_scope

OWNER = "user:owner"
_TOKEN_POST = oauth._post_token
_IDENTITY_GET = oauth._provider_identity


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    import os
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    config.config_path().write_text("[connections]\nenable=true\n[oauth]\nvault=true\n")
    monkeypatch.setattr(oauth, "_post_token", lambda *a, **k: pytest.fail("Unexpected provider token request"))
    monkeypatch.setattr(oauth, "_jira_sites", lambda *a, **k: pytest.fail("Unexpected provider site request"))
    monkeypatch.setattr(oauth, "_provider_identity", lambda provider, token, **_identity_inputs: {
        "provider": provider, "subject": "fixture-account", "display_name": "Fixture Account",
        "email": "fixture@example.test",
        **({"email_verified": True, "hosted_domain": "example.test"} if provider == "google"
           else {"account_status": "active"}),
    })
    with tenant_scope(tenant="tenant-a"):
        yield
    config.reset_config_cache()


def app(provider="google"):
    return oauth.save_application(OWNER, provider=provider, client_id="synthetic-client-id", client_secret="synthetic-client-secret", expected_revision="")


def start(profile="google-drive", **kwargs):
    return oauth.begin(OWNER, profile=profile, name="evidence", redirect_uri="https://lightwork.example/connections", context="fixture-context", **kwargs)


def exchange(begin, monkeypatch, *, profile="google-drive"):
    monkeypatch.setattr(oauth, "_post_token", lambda *a: {"access_token": "synthetic-access-token", "refresh_token": "synthetic-refresh-token", "expires_in": 3600, "scope": " ".join(oauth.PROFILES[profile]["scopes"])})
    return oauth.finish(OWNER, state=begin["state"], code="synthetic-code", context="fixture-context", redirect_uri="https://lightwork.example/connections")


def expire():
    with connections._mutation_lock():
        records = connections._load()
        records["evidence"]["oauth"]["expires_at"] = time.time() - 1
        connections._save(records)


def test_real_state_pkce_and_sealed_named_connection(monkeypatch):
    applications = app()
    begin = start()
    query = parse_qs(urlsplit(begin["authorize_url"]).query)
    assert query["state"] == [begin["state"]]
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == [" ".join(oauth.PROFILES["google-drive"]["scopes"])]
    assert query["access_type"] == ["offline"] and query["prompt"] == ["consent"]
    assert "verifier" not in begin
    saved = exchange(begin, monkeypatch)
    assert saved["owner"] == OWNER and saved["connector"] == "gdrive"
    assert saved["has_token"] and saved["oauth"]["renewal_state"] == "ready"
    assert saved["oauth"]["identity"] == {
        "provider": "google", "subject": "fixture-account",
        "display_name": "Fixture Account", "email": "fixture@example.test",
        "email_verified": True, "hosted_domain": "example.test",
    }
    assert saved["oauth"]["requested_scopes"] == sorted(oauth.PROFILES["google-drive"]["scopes"])
    assert saved["oauth"]["granted_scopes"] == sorted(oauth.PROFILES["google-drive"]["scopes"])
    assert saved["oauth"]["scope_status"] == "token_response"
    for value in (str(applications), str(saved), oauth._path().read_bytes().decode(errors="replace"), connections._path().read_bytes().decode(errors="replace")):
        assert "synthetic-client-secret" not in value
        assert "synthetic-refresh-token" not in value
        assert "synthetic-access-token" not in value
    with pytest.raises(PermissionError):
        oauth.finish(OWNER, state=begin["state"], code="synthetic-code", context="fixture-context", redirect_uri="https://lightwork.example/connections")


@pytest.mark.parametrize("changed", ["actor", "tenant", "context", "callback", "application", "connection"])
def test_consent_cannot_cross_current_authority_or_versions(monkeypatch, changed):
    application = app()[0]
    begin = start()
    if changed == "application":
        oauth.save_application(OWNER, provider="google", client_id="changed", client_secret="changed-fixture-secret", expected_revision=application["revision"])
    if changed == "connection":
        connections.set_connection("evidence", owner="user:other", token="synthetic-other")
    with tenant_scope(tenant="tenant-b" if changed == "tenant" else "tenant-a"):
        with pytest.raises((PermissionError, connections.ConnectionVersionConflict)):
            oauth.finish("user:other" if changed == "actor" else OWNER, state=begin["state"], code="synthetic-code", context="changed" if changed == "context" else "fixture-context", redirect_uri="https://other.example/connections" if changed == "callback" else "https://lightwork.example/connections")
        assert connections.get_connection("evidence") is None or changed == "connection"


def test_renewal_keeps_review_generation_and_rotation_is_singleflight(monkeypatch):
    app()
    saved = exchange(start(), monkeypatch)
    expire()
    calls = []
    def fresh(provider, payload):
        calls.append(payload)
        time.sleep(.02)
        return {"access_token": "new-synthetic-access", "refresh_token": "rotated-synthetic-refresh", "expires_in": 3600}
    monkeypatch.setattr(oauth, "_post_token", fresh)
    def resolve():
        with tenant_scope(tenant="tenant-a"), connections.bind_principal(OWNER):
            return connections.resolve_named("evidence", expected_revision=saved["revision"], connector="gdrive", origin="https://www.googleapis.com")
    with ThreadPoolExecutor(max_workers=2) as executor:
        values = list(executor.map(lambda _: resolve(), range(2)))
    assert len(calls) == 1
    assert all(row["token"] == "new-synthetic-access" and row["revision"] == saved["revision"] for row in values)
    assert connections.get_connection("evidence")["oauth"]["refresh_token"] == "rotated-synthetic-refresh"


@pytest.mark.parametrize("registry", ["connections", "oauth"])
def test_sealed_registry_reader_excludes_rotation_during_file_verification(monkeypatch, registry):
    from maverick import file_lock

    app()
    exchange(start(), monkeypatch)
    store = connections if registry == "connections" else oauth
    path = store._path()
    verifying, release, attempting, acquired = Event(), Event(), Event(), Event()
    real_check = file_lock.ensure_private_file

    def hold_verification(candidate, *args, **kwargs):
        result = real_check(candidate, *args, **kwargs)
        if Path(candidate) == path and current_thread().name.startswith("registry-reader"):
            verifying.set()
            assert release.wait(5), "reader was not released"
        return result

    monkeypatch.setattr(file_lock, "ensure_private_file", hold_verification)
    monkeypatch.setattr(oauth, "ensure_private_file", hold_verification)

    def read():
        with tenant_scope(tenant="tenant-a"):
            return store._load()

    def rotate():
        with tenant_scope(tenant="tenant-a"):
            attempting.set()
            with connections._mutation_lock():
                acquired.set()
                records = store._load()
                if registry == "connections":
                    records["evidence"]["token"] = "synthetic-rotated-token"
                else:
                    records["applications"][oauth._app_key(OWNER, "google")]["client_id"] = "rotated-client"
                store._save(records)

    with (ThreadPoolExecutor(max_workers=1, thread_name_prefix="registry-reader") as readers,
          ThreadPoolExecutor(max_workers=1, thread_name_prefix="registry-writer") as writers):
        reader = readers.submit(read)
        try:
            assert verifying.wait(5), "reader did not reach file verification"
            writer = writers.submit(rotate)
            assert attempting.wait(5), "writer did not attempt rotation"
            assert not acquired.wait(.2), "rotation raced the file verification/read boundary"
        finally:
            release.set()
        snapshot = reader.result(timeout=5)
        writer.result(timeout=5)
    latest = store._load()
    if registry == "connections":
        assert snapshot["evidence"]["token"] == "synthetic-access-token"
        assert latest["evidence"]["token"] == "synthetic-rotated-token"
    else:
        key = oauth._app_key(OWNER, "google")
        assert snapshot["applications"][key]["client_id"] == "synthetic-client-id"
        assert latest["applications"][key]["client_id"] == "rotated-client"


def test_wrong_origin_or_revoked_grant_refuses_before_token_refresh(monkeypatch):
    app()
    saved = exchange(start(), monkeypatch)
    expire()
    monkeypatch.setattr(oauth, "_post_token", lambda *a: pytest.fail("Refresh leaked under rejected authority"))
    with connections.bind_principal(OWNER):
        with pytest.raises(PermissionError):
            connections.resolve_named("evidence", expected_revision=saved["revision"], connector="gdrive", origin="https://attacker.example")
    with connections.bind_principal("user:ungranted"):
        with pytest.raises(PermissionError):
            connections.resolve_named("evidence", expected_revision=saved["revision"], connector="gdrive", origin="https://www.googleapis.com")
    changed = connections.set_connection("evidence", expected_owner=OWNER, allowed_principals=["user:reviewer"], expected_revision=saved["revision"])
    assert changed["oauth"] is not None and changed["revision"] != saved["revision"]
    with connections.bind_principal(OWNER):
        with pytest.raises(connections.ConnectionVersionConflict):
            connections.resolve_named("evidence", expected_revision=saved["revision"], connector="gdrive", origin="https://www.googleapis.com")
    with pytest.raises(ValueError):
        connections.set_connection("evidence", base_url="https://attacker.example", expected_revision=changed["revision"])


def test_lost_rotating_refresh_reply_is_not_replayed(monkeypatch):
    app()
    exchange(start(), monkeypatch)
    expire()
    calls = []
    def lost(*args):
        calls.append(args)
        raise OSError("synthetic connection lost after provider rotated token")
    monkeypatch.setattr(oauth, "_post_token", lost)
    for _ in range(2):
        with pytest.raises(PermissionError, match="Reconnect"):
            oauth.renew(connections.get_connection("evidence"), actor=OWNER)
    assert len(calls) == 1
    assert connections.get_connection("evidence")["oauth"]["refresh_state"] == "pending"


def test_refresh_cannot_replace_the_connected_provider_account(monkeypatch):
    app()
    saved = exchange(start(), monkeypatch)
    expire()
    monkeypatch.setattr(oauth, "_post_token", lambda *a: {
        "access_token": "different-account-access", "refresh_token": "rotated-refresh",
        "expires_in": 3600, "scope": " ".join(oauth.PROFILES["google-drive"]["scopes"]),
    })
    monkeypatch.setattr(oauth, "_provider_identity", lambda *a, **_identity_inputs: {
        "provider": "google", "subject": "different-account", "display_name": "Other Account",
        "email": "other@example.test", "email_verified": True, "hosted_domain": "example.test",
    })
    with pytest.raises(PermissionError, match="could not be confirmed"):
        oauth.renew(connections.get_connection("evidence"), actor=OWNER)
    stored = connections.get_connection("evidence")
    assert stored["token"] != "different-account-access"
    assert stored["revision"] == saved["revision"]
    assert stored["oauth"]["refresh_state"] == "pending"


def test_gcs_named_reference_is_consumed_by_actual_discovery_resolver(monkeypatch):
    from maverick.privacy_discovery_credentials import resolve_connection
    app()
    saved = exchange(start("google-cloud-storage"), monkeypatch, profile="google-cloud-storage")
    expire()
    monkeypatch.setattr(oauth, "_post_token", lambda *a: {"access_token": "renewed-gcs-fixture", "expires_in": 3600})
    with connections.bind_principal(OWNER):
        row = resolve_connection("connection:evidence:" + saved["revision"], provider="google_cloud_storage", origin="https://storage.googleapis.com")
    assert row["token"] == "renewed-gcs-fixture" and row["revision"] == saved["revision"]


def test_jira_authorization_selects_actual_site_and_pins_cloud_api(monkeypatch):
    app("atlassian")
    cloud = "f13718a7-c4a3-49ac-8db9-20f1da1a3af9"
    monkeypatch.setattr(oauth, "_jira_sites", lambda token: [{"id": cloud, "url": "https://customer.atlassian.net", "scopes": ["read:jira-work", "write:jira-work"]}])
    begin = start("jira-cloud", site_url="https://customer.atlassian.net")
    query = parse_qs(urlsplit(begin["authorize_url"]).query)
    assert query["audience"] == ["api.atlassian.com"] and query["prompt"] == ["consent"]
    saved = exchange(begin, monkeypatch, profile="jira-cloud")
    assert saved["base_url"] == "https://api.atlassian.com"
    with connections.bind_principal(OWNER):
        resolved = connections.resolve("jira")
    assert resolved[0] == "https://api.atlassian.com/ex/jira/" + cloud
    assert saved["oauth"]["site_url"] == "https://customer.atlassian.net"
    assert saved["oauth"]["workspace"]["provider_id"] == cloud
    assert saved["oauth"]["identity"]["provider"] == "atlassian"


def test_mismatched_jira_site_and_missing_refresh_token_do_not_save(monkeypatch):
    app("atlassian")
    begin = start("jira-cloud", site_url="https://customer.atlassian.net")
    monkeypatch.setattr(oauth, "_jira_sites", lambda _: [{"id": "f13718a7-c4a3-49ac-8db9-20f1da1a3af9", "url": "https://other.atlassian.net"}])
    with pytest.raises(ValueError, match="selected Jira site"):
        exchange(begin, monkeypatch, profile="jira-cloud")
    assert connections.get_connection("evidence") is None
    with pytest.raises(ValueError, match="renewable"):
        oauth._tokens({"access_token": "synthetic-token", "expires_in": 3600}, [])


def test_changed_app_registration_invalidates_even_unexpired_access(monkeypatch):
    application = app()[0]
    exchange(start(), monkeypatch)
    oauth.save_application(OWNER, provider="google", client_id="new-client", client_secret=None, expected_revision=application["revision"])
    monkeypatch.setattr(oauth, "_post_token", lambda *a: pytest.fail("Old app authority was refreshed"))
    with pytest.raises(connections.ConnectionVersionConflict, match="registration changed"):
        oauth.renew(connections.get_connection("evidence"), actor=OWNER)


def test_token_http_contract_uses_pinned_fixed_endpoint_bounded_json_and_no_redirects(monkeypatch):
    import httpx
    from maverick.tools import _ssrf
    # Exercise the real transport wrapper, including Atlassian's JSON body.
    actual = monkeypatch.context()
    with actual as patch:
        # Call the real transport behind the fixture's fail-on-network seam.
        calls = []
        def response(request):
            calls.append(request)
            assert request.url == "https://auth.atlassian.com/oauth/token"
            assert request.headers["content-type"].startswith("application/json")
            return httpx.Response(302, headers={"Location": "https://attacker.example/token"})
        patch.setattr(_ssrf, "safe_client", lambda *a, **kw: httpx.Client(transport=httpx.MockTransport(response), follow_redirects=False))
        with pytest.raises(httpx.HTTPStatusError):
            _TOKEN_POST("atlassian", {"refresh_token": "synthetic-never-followed"})
        assert len(calls) == 1
        patch.setattr(_ssrf, "safe_client", lambda *a, **kw: httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"x" * 100001))))
        with pytest.raises(ValueError, match="exceeds"):
            _TOKEN_POST("atlassian", {"refresh_token": "synthetic-bounded"})


def test_deployment_floor_cannot_be_waived_by_tenant_network_config(monkeypatch):
    from maverick import enterprise
    monkeypatch.setattr(enterprise, "deployment_enterprise_enabled", lambda: True)
    monkeypatch.setattr(enterprise, "enterprise_egress_denial", lambda *a, **k: None)
    monkeypatch.setattr(config, "load_global_config", lambda: {"enterprise": {"allowed_hosts": []}})
    with pytest.raises(PermissionError, match="Deployment network"):
        oauth._network_allowed("https://oauth2.googleapis.com/token")


@pytest.mark.parametrize("scopes", [None, [], ["read:jira-work"], ["read:jira-work", 3]])
def test_jira_site_resource_scopes_required_even_when_token_scope_omitted(monkeypatch, scopes):
    app("atlassian")
    begin = start("jira-cloud", site_url="https://customer.atlassian.net")
    monkeypatch.setattr(oauth, "_post_token", lambda *a: {"access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "expires_in": 3600})
    monkeypatch.setattr(oauth, "_jira_sites", lambda _: [{"id": "f13718a7-c4a3-49ac-8db9-20f1da1a3af9", "url": "https://customer.atlassian.net", "scopes": scopes}])
    with pytest.raises(ValueError, match="required read and write"):
        oauth.finish(OWNER, state=begin["state"], code="synthetic-code", context="fixture-context", redirect_uri="https://lightwork.example/connections")
    assert connections.get_connection("evidence") is None


def test_unsupported_token_type_and_control_character_code_are_rejected():
    with pytest.raises(ValueError, match="Bearer"):
        oauth._tokens({"token_type": "MAC", "access_token": "synthetic", "refresh_token": "synthetic-refresh", "expires_in": 3600}, [])
    app()
    begin = start()
    with pytest.raises(ValueError, match="response was invalid"):
        oauth.finish(OWNER, state=begin["state"], code="synthetic\r\ninjection", context="fixture-context", redirect_uri="https://lightwork.example/connections")


def test_provider_scope_aliases_are_normalized_and_missing_access_is_rejected():
    requested = oauth.PROFILES["google-drive"]["scopes"]
    response = {"access_token": "synthetic", "refresh_token": "synthetic-refresh",
                "expires_in": 3600,
                "scope": "openid profile email https://www.googleapis.com/auth/drive.readonly"}
    _, _, _, granted, status = oauth._tokens(response, requested, provider="google")
    assert granted == sorted(requested)
    assert status == "token_response"
    response["scope"] = "openid profile email"
    with pytest.raises(ValueError, match="did not grant"):
        oauth._tokens(response, requested, provider="google")


def test_desktop_broker_profile_scope_contract_matches_backend_profiles():
    contract = (
        Path(__file__).resolve().parents[3]
        / "apps" / "desktop-oauth-return" / "oauth-profile-scopes.tsv"
    )
    actual = {
        tuple(line.split("\t"))
        for line in contract.read_text(encoding="utf-8").splitlines()
        if line
    }
    expected = {
        (profile, value["provider"], " ".join(value["scopes"]))
        for profile, value in oauth.PROFILES.items()
    }
    assert actual == expected


@pytest.mark.parametrize("provider,field", [("google", "sub"), ("atlassian", "account_id")])
def test_provider_identity_uses_fixed_endpoint_and_stable_subject(monkeypatch, provider, field):
    calls = []
    def read(url, token, *, label):
        calls.append((url, token, label))
        return {field:"stable-account", "name":"Named Account", "email":"named@example.test",
                "email_verified":True, "hd":"example.test", "account_status":"active"}
    monkeypatch.setattr(oauth, "_bearer_json", read)
    identity = _IDENTITY_GET(provider, "private-access")
    assert identity["subject"] == "stable-account"
    assert identity["display_name"] == "Named Account"
    expected = "https://openidconnect.googleapis.com/v1/userinfo" if provider == "google" else "https://api.atlassian.com/me"
    assert calls == [(expected, "private-access", "Provider account identity")]


def test_identity_failure_consumes_consent_without_saving_connection(monkeypatch):
    app()
    begin = start()
    monkeypatch.setattr(oauth, "_post_token", lambda *a: {
        "access_token": "synthetic-access", "refresh_token": "synthetic-refresh",
        "expires_in": 3600, "scope": " ".join(oauth.PROFILES["google-drive"]["scopes"]),
    })
    monkeypatch.setattr(
        oauth, "_provider_identity",
        lambda *a, **_identity_inputs: (_ for _ in ()).throw(ValueError("synthetic identity failure")),
    )
    with pytest.raises(ValueError, match="identity failure"):
        oauth.finish(
            OWNER, state=begin["state"], code="synthetic-code",
            context="fixture-context", redirect_uri="https://lightwork.example/connections",
        )
    assert connections.get_connection("evidence") is None
    with pytest.raises(PermissionError):
        oauth.finish(
            OWNER, state=begin["state"], code="synthetic-code",
            context="fixture-context", redirect_uri="https://lightwork.example/connections",
        )


def test_actual_vendor_jira_refresh_retains_approval_generation_and_app_rotation_blocks_write(monkeypatch):
    import httpx
    from maverick.governed_operations import ServiceContext
    from maverick.tools import _ssrf
    from maverick.vendor_onboarding_adapters import JiraTickets
    application = app("atlassian")[0]
    cloud = "f13718a7-c4a3-49ac-8db9-20f1da1a3af9"
    monkeypatch.setattr(oauth, "_jira_sites", lambda _: [{"id": cloud, "url": "https://customer.atlassian.net", "scopes": ["read:jira-work", "write:jira-work"]}])
    saved = exchange(start("jira-cloud", site_url="https://customer.atlassian.net"), monkeypatch, profile="jira-cloud")
    expire()
    calls = []
    def transport(request):
        calls.append(request)
        assert request.url == "https://api.atlassian.com/ex/jira/" + cloud + "/rest/api/3/issue"
        assert request.headers["authorization"] == "Bearer renewed-jira-fixture"
        return httpx.Response(201, json={"key": "VEND-1"})
    monkeypatch.setattr(_ssrf, "safe_client", lambda *a, **k: httpx.Client(transport=httpx.MockTransport(transport)))
    monkeypatch.setattr(oauth, "_post_token", lambda *a: {"access_token": "renewed-jira-fixture", "expires_in": 3600})
    ctx = ServiceContext("tenant-a", OWNER, "vendor-team", OWNER, "evidence", human=True)
    jira = JiraTickets()
    assert jira.authority_version(ctx) == saved["revision"]
    assert connections.get_connection("evidence")["oauth"]["expires_at"] < time.time()
    body = {"project": "VEND", "summary": "Synthetic reviewed vendor", "description": "Synthetic approved evidence", "marker": "lightwork-vop-" + "1" * 32}
    assert jira.create(ctx, body, "VOP-" + "1" * 32, expected_credential_version=saved["revision"])["key"] == "VEND-1"
    assert connections.get_connection("evidence")["revision"] == saved["revision"]
    oauth.save_application(OWNER, provider="atlassian", client_id="new-client", client_secret=None, expected_revision=application["revision"])
    with pytest.raises(connections.ConnectionVersionConflict, match="registration changed"):
        jira.create(ctx, body, "VOP-" + "1" * 32, expected_credential_version=saved["revision"])
    assert len(calls) == 1
