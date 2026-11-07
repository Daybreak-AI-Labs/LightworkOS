"""Settings > All settings: access, identity and deployment rows (WP1).

Every row added by ``settings_catalog_access`` saves and reads back through
the catalog API, refuses invalid values, never returns a secret, asks before
loosening a protection and writes one audit row. The shared ``path`` control
and the "Test connection" checks are bounded and quiet. Readers that ignored
the dashboard settings now honour them (environment still wins), and the
lock-out guard refuses sign-in, administrator and key changes that would lock
the person saving -- or saved records -- out.
"""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_access_guard as guard
from maverick_dashboard import settings_all_page as page
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard import settings_catalog_access as access
from maverick_dashboard import settings_tests
from maverick_dashboard.app import app

from test_support.settings_pages import every_group, save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"
CHECK = API + "/test"
ROWS = [catalog.BY_ID[s.id] for s in access.entries(catalog.S, catalog.C, catalog.Column)]
# The server access token has its own test: these tests sign in with it.
EDITABLE = [s for s in ROWS if s.id != "dashboard.token"]
_KEY = "11" * 32
_TOKEN = "server-access-token-for-tests-only-000000"  # pragma: allowlist secret
_SECRET = "correct-horse-battery-staple-long-enough-0001"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in list(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")) and name not in {
                "MAVERICK_HOME", "MAVERICK_ENCRYPT_AT_REST"}:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(page, "_CHECK_TIMES", [])
    config.reset_config_cache()
    from maverick import client as binding

    binding.reset_client_cache()
    yield
    binding.reset_client_cache()
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        # The settings-change rows only: using the server token (as_token)
        # also writes one rate-limited break-glass row per process.
        if getattr(kind, "value", kind) == "break_glass_token_used":
            return True
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


@pytest.fixture()
def as_token(monkeypatch):
    """The person saving uses the server's access token (the break-glass way in)."""
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", _TOKEN)
    client.headers["Authorization"] = "Bearer " + _TOKEN
    yield
    client.headers.pop("Authorization", None)


def _loaded():
    from maverick import config

    config.reset_config_cache()
    return config.load_config()


def _save(changes, confirm=False, http=client):
    return save_catalog(http, API, json={"changes": changes, "confirm": confirm})


def _row(setting_id):
    for group in client.get(API).json()["groups"]:
        for row in group["settings"]:
            if row["id"] == setting_id:
                return row
    raise AssertionError(setting_id)


def _file(tmp_path, name="server.pem", mode=0o600):
    path = tmp_path / "certs" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    path.chmod(mode)
    return path


_TEXT = {
    "plugins.workbench_image": "sha256:" + "a" * 64,
    "connections.self_connect_profiles": "google-drive,google-cloud-storage",
    "auth.oidc.issuer": "https://login.example.com/realm",
    "auth.oidc.client_id": "lightwork-dashboard",
    "auth.oidc.audience": "lightwork-dashboard",
    "auth.oidc.redirect_uri": "https://lightwork.example.com/auth/callback",
    "auth.oidc.jwks_uri": "https://login.example.com/keys",
    "auth.oidc.authorization_endpoint": "https://login.example.com/authorize",
    "auth.oidc.token_endpoint": "https://login.example.com/token",
    "auth.oidc.end_session_endpoint": "https://login.example.com/logout",
    "auth.saml.idp_metadata_url": "https://idp.example.com/metadata",
    "auth.saml.sp_entity_id": "https://lightwork.example.com/saml/metadata",
    "auth.saml.acs_url": "https://lightwork.example.com/saml/acs",
    "auth.saml.name_attr": "displayName",
    "auth.saml.default_relay_state": "/goals",
    "auth.proxy.header": "X-Auth-User",
    "dashboard.public_url": "https://lightwork.example.com",
    "dashboard.api_key_prefix": "acme_",  # pragma: allowlist secret - a sample prefix
    "kms.key_id": "arn:aws:kms:us-east-1:123:key/abc",
    "kms.region": "eu-west-1",
    "kms.address": "https://vault.example.com",
    "kms.mount": "lightwork-transit",
    "audit.siem_dest": "https://siem.example.com/raw",
    "audit.sentinel_tenant_id": "11111111-2222-3333-4444-555555555555",
    "audit.sentinel_client_id": "66666666-7777-8888-9999-000000000000",
    "audit.worm.bucket": "acme-audit-worm",
    "audit.worm.prefix": "lightwork/audit/",
    "audit.worm.region": "us-east-1",
    "queue.namespace": "acme-fleet",
    "grpc_dispatch.target": "worker.example.com:50051",
    "federation.node": "east-1",
    "external_agents.approval_webhook": "https://hooks.example.com/approvals",
    "a2a.base_url": "https://agents.example.com",
}
_LIST = {
    "auth.proxy.trusted_proxies": ["10.0.0.5", "10.1.0.0/16"],
    "dashboard.admins": ["user:ada@example.com"],
    "enterprise.allowed_hosts": ["api.example.com"],
    "enterprise.local_providers": ["my-internal-vllm"],
    "a2a.allowed_origins": ["https://app.example.com"],
    "a2a.tools": ["web_search"],
    "a2a.deny_tools": ["shell"],
    "residency.allowed_regions": ["EU"],
    "auth.mfa.amr_values": ["mfa", "corp-push"],
    "auth.mfa.acr_values": ["urn:example:mfa"],
    "auth.mfa.saml_authn_contexts": ["urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"],
    # The saving request comes from loopback: the list must contain it.
    "auth.ip_allowlist.cidrs": ["127.0.0.1/32", "10.0.0.0/8"],
    "auth.ip_allowlist.workspace_cidrs": ["127.0.0.1/32", "10.0.0.0/8"],
}
_SECRETS = {
    "queue.redis_dsn": "rediss://:pw@queue.example.com:6380/0",  # pragma: allowlist secret
    "world_model.dsn": "postgres://lw:pw@db.example.com:5432/lightwork",  # pragma: allowlist secret
}
_THEME = {"bg": "#101020", "panel": "#181830", "text": "#e0e0f0", "accent": "#7aa2f7"}
_NUMBERS = {"audit.unified.custody.max_retry_backoff_seconds": 7200,
            "governed_records.pool_min_size": 2}  # minimum + 1 is its default
# Rows whose kernel reader refuses them alone: saved together with these.
_WITH = {
    "dashboard.require_auth": [{"id": "dashboard.invites", "value": True}],
    "audit.unified.custody.enable": [{"id": "audit.unified.enable", "value": True}],
    "audit.unified.custody.worm_enable": [{"id": "audit.worm.provider", "value": "local"}],
}


def _sample(setting, tmp_path):  # noqa: C901 - one branch per control
    control = setting.control
    if control == "toggle":
        return not setting.default
    if control == "number":
        if setting.id in _NUMBERS:
            return _NUMBERS[setting.id]
        low = setting.minimum if setting.minimum is not None else 0
        value = low + 1 if setting.integer or float(low).is_integer() else low * 2
        return int(value) if setting.integer else value
    if control == "text":
        return _TEXT[setting.id]
    if control == "secret":
        return _SECRETS.get(setting.id, _SECRET)
    if control == "list":
        return _LIST[setting.id]
    if control == "keys":
        return [_KEY]
    if control == "path":
        if setting.path_kind == "folder":
            folder = tmp_path / "places" / setting.id.replace(".", "-")
            folder.mkdir(parents=True, exist_ok=True)
            return str(folder)
        return str(_file(tmp_path, setting.id.replace(".", "-") + ".pem"))
    if setting.id == "plugins.workbench_image":
        return _IMAGE_ID
    choices = [v for v, _ in page._resolved(setting).choices]
    if control == "select":
        return next(v for v in choices if v != setting.default)
    if control == "multiselect":
        return [v for v in choices if v not in (setting.default or [])][:1]
    if setting.id == "tenancy.egress":
        return [{"name": "acme", "allow": ["api.example.com"], "deny": ["*.bad.example"]}]
    if setting.id == "federation.peers":
        return [{"name": "west-1", "target": "west.example.com:50052", "token": _SECRET}]
    if setting.id == "dashboard.themes":
        return [dict(_THEME, name="midnight")]
    columns = setting.columns
    first = next(v for v in [c for c, _ in page._resolved(setting).columns[0].choices] if v)
    return [{"name": choices[0], columns[0].key: first}]


def _expected(setting, value):
    if setting.control == "path":
        return value
    if setting.control == "number" and setting.scale != 1.0:
        return int(value * setting.scale)
    if setting.id == "dashboard.themes":
        return {"midnight": {k: v for k, v in _THEME.items()}}
    if setting.control == "table" and setting.id == "tenancy.egress":
        return {"acme": {"allow": ["api.example.com"], "deny": ["*.bad.example"]}}
    if setting.control == "table":
        return {value[0]["name"]: value[0][setting.columns[0].key]}
    if setting.id == "federation.peers":
        return value  # the kernel reads the passwords unsealed
    return value


def _lookup(tree, setting):
    return catalog.lookup(tree, setting.path)


_IMAGE_ID = "sha256:" + "ab" * 32


@pytest.fixture()
def local_image(monkeypatch):
    """Stand in for one installed practice environment at the engine boundary."""
    from maverick.sandbox import local_images

    def selected(identity):
        if identity != _IMAGE_ID:
            raise local_images.LocalImageUnavailable("The selected practice environment is missing.")
        return local_images.LocalImage(_IMAGE_ID, "Plugin practice")
    monkeypatch.setattr(local_images, "selected", selected)
    monkeypatch.setattr(local_images, "inventory", lambda *, refresh=False: (
        (local_images.LocalImage(_IMAGE_ID, "Plugin practice"),), "One installed environment."))


@pytest.fixture()
def workspaces(monkeypatch):
    monkeypatch.setitem(page._ACCESS_SOURCES, "workspaces", lambda: [("acme", "Acme")])
    monkeypatch.setitem(page._ACCESS_SOURCES, "capability_roles",
                        lambda: [("analyst", "Analyst")])


# ------------------------------------------------------------ round trip
@pytest.mark.parametrize("setting", EDITABLE, ids=lambda s: s.id)
def test_every_access_row_saves_reads_back_and_resets(setting, tmp_path, monkeypatch, as_token,
                                                      workspaces, local_image, audit_rows):
    monkeypatch.setattr(guard, "_prerequisites", lambda changed, values: None)
    monkeypatch.setattr(settings_tests, "check_kms",
                        lambda values: settings_tests.Outcome(True, "ok"))
    value = _sample(setting, tmp_path)
    changes = [*_WITH.get(setting.id, []), {"id": setting.id, "value": value}]
    r = _save(changes, confirm=True)
    assert r.status_code == 200, r.text
    present, stored = _lookup(_loaded(), setting)
    assert present and stored == _expected(setting, value)
    row = _row(setting.id)
    assert row["source"] == "here"
    if setting.secret:
        assert row["value"] is None and row["is_set"] is True
        assert value not in r.text and value not in client.get(API).text
        assert value not in client.get("/settings/all", params={"id": setting.id}).text
        audited = [a for a in audit_rows if a["key"] == setting.key]
        assert audited and audited[-1]["new"] == "set" and value not in repr(audit_rows)
    else:
        assert audit_rows[-1]["key"] == setting.key
    r = _save([{"id": setting.id, "reset": True}], confirm=True)
    assert r.status_code == 200, r.text
    row = _row(setting.id)
    if row["source"] == "here":
        from maverick.config_resets import is_reset
        assert is_reset(page._sources()["here"], setting), "Only an explicit product-default mask may remain local after reset"
    else:
        assert row["source"] in {"default", "installer"}


def _invalid(setting, tmp_path):  # noqa: C901 - one branch per control
    control = setting.control
    if control == "toggle":
        return "yes"
    if control in {"select", "multiselect"}:
        return "no-such-choice" if control == "select" else ["no-such-choice"]
    if control == "number":
        if setting.maximum is not None:
            return setting.maximum + 1
        return (setting.minimum or 0) - 1
    if control in {"text", "secret"}:
        return "not valid <script>" if setting.pattern else "x" * (setting.max_length + 1)
    if control == "list":
        return ["not valid <script>"]
    if control == "keys":
        return ["not a key"]
    if control == "path":
        return str(tmp_path / "missing" / "nothing-here")
    if control == "rules":
        return [{"name": "bad name!", "target": "x"}]
    return [{"name": "no-such-row"}]


@pytest.mark.parametrize("setting", EDITABLE, ids=lambda s: s.id)
def test_every_access_row_refuses_invalid_values(setting, tmp_path, as_token, workspaces,
                                                 audit_rows):
    r = _save([{"id": setting.id, "value": _invalid(setting, tmp_path)}], confirm=True)
    assert r.status_code == 400, r.text
    if setting.control != "keys":  # a key file names no setting: it asks for the right file
        assert r.json()["message"].startswith(setting.label)
    assert not _lookup(_loaded(), setting)[0]
    assert audit_rows == []


# ----------------------------------------------------------------- paths
def test_paths_must_be_full_existing_readable_and_inside_allowed_places(
    tmp_path, tmp_path_factory, monkeypatch, as_token, audit_rows,
):
    key = "auth.saml.sp_key_file"
    outside = tmp_path_factory.mktemp("outside-settings-root") / "status.txt"
    outside.write_text("Synthetic outside-root file", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_SETTINGS_PATH_ROOTS", str(tmp_path))
    cases = {
        "relative/key.pem": "full location",
        str(tmp_path / "nope.pem"): "nothing was found",
        str(tmp_path): "is a folder",
        str(outside): "only uses locations",
    }
    for value, words in cases.items():
        r = _save([{"id": key, "value": value}], confirm=True)
        assert r.status_code == 400, value
        assert words in r.json()["message"], (value, r.json()["message"])
    ordinary_file = _file(tmp_path, "ordinary.pem")
    folder = _save([{"id": "workspace.snapshot_dir", "value": str(ordinary_file)}], confirm=True)
    assert folder.status_code == 400 and "Choose a folder" in folder.json()["message"]
    private = _file(tmp_path, "ok.key", mode=0o600)
    assert _save([{"id": key, "value": str(private)}], confirm=True).status_code == 200
    assert _loaded()["auth"]["saml"]["sp_key_file"] == str(private)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits; Windows native ACL qualification is separate")
def test_private_key_path_rejects_world_readable_posix_mode(tmp_path, as_token, audit_rows):
    world_readable = _file(tmp_path, "open.key", mode=0o644)
    response = _save([{"id": "auth.saml.sp_key_file", "value": str(world_readable)}], confirm=True)
    assert response.status_code == 400 and "anyone on the server can read" in response.json()["message"]


def test_a_link_cannot_lead_outside_the_allowed_places(
    tmp_path, tmp_path_factory, monkeypatch, as_token, audit_rows,
):
    link = tmp_path / "certs" / "sneaky.pem"
    link.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path_factory.mktemp("outside-settings-link") / "key.pem"
    outside.write_text("Synthetic outside-root file", encoding="utf-8")
    try:
        link.symlink_to(outside)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("This Windows account cannot create symbolic links")
        raise
    monkeypatch.setenv("MAVERICK_SETTINGS_PATH_ROOTS", str(tmp_path))
    r = _save([{"id": "queue.redis_ca_certs", "value": str(link)}], confirm=True)
    assert r.status_code == 400 and "only uses locations" in r.json()["message"]


def test_the_check_button_checks_a_location_without_saving(tmp_path, audit_rows):
    good = _file(tmp_path, "ca.pem", mode=0o640)
    r = client.post(CHECK, json={"id": "queue.redis_ca_certs", "value": str(good)})
    assert r.status_code == 200 and r.json() == {
        "ok": True, "message": "Found. Lightwork can read this file."}
    r = client.post(CHECK, json={"id": "queue.redis_ca_certs", "value": str(tmp_path / "x")})
    assert r.json()["ok"] is False
    assert r.json()["message"] == "Nothing was found at that location on the server."
    assert "queue" not in _loaded() and audit_rows == []


# ----------------------------------------------------------------- checks
def test_checks_answer_in_one_sentence_and_never_echo_secrets(monkeypatch, audit_rows):
    seen = {}

    def fake_resolve(host):
        seen["host"] = host
        raise OSError("refused: " + _SECRET)

    from maverick.tools import _ssrf

    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", fake_resolve)
    dsn = f"postgres://lw:{_SECRET}@db.example.com:5432/lightwork"
    r = client.post(CHECK, json={"id": "world_model.dsn", "value": dsn})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and body["message"].endswith(".")
    assert "\n" not in body["message"]
    assert _SECRET not in r.text
    assert seen["host"] == "db.example.com"
    assert "world_model" not in _loaded() or "dsn" not in _loaded()["world_model"]


def test_checks_refuse_private_addresses_through_the_network_guard(audit_rows):
    r = client.post(CHECK, json={"id": "external_agents.approval_webhook",
                                 "value": "https://127.0.0.1/hook"})
    assert r.status_code == 200
    assert r.json()["ok"] is False and "private network" in r.json()["message"]
    r = client.post(CHECK, json={"id": "grpc_dispatch.target", "value": "10.0.0.8:50051"})
    assert r.json()["ok"] is False and "private network" in r.json()["message"]


def test_check_validates_the_entered_value_first(audit_rows):
    r = client.post(CHECK, json={"id": "external_agents.approval_webhook",
                                 "value": "http://hooks.example.com"})
    assert r.json() == {"ok": False, "message": "Approval requests for outside agents go to: "
                                                "this value is not in the expected form."}


def test_checks_are_admin_same_origin_bounded_and_only_where_offered(monkeypatch, audit_rows):
    assert TestClient(app, base_url="http://127.0.0.1").post(
        CHECK, json={"id": "external_agents.approval_webhook"}).status_code == 403
    r = client.post(CHECK, json={"id": "safety.profile"})
    assert r.status_code == 404 and r.json()["message"] == "This setting has nothing to test."
    monkeypatch.setattr(page, "_CHECK_LIMIT", 2)
    monkeypatch.setattr(settings_tests, "fetch", lambda url, headers=None: (200, b"{}"))
    for _ in range(2):
        assert client.post(CHECK, json={"id": "external_agents.approval_webhook",
                                        "value": "https://hooks.example.com/x"}).status_code == 200
    r = client.post(CHECK, json={"id": "external_agents.approval_webhook",
                                 "value": "https://hooks.example.com/x"})
    assert r.status_code == 429 and "Wait a minute" in r.json()["message"]
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:vera", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vera")
    monkeypatch.setattr(page, "_CHECK_TIMES", [])
    assert client.post(CHECK, json={"id": "external_agents.approval_webhook"}).status_code == 403


def _oidc_fetch(issuer="https://login.example.com/realm", keys=True):
    def fetch(url, headers=None):
        if url.endswith("/.well-known/openid-configuration"):
            import json

            return 200, json.dumps({
                "issuer": issuer, "authorization_endpoint": issuer + "/auth",
                "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
            }).encode()
        return 200, b'{"keys": [{"kty": "RSA"}]}' if keys else b'{"keys": []}'
    return fetch


def test_the_sign_in_provider_check(monkeypatch):
    values = {"auth.oidc.issuer": "https://login.example.com/realm"}
    monkeypatch.setattr(settings_tests, "fetch", _oidc_fetch())
    assert settings_tests.check_oidc(values).ok
    monkeypatch.setattr(settings_tests, "fetch", _oidc_fetch(issuer="https://other.example"))
    assert "different address" in settings_tests.check_oidc(values).message
    monkeypatch.setattr(settings_tests, "fetch", _oidc_fetch(keys=False))
    assert not settings_tests.check_oidc(values).ok
    assert not settings_tests.check_oidc({}).ok


def test_browser_sign_in_check_rejects_missing_or_wrong_return_address(monkeypatch):
    monkeypatch.setattr(settings_tests, "fetch", _oidc_fetch())
    values = {
        "auth.oidc.issuer": "https://login.example.com/realm",
        "auth.oidc.client_id": "lightwork",
        "auth.oidc.client_secret": "client-secret",  # pragma: allowlist secret
        "auth.oidc.audience": "lightwork",
        "auth.oidc.session_secret": _SECRET,
        "auth.oidc.redirect_uri": "https://lightwork.example.com/auth/callback",
    }
    assert settings_tests.check_oidc_login(values).ok
    assert not settings_tests.check_oidc_login({**values, "auth.oidc.client_secret": ""}).ok
    assert not settings_tests.check_oidc_login({**values, "auth.oidc.redirect_uri": "https://lightwork.example.com/wrong"}).ok


def test_single_sign_on_check_requires_real_metadata_and_callback(monkeypatch):
    metadata = (
        b'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">'
        b'<IDPSSODescriptor><SingleSignOnService Location="https://idp.example.com/login"/>'
        b'</IDPSSODescriptor></EntityDescriptor>'
    )
    monkeypatch.setattr(settings_tests, "fetch", lambda _url: (200, metadata))
    values = {
        "auth.saml.idp_metadata_url": "https://idp.example.com/metadata",
        "auth.saml.sp_entity_id": "https://lightwork.example.com/saml/metadata",
        "auth.saml.acs_url": "https://lightwork.example.com/saml/acs",
        "auth.oidc.session_secret": _SECRET,
    }
    assert settings_tests.check_saml(values).ok
    assert not settings_tests.check_saml_login({**values, "auth.saml.acs_url": "https://lightwork.example.com/wrong"}).ok
    monkeypatch.setattr(settings_tests, "fetch", lambda _url: (200, b'<EntityDescriptor/>'))
    assert not settings_tests.check_saml(values).ok


def test_the_key_service_check_opens_the_keys_already_in_use(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    from maverick.tenant import kms as tenant_kms

    assert settings_tests.check_kms({"kms.provider": "local"}).ok
    path = tenant_kms._wrapped_dek_path(None)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"not a wrapped key")
    outcome = settings_tests.check_kms({"kms.provider": "local"})
    assert not outcome.ok and "saved records would become unreadable" in outcome.message
    assert not settings_tests.check_kms({"kms.provider": "aws"}).ok



def test_the_key_service_offers_azure_and_rejects_a_bare_key_name():
    from maverick_dashboard.settings_catalog import BY_ID

    assert "azure" in {key for key, _label in BY_ID["kms.provider"].choices}
    assert not settings_tests.check_kms({"kms.provider": "azure", "kms.key_id": "tenant-kek"}).ok


# ------------------------------------------------------------- safety
def test_loosening_access_rows_needs_confirmation(as_token, audit_rows):
    for change in (
        {"id": "auth.saml.want_assertions_signed", "value": False},
        {"id": "dashboard.max_request_mb", "value": 2000},
        {"id": "enterprise.allowed_hosts", "value": ["api.example.com"]},
        {"id": "audit.worm.mode", "value": "GOVERNANCE"},
        {"id": "world_model.synchronous", "value": "NORMAL"},
    ):
        if change["id"] == "world_model.synchronous":
            assert _save([{"id": change["id"], "value": "FULL"}]).status_code == 200
        r = _save([change])
        assert r.status_code == 409, change
        assert r.json()["confirm"][0]["id"] == change["id"]
        assert _save([change], confirm=True).status_code == 200
    assert audit_rows[-1]["confirmed"] is True


def test_cross_checks_keep_the_kernel_startable(as_token, audit_rows):
    r = _save([{"id": "client.enforce", "value": True}], confirm=True)
    assert r.status_code == 409 and "no client name" in r.json()["message"]
    r = _save([{"id": "audit.worm.provider", "value": "s3"}], confirm=True)
    assert r.status_code == 400 and "Storage bucket" in r.json()["message"]
    r = _save([{"id": "audit.unified.custody.retry_backoff_seconds", "value": 600},
               {"id": "audit.unified.custody.max_retry_backoff_seconds", "value": 60}],
              confirm=True)
    assert r.status_code == 400
    r = _save([{"id": "queue.backend", "value": "arq"}], confirm=True)
    assert r.status_code == 409 and "queue key" in r.json()["message"]
    r = _save([{"id": "world_model.backend", "value": "postgres"}], confirm=True)
    assert r.status_code == 409 and "connection filled in" in r.json()["message"]
    assert "queue" not in _loaded() and "world_model" not in _loaded()


def test_the_off_server_signing_key_is_needed_first(monkeypatch, as_token, audit_rows):
    from maverick.audit import signing

    monkeypatch.setattr(signing, "active_key_is_offhost", lambda: False)
    r = _save([{"id": "audit.require_offhost_key", "value": True}], confirm=True)
    assert r.status_code == 409 and "Set up that key first" in r.json()["message"]
    monkeypatch.setattr(signing, "active_key_is_offhost", lambda: True)
    assert _save([{"id": "audit.require_offhost_key", "value": True}],
                 confirm=True).status_code == 200


def test_key_service_changes_are_checked_then_confirmed(monkeypatch, as_token, audit_rows):
    outcome = settings_tests.Outcome(False, "Lightwork could not use this key service.")
    monkeypatch.setattr(settings_tests, "check_kms", lambda values: outcome)
    r = _save([{"id": "kms.key_id", "value": "alias/lightwork"},
               {"id": "kms.provider", "value": "aws"}], confirm=True)
    assert r.status_code == 409 and r.json()["lockout"] is True
    assert "Nothing was changed" in r.json()["message"]
    assert "kms" not in _loaded() and audit_rows == []
    monkeypatch.setattr(settings_tests, "check_kms",
                        lambda values: settings_tests.Outcome(True, "ok"))
    r = _save([{"id": "kms.key_id", "value": "alias/lightwork"},
               {"id": "kms.provider", "value": "aws"}])
    assert r.status_code == 409
    assert any(item.get("kind") == "access" for item in r.json()["confirm"])
    r = _save([{"id": "kms.key_id", "value": "alias/lightwork"},
               {"id": "kms.provider", "value": "aws"}], confirm=True)
    assert r.status_code == 200 and _loaded()["kms"]["provider"] == "aws"


# ------------------------------------------------------------ lock-out
def test_turning_on_company_sign_in_needs_a_passing_test(monkeypatch, audit_rows):
    base = [{"id": "auth.oidc.issuer", "value": _TEXT["auth.oidc.issuer"]},
            {"id": "auth.oidc.client_id", "value": "lightwork"},
            {"id": "auth.oidc.client_secret", "value": "client-secret"},
            {"id": "auth.oidc.audience", "value": "lightwork"},
            {"id": "auth.oidc.redirect_uri", "value": _TEXT["auth.oidc.redirect_uri"]},
            {"id": "auth.oidc.session_secret", "value": _SECRET}]
    fail = settings_tests.Outcome(False, "Lightwork could not reach this address. Check it "
                                         "and try again.")
    monkeypatch.setattr(settings_tests, "check_oidc", lambda values: fail)
    r = _save([*base, {"id": "auth.oidc.enabled", "value": True}], confirm=True)
    assert r.status_code == 409 and r.json()["lockout"] is True
    assert "would lock you out" in r.json()["message"]
    assert "auth" not in _loaded() and audit_rows == []

    monkeypatch.setattr(settings_tests, "check_oidc",
                        lambda values: settings_tests.Outcome(True, "ok"))
    r = _save([*base, {"id": "auth.oidc.enabled", "value": True}], confirm=True)
    assert r.status_code == 409 and "no person has completed a sign-in" in r.json()["message"]

    with_admin = [*base, {"id": "dashboard.admins", "value": ["user:ada@example.com"]},
                  {"id": "auth.oidc.enabled", "value": True}]
    r = _save(with_admin, confirm=True)
    assert r.status_code == 409 and r.json()["lockout"] is True
    assert "no person has completed a sign-in" in r.json()["message"]
    assert "auth" not in _loaded() and audit_rows == []


def test_half_set_up_single_sign_on_is_refused(audit_rows):
    # Any single sign-on detail ends access without sign-in on this computer.
    r = _save([{"id": "auth.saml.acs_url", "value": _TEXT["auth.saml.acs_url"]}], confirm=True)
    assert r.status_code == 409 and "isn't fully set up" in r.json()["message"]
    assert "auth" not in _loaded()


def test_requiring_sign_in_with_nothing_set_up_is_refused(audit_rows):
    r = _save([{"id": "dashboard.require_auth", "value": True}], confirm=True)
    assert r.status_code == 409 and "refuse to start" in r.json()["message"]


def test_turning_on_invitations_or_the_proxy_from_an_unsigned_session_is_refused(audit_rows):
    r = _save([{"id": "dashboard.invites", "value": True}], confirm=True)
    assert r.status_code == 409 and "owner account first" in r.json()["message"]
    r = _save([{"id": "auth.proxy.trusted_proxies", "value": ["10.0.0.5"]},
               {"id": "auth.proxy.enabled", "value": True}], confirm=True)
    assert r.status_code == 409 and "company proxy" in r.json()["message"]


def test_enterprise_protections_from_an_unsigned_session_are_refused(audit_rows):
    r = _save([{"id": "enterprise.mode", "value": True}], confirm=True)
    assert r.status_code == 409 and r.json()["lockout"] is True
    r = _save([{"id": "profile.name", "value": "enterprise"}], confirm=True)
    assert r.status_code == 409 and r.json()["lockout"] is True
    assert "profile" not in _loaded()
    assert "enterprise" not in _loaded()


def test_the_access_token_is_the_break_glass_way_in(as_token, audit_rows):
    r = _save([{"id": "dashboard.invites", "value": True}], confirm=True)
    assert r.status_code == 200


def _invite_client(email: str) -> TestClient:
    """A browser signed in with an invitation session (a real, signed cookie)."""
    from maverick_dashboard import invites

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"},
                      cookies={"mvk_session": invites.mint_local_session(email)})


def _base_config(text: str) -> None:
    from maverick import config

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text(text, encoding="utf-8")
    config.reset_config_cache()


def test_you_cannot_remove_your_own_administrator_access(audit_rows):
    _base_config('[dashboard]\ninvites = true\n'
                 'admins = ["user:ada@example.com", "user:bo@example.com"]\n')
    ada = _invite_client("ada@example.com")
    r = _save([{"id": "dashboard.admins", "value": ["user:bo@example.com"]}], confirm=True,
              http=ada)
    assert r.status_code == 409 and "your own administrator access" in r.json()["message"]
    r = _save([{"id": "dashboard.default_role", "value": "viewer"}], confirm=True, http=ada)
    assert r.status_code == 200, r.text  # ada stays an administrator through the list
    bo = _invite_client("bo@example.com")
    assert _save([{"id": "dashboard.admins", "value": ["user:bo@example.com"]}],
                 confirm=True, http=bo).status_code == 200


def test_turning_off_the_way_you_signed_in_is_refused(audit_rows):
    _base_config('[dashboard]\ninvites = true\nadmins = ["user:ada@example.com"]\n')
    ada = _invite_client("ada@example.com")
    assert _save([{"id": "dashboard.invite_email", "value": False}], http=ada).status_code == 200
    r = _save([{"id": "dashboard.invites", "value": False}], confirm=True, http=ada)
    assert r.status_code == 409 and "no working way back in" in r.json()["message"]
    r = _save([{"id": "dashboard.session_secret", "value": _SECRET}], confirm=True, http=ada)
    assert r.status_code == 409 and "no working way back in" in r.json()["message"]
    assert "session_secret" not in _loaded()["dashboard"]
    assert _loaded()["dashboard"]["invites"] is True


def test_disabled_company_sign_in_details_keep_the_owner_passphrase_available(monkeypatch,
                                                                              audit_rows):
    _base_config('[dashboard]\ninvites = true\nadmins = ["user:ada@example.com"]\n')
    monkeypatch.setattr(guard, "_is_owner", lambda principal: principal == "user:ada@example.com")
    ada = _invite_client("ada@example.com")
    change = [{"id": "auth.oidc.client_id", "value": "lightwork"}]
    r = _save(change, http=ada)
    assert r.status_code == 200
    from maverick_dashboard import local_owner

    local_owner._policy()
    assert _save([{"id": "auth.oidc.redirect_uri", "value": _TEXT["auth.oidc.redirect_uri"]}],
                 http=ada).status_code == 200


def test_partial_saml_save_cannot_strand_local_owner_after_sign_out(audit_rows):
    password = "a long local owner fixture phrase"  # pragma: allowlist secret
    with TestClient(app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 53210),
                    headers={"Origin": "http://127.0.0.1:8765"},
                    follow_redirects=False) as owner:
        response = owner.post("/auth/local-owner", data={
            "email": "owner@example.com", "password": password, "confirm": "yes"})
        assert response.status_code == 303, response.text
        # The owner starts in the first workspace; the browser client sends its guard.
        owner.headers["X-Lightwork-Expected-Tenant"] = "local"
        # Disabled OIDC details can be staged without closing owner recovery.
        assert _save([{"id": "auth.oidc.client_id", "value": "lightwork"}],
                     http=owner).status_code == 200
        refused = _save([{"id": "auth.saml.acs_url",
                          "value": _TEXT["auth.saml.acs_url"]}], confirm=True, http=owner)
        assert refused.status_code == 409 and refused.json()["lockout"] is True
        assert "saml" not in _loaded().get("auth", {})
        owner.cookies.clear()
        assert owner.get("/auth/local-login").status_code == 200
        response = owner.post("/auth/local-login", data={
            "email": "owner@example.com", "password": password})
        assert response.status_code == 303, response.text
        assert owner.get(API).status_code == 200


def _request(host="10.0.0.5", headers=None):
    return SimpleNamespace(client=SimpleNamespace(host=host), headers=headers or {},
                           state=SimpleNamespace(principal=None))


def test_a_proxy_session_survives_only_while_its_proxy_stays_trusted():
    before = guard.access_for({"auth": {"proxy": {"enabled": True,
                                                  "trusted_proxies": ["10.0.0.5"]}}})
    request = _request(headers={"X-Forwarded-User": "ada"})
    assert guard._route_survives("proxy", request, before, before)
    moved = guard.access_for({"auth": {"proxy": {"enabled": True,
                                                 "trusted_proxies": ["10.9.9.9"]}}})
    assert not guard._route_survives("proxy", request, before, moved)
    renamed = guard.access_for({"auth": {"proxy": {"enabled": True, "header": "X-User",
                                                   "trusted_proxies": ["10.0.0.5"]}}})
    assert not guard._route_survives("proxy", request, before, renamed)


def test_invitation_sessions_end_when_company_sign_in_takes_over():
    before = guard.access_for({"dashboard": {"invites": True}})
    after = guard.access_for({"dashboard": {"invites": True}, "auth": {"oidc": {
        "enabled": True, "client_id": "x", "client_secret": "client-secret",
        "redirect_uri": "https://lightwork.example.com/auth/callback",
        "audience": "x", "session_secret": _SECRET,
        "issuer": "https://login.example.com"}}})
    assert guard._route_survives("invite", _request(), before, before)
    assert not guard._route_survives("invite", _request(), before, after)


def test_provider_changes_do_not_count_existing_session_or_bearer_as_recovery():
    original = {"enabled": True, "issuer": "https://login.example.com",
                "client_id": "lightwork", "client_secret": "client-secret",
                "redirect_uri": "https://lightwork.example.com/auth/callback",
                "audience": "lightwork", "jwks_uri": "https://login.example.com/keys",
                "algorithms": ["RS256"], "session_secret": _SECRET}
    before = guard.access_for({"auth": {"oidc": original}})
    assert guard._route_survives("session", _request(), before, before)
    assert guard._route_survives("bearer", _request(), before, before)
    for key, changed_value in (
        ("issuer", "https://other.example.com"),
        ("client_secret", "different-secret"),
        ("redirect_uri", "https://other.example.com/auth/callback"),
        ("audience", "other-audience"),
        ("jwks_uri", "https://other.example.com/keys"),
        ("algorithms", ["ES256"]),
    ):
        after = guard.access_for({"auth": {"oidc": {**original, key: changed_value}}})
        assert not guard._route_survives("session", _request(), before, after), key
        assert not guard._route_survives("bearer", _request(), before, after), key


def test_turning_everything_off_on_this_computer_opens_it_again(monkeypatch):
    before = guard.access_for({"dashboard": {"invites": True}})
    after = guard.access_for({"dashboard": {"invites": False}})
    assert after.anonymous_ok
    warning = guard._way_back(_request(host="127.0.0.1"), "invite", "user:ada@example.com",
                              {}, after, {})
    assert "open again without sign-in" in warning
    with pytest.raises(guard.Refused):
        guard._way_back(_request(host="10.0.0.7"), "invite", "user:ada@example.com",
                        {}, after, {})
    assert before.invites and not after.invites


# ------------------------------------------------------------ readers
def test_governed_record_store_follows_the_saved_choice(monkeypatch, as_token, audit_rows):
    from maverick import governed_records

    monkeypatch.setattr(guard, "_prerequisites", lambda changed, values: None)
    assert governed_records._selection().kind == "local"
    r = _save([{"id": "world_model.dsn", "value": _SECRETS["world_model.dsn"]},
               {"id": "governed_records.backend", "value": "postgres"},
               {"id": "governed_records.pool_size", "value": 4}], confirm=True)
    assert r.status_code == 200, r.text
    selected = governed_records._selection()
    assert selected.kind == "postgres" and selected.dsn == _SECRETS["world_model.dsn"]
    assert selected.pool_size == 4
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    assert governed_records._selection().kind == "local"  # the environment still wins


def test_saved_values_reach_their_kernel_readers(monkeypatch, tmp_path, as_token, audit_rows):
    from maverick import config

    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme-corp")  # chosen at install
    from maverick import client as binding
    from maverick import grpc_tls, oidc, paths, proxy_auth
    from maverick.tenant import kms as tenant_kms
    from maverick.world_model_backends import postgres
    from maverick_dashboard import invites, request_size

    monkeypatch.setattr(guard, "_prerequisites", lambda changed, values: None)
    monkeypatch.setattr(settings_tests, "check_kms",
                        lambda values: settings_tests.Outcome(True, "ok"))
    r = _save([
        {"id": "auth.oidc.issuer", "value": _TEXT["auth.oidc.issuer"]},
        {"id": "auth.proxy.header", "value": "X-Auth-User"},
        {"id": "dashboard.max_request_mb", "value": 50},
        {"id": "dashboard.invite_session_days", "value": 7},
        {"id": "tenancy.by_user", "value": True},
        {"id": "grpc.tls", "value": True},
        {"id": "kms.dek_cache_ttl", "value": 120},
        {"id": "world_model.dsn", "value": _SECRETS["world_model.dsn"]},
        {"id": "client.enforce", "value": True},
    ], confirm=True)
    assert r.status_code == 200, r.text
    binding.reset_client_cache()
    assert oidc.load_oidc_config().issuer == _TEXT["auth.oidc.issuer"]
    assert proxy_auth.proxy_header_name() == "X-Auth-User"
    assert request_size.max_request_bytes() == 50 * 1024 * 1024
    assert invites.session_ttl_seconds() == 7 * 86400
    assert paths.tenant_by_user_enabled() is True
    assert grpc_tls.tls_enabled("grpc") is True and grpc_tls._section("elsewhere") == {}
    assert tenant_kms._dek_cache_ttl() == 120
    assert postgres._configured_dsn() == _SECRETS["world_model.dsn"]
    assert binding.client_id() == "acme-corp" and binding.client_binding_enforced() is True
    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert "pw@db" not in stored
    monkeypatch.setenv("MAVERICK_PG_DSN", "postgres://env@db/lightwork")
    assert _row("world_model.dsn")["locked"] is True


def test_the_dashboard_session_key_is_sealed_in_the_settings_file(tmp_path, as_token,
                                                                 audit_rows):
    from maverick import config
    from maverick_dashboard import invites, settings_store

    r = _save([{"id": "dashboard.session_secret", "value": _SECRET}], confirm=True)
    assert r.status_code == 200
    raw = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert _SECRET not in raw and "MVKAR1:" in raw
    assert invites.local_session_secret() == _SECRET
    settings_store.set_toggle("features", "skills", False)  # another save keeps it sealed
    raw = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert _SECRET not in raw and "MVKAR1:" in raw


def test_the_page_shows_the_new_controls_in_plain_language(workspaces):
    from test_support.plain_language import developer_terms

    html = every_group(client)
    assert "Server &amp; deployment" in html
    assert "Test connection" in html and "Check this location" in html
    assert 'data-control="path"' in html
    assert developer_terms(html) == []


def test_the_page_renders_a_row_for_each_vendor_audit_control(workspaces):
    # The plain-language test above checks wording only; this one checks the rows exist.
    html = every_group(client)
    for setting_id in ("audit.datadog_api_key", "audit.sentinel_tenant_id",
                       "audit.sentinel_client_id", "audit.sentinel_client_secret"):
        assert f'data-setting-id="{setting_id}"' in html, setting_id


def test_vendor_destination_settings_reach_the_forwarder(monkeypatch, as_token, audit_rows):
    from maverick.audit import forwarder

    sentinel = ("sentinel://my-dce-5kyl.eastus-1.ingest.monitor.azure.com/"
                "dcr-000a00a000a00000a000000aa000a0aa/Custom-MaverickAudit")
    r = _save([
        {"id": "audit.siem_dest", "value": sentinel},
        {"id": "audit.datadog_api_key", "value": _SECRET},
        {"id": "audit.sentinel_tenant_id", "value": _TEXT["audit.sentinel_tenant_id"]},
        {"id": "audit.sentinel_client_id", "value": _TEXT["audit.sentinel_client_id"]},
        {"id": "audit.sentinel_client_secret", "value": _SECRET},
    ], confirm=True)
    assert r.status_code == 200, r.text
    assert forwarder._audit_secret("MAVERICK_DATADOG_API_KEY", "datadog_api_key") == _SECRET
    assert forwarder._sentinel_credentials() == (
        _TEXT["audit.sentinel_tenant_id"], _TEXT["audit.sentinel_client_id"], _SECRET)
    assert _row("audit.datadog_api_key")["is_set"] is True
    assert _SECRET not in r.text and _SECRET not in client.get(API).text
    monkeypatch.setenv("MAVERICK_SENTINEL_CLIENT_SECRET", "from-the-environment")
    assert forwarder._sentinel_credentials()[2] == "from-the-environment"
    # Saving checks the address shape; the vendor form (site, stream) is checked by
    # the Test connection button and again when forwarding, as for the other schemes.
    for bad in ("ftp://siem.example.com/raw", "datadog://example com"):
        r = _save([{"id": "audit.siem_dest", "value": bad}], confirm=True)
        assert r.status_code == 400, bad


def test_vendor_addresses_are_checked_for_form_and_reachability(monkeypatch, audit_rows):
    reached = []
    monkeypatch.setattr(settings_tests, "reach", lambda host, port: reached.append((host, port)))
    r = client.post(CHECK, json={"id": "audit.siem_dest", "value": "datadog://datadoghq.eu"})
    assert r.json() == {"ok": True, "message": "Lightwork reached your security monitoring service."}
    assert reached == [("http-intake.logs.datadoghq.eu", 443)]
    r = client.post(CHECK, json={"id": "audit.siem_dest", "value": "datadog://example.com"})
    assert r.json()["ok"] is False and "form this service needs" in r.json()["message"]
    assert len(reached) == 1


def test_switches_that_lived_only_in_the_environment_now_have_settings(monkeypatch, as_token,
                                                                      audit_rows):
    from maverick import (
        a2a,
        a2a_tasks,
        db_timeouts,
        federation,
        residency,
        worker,
        workspace_journal,
        world_model,
    )
    from maverick.audit import forwarder
    from maverick.grpc_api import server as grpc_server
    from maverick_dashboard import _lifecycle, _shared, scim
    from maverick_dashboard import app as dashboard_app

    r = _save([
        {"id": "a2a.token", "value": _SECRET},
        {"id": "a2a.base_url", "value": "https://agents.example.com"},
        {"id": "a2a.allowed_origins", "value": ["https://app.example.com"]},
        {"id": "a2a.max_concurrency", "value": 2},
        {"id": "a2a.max_dollars", "value": 1.5},
        {"id": "dashboard.max_goals_per_min", "value": 7},
        {"id": "dashboard.max_sse", "value": 9},
        {"id": "dashboard.shutdown_timeout_seconds", "value": 45},
        {"id": "dashboard.scim_token", "value": _SECRET},
        {"id": "world_model.connect_timeout_seconds", "value": 20},
        {"id": "world_model.statement_timeout_ms", "value": 12},
        {"id": "world_model.orphan_reclaim_seconds", "value": 300},
        {"id": "queue.goal_acquire_timeout_seconds", "value": 9},
        {"id": "audit.siem_token", "value": _SECRET},
        {"id": "audit.siem_allow_insecure", "value": True},
        {"id": "federation.rate_limit", "value": 11},
        {"id": "grpc.rate_limit", "value": 13},
        {"id": "grpc.token", "value": _SECRET},
        {"id": "residency.allowed_regions", "value": ["DE"]},
        {"id": "workspace.journal_strict", "value": True},
        {"id": "workspace.journal_max_file_mb", "value": 3},
    ], confirm=True)
    assert r.status_code == 200, r.text
    assert a2a_tasks._a2a_value("MAVERICK_A2A_TOKEN", "token") == _SECRET
    assert a2a._base_url() == "https://agents.example.com"
    assert "https://app.example.com" in a2a._a2a_allowed_origins()
    assert a2a_tasks._max_concurrency() == 2
    assert float(a2a_tasks._a2a_value("MAVERICK_A2A_MAX_DOLLARS", "max_dollars", 5.0)) == 1.5
    assert dashboard_app._max_goals_per_min() == 7
    assert dashboard_app._max_goals_global_per_min() == 70
    assert _shared._max_sse_streams() == 9
    assert _lifecycle.shutdown_seconds() == 45
    assert scim._scim_secrets() == [_SECRET]
    assert db_timeouts.postgres_connect_timeout() == 20
    assert world_model.reclaim_window_seconds() == 300
    assert worker._queue_goal_acquire_timeout() == 9
    assert forwarder._siem_token() == _SECRET and forwarder._insecure_siem_allowed() is True
    assert federation._fed_rate_limit_per_min() == 11
    assert grpc_server._grpc_rate_limit_per_min() == 13
    assert grpc_server._resolve_bearer_token() == _SECRET
    assert residency.allowed_regions() == {"DE"}
    assert workspace_journal.strict() is True
    assert workspace_journal._max_file_bytes() == 3 * 1024 * 1024
    assert _loaded()["world_model"]["statement_timeout_ms"] == 12000
    # The environment still wins over every one of them.
    for name, value in (("MAVERICK_A2A_MAX_CONCURRENCY", "5"),
                        ("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "3"),
                        ("MAVERICK_ORPHAN_RECLAIM_SECONDS", "10"),
                        ("MAVERICK_FEDERATION_RATE_LIMIT", "4"),
                        ("MAVERICK_SIEM_ALLOW_INSECURE", "0"),
                        ("MAVERICK_GRPC_BEARER_TOKEN", "from-the-environment")):
        monkeypatch.setenv(name, value)
    assert a2a_tasks._max_concurrency() == 5
    assert dashboard_app._max_goals_per_min() == 3
    assert world_model.reclaim_window_seconds() == 10
    assert federation._fed_rate_limit_per_min() == 4
    assert forwarder._insecure_siem_allowed() is False
    assert grpc_server._resolve_bearer_token() == "from-the-environment"
    assert _row("dashboard.max_goals_per_min")["locked"] is True


def test_the_default_permission_set_is_never_stored_empty(workspaces, audit_rows):
    r = _save([{"id": "role_assignments.default", "value": ""}], confirm=True)
    assert r.status_code == 400
    assert _save([{"id": "role_assignments.default", "value": "analyst"}],
                 confirm=True).status_code == 200
    assert _save([{"id": "role_assignments.default", "reset": True}],
                 confirm=True).status_code == 200
    assert "role_assignments" not in _loaded()


def test_linked_server_passwords_are_sealed_kept_and_never_shown(as_token, audit_rows):
    from maverick import config, federation

    peer = {"name": "west-1", "target": "west.example.com:50052", "token": _SECRET}
    r = _save([{"id": "federation.peers", "value": [peer]}], confirm=True)
    assert r.status_code == 200, r.text
    raw = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert _SECRET not in raw and "MVKAR1:" in raw
    assert [(p.name, p.target, p.token) for p in federation.load_peers()] == [
        ("west-1", "west.example.com:50052", _SECRET)]
    row = _row("federation.peers")
    assert row["grid"]["rows"][0]["cells"]["token"] == {"is_set": True}
    assert _SECRET not in client.get(API).text and _SECRET not in repr(audit_rows)
    assert audit_rows[-1]["new"] == [{"name": "west-1", "target": "west.example.com:50052",
                                      "token": "set"}]
    # Leaving the password empty keeps it; a new server must have one.
    moved = {"name": "west-1", "target": "west2.example.com:50052", "token": ""}
    assert _save([{"id": "federation.peers", "value": [moved]}], confirm=True).status_code == 200
    assert federation.load_peers()[0].token == _SECRET
    assert federation.load_peers()[0].target == "west2.example.com:50052"
    fresh = {"name": "east-2", "target": "east.example.com:50052", "token": ""}
    r = _save([{"id": "federation.peers", "value": [moved, fresh]}], confirm=True)
    assert r.status_code == 400 and "shared password for each new linked server" in r.json()["message"]
    r = _save([{"id": "federation.peers", "value": [moved, dict(fresh, token="short")]}],
              confirm=True)
    assert r.status_code == 400


def test_the_server_access_token_can_be_set_here_and_is_checked(monkeypatch, audit_rows):
    from maverick import config
    from maverick_dashboard import _shared, settings_store

    # Nobody can sign in yet: setting a token would lock this browser out.
    r = _save([{"id": "dashboard.token", "value": _TOKEN}], confirm=True)
    assert r.status_code == 409 and r.json()["lockout"] is True
    assert _shared.dashboard_token() == ""
    # Set by a deployment tool (as a break-glass holder would), it works.
    settings_store.set_catalog_values({("dashboard", "token"): _TOKEN})
    raw = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert _TOKEN not in raw
    assert _shared.dashboard_token() == _TOKEN
    assert client.get(API).status_code == 401
    bearer = {"Authorization": "Bearer " + _TOKEN}
    assert client.get(API, headers=bearer).status_code == 200
    assert _row_with(bearer, "dashboard.token")["is_set"] is True
    # Removing it with only the token to get back in would lock you out.
    r = save_catalog(client, API, json={"changes": [{"id": "dashboard.token", "reset": True}],
                               "confirm": True}, headers=bearer)
    assert r.status_code == 409 and "no other working way back in" in r.json()["message"]
    r = save_catalog(client, API, json={"changes": [{"id": "dashboard.token", "value": "short"}],
                               "confirm": True}, headers=bearer)
    assert r.status_code == 400 and r.json()["message"].startswith("Server access token")
    # The environment still wins.
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "other-token-from-the-environment-0000")
    assert _shared.dashboard_token() == "other-token-from-the-environment-0000"
    assert client.get(API, headers=bearer).status_code == 401


def _row_with(headers, setting_id):
    for group in client.get(API, headers=headers).json()["groups"]:
        for row in group["settings"]:
            if row["id"] == setting_id:
                return row
    raise AssertionError(setting_id)


def test_install_record_and_profile_reach_their_readers(as_token, audit_rows):
    from maverick import config

    r = _save([{"id": "deployment.type", "value": "vps"}], confirm=True)
    assert r.status_code == 200, r.text
    assert config.get_deployment()["type"] == "vps"
    from maverick import profile

    assert _save([{"id": "profile.name", "value": "enterprise"}]).status_code == 200
    assert profile.active_profile() == "enterprise"


def test_the_oversight_report_sees_delegation_rules_set_on_the_page():
    from maverick import ai_act_package, config

    assert ai_act_package._oversight()["approval_delegation_configured"] is False
    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text(
        '[approval]\ndelegation = [{ delegate_to = "user:ada", tool_glob = "*" }]\n',
        encoding="utf-8")
    config.reset_config_cache()
    assert ai_act_package._oversight()["approval_delegation_configured"] is True


def test_colour_themes_are_made_on_the_page_and_offered_to_everyone(as_token, audit_rows):
    from maverick_dashboard import themes

    theme = dict(_THEME, name="midnight", warn="#FFAA00", danger="")
    r = _save([{"id": "dashboard.themes", "value": [theme]}], confirm=True)
    assert r.status_code == 200, r.text
    assert themes.custom_themes() == {"midnight": dict(
        _THEME, warn="#ffaa00", danger="#e0e0f0", muted="#e0e0f0", border="#e0e0f0",
    )}
    assert "body.theme-midnight" in themes.theme_css(themes.custom_themes())
    assert "midnight" in [c["value"] for c in _row("dashboard.theme")["choices"]]
    assert _save([{"id": "dashboard.theme", "value": "midnight"}]).status_code == 200
    for bad in (dict(theme, name="dark"), dict(theme, name="Bad Name"),
                dict(theme, bg="red"), {k: v for k, v in theme.items() if k != "text"}):
        r = _save([{"id": "dashboard.themes", "value": [bad]}], confirm=True)
        assert r.status_code == 400, bad
        assert r.json()["message"].startswith("Your own colour themes")
