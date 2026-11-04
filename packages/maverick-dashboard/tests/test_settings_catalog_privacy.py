"""Settings > All settings: the privacy and consent module rows (WP4).

Every row saves and reads back through the catalog API and lands where the
kernel's ``load_config`` returns it; values outside the reader's bounds or
formats are refused; secrets and the names of server-held keys are sealed and
never shown or audited; loosening a protection needs a confirmation (409, then
200 with ``confirm``); every change writes one audit row; combinations a
module's reader would refuse are refused before anything is written; and the
saved values reach the real module parsers.
"""
from __future__ import annotations

import math
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard import settings_catalog_privacy as privacy
from maverick_dashboard.app import app

from test_support.settings_pages import every_group, save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"

_IDS = [row.id for row in privacy.entries(catalog.S, catalog.C, catalog.Column)]
ROWS = [catalog.BY_ID[i] for i in _IDS]

_DEST = "consent_preferences.delivery.destinations"
_SRC = "privacy_automation.rights_orchestration.source_adapters"
_FIX = "privacy_automation.data_discovery.remediation"
_NOTICE = "privacy_automation.notice_governance.publication_runtime"
_ID = "consent_preferences.identity"

_SALESFORCE = {
    f"{_DEST}.salesforce.destination_id": "sf-main",
    f"{_DEST}.salesforce.origin": "https://acme.my.salesforce.com",
    f"{_DEST}.salesforce.credential_secret_ref": "$MAVERICK_SALESFORCE_CONSENT_TOKEN",
    f"{_DEST}.salesforce.credential_revision": 1,
    f"{_DEST}.salesforce.api_version": "v65.0",
    f"{_DEST}.salesforce.object_api_name": "Lightwork_Consent_Event__c",
    f"{_DEST}.salesforce.external_id_field": "Lightwork_Message_Id__c",
    f"{_DEST}.salesforce.payload_digest_field": "Lightwork_Payload_SHA256__c",
}
_GRAPH = f"{_SRC}.providers.microsoft_graph_users"
_GRAPH_FIELDS = {
    f"{_GRAPH}.source_id": "directory-graph",
    f"{_GRAPH}.origin": "https://graph.microsoft.com",
    f"{_GRAPH}.credential_ref": "env:GRAPH_RIGHTS_TOKEN",
    f"{_GRAPH}.capabilities": ["discover", "retrieve"],
}

# Values that are valid and differ from the default, for rows a number or a
# switch can't cover on its own.
SAMPLES: dict[str, object] = {
    f"{_ID}.issuer": "https://login.example.com/acme/v2.0",
    f"{_ID}.audience": "lightwork-consent",
    f"{_ID}.jwks_origin": "https://login.example.com",
    **_SALESFORCE,
    f"{_DEST}.enabled_providers": ["salesforce"],
    f"{_DEST}.marketo.destination_id": "mkto-main",
    f"{_DEST}.marketo.origin": "https://123-ABC-456.mktorest.com",
    f"{_DEST}.marketo.credential_secret_ref": "${MAVERICK_MARKETO_CONSENT_TOKEN}",
    f"{_DEST}.marketo.custom_object_name": "lightworkConsentEvent",
    f"{_DEST}.marketo.dedupe_field": "lightworkMessageId",
    f"{_DEST}.marketo.message_id_field": "lightworkMessageRef",
    f"{_DEST}.marketo.payload_digest_field": "payloadSha256",
    f"{_DEST}.adobe_experience_platform.destination_id": "aep-main",
    f"{_DEST}.adobe_experience_platform.origin": "https://dcs.adobedc.net",
    f"{_DEST}.adobe_experience_platform.credential_secret_ref": "$MAVERICK_AEP_CONSENT_CREDENTIAL",
    f"{_DEST}.adobe_experience_platform.connection_id": "conn-1",
    f"{_DEST}.adobe_experience_platform.flow_id": "flow-1",
    f"{_DEST}.adobe_experience_platform.dataset_id": "dataset-1",
    f"{_DEST}.adobe_experience_platform.schema_id": "https://ns.adobe.com/acme/schemas/1",
    f"{_DEST}.adobe_experience_platform.ims_org_id": "ABC123@AdobeOrg",
    f"{_DEST}.snowflake.destination_id": "snow-main",
    f"{_DEST}.snowflake.origin": "https://acme.eu-west-1.snowflakecomputing.com",
    f"{_DEST}.snowflake.credential_secret_ref": "$MAVERICK_SNOWFLAKE_CONSENT_TOKEN",
    f"{_DEST}.snowflake.database": "LIGHTWORK",
    f"{_DEST}.snowflake.schema": "CONSENT",
    f"{_DEST}.snowflake.table": "PREFERENCE_EVENTS",
    f"{_DEST}.snowflake.warehouse": "LIGHTWORK_WH",
    f"{_DEST}.snowflake.role": "LIGHTWORK_CONSENT_WRITER",
    "consent_preferences.native_sdk.receipt_key_id": "native-consent-receipt",
    "consent_preferences.native_sdk.receipt_key_secret_ref": "ACME_NATIVE_CONSENT_KEY",  # pragma: allowlist secret
    "consent_preferences.profile_data.custom_index.key_secret_ref": "ACME_CONSENT_INDEX_KEY",  # pragma: allowlist secret
    "consent_preferences.trust_center.branding.key_ref": "vault:brand-asset-key",
    "consent_registry.subject_salt": "a-private-salt-value-0001",  # pragma: allowlist secret
    "consent_registry.webhook_secret_env": "ACME_CONSENT_WEBHOOK_SECRET",  # pragma: allowlist secret
    "data_use_governance.snowflake.origin": "https://acme.snowflakecomputing.com",
    "data_use_governance.snowflake.credential_secret_ref": "$ACME_DATA_USE_TOKEN",
    "data_use_governance.databricks.origin": "https://acme.cloud.databricks.com",
    "data_use_governance.databricks.credential_secret_ref": "${ACME_DATA_USE_TOKEN}",
    "privacy_automation.data_discovery.adapters.enabled_providers": ["aws_s3"],
    "privacy_automation.drop_management.principal_binding_key_ref": "vault://kv/drop-binding",
    f"{_NOTICE}.active_tenants": ["default"],
    "privacy_automation.rights_consumer_delivery.digest_key_ref": "env:ACME_RIGHTS_DIGEST_KEY",
    "privacy_automation.rights_consumer_delivery.export_signing_key_ref":
        "env:ACME_RIGHTS_EXPORT_KEY",
    "privacy_automation.rights_consumer_delivery.package_encryption_key_ref":
        "secret:ACME_PACKAGE_KEY",
    **_GRAPH_FIELDS,
    f"{_SRC}.providers.google_workspace_users.source_id": "directory-google",
    f"{_SRC}.providers.google_workspace_users.origin": "https://admin.googleapis.com",
    f"{_SRC}.providers.google_workspace_users.credential_ref": "env:GOOGLE_RIGHTS_TOKEN",
    f"{_SRC}.providers.google_workspace_users.capabilities": ["discover"],
    f"{_SRC}.providers.salesforce_contacts.source_id": "crm-salesforce",
    f"{_SRC}.providers.salesforce_contacts.origin": "https://acme.my.salesforce.com",
    f"{_SRC}.providers.salesforce_contacts.credential_ref": "vault:SALESFORCE_RIGHTS_TOKEN",
    f"{_SRC}.providers.salesforce_contacts.capabilities": ["discover", "delete"],
    f"{_SRC}.providers.servicenow_users.source_id": "itsm-servicenow",
    f"{_SRC}.providers.servicenow_users.origin": "https://acme.service-now.com",
    f"{_SRC}.providers.servicenow_users.credential_ref": "secret:SERVICENOW_RIGHTS_TOKEN",
    f"{_SRC}.providers.servicenow_users.capabilities": ["verify_delete"],
    "compliance.profiles": ["gdpr"],
    "deadline_alerts.mode": "digest",
    "deadline_alerts.quiet_hours": "22:00-07:00",
    "deadline_alerts.owner": "Dana (privacy owner)",
    "deadline_alerts.lead_days.dsar": ["10", "3"],
    "deadline_alerts.lead_days.assessment": ["45", "10"],
    "deadline_alerts.lead_days.vendor": ["60", "14"],
    "deadline_alerts.lead_hours.incident": ["48", "8"],
    "deadline_alerts.lead_hours.approval": ["12", "2"],
    "data_use_governance.enforcement.retry_base_seconds": 0.5,
    "consent_preferences.storage.backend": "postgres",
    "consent_preferences.storage.dsn": "postgresql://consent@db.example.com:5432/consent",  # pragma: allowlist secret
    "consent_preferences.storage.dsn_secret_ref": "$ACME_CONSENT_DSN",  # pragma: allowlist secret
    # Letting the person who asked approve their own risky request loosens it.
    "approval.separate_approver": "never",
}

# Other settings a switch needs before the module's reader accepts it.
NEEDS: dict[str, dict[str, object]] = {
    f"{_ID}.enable": {k: SAMPLES[k] for k in (f"{_ID}.issuer", f"{_ID}.audience",
                                             f"{_ID}.jwks_origin")},
    f"{_DEST}.enable": {f"{_DEST}.enabled_providers": ["salesforce"], **_SALESFORCE},
    f"{_DEST}.enabled_providers": {f"{_DEST}.enable": True, **_SALESFORCE},
    "privacy_automation.data_discovery.adapters.enable": {
        "privacy_automation.data_discovery.adapters.enabled_providers": ["aws_s3"]},
    f"{_FIX}.enable": {f"{_FIX}.data_map.enable": True},
    f"{_FIX}.data_map.enable": {f"{_FIX}.enable": True},
    f"{_FIX}.scheduler.enable": {f"{_FIX}.enable": True, f"{_FIX}.data_map.enable": True},
    f"{_NOTICE}.enable": {f"{_NOTICE}.active_tenants": ["default"]},
    f"{_NOTICE}.scheduler_enable": {f"{_NOTICE}.enable": True,
                                    f"{_NOTICE}.active_tenants": ["default"]},
    f"{_SRC}.enable": {f"{_GRAPH}.enable": True, **_GRAPH_FIELDS},
    "consent_preferences.storage.backend": {
        "consent_preferences.storage.dsn": SAMPLES["consent_preferences.storage.dsn"]},
}
for _key, _name, _pattern, _example in privacy._RIGHTS_SOURCES:
    _base = f"{_SRC}.providers.{_key}"
    NEEDS[f"{_base}.enable"] = {f"{_base}.{f}": SAMPLES[f"{_base}.{f}"]
                                for f in ("source_id", "origin", "credential_ref",
                                          "capabilities")}


_TARGET_TOML = (
    "[privacy_automation.notice_governance.publication_runtime.bindings.primary]\n"
    'tenant_id = "{tenant}"\nnotice_id = "privacy-main"\n'
    'consent_publication_ref = "consent-binding:1"\nproperty_id = "property-main"\n'
    'rule_group_id = "production-rules"\nrule_group_version = 1\n'
    'notice_resource_id = "privacy-notice"\nnotice_resource_version = 1\n'
)


def _installer_config(text: str) -> None:
    from maverick import config

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text(text, encoding="utf-8")
    config.reset_config_cache()


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch, request):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
                 "MAVERICK_REDACT_EGRESS", "MAVERICK_CONSENT_DASHBOARD_TIMEOUT",
                 "MAVERICK_COMPLIANCE_PROFILES", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    from maverick import consent_storage

    # Saving the shared consent database checks its driver is installed; these
    # tests cover the settings, not the optional driver.
    monkeypatch.setattr(consent_storage, "driver_available", lambda: True)
    for name in (consent_storage.BACKEND_ENV, consent_storage.DEFAULT_DSN_ENV):
        monkeypatch.delenv(name, raising=False)
    setting = getattr(getattr(request, "node", None), "callspec", None)
    chosen = setting.params.get("setting") if setting is not None else None
    if chosen is not None and chosen.id.startswith(_NOTICE):
        # Publishing workspaces and targets match one to one (set by the installer here).
        active = "" if chosen.id.endswith("active_tenants") else (
            "[privacy_automation.notice_governance.publication_runtime]\n"
            'active_tenants = ["default"]\n')
        _installer_config(active + _TARGET_TOML.format(tenant="default"))
    yield
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def _loaded() -> dict:
    from maverick import config

    config.reset_config_cache()
    return config.load_config()


def _lookup(tree, setting):
    return catalog.lookup(tree, setting.path)


def _save(changes: dict, confirm=False, reset=()):
    body = [{"id": k, "value": v} for k, v in changes.items()]
    body += [{"id": k, "reset": True} for k in reset]
    return save_catalog(client, API, json={"changes": body, "confirm": confirm})


def _rows(state: dict) -> dict:
    return {row["id"]: row for group in state["groups"] for row in group["settings"]}


def _shown_default(setting):
    if setting.default is None:
        return None
    shown = setting.default / setting.scale
    return int(shown) if shown == int(shown) else shown


def _sample(setting):
    if setting.id in SAMPLES:
        return SAMPLES[setting.id]
    if setting.control == "toggle":
        return not setting.default
    assert setting.control == "number", setting.id
    shown = _shown_default(setting)
    if shown is None:
        return setting.minimum
    return shown + 1 if shown + 1 <= setting.maximum else shown - 1


def _invalid(setting) -> list:
    if setting.control == "toggle":
        return ["yes", 1]
    if setting.control == "number":
        return [setting.minimum - 1, setting.maximum + 1, "many"]
    if setting.control in {"text", "secret"}:
        return ["not valid !"]
    if setting.control in {"multiselect", "select"}:
        return [["nope"]] if setting.control == "multiselect" else ["nope"]
    assert setting.control == "list", setting.id
    return [["not valid !"]]


# ----------------------------------------------------------------- shape
def test_privacy_rows_are_grouped_and_plain():
    from test_support.plain_language import developer_terms

    assert len(ROWS) >= 200
    for setting in ROWS:
        assert setting.group in {"Privacy", "AI governance", "Safety"}, setting.id
        assert setting.subgroup or setting.id == "privacy.redact_egress", setting.id
        assert developer_terms(f"<main>{setting.label} {setting.help} {setting.warning}</main>") \
            == [], setting.id
    page = every_group(client)
    assert developer_terms(page) == []
    for heading in ("Consent preferences — privacy signals",
                    "Consent preferences — Salesforce delivery",
                    "Data use governance — platform audit logs",
                    "Privacy automation — California DROP",
                    "Privacy automation — Microsoft 365 users for requests"):
        assert heading in page


def test_every_key_name_row_is_a_sealed_secret():
    names = [s for s in ROWS if s.key.endswith(("_ref", "_secret_env", "_token_env", "_salt"))]
    assert len(names) == 20
    assert all(s.control == "secret" for s in names), [s.id for s in names if not s.secret]


# ------------------------------------------------------------ round trip
@pytest.mark.parametrize("setting", ROWS, ids=lambda s: s.id)
def test_row_saves_reads_back_and_reaches_load_config(setting, audit_rows):
    value = _sample(setting)
    changes = {**NEEDS.get(setting.id, {}), setting.id: value}
    r = _save(changes, confirm=True)
    assert r.status_code == 200, r.text
    body = r.json()
    assert setting.id in body["changed"]
    assert body["restart"] is (any(catalog.BY_ID[k].restart for k in body["changed"]))
    row = _rows(body)[setting.id]
    stored = catalog.coerce(setting, value)
    present, loaded = _lookup(_loaded(), setting)
    assert present and loaded == stored
    if setting.secret:
        assert row["is_set"] is True and row["value"] is None
        assert str(value) not in r.text
        assert all(a["new"] == "set" for a in audit_rows if a["key"] == setting.key)
    else:
        expected = value if setting.control != "number" else (
            int(value) if float(value) == int(value) else value)
        assert row["value"] == expected
        assert row["source"] == "here"
    mine = [a for a in audit_rows
            if (a["section"], a["key"]) == (setting.section, setting.key)]
    assert len(mine) == 1 and mine[0]["kind"] == "setting_changed" and mine[0]["_global"]
    # Reset gives the default back and is recorded too.
    needs = [] if setting.id.startswith(_NOTICE) else list(NEEDS.get(setting.id, {}))
    r = save_catalog(client, API, json={"changes": [{"id": setting.id, "reset": True}]
                               + [{"id": k, "reset": True} for k in needs],
                               "confirm": True})
    if setting.id == f"{_NOTICE}.active_tenants":
        # The workspace still has a publishing target, so it must keep publishing.
        assert r.status_code == 400 and "publishing target" in r.json()["message"]
        return
    assert r.status_code == 200, r.text
    assert not _lookup(_loaded(), setting)[0]


@pytest.mark.parametrize("setting", ROWS, ids=lambda s: s.id)
def test_row_refuses_invalid_values(setting, audit_rows):
    for bad in _invalid(setting):
        r = _save({setting.id: bad}, confirm=True)
        assert r.status_code == 400, (setting.id, bad)
        assert r.json()["message"].startswith(setting.label)
    assert not _lookup(_loaded(), setting)[0]
    assert audit_rows == []


def _weaken(setting):
    """``(first, second)``: saving ``second`` after ``first`` loosens ``setting``."""
    if setting.control == "toggle":
        return (None, True) if setting.weaker is True else (True, False)
    if setting.control == "number":
        shown = _shown_default(setting)
        if shown is None:  # "no limit" by default: set one, then raise it
            return (setting.minimum, setting.minimum + 1)
        if setting.weaker == "lower":
            if shown - 1 < setting.minimum:
                return (shown + 1, shown)
            return (None, shown - 1)
        if shown + 1 > setting.maximum:
            return (shown - 1, shown)
        return (None, shown + 1)
    if setting.weaker == "shrink":
        return (["gdpr", "eu_ai_act"], ["gdpr"])
    return (None, _sample(setting))


@pytest.mark.parametrize("setting", [s for s in ROWS if s.warning], ids=lambda s: s.id)
def test_loosening_needs_confirmation(setting, audit_rows):
    first, second = _weaken(setting)
    needs = NEEDS.get(setting.id, {}) if second is True or setting.control != "toggle" else {}
    if first is not None:
        assert _save({**NEEDS.get(setting.id, {}), setting.id: first},
                     confirm=True).status_code == 200
        needs = {}
    audit_rows.clear()
    r = _save({**needs, setting.id: second})
    assert r.status_code == 409, r.text
    assert setting.id in [item["id"] for item in r.json()["confirm"]]
    assert audit_rows == []
    r = _save({**needs, setting.id: second}, confirm=True)
    assert r.status_code == 200, r.text
    mine = [a for a in audit_rows if (a["section"], a["key"]) == (setting.section, setting.key)]
    assert mine and mine[-1]["confirmed"] is True


# ---------------------------------------------------- addresses and names
@pytest.mark.parametrize("address", [
    "http://login.example.com",
    "https://10.0.0.5",
    "https://[::1]",
    "https://localhost",
    "https://metadata.google.internal",
    "https://printer.local",
    "https://user:pass@login.example.com",  # pragma: allowlist secret
    "https://login.example.com/keys?token=1",
])
def test_sign_in_key_address_must_be_a_public_secure_origin(address, audit_rows):
    r = _save({f"{_ID}.jwks_origin": address}, confirm=True)
    assert r.status_code == 400
    assert f"{_ID}.jwks_origin".split(".")[-1] not in str(_loaded().get("consent_preferences"))


@pytest.mark.parametrize("setting_id, address", [
    (f"{_DEST}.salesforce.origin", "https://evil.example.com"),
    (f"{_DEST}.salesforce.origin", "https://salesforce.com.evil.example.com"),
    (f"{_DEST}.marketo.origin", "https://acme.my.salesforce.com"),
    (f"{_DEST}.snowflake.origin", "https://acme.snowflakecomputing.com:8443"),
    ("data_use_governance.databricks.origin", "https://acme.cloud.databricks.com:443"),
    (f"{_GRAPH}.origin", "https://graph.microsoft.com.evil.example.com"),
    (f"{_SRC}.providers.servicenow_users.origin", "https://service-now.com"),
])
def test_service_addresses_only_reach_that_service(setting_id, address, audit_rows):
    assert _save({setting_id: address}, confirm=True).status_code == 400


@pytest.mark.parametrize("setting_id, name", [
    (f"{_DEST}.salesforce.credential_secret_ref", "$MAVERICK_ENCRYPTION_KEY"),
    (f"{_DEST}.salesforce.credential_secret_ref", "${ANTHROPIC_API_KEY}"),
    ("data_use_governance.snowflake.credential_secret_ref", "$GITHUB_TOKEN"),
    (f"{_GRAPH}.credential_ref", "env:MAVERICK_DASHBOARD_TOKEN"),
    ("consent_registry.webhook_secret_env", "PATH"),
    ("consent_preferences.native_sdk.receipt_key_secret_ref", "HOME"),
])
def test_key_names_cannot_point_at_unrelated_server_credentials(setting_id, name, audit_rows):
    r = _save({setting_id: name}, confirm=True)
    assert r.status_code == 400
    assert name not in r.text


def test_sealed_key_names_are_never_shown_or_audited(audit_rows):
    from maverick import config

    salt = "do-not-show-this-salt-0001"  # pragma: allowlist secret
    ref = "$MAVERICK_SALESFORCE_CONSENT_TOKEN"
    r = _save({"consent_registry.subject_salt": salt,
               f"{_DEST}.salesforce.credential_secret_ref": ref}, confirm=True)
    assert r.status_code == 200
    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert salt not in stored and "SALESFORCE_CONSENT" not in stored and "MVKAR1:" in stored
    for text in (r.text, client.get(API).text, every_group(client),
                 repr(audit_rows)):
        assert salt not in text and "SALESFORCE_CONSENT_TOKEN" not in text
    loaded = _loaded()
    assert loaded["consent_registry"]["subject_salt"] == salt
    assert loaded["consent_preferences"]["delivery"]["destinations"]["salesforce"][
        "credential_secret_ref"] == ref


# ----------------------------------------------------------- cross checks
@pytest.mark.parametrize("changes, words", [
    ({f"{_ID}.enable": True}, "Sign-in provider address"),
    ({f"{_DEST}.enable": True}, "Services to send to"),
    ({f"{_DEST}.enable": True, f"{_DEST}.enabled_providers": ["marketo"]}, "Marketo"),
    ({"privacy_automation.data_discovery.adapters.enable": True}, "Services to look in"),
    ({f"{_FIX}.enable": True}, "together"),
    ({f"{_FIX}.scheduler.enable": True}, "Fix findings through approved fixes"),
    ({f"{_FIX}.scheduler.jitter_seconds": 120}, "Random extra wait"),
    ({"privacy_automation.drop_management.scheduler_jitter_seconds": 3600},
     "must be less than"),
    ({f"{_NOTICE}.scheduler_enable": True}, "Publish approved privacy notices"),
    ({f"{_NOTICE}.enable": True}, "Workspaces that publish notices"),
    ({f"{_GRAPH}.enable": True}, "Microsoft 365 users name in Lightwork"),
    ({f"{_SRC}.enable": True}, "at least one system"),
    ({f"{_SRC}.lease_seconds": 20}, "at least 35 seconds"),
    ({f"{_SRC}.max_retrieval_bytes": 512}, "can't be more than"),
    ({"privacy_automation.rights_consumer_intake.max_active_requests": 10}, "Open requests"),
    ({"data_use_governance.provider_audit.retention_seconds": 1,
      "data_use_governance.provider_audit.audit_window_seconds": 48}, "Time allowed"),
    ({"consent_preferences.trust_center.branding.max_width": 100}, "Most pixels"),
])
def test_combinations_the_modules_refuse_are_refused(changes, words, audit_rows):
    r = _save(changes, confirm=True)
    assert r.status_code == 400, r.text
    assert words in r.json()["message"]
    assert audit_rows == []


def test_two_services_cannot_share_a_name(audit_rows):
    marketo = {k: v for k, v in SAMPLES.items() if k.startswith(f"{_DEST}.marketo.")}
    marketo[f"{_DEST}.marketo.destination_id"] = "sf-main"
    marketo[f"{_DEST}.marketo.credential_revision"] = 1
    r = _save({**_SALESFORCE, **marketo, f"{_DEST}.enable": True,
               f"{_DEST}.enabled_providers": ["salesforce", "marketo"]}, confirm=True)
    assert r.status_code == 400 and "its own delivery name" in r.json()["message"]


# ------------------------------------------------ values reach the readers
def _modules_on(*paths: str) -> None:
    from maverick_dashboard import settings_store

    settings_store.set_module_enables(paths, True)


def test_delivery_destination_reaches_the_registry(audit_rows):
    from maverick.consent_delivery_destinations import build_consent_destination_registry

    r = _save({**_SALESFORCE, f"{_DEST}.enable": True, f"{_DEST}.enabled_providers":
               ["salesforce"], f"{_DEST}.timeout_seconds": 2.5,
               f"{_DEST}.max_response_bytes": 32}, confirm=True)
    assert r.status_code == 200, r.text
    registry = build_consent_destination_registry(_loaded(), "default")
    binding = registry.binding("sf-main")
    assert binding.origin == "https://acme.my.salesforce.com"
    assert binding.credential_name == "MAVERICK_SALESFORCE_CONSENT_TOKEN"
    assert registry.timeout_seconds == 2.5 and registry.max_response_bytes == 32 * 1024


def test_native_app_settings_reach_the_native_runtime(audit_rows):
    from maverick_dashboard.consent_native_composition import native_consent_settings

    _modules_on("consent_preferences", "consent_preferences.publishing",
                "consent_preferences.public_api", "consent_preferences.native_sdk")
    r = _save({"consent_preferences.native_sdk.receipt_key_id": "native-receipt",
               "consent_preferences.native_sdk.receipt_key_secret_ref": "ACME_CONSENT_KEY",  # pragma: allowlist secret
               "consent_preferences.native_sdk.max_devices": 50,
               "consent_preferences.native_sdk.require_profile_linking": True,
               "consent_preferences.standards.tcf": True}, confirm=True)
    assert r.status_code == 200, r.text
    settings = native_consent_settings(_loaded())
    assert settings.max_devices == 50 and settings.require_profile_linking is True
    assert settings.receipt_key_secret_ref == "ACME_CONSENT_KEY"  # pragma: allowlist secret
    assert settings.standards_wire_required is True


def test_consent_limits_reach_their_modules(audit_rows):
    from maverick.consent_global_opt_out import load_global_opt_out_limits
    from maverick.consent_identity_federation import load_consent_identity_settings
    from maverick.consent_scan_inventory import _authenticated_scans_enabled
    from maverick.consent_web_publish_settings import WebPublishSettingsConfig
    from maverick.trust_center_branding import TrustCenterBrandingConfig
    from maverick_dashboard.consent_application_scanner_composition import (
        consent_application_scanner_settings,
    )
    from maverick_dashboard.consent_bulk_jobs_composition import consent_bulk_jobs_settings
    from maverick_dashboard.consent_custom_index_composition import (
        consent_custom_index_settings,
    )
    from maverick_dashboard.consent_scan_scheduler import scheduler_settings
    from maverick_dashboard.trust_center_branding_composition import (
        trust_center_branding_enabled,
    )

    _modules_on("consent_preferences", "consent_preferences.publishing",
                "consent_preferences.public_api", "consent_preferences.scanner",
                "consent_preferences.bulk_jobs", "consent_preferences.application_scanner",
                "consent_preferences.profile_data", "consent_preferences.profile_data.custom_index",
                "consent_preferences.global_opt_out", "consent_preferences.trust_center",
                "consent_preferences.publishing.web_settings")
    cp = "consent_preferences"
    r = _save({**NEEDS[f"{_ID}.enable"], f"{_ID}.enable": True, f"{_ID}.token_ttl_seconds": 5,
               f"{cp}.bulk_jobs.max_jobs": 7, f"{cp}.bulk_jobs.retention_seconds": 2,
               f"{cp}.application_scanner.max_records": 11,
               f"{cp}.profile_data.custom_index.max_indexes": 3,
               f"{cp}.global_opt_out.submission_ttl_seconds": 2,
               f"{cp}.publishing.web_settings.max_history": 9,
               f"{cp}.scanner.allow_authenticated_scans": True,
               f"{cp}.scanner.scheduler.enable": True, f"{cp}.scanner.scheduler.claim_limit": 2,
               f"{cp}.trust_center.branding.enable": True,
               f"{cp}.trust_center.branding.max_width": 3000}, confirm=True)
    assert r.status_code == 200, r.text
    assert r.json()["restart"] is True
    loaded = _loaded()
    assert consent_bulk_jobs_settings(loaded).max_jobs == 7
    assert consent_bulk_jobs_settings(loaded).retention_seconds == 2 * 86400
    assert consent_application_scanner_settings(loaded).max_records == 11
    assert consent_custom_index_settings(loaded).max_indexes == 3
    assert load_global_opt_out_limits(loaded).submission_ttl_seconds == 120
    assert WebPublishSettingsConfig.from_mapping(loaded).max_history == 9
    identity = load_consent_identity_settings(loaded)
    assert identity.jwks_origin == "https://login.example.com"
    assert identity.token_ttl_seconds == 300
    assert _authenticated_scans_enabled() is True
    assert scheduler_settings(loaded).claim_limit == 2
    assert TrustCenterBrandingConfig.from_mapping(loaded).max_width == 3000
    assert trust_center_branding_enabled() is True


def test_consent_register_reads_the_saved_values(audit_rows):
    from maverick.consent_registry import get_consent_registry_config, webhook_enabled

    _modules_on("consent_registry")
    r = _save({"consent_registry.subject_salt": "a-private-salt-value-0001",
               "consent_registry.webhook_enable": True,
               "consent_registry.webhook_secret_env": "ACME_CONSENT_WEBHOOK_SECRET"},  # pragma: allowlist secret
              confirm=True)
    assert r.status_code == 200, r.text
    settings = get_consent_registry_config()
    assert settings["subject_salt"] == "a-private-salt-value-0001"  # pragma: allowlist secret
    assert settings["webhook_secret_env"] == "ACME_CONSENT_WEBHOOK_SECRET"  # pragma: allowlist secret
    assert webhook_enabled() is True


def test_data_use_settings_reach_the_provider_runtime(audit_rows):
    from maverick_dashboard.data_use_provider_audit_composition import operation_settings
    from maverick_dashboard.data_use_provider_audit_scheduler import (
        scheduler_settings as audit_scheduler,
    )
    from maverick_dashboard.data_use_provider_audit_transport import _native_limits
    from maverick_dashboard.data_use_provider_runtime import (
        credential_metadata,
        provider_limits,
    )

    _modules_on("data_use_governance", "data_use_governance.compiler",
                "data_use_governance.enforcement", "data_use_governance.snowflake")
    du = "data_use_governance"
    r = _save({f"{du}.snowflake.origin": "https://acme.snowflakecomputing.com",
               f"{du}.snowflake.credential_secret_ref": "$ACME_DATA_USE_TOKEN",
               f"{du}.snowflake.credential_revision": 4,
               f"{du}.snowflake.timeout_seconds": 20,
               f"{du}.enforcement.max_attempts": 2,
               f"{du}.provider_audit.enable": True,
               f"{du}.provider_audit.audit_window_seconds": 4,
               f"{du}.provider_audit.max_pages_per_read": 7,
               f"{du}.provider_audit.snowflake_latency_watermark_seconds": 3,
               f"{du}.provider_audit.scheduler.enable": True,
               f"{du}.provider_audit.scheduler.event_limit": 9}, confirm=True)
    assert r.status_code == 200, r.text
    loaded = _loaded()
    limits = provider_limits(loaded, "snowflake")
    assert limits.timeout_seconds == 20 and limits.max_attempts == 2
    metadata = credential_metadata(loaded, "snowflake")
    assert metadata.secret_name == "ACME_DATA_USE_TOKEN" and metadata.key_revision == 4  # pragma: allowlist secret
    assert operation_settings(loaded).audit_window_seconds == 4 * 3600
    native = _native_limits(loaded)
    assert native.max_pages_per_read == 7
    assert native.snowflake_latency_watermark_seconds == 3 * 3600
    assert audit_scheduler(loaded).event_limit == 9


def test_privacy_automation_settings_reach_their_modules(audit_rows):
    from maverick.privacy_data_discovery_adapters import build_stock_discovery_adapter_registry
    from maverick.privacy_discovery_data_use_bridge import enabled as bridge_enabled
    from maverick.privacy_rights_ott_ctv import enabled as ott_enabled
    from maverick_dashboard.privacy_data_discovery_adapters_composition import (
        _remediation_settings,
    )
    from maverick_dashboard.privacy_drop_management_composition import _settings as drop
    from maverick_dashboard.privacy_rights_consumer_delivery_composition import (
        settings_for_tenant as delivery_settings,
    )
    from maverick_dashboard.privacy_rights_intake_composition import _settings as intake
    from maverick_dashboard.privacy_rights_source_composition import settings_from_config

    _modules_on("privacy_automation", "privacy_automation.data_discovery",
                "privacy_automation.rights_orchestration",
                "privacy_automation.rights_consumer_delivery",
                "privacy_automation.drop_management", "data_use_governance",
                "consent_preferences", "consent_preferences.publishing",
                "consent_preferences.public_api", "consent_preferences.trust_center")
    pa = "privacy_automation"
    changes = {
        f"{pa}.data_discovery.adapters.enable": True,
        f"{pa}.data_discovery.adapters.enabled_providers": ["aws_s3", "entra_assets"],
        f"{pa}.data_discovery.adapters.max_pages": 12,
        f"{_FIX}.enable": True, f"{_FIX}.data_map.enable": True,
        f"{_FIX}.scheduler.worker_limit": 3,
        f"{pa}.discovery_data_use_bridge.enable": True,
        f"{pa}.drop_management.scheduler_interval_seconds": 5,
        f"{pa}.rights_consumer_intake.enable": True,
        f"{pa}.rights_consumer_intake.max_active_requests_per_subject": 4,
        f"{pa}.rights_consumer_delivery.digest_key_ref": "env:ACME_RIGHTS_DIGEST_KEY",
        f"{pa}.rights_consumer_delivery.export_signing_key_ref": "env:ACME_EXPORT_KEY",
        f"{pa}.rights_consumer_delivery.package_encryption_key_ref": "env:ACME_PACKAGE_KEY",
        f"{pa}.rights_consumer_delivery.server_grant_ttl_seconds": 45,
        f"{pa}.ott_ctv_rights.enable": True,
        f"{_SRC}.enable": True, f"{_GRAPH}.enable": True, **_GRAPH_FIELDS,
        f"{_SRC}.max_records": 50,
    }
    r = _save(changes, confirm=True)
    assert r.status_code == 200, r.text
    loaded = _loaded()
    registry = build_stock_discovery_adapter_registry(loaded)
    assert registry.enabled and sorted(registry.unstructured) == ["aws_s3"]
    fixes = _remediation_settings(loaded)
    assert fixes.enabled and fixes.data_map_enabled and fixes.scheduler.worker_limit == 3
    assert bridge_enabled() is True
    assert drop(loaded).scheduler_interval_seconds == 300
    assert intake(loaded).max_active_requests_per_subject == 4
    delivery = delivery_settings(SimpleNamespace(state=SimpleNamespace()), "default")
    assert delivery.server_grant_ttl_seconds == 45
    assert delivery.export_signing_key_ref == "env:ACME_EXPORT_KEY"
    sources = settings_from_config(loaded)
    assert sources.enabled and sources.limits.max_records == 50
    assert [(s.provider, s.capabilities) for s in sources.sources] == [
        ("microsoft_graph_users", ("discover", "retrieve"))]
    assert ott_enabled() is False  # it also needs sign-in for people
    assert _save({**NEEDS[f"{_ID}.enable"], f"{_ID}.enable": True},
                 confirm=True).status_code == 200
    assert ott_enabled() is True


def test_notice_publishing_reads_the_saved_workspaces(audit_rows):
    from maverick_dashboard.privacy_notice_publication_composition import settings_from_config

    _installer_config(_TARGET_TOML.format(tenant="acme"))
    _modules_on("privacy_automation", "privacy_automation.notice_governance",
                "consent_preferences", "consent_preferences.publishing")
    r = _save({f"{_NOTICE}.enable": True, f"{_NOTICE}.active_tenants": ["acme"],
               f"{_NOTICE}.poll_seconds": 90}, confirm=True)
    assert r.status_code == 200, r.text
    settings = settings_from_config(_loaded())
    assert settings.enabled and settings.active_tenants == ("acme",)
    assert settings.poll_seconds == 90


def test_outbound_redaction_follows_the_saved_value_and_the_environment(monkeypatch,
                                                                         audit_rows):
    from maverick.privacy_egress import redact_egress_enabled

    assert redact_egress_enabled() is False
    assert _save({"privacy.redact_egress": True}).status_code == 200
    assert redact_egress_enabled() is True
    r = _save({"privacy.redact_egress": False})
    assert r.status_code == 409  # turning the protection off is confirmed
    monkeypatch.setenv("MAVERICK_REDACT_EGRESS", "0")
    assert redact_egress_enabled() is False
    assert _rows(client.get(API).json())["privacy.redact_egress"]["locked"] is True


def test_compliance_profiles_follow_the_saved_list(audit_rows):
    from maverick.compliance_profiles import resolve_profiles

    assert _save({"compliance.profiles": ["gdpr", "eu_ai_act"]}).status_code == 200
    assert sorted(resolve_profiles()) == ["eu_ai_act", "gdpr"]
    assert _save({"compliance.profiles": ["gdpr"]}).status_code == 409
    assert _save({"compliance.profiles": ["gdpr"]}, confirm=True).status_code == 200
    assert resolve_profiles() == ["gdpr"]


def test_dashboard_approval_wait_reads_the_setting_and_env_wins(monkeypatch, audit_rows):
    from maverick.safety.consent import _dashboard_timeout
    from maverick_dashboard import settings_catalog as catalog

    # Risky steps wait 30 minutes by default (it was 5).
    assert _dashboard_timeout() == 1800.0
    assert catalog.BY_ID["approval.dashboard_wait_seconds"].default == 1800
    assert _save({"approval.dashboard_wait_seconds": 2}).status_code == 200
    assert _dashboard_timeout() == 120.0
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "45")
    assert _dashboard_timeout() == 45.0
    assert _rows(client.get(API).json())["approval.dashboard_wait_seconds"]["locked"] is True


def test_who_approves_a_risky_request_reads_the_setting_and_env_wins(monkeypatch, audit_rows):
    from maverick.safety.dual_control import SEPARATE_APPROVER_MODES, separate_approver_mode
    from maverick_dashboard import settings_catalog as catalog

    monkeypatch.delenv("MAVERICK_SEPARATE_APPROVER", raising=False)
    row = catalog.BY_ID["approval.separate_approver"]
    assert row.default == separate_approver_mode() == "when_available"
    assert tuple(value for value, _label in row.choices) == SEPARATE_APPROVER_MODES
    assert _save({"approval.separate_approver": "always"}).status_code == 200
    assert separate_approver_mode() == "always"
    # Letting people approve their own risky requests weakens a protection.
    assert _save({"approval.separate_approver": "never"}).status_code == 409
    assert _save({"approval.separate_approver": "never"}, confirm=True).status_code == 200
    assert separate_approver_mode() == "never"
    monkeypatch.setenv("MAVERICK_SEPARATE_APPROVER", "when_available")
    assert separate_approver_mode() == "when_available"
    assert _rows(client.get(API).json())["approval.separate_approver"]["locked"] is True


def test_a_module_page_value_survives_a_catalog_save(audit_rows):
    """Module switches and catalog values share one table without losing either."""
    _modules_on("consent_preferences", "consent_preferences.scanner")
    assert _save({"consent_preferences.scanner.scheduler.poll_seconds": 30}).status_code == 200
    scanner = _loaded()["consent_preferences"]["scanner"]
    assert scanner["enable"] is True and scanner["scheduler"]["poll_seconds"] == 30
    assert math.isclose(_loaded()["consent_preferences"]["scanner"]["scheduler"]
                        ["poll_seconds"], 30)


@pytest.mark.parametrize("profile", ["hipaa", "soc2"])
def test_profiles_that_switch_on_enterprise_mode_cannot_lock_the_admin_out(profile, monkeypatch,
                                                                          audit_rows):
    from maverick import enterprise

    r = _save({"compliance.profiles": ["gdpr", profile]}, confirm=True)
    assert r.status_code == 400 and "enterprise mode" in r.json()["message"]
    assert "compliance" not in _loaded()
    # Once enterprise mode already works (sign-in and binding in place) it is allowed.
    monkeypatch.setattr(enterprise, "enterprise_enabled", lambda: True)
    privacy.cross_checks({"compliance.profiles": [profile]}, catalog.BY_ID,
                         catalog.SettingError)


@pytest.mark.parametrize("values, words", [
    ({f"{_ID}.token_ttl_seconds": 7200, f"{_ID}.link_lifecycle_retention_seconds": 3600},
     "Oldest sign-in token accepted can't be more than keep sign-in link history for."),
    ({"privacy_automation.drop_management.scheduler_jitter_seconds": 60,
      "privacy_automation.drop_management.scheduler_interval_seconds": 60},
     "must be less than"),
    ({f"{_DEST}.enable": True, f"{_DEST}.enabled_providers": ["salesforce"],
      **{k: v for k, v in _SALESFORCE.items() if not k.endswith("credential_revision")}},
     "Salesforce sign-in key version"),
])
def test_cross_checks_mirror_the_readers(values, words):
    with pytest.raises(catalog.SettingError, match=words):
        privacy.cross_checks(values, catalog.BY_ID, catalog.SettingError)


def test_data_map_key_is_left_to_the_integrations_rows():
    assert not any(row.id.startswith("data_map.") for row in ROWS)


# ------------------------------- installation defaults and caps
def test_consent_script_cache_follows_the_edge_cache_settings(audit_rows):
    _modules_on("consent_preferences", "consent_preferences.publishing",
                "consent_preferences.public_api")
    assert client.get("/api/v1/public/consent/sdk.js").headers["cache-control"] == \
        "public, max-age=300"
    assert _save({"consent_preferences.edge_cache.enable": True,
                  "consent_preferences.edge_cache.max_age_seconds": 60,
                  "consent_preferences.edge_cache.stale_if_error_seconds": 24}).status_code == 200
    assert client.get("/api/v1/public/consent/sdk.js").headers["cache-control"] == \
        "public, max-age=3600, stale-if-error=86400"
    # Settings and people's choices are never cached.
    from maverick_dashboard.consent_public_api import _set_private_response_headers
    from starlette.responses import Response

    response = Response()
    _set_private_response_headers(response)
    assert response.headers["cache-control"] == "no-store, private"


def test_public_consent_service_limits_follow_the_settings(audit_rows):
    from maverick_dashboard import consent_public_api as public

    _modules_on("consent_preferences", "consent_preferences.publishing",
                "consent_preferences.public_api")
    body = b"{" + b" " * (70 * 1024) + b"}"
    headers = {"Content-Type": "application/json"}
    path = "/api/v1/public/consent/profiles/bootstrap"
    assert client.post(path, content=body, headers=headers).status_code == 413
    assert public._response_byte_limit() == 256 * 1024
    assert public.configured_requests_per_minute() is None
    assert _save({"consent_preferences.public_api.max_request_bytes": 128,
                  "consent_preferences.public_api.max_response_bytes": 2,
                  "consent_preferences.public_api.requests_per_minute": 2},
                 confirm=True).status_code == 200
    # Past the body cap now; refused for having no sign-in key instead.
    assert client.post(path, content=body, headers=headers).status_code == 401
    assert public._response_byte_limit() == 2 * 1024
    with pytest.raises(Exception, match="503"):
        public._bounded_response({"text": "x" * 4096})
    limiter = public.PublicConsentRateLimiter(
        limit_source=public.configured_requests_per_minute)
    limiter("client", "configuration")
    limiter("client", "configuration")
    with pytest.raises(public.PublicConsentRateLimitExceeded):
        limiter("client", "configuration")


class _FakeConsentStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def list_profiles(self, tenant_id, *, limit, after=None, search=""):
        self.calls.append(("profiles", limit))
        return {"items": []}

    def export_profile(self, tenant_id, profile_id, *, actor_sha256, access_purpose,
                       receipt_limit, **_page):
        self.calls.append(("receipts", receipt_limit))
        return {"receipts": []}


def test_consent_records_page_sizes_and_body_limit_follow_the_settings(monkeypatch,
                                                                       audit_rows):
    from maverick_dashboard import consent_preferences_api as api

    store = _FakeConsentStore()
    monkeypatch.setattr(api, "_ops", lambda: SimpleNamespace())
    monkeypatch.setattr(api, "_tenant_id", lambda: "default")
    monkeypatch.setattr(api, "_store", lambda tenant: store)

    async def direct(ops, function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(api, "_call", direct)
    export = "/api/v1/consent/profiles/p-1/export?access_purpose=review"
    assert client.get("/api/v1/consent/profiles").status_code == 200
    assert client.get("/api/v1/consent/profiles?limit=400").status_code == 200
    assert client.get(export).status_code == 200
    assert store.calls == [("profiles", 100), ("profiles", 400), ("receipts", 500)]
    assert _save({"consent_preferences.limits.profile_page_size": 20,
                  "consent_preferences.limits.receipt_page_size": 50,
                  "consent_preferences.limits.request_body_bytes": 1},
                 confirm=True).status_code == 200
    store.calls.clear()
    client.get("/api/v1/consent/profiles")
    client.get("/api/v1/consent/profiles?limit=400")
    client.get(export)
    assert store.calls == [("profiles", 20), ("profiles", 20), ("receipts", 50)]
    big = client.post("/api/v1/consent/policies", content=b"{" + b" " * 2048 + b"}",
                      headers={"Content-Type": "application/json"})
    assert big.status_code == 413


def test_analytics_settings_reach_the_consent_reports(audit_rows):
    from maverick.consent_analytics import analytics_limits

    assert analytics_limits() == (10, 2, None)
    assert _save({"consent_preferences.analytics.min_cohort_size": 20,
                  "consent_preferences.analytics.retention_days": 90}).status_code == 200
    assert analytics_limits() == (20, 20, 90)
    r = _save({"consent_preferences.analytics.min_cohort_size": 5})
    assert r.status_code == 409  # a smaller group can single people out


def test_delivery_and_scan_settings_reach_their_modules(audit_rows):
    from maverick.consent_delivery import delivery_retry_settings
    from maverick.consent_scanner import ScanLimits, capped_scan_limits, scan_limit_settings

    assert delivery_retry_settings() == (6, 20, 5.0, 3600.0)
    assert scan_limit_settings() == {}
    r = _save({"consent_preferences.delivery.max_attempts": 3,
               "consent_preferences.delivery.retry_base_seconds": 10,
               "consent_preferences.delivery.retry_max_seconds": 600,
               "consent_preferences.scanner.max_pages": 40,
               "consent_preferences.scanner.interval_seconds": 60})
    assert r.status_code == 200, r.text
    assert delivery_retry_settings() == (3, 3, 10.0, 600.0)
    assert scan_limit_settings() == {"max_pages": 40, "interval_seconds": 3600}
    assert capped_scan_limits(ScanLimits(max_pages=500)).max_pages == 40
    r = _save({"consent_preferences.delivery.retry_base_seconds": 900})
    assert r.status_code == 400 and "First wait before trying again" in r.json()["message"]


def test_data_use_retry_waits_reach_the_provider_runtime(audit_rows):
    from maverick_dashboard.data_use_provider_runtime import _retry_waits

    assert _retry_waits({}) == (0.25, 1.0)
    # Values older installers wrote (never applied) keep the built-in waits.
    assert _retry_waits({"retry_base_seconds": 30, "retry_max_seconds": 300}) == (0.25, 1.0)
    assert _save({"data_use_governance.enforcement.retry_base_seconds": 0.5,
                  "data_use_governance.enforcement.retry_max_seconds": 4}).status_code == 200
    enforcement = _loaded()["data_use_governance"]["enforcement"]
    assert _retry_waits(enforcement) == (0.5, 4.0)
    from maverick.data_use_provider_adapters import ProviderLimits

    limits = ProviderLimits(retry_base_seconds=0.5, retry_max_seconds=4.0)
    adapter = SimpleNamespace(_limits=limits)
    from maverick.data_use_provider_adapters import _NativeProviderAdapter

    delays = [_NativeProviderAdapter._retry_delay(adapter, n) for n in (1, 2, 3, 4)]
    assert delays == [0.5, 1.0, 2.0, 4.0]


def test_data_use_limits_and_compiler_settings_are_read(audit_rows):
    from maverick.data_use_governance import data_use_limits
    from maverick.data_use_policy_compiler import compiler_limits

    assert data_use_limits() == {} and compiler_limits() == (256, None)
    assert _save({"data_use_governance.limits.max_assets": 10,
                  "data_use_governance.limits.max_context_age_seconds": 2,
                  "data_use_governance.compiler.max_operations": 50,
                  "data_use_governance.compiler.max_row_filter_nodes": 64}).status_code == 200
    assert data_use_limits() == {"max_assets": 10, "max_context_age_seconds": 2 * 86400}
    assert compiler_limits() == (64, 50)


# ------------------------------------------------ four-eyes on provider writes
@pytest.fixture()
def provider_write(monkeypatch):
    """A data platform connection whose writes are recorded, not sent."""
    from maverick import data_use_provider_adapters as ops
    from maverick_dashboard import auth
    from maverick_dashboard import data_use_provider_api as api

    applied: list[str] = []
    who = {"principal": "user:alice"}
    settings = {"require_four_eyes": True}

    class Adapter:
        def apply_control_ir(self, control_ir, *, idempotency_sha256):
            applied.append(idempotency_sha256)
            return {"state": "completed"}

        rollback_control_ir = apply_control_ir

    async def compile_ir(*_args, **_kwargs):
        return "compiled"

    monkeypatch.setattr(api, "_provider_ops", lambda provider_id: ops)
    monkeypatch.setattr(api, "_tenant_id", lambda: "default")
    monkeypatch.setattr(api, "_binding_store", lambda ops_, tenant: SimpleNamespace(
        get_binding=lambda tenant_id, binding_id: {"provider_id": "snowflake"}))
    monkeypatch.setattr(api, "_config", lambda: {
        "data_use_governance": {"enforcement": dict(settings)}})
    monkeypatch.setattr(api, "_provider_audit_required", lambda config: False)
    monkeypatch.setattr(api, "_adapter", lambda request, **kwargs: Adapter())
    monkeypatch.setattr(api, "_compile", compile_ir)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who["principal"])
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "admin")
    rbac.set_role("user:bob", "admin")
    return SimpleNamespace(applied=applied, who=who, settings=settings)


def _apply(body):
    return client.post("/api/v1/data-use/providers/snowflake/bindings/orders/decisions/"
                       "dec-1/apply", json=body)


def test_four_eyes_off_keeps_writes_immediate(provider_write):
    provider_write.settings["require_four_eyes"] = False
    r = _apply({"expected_decision_sha256": "a" * 64, "idempotency_key": "once"})
    assert r.status_code == 200 and len(provider_write.applied) == 1


def test_four_eyes_needs_a_second_different_person(provider_write):
    from maverick_dashboard._shared import _world

    body = {"expected_decision_sha256": "a" * 64, "idempotency_key": "change-1"}
    first = _apply(body)
    assert first.status_code == 202 and first.json()["state"] == "approval_required"
    approval_id = first.json()["approval_id"]
    assert provider_write.applied == []
    waiting = _apply({**body, "approval_id": approval_id})
    assert waiting.status_code == 202 and waiting.json()["state"] == "approval_pending"
    # Approving your own request does not count.
    assert _world().decide_approval(approval_id, "approved", decided_by="user:alice")
    assert _apply({**body, "approval_id": approval_id}).status_code == 403
    assert provider_write.applied == []
    second = _apply(body).json()["approval_id"]
    assert _world().decide_approval(second, "approved", decided_by="user:bob")
    # The approval covers only this exact change.
    other = {"expected_decision_sha256": "b" * 64, "idempotency_key": "change-1",
             "approval_id": second}
    assert _apply(other).status_code == 409
    done = _apply({**body, "approval_id": second})
    assert done.status_code == 200 and len(provider_write.applied) == 1


def test_four_eyes_refuses_when_nobody_is_signed_in(provider_write):
    provider_write.who["principal"] = None
    r = _apply({"expected_decision_sha256": "a" * 64, "idempotency_key": "change-2"})
    assert r.status_code == 403 and provider_write.applied == []


def test_four_eyes_setting_is_saved_and_turning_it_off_is_confirmed(audit_rows):
    assert _save({"data_use_governance.enforcement.require_four_eyes": True}).status_code == 200
    assert _loaded()["data_use_governance"]["enforcement"]["require_four_eyes"] is True
    assert _save({"data_use_governance.enforcement.require_four_eyes": False}).status_code \
        == 409


def test_turning_delivery_off_is_clean_with_installer_services_listed(audit_rows):
    from maverick.consent_delivery_destinations import build_consent_destination_registry

    _installer_config(
        "[consent_preferences.delivery.destinations]\n"
        'enable = true\nenabled_providers = ["salesforce"]\n'
        "[consent_preferences.delivery.destinations.salesforce]\n"
        'destination_id = "sf-main"\norigin = "https://acme.my.salesforce.com"\n'
        'credential_secret_ref = "$MAVERICK_SALESFORCE_CONSENT_TOKEN"\n'
        "credential_revision = 1\n"
        'api_version = "v65.0"\nobject_api_name = "Lightwork_Consent_Event__c"\n'
        'external_id_field = "Lightwork_Message_Id__c"\n'
        'payload_digest_field = "Lightwork_Payload_SHA256__c"\n')
    assert build_consent_destination_registry(_loaded(), "default").status()["enabled"]
    # The installer's list stays ticked; turning sending off is still clean.
    assert _save({f"{_DEST}.enable": False}).status_code == 200
    loaded = _loaded()
    assert loaded["consent_preferences"]["delivery"]["destinations"]["enabled_providers"] == [
        "salesforce"]
    status = build_consent_destination_registry(loaded, "default").status()
    assert status["enabled"] is False and status["destinations"] == []
