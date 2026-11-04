"""Privacy notices page: where approved notices are published (publication targets).

Targets land in the dashboard overlay where the publication runtime reads them,
are checked with the runtime's own parser, need confirmation to add or change,
write one audit row each, and keep workspaces and targets one to one.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/privacy/notice-publication/targets"
TARGET = {
    "tenant_id": "acme",
    "notice_id": "privacy-main",
    "consent_publication_ref": "consent-binding:1",
    "property_id": "property-main",
    "rule_group_id": "production-rules",
    "rule_group_version": 1,
    "notice_resource_id": "privacy-notice",
    "notice_resource_version": 2,
}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
                 "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
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


def _runtime():
    from maverick import config
    from maverick_dashboard.privacy_notice_publication_composition import settings_from_config

    config.reset_config_cache()
    return settings_from_config(config.load_config())


def test_adding_a_target_needs_confirmation_and_reaches_the_runtime(audit_rows):
    r = client.put(f"{API}/primary", json=TARGET)
    assert r.status_code == 409 and r.json()["confirm"]
    assert _runtime().bindings == ()
    r = client.put(f"{API}/primary", json={**TARGET, "confirm": True})
    assert r.status_code == 200, r.text
    runtime = _runtime()
    assert runtime.active_tenants == ("acme",)
    assert [(b.binding_id, b.notice_resource_version) for b in runtime.bindings] == [
        ("primary", 2)]
    assert [(row["key"], row["new"]["notice_id"]) for row in audit_rows] == [
        ("primary", "privacy-main")]
    listed = client.get(API).json()
    assert listed["workspaces"] == ["acme"]
    assert listed["targets"][0]["source"] == "here" and listed["targets"][0]["removable"]


def test_changing_and_removing_a_target(audit_rows):
    client.put(f"{API}/primary", json={**TARGET, "confirm": True})
    changed = client.put(f"{API}/primary",
                         json={**TARGET, "notice_resource_version": 3, "confirm": True})
    assert changed.status_code == 200
    assert _runtime().bindings[0].notice_resource_version == 3
    removed = client.delete(f"{API}/primary")
    assert removed.status_code == 200
    runtime = _runtime()
    assert runtime.bindings == () and runtime.active_tenants == ()
    assert [row["new"] for row in audit_rows][-1] is None


@pytest.mark.parametrize("bad", [
    {"notice_id": "has space"},
    {"rule_group_version": 0},
    {"tenant_id": "bad."},
    {"extra": "field"},
])
def test_invalid_targets_are_refused(bad, audit_rows):
    r = client.put(f"{API}/primary", json={**TARGET, **bad, "confirm": True})
    assert r.status_code in {400, 422}
    assert audit_rows == [] and _runtime().bindings == ()


def test_the_runtime_parser_refuses_a_reused_banner_release(audit_rows):
    assert client.put(f"{API}/one", json={**TARGET, "confirm": True}).status_code == 200
    r = client.put(f"{API}/two", json={**TARGET, "confirm": True})
    assert r.status_code == 400
    assert "banner release" in r.json()["detail"]


def test_the_last_target_cannot_be_removed_while_publishing_is_on(audit_rows):
    from maverick_dashboard import settings_store

    client.put(f"{API}/primary", json={**TARGET, "confirm": True})
    settings_store.set_module_enables(
        ["privacy_automation", "privacy_automation.notice_governance",
         "consent_preferences", "consent_preferences.publishing"], True)
    revision = client.get("/api/v1/settings/catalog", params={"q": "__revision__"}).json()["revision"]
    r = client.post("/api/v1/settings/catalog", json={"expected_revision": revision, "changes": [
        {"id": "privacy_automation.notice_governance.publication_runtime.enable",
         "value": True}]})
    assert r.status_code == 200, r.text
    refused = client.delete(f"{API}/primary")
    assert refused.status_code == 400 and "turn publishing off" in refused.json()["detail"]


def test_installer_targets_can_be_changed_but_not_removed(audit_rows):
    from maverick import config

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text(
        "[privacy_automation.notice_governance.publication_runtime]\n"
        'active_tenants = ["acme"]\n'
        "[privacy_automation.notice_governance.publication_runtime.bindings.primary]\n"
        'tenant_id = "acme"\nnotice_id = "privacy-main"\n'
        'consent_publication_ref = "consent-binding:1"\nproperty_id = "property-main"\n'
        'rule_group_id = "production-rules"\nrule_group_version = 1\n'
        'notice_resource_id = "privacy-notice"\nnotice_resource_version = 1\n',
        encoding="utf-8")
    config.reset_config_cache()
    listed = client.get(API).json()["targets"][0]
    assert listed["source"] == "installer" and listed["removable"] is False
    assert client.delete(f"{API}/primary").status_code == 409
    changed = client.put(f"{API}/primary", json={**TARGET, "confirm": True})
    assert changed.status_code == 200
    assert _runtime().bindings[0].notice_resource_version == 2


def test_only_admins_on_the_same_origin_may_change_targets(monkeypatch, audit_rows):
    from maverick_dashboard import auth, rbac

    assert TestClient(app, base_url="http://127.0.0.1").put(f"{API}/primary",
                               json={**TARGET, "confirm": True}).status_code == 403
    rbac.set_role("user:vera", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vera")
    assert client.get(API).status_code == 403
    assert client.put(f"{API}/primary", json={**TARGET, "confirm": True}).status_code == 403
    assert [row for row in audit_rows if row["kind"] == "setting_changed"] == []


def test_notices_page_offers_the_target_editor_in_plain_language():
    from maverick_dashboard import settings_store

    from test_support.plain_language import developer_terms

    settings_store.set_module_enables(
        ["privacy_automation", "privacy_automation.notice_governance"], True)
    page = client.get("/privacy/notice-governance").text
    assert "Where approved notices are published" in page
    assert "Add a publishing target" in page
    start = page.index('id="png-targets"')
    assert developer_terms(page[start:page.index("</section>", start)]) == []
