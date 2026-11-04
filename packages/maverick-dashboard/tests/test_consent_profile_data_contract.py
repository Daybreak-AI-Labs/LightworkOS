"""The profile-data contract lookup matches what the public banner publishes."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
PUB = "/api/v1/consent/publishing"
PD = "/api/v1/consent/profile-data"


@pytest.fixture(autouse=True)
def _enabled(tmp_path, monkeypatch):
    from maverick import config, world_model

    path = tmp_path / "config.toml"
    path.write_text(
        "[consent_preferences]\nenable = true\n"
        "[consent_preferences.publishing]\nenable = true\n"
        "[consent_preferences.public_api]\nenable = true\n"
        "[consent_preferences.profile_data]\nenable = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_TENANT", "contract-tenant")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT_BY_USER"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _ok(response):
    assert response.status_code < 300, response.text
    return response.json()


def _version(path: str, body: dict) -> None:
    _ok(client.post(f"{PUB}/{path}/versions", json={
        "version": 1, "expected_current_version": 0, "idempotency_key": "k-" + path.replace("/", "-"), **body}))


def _publish_banner_with_a_question() -> str:
    _ok(client.put(f"{PUB}/properties/site", json={
        "kind": "web", "consent_group_id": "customers", "expected_revision": 0, "idempotency_key": "site-1",
        "web_domains": ["www.example.com"], "origin_allowlist": ["https://www.example.com"], "mobile_bundle_ids": []}))
    _version("translations/copy/en-US", {"messages": {
        "p.t": "Analytics", "p.d": "Improve", "n.t": "Notice", "n.b": "Body", "t.t": "Choices", "t.b": "Pick",
        "a": "Accept", "r": "Reject", "s": "Save", "q.t": "Newsletter", "q.d": "News"}})
    _version("purposes/analytics", {"title_key": "p.t", "description_key": "p.d", "lawful_basis": "consent",
                                    "required": False, "default_choice": "denied"})
    _version("custom-preferences/newsletter", {"title_key": "q.t", "description_key": "q.d",
                                               "value_type": "single_select", "option_ids": ["weekly", "monthly"],
                                               "required": False})
    _version("notices/privacy", {"title_key": "n.t", "body_key": "n.b", "document_sha256": "a" * 64})
    _version("templates/banner", {"surface": "banner", "title_key": "t.t", "body_key": "t.b",
                                  "actions": {"accept_all": "a", "reject_all": "r", "save_preferences": "s"},
                                  "theme_token_id": "default", "theme_token_version": None})
    _version("rule-groups/main", {"rules": [{
        "rule_id": "all", "priority": 1, "locales": ["en-US"], "default_locale": "en-US", "consent_mode": "opt_in",
        "purposes": [{"id": "analytics", "version": 1}], "custom_preferences": [{"id": "newsletter", "version": 1}],
        "notice": {"id": "privacy", "version": 1}, "template": {"id": "banner", "version": 1},
        "translation_catalog_id": "copy", "translation_versions": {"en-US": 1}}]})
    _ok(client.post(f"{PUB}/properties/site/publish", json={
        "rule_group_id": "main", "rule_group_version": 1, "expected_property_revision": 1,
        "expected_publication_revision": 0, "idempotency_key": "publish-1"}))
    _ok(client.post("/api/v1/consent/policies", json={
        "policy_id": "web", "version": 1, "purposes": {"analytics": "consent"}, "notice_sha256": "a" * 64,
        "effective_at": time.time() - 60}))
    key = _ok(client.post("/api/v1/consent/public-clients", json={
        "property_id": "site", "client_kind": "browser", "browser_origin": "https://www.example.com",
        "jurisdiction": "global", "country_code": "US", "region_code": "", "default_locale": "en-US",
        "rule_group_id": "main", "rule_group_version": 1, "policy_id": "web", "policy_version": 1}))
    return key["credential_id"]


def test_contract_derives_the_public_ids_and_a_catalog_the_store_accepts() -> None:
    from maverick_dashboard.consent_profile_data_api import public_profile_data_ids

    credential = _publish_banner_with_a_question()
    contract = _ok(client.get(f"{PD}/contract?credential_id={credential}"))
    assert [q["preference_id"] for q in contract["questions"]] == ["newsletter"]
    assert sorted(contract["questions"][0]["option_ids"]) == ["monthly", "weekly"]
    assert (contract["catalog_id"], contract["journey_id"]) == public_profile_data_ids(
        tenant_id="contract-tenant", property_id="site",
        publication_sha256=contract["publication_sha256"], bundle_sha256=contract["bundle_sha256"],
        configuration_sha256=contract["configuration_sha256"], policy_id="web", policy_version=1,
        policy_sha256=contract["policy_sha256"])
    created = _ok(client.post(f"{PD}/catalogs", json={
        **{k: contract[k] for k in ("catalog_id", "property_id", "publication_sha256", "bundle_sha256",
                                    "configuration_sha256", "policy_id", "policy_version", "policy_sha256")},
        "definitions": [{"preference_id": "newsletter", "definition_version": 1, "label_ref": "newsletter",
                         "value_type": "single_select",
                         "options": [{"value_id": o, "label_ref": o}
                                     for o in contract["questions"][0]["option_ids"]],
                         "required": False, "expires_after_seconds": None, "retention_seconds": 86400}],
        "retention_seconds": 86400, "expected_latest_version": 0, "idempotency_key": "catalog-from-contract"}))
    assert created["state"] == "pending_approval"
    assert client.get(f"{PD}/contract?credential_id=unknown-key").status_code == 404
