from __future__ import annotations

import hashlib
import itertools
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick.consent_preferences import ConsentPreferenceStore
from maverick.consent_publishing import ConsentPublishingStore
from maverick_dashboard.app import app
from maverick_dashboard.consent_public_api import (
    PublicConsentCredentialError,
    PublicConsentCredentialStore,
)

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/consent/public-clients"
NOW = 1_800_000_000.0
ORIGIN = "https://www.example.com"
NOTICE = hashlib.sha256(b"notice").hexdigest()


def _seed(publishing: ConsentPublishingStore, preferences: ConsentPreferenceStore) -> None:
    publishing.upsert_property(
        "tenant-a",
        "web-main",
        kind="web",
        consent_group_id="consumer-global",
        web_domains=["example.com"],
        origin_allowlist=[ORIGIN],
        expected_revision=0,
        idempotency_key="property",
    )
    publishing.put_purpose_version(
        "tenant-a",
        "analytics",
        1,
        title_key="purpose.title",
        description_key="purpose.description",
        lawful_basis="consent",
        required=False,
        default_choice="denied",
        expected_current_version=0,
        idempotency_key="purpose",
    )
    publishing.put_notice_version(
        "tenant-a",
        "notice",
        1,
        title_key="notice.title",
        body_key="notice.body",
        document_sha256=NOTICE,
        expected_current_version=0,
        idempotency_key="notice",
    )
    publishing.put_translation_version(
        "tenant-a",
        "copy",
        "en-US",
        1,
        messages={
            "purpose.title": "Analytics",
            "purpose.description": "Measure performance",
            "notice.title": "Privacy",
            "notice.body": "Choose analytics.",
            "template.title": "Choices",
            "template.body": "Control analytics.",
            "action.accept": "Accept",
            "action.reject": "Reject",
            "action.save": "Save",
        },
        expected_current_version=0,
        idempotency_key="translation",
    )
    publishing.put_template_version(
        "tenant-a",
        "banner",
        1,
        surface="banner",
        title_key="template.title",
        body_key="template.body",
        actions={
            "accept_all": "action.accept",
            "reject_all": "action.reject",
            "save_preferences": "action.save",
        },
        theme_token_id="brand",
        expected_current_version=0,
        idempotency_key="template",
    )
    publishing.put_rule_group_version(
        "tenant-a",
        "production",
        1,
        rules=[
            {
                "rule_id": "global",
                "priority": 1,
                "locales": ["en-US"],
                "default_locale": "en-US",
                "purposes": [{"id": "analytics", "version": 1}],
                "notice": {"id": "notice", "version": 1},
                "template": {"id": "banner", "version": 1},
                "translation_catalog_id": "copy",
                "translation_versions": {"en-US": 1},
            }
        ],
        expected_current_version=0,
        idempotency_key="rules",
    )
    publishing.publish(
        "tenant-a",
        "web-main",
        "production",
        1,
        expected_property_revision=1,
        expected_publication_revision=0,
        idempotency_key="publish",
    )
    preferences.publish_policy(
        "tenant-a",
        "public-consent",
        1,
        {"analytics": "consent"},
        NOTICE,
        NOW - 1,
    )


@pytest.fixture()
def authorities(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick import config, world_model
    from maverick_dashboard import consent_public_admin_api

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[consent_preferences]\nenable = true\n"
        "[consent_preferences.publishing]\nenable = true\n"
        "require_signed_publications = true\n"
        "[consent_preferences.public_api]\nenable = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    # require_signed_publications is on: every publish here is signed.
    monkeypatch.setenv("MAVERICK_CONSENT_PUBLICATION_SIGNING_KEY", "hex:" + "5a" * 32)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in (
        "MAVERICK_DASHBOARD_ADMINS",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    ids = itertools.count(1)
    publishing = ConsentPublishingStore(
        tmp_path / "publishing.sqlite3",
        clock=lambda: NOW,
        id_factory=lambda prefix: f"{prefix}-{next(ids)}",
    )
    preferences = ConsentPreferenceStore(
        tmp_path / "preferences.sqlite3",
        clock=lambda: NOW,
        id_factory=lambda prefix: f"{prefix}-{next(ids)}",
    )
    registry = PublicConsentCredentialStore(
        tmp_path / "registry.sqlite3",
        clock=lambda: NOW,
        id_factory=lambda: f"client-{next(ids)}",
    )
    _seed(publishing, preferences)
    monkeypatch.setattr(consent_public_admin_api, "_registry", lambda: registry)
    monkeypatch.setattr(
        consent_public_admin_api,
        "_publishing_store",
        lambda _tenant: publishing,
    )
    monkeypatch.setattr(
        consent_public_admin_api,
        "_preference_store",
        lambda _tenant: preferences,
    )
    yield registry, preferences, config_path
    config.reset_config_cache()


def _body() -> dict:
    return {
        "property_id": "web-main",
        "client_kind": "browser",
        "browser_origin": ORIGIN,
        "service_client_id": None,
        "target_origin": None,
        "target_bundle_id": None,
        "target_platform": None,
        "jurisdiction": "global",
        "country_code": "US",
        "region_code": "",
        "default_locale": "en-US",
        "rule_group_id": "production",
        "rule_group_version": 1,
        "policy_id": "public-consent",
        "policy_version": 1,
        "expires_at": None,
    }


def test_admin_mints_once_lists_safely_and_revokes_by_safe_id(authorities) -> None:
    registry, _preferences, _config = authorities
    created = client.post(API, json=_body())
    assert created.status_code == 201, created.text
    body = created.json()
    raw = body["client_credential"]
    assert body["credential_returned_once"] is True
    assert "credential_sha256" not in body
    assert registry.resolve_client(raw).property_id == "web-main"
    assert raw.encode() not in registry.path.read_bytes()

    listed = client.get(API)
    assert listed.status_code == 200
    assert "client_credential" not in listed.text
    assert "credential_sha256" not in listed.text
    credential_id = listed.json()["items"][0]["credential_id"]
    revoked = client.post(
        f"{API}/{credential_id}/revoke",
        json={"expected_revision": 1},
    )
    assert revoked.status_code == 200
    with pytest.raises(PublicConsentCredentialError):
        registry.resolve_client(raw)


def test_admin_profile_revocation_invalidates_capability(authorities) -> None:
    registry, preferences, _config = authorities
    created = client.post(API, json=_body()).json()
    binding = registry.resolve_client(created["client_credential"])
    profile_credential = "profile-capability-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    profile_sha = hashlib.sha256(profile_credential.encode()).hexdigest()

    def create_profile(profile_id, subject_sha, idempotency):
        return preferences.create_profile(
            "tenant-a", profile_id, "anonymous", subject_sha, idempotency
        )

    bootstrapped = registry.bootstrap_profile(
        binding,
        subject_sha256=hashlib.sha256(b"subject").hexdigest(),
        profile_credential_sha256=profile_sha,
        idempotency_key="bootstrap",
        create_profile=create_profile,
    )
    listed = client.get(f"{API}/profiles")
    assert listed.status_code == 200, listed.text
    safe = listed.json()
    assert safe["raw_credentials_returned"] is False
    assert safe["subject_identifiers_returned"] is False
    assert safe["items"] == [
        {
            "client_credential_id": binding.credential_id,
            "client_revision": binding.revision,
            "client_status": "active",
            "property_id": "web-main",
            "profile_id": bootstrapped["profile_ref"],
            "profile_status": "active",
            "created_at": NOW,
            "profile_revision": 0,
        }
    ]
    assert profile_credential not in listed.text
    assert profile_sha not in listed.text
    assert "subject_sha256" not in listed.text
    response = client.post(
        f"{API}/profiles/{bootstrapped['profile_ref']}/revoke",
        json={
            "property_id": "web-main",
            "evidence_sha256": hashlib.sha256(b"ticket").hexdigest(),
        },
    )
    assert response.status_code == 200, response.text
    with pytest.raises(PublicConsentCredentialError):
        registry.resolve_profile(profile_credential, binding)


def test_admin_enrollment_fails_closed_on_contract_mismatch_and_gate_off(
    authorities,
) -> None:
    _registry, _preferences, config_path = authorities
    mismatched = _body()
    mismatched["policy_version"] = 2
    response = client.post(API, json=mismatched)
    assert response.status_code == 409
    assert "not active" in response.text

    config_path.write_text(
        "[consent_preferences]\nenable = true\n"
        "[consent_preferences.publishing]\nenable = true\n"
        "[consent_preferences.public_api]\nenable = false\n",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    assert client.get(API).status_code == 403
