from __future__ import annotations

import hashlib
import sqlite3

import pytest
from fastapi import FastAPI
from maverick import consent_publishing
from maverick import consent_web_publish_settings as web
from maverick_dashboard import consent_web_publish_settings_composition as composition


def _config(enabled: object = True):
    return {
        "consent_preferences": {
            "enable": True,
            "publishing": {
                "enable": True,
                "web_settings": {"enable": enabled, "retention_seconds": 60},
            },
        }
    }


def _authority() -> web.WebsitePublishingAuthority:
    return web.WebsitePublishingAuthority(
        tenant_id="tenant-a",
        property_id="website-main",
        property_kind="web",
        property_revision=1,
        property_sha256="a" * 64,
        publication_id="publication-1",
        publication_revision=1,
        publication_sha256="b" * 64,
        publication_bundle_sha256="c" * 64,
        publication_action="publish",
        publication_property_revision=1,
    )


def _publishing_fixture(path) -> None:
    consent_publishing.ConsentPublishingStore(path)
    tenant = "tenant-a"
    created_at = 1_700_000_000.0
    property_body = {
        "tenant_sha256": hashlib.sha256(tenant.encode()).hexdigest(),
        "property_id": "website-main",
        "kind": "web",
        "consent_group_id": "consent-main",
        "web_domains": ["example.com"],
        "origin_allowlist": ["https://example.com"],
        "mobile_bundle_ids": [],
        "platform": None,
        "revision": 1,
    }
    bundle = {"schema": consent_publishing.PREVIEW_SCHEMA}
    bundle_sha256 = consent_publishing._sha256(bundle)  # noqa: SLF001
    publication_body = {
        "schema": consent_publishing.PUBLICATION_SCHEMA,
        "tenant_sha256": hashlib.sha256(tenant.encode()).hexdigest(),
        "publication_id": "publication-1",
        "property_id": "website-main",
        "publication_revision": 1,
        "action": "publish",
        "source_publication_id": None,
        "property_revision": 1,
        "bundle_sha256": bundle_sha256,
        "created_at": created_at,
    }
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO publishing_properties VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                tenant,
                "website-main",
                "web",
                "consent-main",
                '["example.com"]',
                '["https://example.com"]',
                "[]",
                None,
                1,
                consent_publishing._sha256(property_body),  # noqa: SLF001
                created_at,
            ),
        )
        connection.execute(
            "INSERT INTO consent_publications(tenant,publication_id,property_id,"
            "publication_revision,action,source_publication_id,property_revision,"
            "bundle_json,bundle_sha256,publication_sha256,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                tenant,
                "publication-1",
                "website-main",
                1,
                "publish",
                None,
                1,
                consent_publishing._canonical(bundle).decode("ascii"),  # noqa: SLF001
                bundle_sha256,
                consent_publishing._sha256(publication_body),  # noqa: SLF001
                created_at,
            ),
        )
        connection.execute(
            "INSERT INTO consent_publication_heads VALUES (?,?,?,?)",
            (tenant, "website-main", "publication-1", 1),
        )


def test_config_requires_all_three_exact_gates() -> None:
    assert composition.consent_web_publish_settings_config({}) is None
    assert composition.consent_web_publish_settings_config(_config(False)) is None
    selected = composition.consent_web_publish_settings_config(_config())
    assert selected is not None and selected.enable is True
    broken = _config()
    broken["consent_preferences"]["publishing"]["enable"] = False
    with pytest.raises(web.WebPublishSettingsConfigError):
        composition.consent_web_publish_settings_config(broken)
    with pytest.raises(web.WebPublishSettingsConfigError):
        composition.consent_web_publish_settings_config(_config("true"))


def test_production_adapter_validates_existing_property_and_publication(tmp_path) -> None:
    path = tmp_path / "consent-publishing.sqlite3"
    _publishing_fixture(path)
    resolver = composition.ConsentPublishingWebsiteAuthorityResolver(path)
    result = resolver("tenant-a", "website-main")
    assert result.property_kind == "web"
    assert result.property_revision == 1
    assert result.publication_id == "publication-1"
    assert result.publication_revision == 1
    assert result.publication_property_revision == 1
    assert result.usable is True


def test_production_adapter_detects_digest_tampering(tmp_path) -> None:
    path = tmp_path / "consent-publishing.sqlite3"
    _publishing_fixture(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE publishing_properties SET record_sha256=?",
            ("f" * 64,),
        )
    resolver = composition.ConsentPublishingWebsiteAuthorityResolver(path)
    with pytest.raises(composition.ConsentWebPublishSettingsCompositionError):
        resolver("tenant-a", "website-main")


def test_attach_is_lazy_idempotent_and_installs_exact_hooks(monkeypatch) -> None:
    app = FastAPI()
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: (_ for _ in ()).throw(AssertionError("must stay lazy")),
    )
    composition.attach_consent_web_publish_settings_composition(app)
    composition.attach_consent_web_publish_settings_composition(app)
    for name in (
        "consent_web_publish_settings_enabled_probe",
        "consent_web_publish_settings_readiness_probe",
        "consent_web_publish_settings_service_factory",
        "consent_web_publish_settings_public_projection",
        "consent_web_publish_settings_publishing_authority_resolver_factory",
        "consent_web_publish_settings_store_path_factory",
        "consent_web_publish_settings_publishing_store_path_factory",
    ):
        assert callable(getattr(app.state, name))
    assert app.state.consent_web_publish_settings_composition_installed is True


def test_disabled_public_projection_does_not_touch_storage(monkeypatch) -> None:
    app = FastAPI()
    monkeypatch.setattr(
        composition,
        "consent_web_publish_settings_enabled",
        lambda _tenant: False,
    )
    app.state.consent_web_publish_settings_store_path_factory = lambda **_kwargs: (
        (_ for _ in ()).throw(AssertionError("disabled path must stay closed"))
    )
    composition.attach_consent_web_publish_settings_composition(app)
    result = app.state.consent_web_publish_settings_public_projection(
        "tenant-a", "website-main"
    )
    assert result == {
        "schema": web.PUBLIC_PROJECTION_SCHEMA,
        "enabled": False,
        "ready": False,
        "reason": "feature_disabled",
        "property_id": "website-main",
        "browser_property_acceptance_verified": False,
    }


def test_enabled_public_hook_returns_explicit_not_ready_without_claims(
    tmp_path, monkeypatch
) -> None:
    app = FastAPI()
    monkeypatch.setattr(
        composition,
        "consent_web_publish_settings_enabled",
        lambda _tenant: True,
    )
    monkeypatch.setattr(
        composition,
        "settings_for_tenant",
        lambda _tenant: web.WebPublishSettingsConfig(enable=True, retention_seconds=60),
    )
    app.state.consent_web_publish_settings_store_path_factory = (
        lambda **_kwargs: tmp_path / "settings.sqlite3"
    )
    app.state.consent_web_publish_settings_publishing_authority_resolver_factory = (
        lambda **_kwargs: lambda tenant, property_id: _authority()
    )
    composition.attach_consent_web_publish_settings_composition(app)
    result = app.state.consent_web_publish_settings_public_projection(
        "tenant-a", "website-main"
    )
    assert result["enabled"] is True
    assert result["ready"] is False
    assert result["reason"] == "settings_not_ready"
    assert result["browser_property_acceptance_verified"] is False
    assert "tenant" not in result
