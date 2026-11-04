from __future__ import annotations

import hashlib
import itertools
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick.consent_publishing import (
    ConsentPublishingError,
    ConsentPublishingStore,
    PublishingConflict,
    PublishingIdempotencyConflict,
    PublishingNotFound,
    PublishingValidationError,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _store(path: Path) -> ConsentPublishingStore:
    identifiers = itertools.count(1)
    return ConsentPublishingStore(
        path,
        clock=lambda: 1_800_000_000.0,
        id_factory=lambda prefix: f"{prefix}-{next(identifiers)}",
    )


def _web_property(
    store: ConsentPublishingStore,
    tenant: str,
    property_id: str = "web-main",
    *,
    origin: str = "https://www.example.com",
    idempotency_key: str | None = None,
) -> dict:
    return store.upsert_property(
        tenant,
        property_id,
        kind="web",
        consent_group_id="consumer-global",
        web_domains=["example.com"],
        origin_allowlist=[origin],
        expected_revision=0,
        idempotency_key=idempotency_key or f"property-{property_id}",
    )


def _messages(label: str, *, french: bool = False) -> dict[str, str]:
    if french:
        return {
            "purpose.title": f"Analyse {label}",
            "purpose.description": "Mesure le fonctionnement du service",
            "topic.title": "Courriels de produit",
            "topic.description": "Choisissez les courriels de produit",
            "preference.title": "Personnalisation",
            "preference.description": "Personnaliser cette experience",
            "notice.title": "Vos choix",
            "notice.body": "Choisissez comment vos donnees sont utilisees.",
            "template.title": "Confidentialite",
            "template.body": "Controlez vos preferences.",
            "action.accept": "Tout accepter",
            "action.reject": "Tout refuser",
            "action.manage": "Gerer les preferences",
            "action.save": "Enregistrer",
            "brand.display_name": "Exemple",
            "brand.heading": "Centre de confidentialite Exemple",
            "brand.description": "Gerez vos choix et vos donnees.",
        }
    return {
        "purpose.title": f"Analytics {label}",
        "purpose.description": "Measure how the service performs",
        "topic.title": "Product email",
        "topic.description": "Choose product email updates",
        "preference.title": "Personalization",
        "preference.description": "Personalize this experience",
        "notice.title": "Your choices",
        "notice.body": "Choose how your data is used.",
        "template.title": "Privacy choices",
        "template.body": "Control your preferences.",
        "action.accept": "Accept all",
        "action.reject": "Reject all",
        "action.manage": "Manage preferences",
        "action.save": "Save choices",
        "brand.display_name": "Example",
        "brand.heading": "Example Privacy Trust Center",
        "brand.description": "Manage your choices and volunteered data.",
    }


def _rule(
    *,
    version: int = 1,
    rule_id: str = "global",
    priority: int = 1,
    jurisdictions: tuple[str, ...] = (),
    countries: tuple[str, ...] = (),
    regions: tuple[str, ...] = (),
    locales: tuple[str, ...] = ("en-US",),
    default_locale: str = "en-US",
) -> dict:
    return {
        "rule_id": rule_id,
        "priority": priority,
        "jurisdictions": list(jurisdictions),
        "country_codes": list(countries),
        "region_codes": list(regions),
        "locales": list(locales),
        "default_locale": default_locale,
        "consent_mode": "opt_in",
        "purposes": [{"id": "analytics", "version": version}],
        "topics": [{"id": "product-email", "version": version}],
        "custom_preferences": [{"id": "personalization", "version": version}],
        "notice": {"id": "privacy-notice", "version": version},
        "template": {"id": "standard-banner", "version": version},
        "translation_catalog_id": "consumer-copy",
        "translation_versions": dict.fromkeys(locales, version),
    }


def _content(
    store: ConsentPublishingStore,
    tenant: str,
    *,
    version: int = 1,
    label: str = "v1",
    rules: list[dict] | None = None,
    rule_group_id: str = "production-rules",
    branded: bool = False,
    message_overrides: dict[str, str] | None = None,
) -> None:
    expected = version - 1
    suffix = f"v{version}-{rule_group_id}"
    store.put_purpose_version(
        tenant,
        "analytics",
        version,
        title_key="purpose.title",
        description_key="purpose.description",
        lawful_basis="consent",
        required=False,
        default_choice="denied",
        expected_current_version=expected,
        idempotency_key=f"purpose-{suffix}",
    )
    store.put_topic_version(
        tenant,
        "product-email",
        version,
        purpose_id="analytics",
        purpose_version=version,
        title_key="topic.title",
        description_key="topic.description",
        default_choice="denied",
        expected_current_version=expected,
        idempotency_key=f"topic-{suffix}",
    )
    store.put_custom_preference_version(
        tenant,
        "personalization",
        version,
        title_key="preference.title",
        description_key="preference.description",
        value_type="boolean",
        option_ids=[],
        required=False,
        expected_current_version=expected,
        idempotency_key=f"preference-{suffix}",
    )
    store.put_notice_version(
        tenant,
        "privacy-notice",
        version,
        title_key="notice.title",
        body_key="notice.body",
        document_sha256=_digest(f"notice-{label}"),
        expected_current_version=expected,
        idempotency_key=f"notice-{suffix}",
    )
    english_messages = _messages(label)
    english_messages.update(message_overrides or {})
    store.put_translation_version(
        tenant,
        "consumer-copy",
        "en-US",
        version,
        messages=english_messages,
        expected_current_version=expected,
        idempotency_key=f"translation-en-{suffix}",
    )
    store.put_translation_version(
        tenant,
        "consumer-copy",
        "fr",
        version,
        messages=_messages(label, french=True),
        expected_current_version=expected,
        idempotency_key=f"translation-fr-{suffix}",
    )
    if branded:
        store.put_theme_token_version(
            tenant,
            "brand-default",
            version,
            display_name_key="brand.display_name",
            heading_key="brand.heading",
            description_key="brand.description",
            primary_color="174b3f",
            primary_text_color="ffffff",
            surface_color="ffffff",
            text_color="16211d",
            expected_current_version=expected,
            idempotency_key=f"theme-{suffix}",
        )
    store.put_template_version(
        tenant,
        "standard-banner",
        version,
        surface="banner",
        title_key="template.title",
        body_key="template.body",
        actions={
            "accept_all": "action.accept",
            "reject_all": "action.reject",
            "manage_preferences": "action.manage",
            "save_preferences": "action.save",
        },
        theme_token_id="brand-default",
        theme_token_version=version if branded else None,
        expected_current_version=expected,
        idempotency_key=f"template-{suffix}",
    )
    store.put_rule_group_version(
        tenant,
        rule_group_id,
        version,
        rules=rules or [_rule(version=version)],
        expected_current_version=expected,
        idempotency_key=f"rules-{suffix}",
    )


def _publish(
    store: ConsentPublishingStore,
    tenant: str,
    *,
    property_id: str = "web-main",
    rule_group_id: str = "production-rules",
    rule_group_version: int = 1,
    publication_revision: int = 0,
    idempotency_key: str | None = None,
) -> dict:
    return store.publish(
        tenant,
        property_id,
        rule_group_id,
        rule_group_version,
        expected_property_revision=1,
        expected_publication_revision=publication_revision,
        idempotency_key=idempotency_key or f"publish-{property_id}-{publication_revision + 1}",
    )


def test_preview_publish_and_geo_locale_fallback(tmp_path: Path) -> None:
    store = _store(tmp_path / "authority" / "publishing.sqlite3")
    tenant = "tenant-a"
    _web_property(store, tenant)
    rules = [
        _rule(
            rule_id="united-states",
            priority=100,
            jurisdictions=("us",),
            countries=("US",),
            locales=("en-US", "fr"),
        ),
        _rule(rule_id="global", priority=1),
    ]
    _content(store, tenant, rules=rules)

    preview = store.preview(tenant, "web-main", "production-rules", 1)
    assert preview["bundle"]["property"]["consent_group_id"] == "consumer-global"
    assert len(preview["bundle_sha256"]) == 64

    publication = _publish(store, tenant)
    assert publication["publication_revision"] == 1
    assert publication["action"] == "publish"

    french = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.com",
        jurisdiction="us-ca",
        country_code="us",
        region_code="CA",
        requested_locale="fr-CA",
    )
    assert french["allowed"] is True
    assert french["rule"] == {
        "rule_id": "united-states",
        "rule_sha256": french["rule"]["rule_sha256"],
        "locale": "fr",
    }
    assert french["configuration"]["purposes"][0]["title"] == "Analyse v1"
    assert french["configuration"]["template"]["actions"]["reject_all"] == ("Tout refuser")

    global_result = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.com",
        jurisdiction="eu-eea",
        country_code="DE",
        requested_locale="de-DE",
    )
    assert global_result["allowed"] is True
    assert global_result["rule"]["rule_id"] == "global"
    assert global_result["rule"]["locale"] == "en-US"


def test_pinned_accessible_branding_is_localized_and_rollback_safe(tmp_path: Path) -> None:
    store = _store(tmp_path / "authority" / "branding.sqlite3")
    tenant = "tenant-a"
    _web_property(store, tenant)
    branded_rules = [_rule(locales=("en-US", "fr"))]
    _content(store, tenant, rules=branded_rules, branded=True)

    preview = store.preview(tenant, "web-main", "production-rules", 1)
    themes = [item for item in preview["bundle"]["resources"] if item["resource_kind"] == "theme"]
    assert len(themes) == 1
    assert themes[0]["resource_id"] == "brand-default"
    first = _publish(store, tenant)

    english = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.com",
        requested_locale="en-US",
    )
    assert english["allowed"] is True
    branding = english["configuration"]["branding"]
    assert branding["display_name"] == "Example"
    assert branding["heading"] == "Example Privacy Trust Center"
    assert branding["primary_color"] == "174b3f"
    assert len(branding["branding_sha256"]) == 64

    french = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.com",
        requested_locale="fr",
    )
    assert french["configuration"]["branding"]["display_name"] == "Exemple"

    _content(
        store,
        tenant,
        version=2,
        label="v2",
        rules=[_rule(version=2, locales=("en-US", "fr"))],
        branded=True,
    )
    _publish(
        store,
        tenant,
        rule_group_version=2,
        publication_revision=1,
        idempotency_key="publish-branded-v2",
    )
    store.rollback(
        tenant,
        "web-main",
        first["publication_id"],
        expected_property_revision=1,
        expected_publication_revision=2,
        idempotency_key="rollback-branding-v1",
    )
    restored = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.com",
        requested_locale="en-US",
    )
    assert restored["configuration"]["branding"] == branding


def test_theme_tokens_reject_low_contrast_before_persistence(tmp_path: Path) -> None:
    store = _store(tmp_path / "authority" / "branding-validation.sqlite3")
    with pytest.raises(PublishingValidationError, match="4.5:1 contrast"):
        store.put_theme_token_version(
            "tenant-a",
            "unsafe-theme",
            1,
            display_name_key="brand.display_name",
            heading_key="brand.heading",
            description_key="brand.description",
            primary_color="ffffff",
            primary_text_color="eeeeee",
            surface_color="ffffff",
            text_color="16211d",
            expected_current_version=0,
            idempotency_key="unsafe-theme",
        )
    with sqlite3.connect(store.path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM publishing_versions WHERE resource_kind='theme'"
        ).fetchone()[0]
    assert count == 0


@pytest.mark.parametrize(
    "unsafe_copy, expected_error",
    [
        ("x" * 513, "bounded plain text"),
        ("Brand\nDescription", "control data"),
    ],
)
def test_branded_copy_uses_the_strict_trust_center_contract(
    tmp_path: Path,
    unsafe_copy: str,
    expected_error: str,
) -> None:
    store = _store(tmp_path / f"brand-copy-{len(unsafe_copy)}.sqlite3")
    _web_property(store, "tenant-a")
    _content(
        store,
        "tenant-a",
        branded=True,
        message_overrides={"brand.description": unsafe_copy},
    )
    with pytest.raises(PublishingValidationError, match=expected_error):
        store.preview("tenant-a", "web-main", "production-rules", 1)


def test_legacy_unbranded_copy_keeps_the_existing_text_contract(tmp_path: Path) -> None:
    store = _store(tmp_path / "legacy-unbranded-copy.sqlite3")
    _web_property(store, "tenant-a")
    legacy_copy = "Legacy line one\n" + ("x" * 513)
    _content(
        store,
        "tenant-a",
        message_overrides={"template.body": legacy_copy},
    )
    _publish(store, "tenant-a")
    resolved = store.resolve_public_configuration(
        "tenant-a",
        "web-main",
        server_origin="https://www.example.com",
        requested_locale="en-US",
    )
    assert resolved["configuration"]["template"]["body"] == legacy_copy


def test_default_deny_when_no_published_rule_matches_or_publication_is_stale(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "publishing.sqlite3")
    tenant = "tenant-a"
    _web_property(store, tenant)
    _content(
        store,
        tenant,
        rules=[
            _rule(
                rule_id="us-only",
                priority=100,
                jurisdictions=("us",),
                countries=("US",),
            )
        ],
    )
    _publish(store, tenant)

    denied = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.com",
        jurisdiction="eu-eea",
        country_code="DE",
        requested_locale="en-US",
    )
    assert denied["allowed"] is False
    assert denied["reason"] == "no_published_rule_match"

    store.upsert_property(
        tenant,
        "web-main",
        kind="web",
        consent_group_id="consumer-global",
        web_domains=["example.com"],
        origin_allowlist=["https://www.example.com", "https://shop.example.com"],
        expected_revision=1,
        idempotency_key="property-revision-2",
    )
    stale = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.com",
        jurisdiction="us-ca",
        country_code="US",
        requested_locale="en-US",
    )
    assert stale["allowed"] is False
    assert stale["reason"] == "stale_publication"


def test_cross_tenant_origin_and_mobile_bundle_authorization(tmp_path: Path) -> None:
    store = _store(tmp_path / "publishing.sqlite3")
    tenant = "tenant-a"
    _web_property(store, tenant)
    _content(store, tenant)
    publication = _publish(store, tenant)
    _web_property(store, "tenant-b")

    with pytest.raises(PublishingNotFound):
        store.preview("tenant-b", "web-main", "production-rules", 1)
    with pytest.raises(PublishingNotFound):
        store.rollback(
            "tenant-b",
            "web-main",
            publication["publication_id"],
            expected_property_revision=1,
            expected_publication_revision=0,
            idempotency_key="tenant-b-cross-rollback",
        )
    other_tenant = store.resolve_public_configuration(
        "tenant-b",
        "web-main",
        server_origin="https://www.example.com",
        requested_locale="en-US",
    )
    assert other_tenant["allowed"] is False
    assert other_tenant["reason"] == "unavailable"

    wrong_origin = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://shop.example.com",
        requested_locale="en-US",
    )
    assert wrong_origin["allowed"] is False
    assert wrong_origin["reason"] == "property_authorization_failed"
    wrong_surface = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.com",
        server_bundle_id="com.example.mobile",
        server_platform="ios",
        requested_locale="en-US",
    )
    assert wrong_surface["allowed"] is False

    store.upsert_property(
        tenant,
        "mobile-main",
        kind="mobile",
        consent_group_id="consumer-global",
        mobile_bundle_ids=["com.example.mobile"],
        platform="ios",
        expected_revision=0,
        idempotency_key="property-mobile",
    )
    _publish(store, tenant, property_id="mobile-main")
    assert (
        store.resolve_public_configuration(
            tenant,
            "mobile-main",
            server_bundle_id="com.example.other",
            server_platform="ios",
            requested_locale="en-US",
        )["allowed"]
        is False
    )
    assert (
        store.resolve_public_configuration(
            tenant,
            "mobile-main",
            server_bundle_id="com.example.mobile",
            server_platform="android",
            requested_locale="en-US",
        )["allowed"]
        is False
    )
    allowed = store.resolve_public_configuration(
        tenant,
        "mobile-main",
        server_bundle_id="com.example.mobile",
        server_platform="ios",
        requested_locale="en-US",
    )
    assert allowed["allowed"] is True
    assert allowed["property"]["kind"] == "mobile"


def test_cas_and_exact_idempotency_replay_and_rebind(tmp_path: Path) -> None:
    store = _store(tmp_path / "publishing.sqlite3")
    tenant = "tenant-a"
    first = _web_property(store, tenant, idempotency_key="property-request")
    replay = _web_property(store, tenant, idempotency_key="property-request")
    assert replay == first

    with pytest.raises(PublishingIdempotencyConflict):
        _web_property(
            store,
            tenant,
            origin="https://shop.example.com",
            idempotency_key="property-request",
        )
    with pytest.raises(PublishingConflict):
        store.upsert_property(
            tenant,
            "web-main",
            kind="web",
            consent_group_id="consumer-global",
            web_domains=["example.com"],
            origin_allowlist=["https://www.example.com"],
            expected_revision=0,
            idempotency_key="stale-property",
        )

    _content(store, tenant)
    publication = _publish(store, tenant, idempotency_key="publish-request")
    assert _publish(store, tenant, idempotency_key="publish-request") == publication
    with pytest.raises(PublishingIdempotencyConflict):
        _publish(
            store,
            tenant,
            publication_revision=1,
            idempotency_key="publish-request",
        )
    with pytest.raises(PublishingConflict):
        _publish(store, tenant, publication_revision=0, idempotency_key="stale-publish")

    with pytest.raises(PublishingConflict):
        store.put_purpose_version(
            tenant,
            "analytics",
            2,
            title_key="purpose.title",
            description_key="purpose.description",
            lawful_basis="consent",
            required=False,
            default_choice="denied",
            expected_current_version=0,
            idempotency_key="stale-purpose",
        )


def test_non_ascii_stored_digests_are_refused_not_type_errors(tmp_path: Path) -> None:
    # Edited digests must not raise TypeError from hmac.compare_digest instead
    # of the idempotency conflict and integrity refusals.
    path = tmp_path / "publishing.sqlite3"
    store = _store(path)
    tenant = "tenant-a"
    _web_property(store, tenant, idempotency_key="property-request")
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER publishing_idempotency_no_update")
        connection.execute("UPDATE publishing_idempotency SET request_sha256 = ?", ("é" * 64,))
        connection.execute("UPDATE publishing_properties SET record_sha256 = ?", ("é" * 64,))
    with pytest.raises(PublishingIdempotencyConflict):
        _web_property(store, tenant, idempotency_key="property-request")
    with pytest.raises(ConsentPublishingError, match="property digest"):
        store.catalog(tenant, kind="property")


def test_rollback_creates_new_immutable_publication_and_restores_bundle(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "publishing.sqlite3")
    tenant = "tenant-a"
    _web_property(store, tenant)
    _content(store, tenant, version=1, label="v1")
    first = _publish(store, tenant, rule_group_version=1)

    _content(store, tenant, version=2, label="v2")
    second = _publish(
        store,
        tenant,
        rule_group_version=2,
        publication_revision=1,
    )
    assert second["publication_revision"] == 2
    current = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.com",
        requested_locale="en-US",
    )
    assert current["configuration"]["purposes"][0]["title"] == "Analytics v2"

    rolled_back = store.rollback(
        tenant,
        "web-main",
        first["publication_id"],
        expected_property_revision=1,
        expected_publication_revision=2,
        idempotency_key="rollback-to-v1",
    )
    assert rolled_back["publication_revision"] == 3
    assert rolled_back["action"] == "rollback"
    assert rolled_back["source_publication_id"] == first["publication_id"]
    restored = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.com",
        requested_locale="en-US",
    )
    assert restored["configuration"]["purposes"][0]["title"] == "Analytics v1"
    assert restored["publication"]["publication_id"] == rolled_back["publication_id"]

    history = store.publication_history(tenant, "web-main", limit=10)
    assert [item["publication_revision"] for item in history["items"]] == [3, 2, 1]
    with pytest.raises(PublishingConflict):
        store.rollback(
            tenant,
            "web-main",
            first["publication_id"],
            expected_property_revision=1,
            expected_publication_revision=2,
            idempotency_key="stale-rollback",
        )

    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE consent_publications SET action = 'publish' WHERE publication_id = ?",
                (first["publication_id"],),
            )


@pytest.mark.parametrize(
    ("domains", "origins"),
    [
        (["*.example.com"], ["https://www.example.com"]),
        (["example.com"], ["http://www.example.com"]),
        (["example.com"], ["https://user@www.example.com"]),
        (["example.com"], ["https://www.example.com/path"]),
        (["example.com"], ["https://example.net"]),
    ],
)
def test_rejects_unsafe_web_property_patterns(
    tmp_path: Path,
    domains: list[str],
    origins: list[str],
) -> None:
    store = _store(tmp_path / "publishing.sqlite3")
    with pytest.raises(PublishingValidationError):
        store.upsert_property(
            "tenant-a",
            "web-main",
            kind="web",
            consent_group_id="consumer-global",
            web_domains=domains,
            origin_allowlist=origins,
            expected_revision=0,
            idempotency_key="unsafe-property",
        )


def test_rejects_markup_executable_text_oversize_and_open_rule_shapes(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "publishing.sqlite3")
    with pytest.raises(PublishingValidationError, match="markup"):
        store.put_translation_version(
            "tenant-a",
            "copy",
            "en-US",
            1,
            messages={"notice.body": "<script>alert(1)</script>"},
            expected_current_version=0,
            idempotency_key="script-copy",
        )
    with pytest.raises(PublishingValidationError, match="executable URI"):
        store.put_translation_version(
            "tenant-a",
            "copy",
            "en-US",
            1,
            messages={"notice.body": "javascript:alert(1)"},
            expected_current_version=0,
            idempotency_key="uri-copy",
        )
    with pytest.raises(PublishingValidationError, match="byte bound"):
        store.put_translation_version(
            "tenant-a",
            "copy",
            "en-US",
            1,
            messages={"notice.body": "x" * 4097},
            expected_current_version=0,
            idempotency_key="oversize-copy",
        )
    with pytest.raises(PublishingValidationError, match="bounded sequence"):
        store.put_rule_group_version(
            "tenant-a",
            "rules",
            1,
            rules=[{}] * 129,
            expected_current_version=0,
            idempotency_key="oversize-rules",
        )
    unsafe_rule = _rule()
    unsafe_rule["raw_html"] = "<p>not permitted</p>"
    with pytest.raises(PublishingValidationError, match="unsupported fields"):
        store.put_rule_group_version(
            "tenant-a",
            "rules",
            1,
            rules=[unsafe_rule],
            expected_current_version=0,
            idempotency_key="open-rule",
        )


def test_public_resolution_fails_closed_when_materialized_output_exceeds_bound(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "publishing.sqlite3")
    tenant = "tenant-a"
    _web_property(store, tenant)
    refs = []
    for index in range(70):
        purpose_id = f"purpose-{index}"
        store.put_purpose_version(
            tenant,
            purpose_id,
            1,
            title_key="purpose.title",
            description_key="purpose.description",
            lawful_basis="consent",
            required=False,
            default_choice="denied",
            expected_current_version=0,
            idempotency_key=f"purpose-{index}",
        )
        refs.append({"id": purpose_id, "version": 1})
    store.put_notice_version(
        tenant,
        "privacy-notice",
        1,
        title_key="notice.title",
        body_key="notice.body",
        document_sha256=_digest("large-notice"),
        expected_current_version=0,
        idempotency_key="large-notice",
    )
    store.put_translation_version(
        tenant,
        "consumer-copy",
        "en-US",
        1,
        messages={
            "purpose.title": "Purpose",
            "purpose.description": "x" * 4090,
            "notice.title": "Notice",
            "notice.body": "Notice body",
            "template.title": "Choices",
            "template.body": "Choose",
            "action.save": "Save",
        },
        expected_current_version=0,
        idempotency_key="large-copy",
    )
    store.put_template_version(
        tenant,
        "standard-banner",
        1,
        surface="banner",
        title_key="template.title",
        body_key="template.body",
        actions={"save_preferences": "action.save"},
        theme_token_id="brand-default",
        expected_current_version=0,
        idempotency_key="large-template",
    )
    store.put_rule_group_version(
        tenant,
        "large-rules",
        1,
        rules=[
            {
                "rule_id": "global",
                "priority": 1,
                "locales": ["en-US"],
                "default_locale": "en-US",
                "purposes": refs,
                "notice": {"id": "privacy-notice", "version": 1},
                "template": {"id": "standard-banner", "version": 1},
                "translation_catalog_id": "consumer-copy",
                "translation_versions": {"en-US": 1},
            }
        ],
        expected_current_version=0,
        idempotency_key="large-rules",
    )
    _publish(store, tenant, rule_group_id="large-rules")
    result = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.com",
        requested_locale="en-US",
    )
    assert result["allowed"] is False
    assert result["reason"] == "public_configuration_too_large"


def test_preview_rejects_missing_translation_contract(tmp_path: Path) -> None:
    store = _store(tmp_path / "publishing.sqlite3")
    tenant = "tenant-a"
    _web_property(store, tenant)
    _content(store, tenant)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER publishing_versions_no_update")
        row = connection.execute(
            "SELECT payload_json FROM publishing_versions WHERE tenant = ? "
            "AND resource_kind = 'translation' AND locale = 'en-US'",
            (tenant,),
        ).fetchone()
        assert row is not None
        # Direct corruption is rejected by the resource digest before a partial
        # or misleading preview can be emitted.
        connection.execute(
            "UPDATE publishing_versions SET payload_json = ? WHERE tenant = ? "
            "AND resource_kind = 'translation' AND locale = 'en-US'",
            ('{"messages":{"notice.title":"incomplete"}}', tenant),
        )
    with pytest.raises(ConsentPublishingError, match="digest"):
        store.preview(tenant, "web-main", "production-rules", 1)


def test_concurrent_first_open_and_property_cas_are_serialized(tmp_path: Path) -> None:
    path = tmp_path / "private" / "publishing.sqlite3"

    def first_open(index: int) -> tuple[int, bool]:
        store = ConsentPublishingStore(path)
        result = store.upsert_property(
            f"tenant-{index}",
            f"property-{index}",
            kind="web",
            consent_group_id="group",
            web_domains=["example.com"],
            origin_allowlist=[f"https://site{index}.example.com"],
            expected_revision=0,
            idempotency_key=f"first-open-{index}",
        )
        history = store.publication_history(
            f"tenant-{index}",
            f"property-{index}",
        )
        return result["revision"], history["items"] == []

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(first_open, range(24)))
    assert results == [(1, True)] * 24
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM publishing_properties").fetchone()[0] == 24
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600

    store = ConsentPublishingStore(path)
    store.upsert_property(
        "tenant-cas",
        "shared",
        kind="web",
        consent_group_id="group",
        web_domains=["example.com"],
        origin_allowlist=["https://www.example.com"],
        expected_revision=0,
        idempotency_key="cas-initial",
    )

    def revise(index: int) -> str:
        contender = ConsentPublishingStore(path)
        try:
            contender.upsert_property(
                "tenant-cas",
                "shared",
                kind="web",
                consent_group_id="group",
                web_domains=["example.com"],
                origin_allowlist=[f"https://revision{index}.example.com"],
                expected_revision=1,
                idempotency_key=f"cas-{index}",
            )
        except PublishingConflict:
            return "conflict"
        return "updated"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(revise, range(2)))
    assert sorted(outcomes) == ["conflict", "updated"]


@pytest.mark.parametrize("tenant", ["", "tenant.", None])
def test_every_public_boundary_rejects_implicit_or_invalid_tenant(
    tmp_path: Path,
    tenant: object,
) -> None:
    store = _store(tmp_path / "publishing.sqlite3")
    with pytest.raises(PublishingValidationError):
        store.publication_history(tenant, "web-main")  # type: ignore[arg-type]


def test_canonical_tenant_ids_accept_spaces_and_normalize_unicode(tmp_path: Path) -> None:
    store = _store(tmp_path / "canonical-publishing.sqlite3")
    decomposed = "Acme Cafe\u0301 Corp"
    canonical = "Acme Caf\u00e9 Corp"

    created = _web_property(store, decomposed)
    assert created["tenant_sha256"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert store.publication_history(canonical, "web-main") == {
        "items": [],
        "truncated": False,
    }
    with pytest.raises(PublishingNotFound):
        store.publication_history("Other Corp", "web-main")
