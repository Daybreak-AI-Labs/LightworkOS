"""A small published consent experience behind the public consent router.

One web property with one purpose, notice, template and rule group, one
published consent policy, one enrolled browser client and (optionally) a
second browser client on another website -- enough to drive the public
``/configuration`` path end to end. Signing and visitor sessions are injected
so tests never depend on a real installation's settings.
"""
from __future__ import annotations

import hashlib
import itertools
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

NOW = 1_800_000_000.0
ORIGIN = "https://www.example.com"
OTHER_ORIGIN = "https://shop.example.com"
CLIENT_CREDENTIAL = "browser-client-credential-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # pragma: allowlist secret
OTHER_CREDENTIAL = "browser-client-credential-dddddddddddddddddddddddddddddddd"  # pragma: allowlist secret
NOTICE_SHA256 = hashlib.sha256(b"public notice v1").hexdigest()


def browser_headers(credential: str = CLIENT_CREDENTIAL, origin: str = ORIGIN,
                    session: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"ConsentPublic {credential}", "Origin": origin}
    if session is not None:
        headers["X-Lightwork-Consent-Session"] = session
    return headers


def seed(
    tmp_path: Path,
    *,
    signing: Callable[[], Any] | None = None,
    session_ttl: Callable[[], int | None] | None = None,
    rate_limit: Callable[[str, str], None] | None = None,
) -> SimpleNamespace:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from maverick.consent_preferences import ConsentPreferenceStore
    from maverick.consent_publishing import ConsentPublishingStore
    from maverick_dashboard.consent_public_api import (
        PublicConsentCredentialStore,
        PublicConsentDependencies,
        create_consent_public_router,
        default_public_request_context,
    )

    clock = {"now": NOW}
    ids = itertools.count(1)
    tenant = "tenant-a"
    publishing = ConsentPublishingStore(
        tmp_path / "publishing.sqlite3",
        clock=lambda: clock["now"],
        id_factory=lambda prefix: f"{prefix}-{next(ids)}",
        signing=signing,
    )
    preferences = ConsentPreferenceStore(
        tmp_path / "preferences.sqlite3",
        clock=lambda: clock["now"],
        id_factory=lambda prefix: f"{prefix}-{next(ids)}",
    )
    registry = PublicConsentCredentialStore(
        tmp_path / "credentials.sqlite3",
        clock=lambda: clock["now"],
        id_factory=lambda: f"public-client-{next(ids)}",
    )
    prop = publishing.upsert_property(
        tenant, "web-main", kind="web", consent_group_id="consumer-global",
        web_domains=["example.com"], origin_allowlist=[ORIGIN, OTHER_ORIGIN],
        expected_revision=0, idempotency_key="property-v1",
    )
    publishing.put_purpose_version(
        tenant, "analytics", 1, title_key="purpose.title",
        description_key="purpose.description", lawful_basis="consent", required=False,
        default_choice="denied", expected_current_version=0, idempotency_key="purpose-v1",
    )
    publishing.put_notice_version(
        tenant, "privacy-notice", 1, title_key="notice.title", body_key="notice.body",
        document_sha256=NOTICE_SHA256, expected_current_version=0, idempotency_key="notice-v1",
    )
    publishing.put_translation_version(
        tenant, "consumer-copy", "en-US", 1,
        messages={
            "purpose.title": "Analytics", "purpose.description": "Measure performance",
            "notice.title": "Your privacy choices", "notice.body": "Choose what we may use.",
            "template.title": "Privacy choices", "template.body": "Control analytics.",
            "action.accept": "Accept", "action.reject": "Reject", "action.save": "Save",
        },
        expected_current_version=0, idempotency_key="translation-v1",
    )
    publishing.put_template_version(
        tenant, "standard-banner", 1, surface="banner", title_key="template.title",
        body_key="template.body",
        actions={"accept_all": "action.accept", "reject_all": "action.reject",
                 "save_preferences": "action.save"},
        theme_token_id="brand-default", expected_current_version=0,
        idempotency_key="template-v1",
    )
    publishing.put_rule_group_version(
        tenant, "production-rules", 1,
        rules=[{
            "rule_id": "global", "priority": 1, "locales": ["en-US"],
            "default_locale": "en-US", "purposes": [{"id": "analytics", "version": 1}],
            "notice": {"id": "privacy-notice", "version": 1},
            "template": {"id": "standard-banner", "version": 1},
            "translation_catalog_id": "consumer-copy", "translation_versions": {"en-US": 1},
        }],
        expected_current_version=0, idempotency_key="rules-v1",
    )
    publication = publishing.publish(
        tenant, "web-main", "production-rules", 1, expected_property_revision=1,
        expected_publication_revision=0, idempotency_key="publication-v1",
    )
    policy = preferences.publish_policy(
        tenant, "public-consent", 1, {"analytics": "consent"}, NOTICE_SHA256, NOW - 100,
    )
    bindings = {}
    for credential, origin in ((CLIENT_CREDENTIAL, ORIGIN), (OTHER_CREDENTIAL, OTHER_ORIGIN)):
        bindings[origin] = registry.enroll_client(
            credential, tenant_id=tenant, property_id="web-main", client_kind="browser",
            browser_origin=origin, jurisdiction="global", country_code="US", region_code="",
            default_locale="en-US", property_revision=prop["revision"],
            property_sha256=prop["record_sha256"], rule_group_id="production-rules",
            rule_group_version=1, publication_sha256=publication["publication_sha256"],
            bundle_sha256=publication["bundle_sha256"], policy_id=policy["policy_id"],
            policy_version=policy["version"], policy_sha256=policy["policy_sha256"],
            expected_revision=0,
        )
    calls: list[tuple[str, str]] = []

    def default_rate_limit(credential_sha256: str, action: str) -> None:
        calls.append((credential_sha256, action))

    dependencies = PublicConsentDependencies(
        credential_store=registry,
        publishing_store_for=lambda _tenant: publishing,
        preference_store_for=lambda _tenant: preferences,
        gate=lambda: True,
        rate_limit=rate_limit or default_rate_limit,
        context_resolver=default_public_request_context,
        clock=lambda: clock["now"],
        experiment_gate=lambda: False,
        profile_data_gate=lambda: False,
        session_ttl=session_ttl,
        publication_signing=signing,
    )
    app = FastAPI()
    app.include_router(create_consent_public_router(dependencies))
    return SimpleNamespace(
        app=app,
        client=TestClient(app, base_url="https://consent.lightwork.test"),
        clock=clock,
        publishing=publishing,
        preferences=preferences,
        registry=registry,
        publication=publication,
        policy=policy,
        bindings=bindings,
        rate_calls=calls,
        tenant=tenant,
    )
