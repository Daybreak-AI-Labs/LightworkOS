from __future__ import annotations

import base64
import hashlib
from dataclasses import replace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick.consent_identity_federation import (
    ConsentIdentityFederationConflict,
    ConsentIdentityFederationStore,
    ConsentIdentitySettings,
    ConsentPairingContext,
    VerifiedConsentOIDCClaims,
)
from maverick.consent_preferences import ConsentPreferenceStore
from maverick_dashboard.consent_identity_federation_api import (
    ConsentIdentityFederationAPIDependencies,
    create_consent_identity_federation_router,
    resolve_consent_pairing_context,
)
from maverick_dashboard.consent_public_api import (
    PublicClientBinding,
    PublicConsentCredentialError,
    PublicConsentCredentialStore,
    PublicConsentDependencies,
    PublicProfileBinding,
    PublicRequestContext,
    create_consent_public_router,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def challenge(verifier: str) -> str:
    raw = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def client(name: str, kind: str) -> PublicClientBinding:
    service = kind == "service"
    return PublicClientBinding(
        credential_id=f"credential-{name}",
        credential_sha256=digest(f"client-token-{name}"),
        tenant_id="tenant-a",
        property_id="property-a",
        client_kind=kind,
        browser_origin=None if service else "https://consent.example.test",
        service_client_id=f"service-{name}" if service else None,
        target_origin=None if service else "https://consent.example.test",
        target_bundle_id="com.example.tv" if service else None,
        target_platform="tvos" if service else None,
        jurisdiction="us",
        country_code="US",
        region_code="NY",
        default_locale="en-US",
        property_revision=1,
        property_sha256=digest("property"),
        rule_group_id="rules",
        rule_group_version=1,
        publication_sha256=digest("publication"),
        bundle_sha256=digest("bundle"),
        policy_id="policy",
        policy_version=1,
        policy_sha256=digest("policy"),
        expires_at=None,
        revision=1,
        record_sha256=digest(f"record-{name}"),
    )


def profile(name: str, binding: PublicClientBinding) -> PublicProfileBinding:
    return PublicProfileBinding(
        credential_sha256=digest(f"profile-token-{name}"),
        client_credential_sha256=binding.credential_sha256,
        tenant_id=binding.tenant_id,
        property_id=binding.property_id,
        profile_id=f"profile-{name}",
        subject_binding_sha256=digest(f"subject-{name}"),
        binding_sha256=digest(f"binding-{name}"),
    )


class FakeCredentials:
    def __init__(self, clients, profiles):
        self.clients = clients
        self.profiles = profiles

    def resolve_client(self, raw):
        return self.clients[raw]

    def resolve_profile(self, raw, resolved_client):
        value = self.profiles[raw]
        assert value.client_credential_sha256 == resolved_client.credential_sha256
        return value

    def resolve_client_authority(self, credential_sha256):
        return next(
            value for value in self.clients.values() if value.credential_sha256 == credential_sha256
        )

    def resolve_profile_authority(self, credential_sha256, resolved_client):
        value = next(
            item for item in self.profiles.values() if item.credential_sha256 == credential_sha256
        )
        assert value.client_credential_sha256 == resolved_client.credential_sha256
        return value

    @staticmethod
    def browser_origin_allowed(origin):
        return origin == "https://consent.example.test"


def test_registry_digest_revalidation_is_not_a_bearer_path(tmp_path):
    registry = PublicConsentCredentialStore(tmp_path / "registry.sqlite3")
    preferences = ConsentPreferenceStore(tmp_path / "registry-preferences.sqlite3")
    raw_client = "opaque-public-client-credential-123456"
    raw_profile = "opaque-public-profile-credential-12345"
    enrolled = registry.enroll_client(
        raw_client,
        tenant_id="tenant-a",
        property_id="property-a",
        client_kind="browser",
        browser_origin="https://consent.example.test",
        jurisdiction="us",
        country_code="US",
        region_code="NY",
        default_locale="en-US",
        property_revision=1,
        property_sha256=digest("property"),
        rule_group_id="rules",
        rule_group_version=1,
        publication_sha256=digest("publication"),
        bundle_sha256=digest("bundle"),
        policy_id="policy",
        policy_version=1,
        policy_sha256=digest("policy"),
        expected_revision=0,
    )
    registry.bootstrap_profile(
        enrolled,
        subject_sha256=digest("anonymous-subject"),
        profile_credential_sha256=digest(raw_profile),
        idempotency_key="bootstrap-profile",
        create_profile=lambda profile_id, subject_sha, idempotency: preferences.create_profile(
            "tenant-a",
            profile_id,
            "anonymous",
            subject_sha,
            idempotency,
        ),
    )
    profile_binding = registry.resolve_profile(raw_profile, enrolled)
    assert registry.resolve_client_authority(enrolled.credential_sha256) == enrolled
    assert (
        registry.resolve_profile_authority(profile_binding.credential_sha256, enrolled)
        == profile_binding
    )

    registry.revoke_client(raw_client, expected_revision=1)
    with pytest.raises(PublicConsentCredentialError):
        registry.resolve_client_authority(enrolled.credential_sha256)


def test_default_pairing_context_resolver_pins_published_policy_and_tv_channel(
    tmp_path,
):
    now = 1_800_000_000.0
    preferences = ConsentPreferenceStore(
        tmp_path / "context-preferences.sqlite3",
        clock=lambda: now,
    )
    policy = preferences.publish_policy(
        "tenant-a",
        "policy",
        1,
        {"analytics": "consent"},
        digest("notice"),
        now - 10,
        expected_current_version=0,
    )
    preferences.create_profile(
        "tenant-a",
        "profile-target",
        "anonymous",
        digest("target-subject"),
        "create-target",
    )
    target_client = replace(client("target", "service"), policy_sha256=policy["policy_sha256"])
    target_profile = profile("target", target_client)
    credentials = FakeCredentials(
        {"target-client-token-value-123456789": target_client},
        {"target-profile-token-value-12345678": target_profile},
    )

    class Publishing:
        @staticmethod
        def preview(*_args):
            return {
                "bundle_sha256": target_client.bundle_sha256,
                "bundle": {"property": {"record_sha256": target_client.property_sha256}},
            }

        @staticmethod
        def resolve_public_configuration(*_args, **_kwargs):
            return {
                "allowed": True,
                "property": {"property_id": "property-a", "revision": 1},
                "publication": {
                    "property_revision": 1,
                    "publication_sha256": target_client.publication_sha256,
                    "bundle_sha256": target_client.bundle_sha256,
                },
                "configuration_sha256": digest("configuration"),
                "configuration": {
                    "purposes": [{"id": "analytics", "lawful_basis": "consent"}],
                    "notice": {"document_sha256": digest("notice")},
                },
            }

    public = PublicConsentDependencies(
        credential_store=credentials,
        publishing_store_for=lambda _tenant: Publishing(),
        preference_store_for=lambda _tenant: preferences,
        gate=lambda: True,
        rate_limit=lambda *_args: None,
        context_resolver=lambda _request, _binding: PublicRequestContext("us", "US", "NY", "en-US"),
        clock=lambda: now,
    )
    resolved = resolve_consent_pairing_context(
        public,
        target_client,
        target_profile,
    )
    assert resolved.configuration_sha256 == digest("configuration")
    assert resolved.policy_sha256 == policy["policy_sha256"]
    assert resolved.channel_kind == "service-client"
    assert resolved.channel_binding_sha256 != digest("target-tvos-service")

    changed = replace(target_client, bundle_sha256=digest("changed-bundle"))
    with pytest.raises(ConsentIdentityFederationConflict):
        resolve_consent_pairing_context(public, changed, target_profile)


def test_narrow_browser_to_tv_pairing_flow_has_no_consumer_selectors(tmp_path):
    source_token = "source-client-token-value-123456789"
    target_token = "target-client-token-value-123456789"
    source_profile_token = "source-profile-token-value-12345678"
    target_profile_token = "target-profile-token-value-12345678"
    source_client = client("source", "browser")
    target_client = client("target", "service")
    source_profile = profile("source", source_client)
    target_profile = profile("target", target_client)
    credentials = FakeCredentials(
        {source_token: source_client, target_token: target_client},
        {source_profile_token: source_profile, target_profile_token: target_profile},
    )
    preferences = ConsentPreferenceStore(tmp_path / "preferences.sqlite3")
    preferences.create_profile(
        "tenant-a", "profile-source", "anonymous", digest("source"), "create-source"
    )
    preferences.create_profile(
        "tenant-a", "profile-target", "anonymous", digest("target"), "create-target"
    )
    base = {
        source_client.credential_sha256: ConsentPairingContext(
            tenant_id="tenant-a",
            property_id="property-a",
            profile_id="profile-source",
            profile_revision=0,
            client_credential_sha256=source_client.credential_sha256,
            client_revision=1,
            client_record_sha256=source_client.record_sha256,
            profile_credential_sha256=source_profile.credential_sha256,
            profile_binding_sha256=source_profile.binding_sha256,
            property_revision=1,
            property_sha256=source_client.property_sha256,
            publication_sha256=source_client.publication_sha256,
            bundle_sha256=source_client.bundle_sha256,
            configuration_sha256=digest("configuration"),
            policy_id="policy",
            policy_version=1,
            policy_sha256=source_client.policy_sha256,
            channel_kind="browser-origin",
            channel_binding_sha256=digest("source-origin"),
        ),
        target_client.credential_sha256: ConsentPairingContext(
            tenant_id="tenant-a",
            property_id="property-a",
            profile_id="profile-target",
            profile_revision=0,
            client_credential_sha256=target_client.credential_sha256,
            client_revision=1,
            client_record_sha256=target_client.record_sha256,
            profile_credential_sha256=target_profile.credential_sha256,
            profile_binding_sha256=target_profile.binding_sha256,
            property_revision=1,
            property_sha256=target_client.property_sha256,
            publication_sha256=target_client.publication_sha256,
            bundle_sha256=target_client.bundle_sha256,
            configuration_sha256=digest("configuration"),
            policy_id="policy",
            policy_version=1,
            policy_sha256=target_client.policy_sha256,
            channel_kind="service-client",
            channel_binding_sha256=digest("target-tvos-service"),
        ),
    }

    def current(expected):
        item = base[expected.client_credential_sha256]
        authority = preferences.get_profile_authority("tenant-a", item.profile_id)
        return replace(item, profile_revision=int(authority["revision"]))

    pairing = ConsentIdentityFederationStore(
        tmp_path / "pairing.sqlite3",
        preference_store_for=lambda _tenant: preferences,
        context_resolver=current,
    )
    public = PublicConsentDependencies(
        credential_store=credentials,
        publishing_store_for=lambda _tenant: None,
        preference_store_for=lambda _tenant: preferences,
        gate=lambda: True,
        rate_limit=lambda *_args: None,
        context_resolver=lambda _request, _binding: PublicRequestContext("us", "US", "NY", "en-US"),
    )
    identity_settings = ConsentIdentitySettings(
        enabled=True,
        issuer="https://id.example.test",
        audience="consent",
        jwks_origin="https://keys.example.test",
        token_ttl_seconds=300,
    )

    def oidc_verifier(token, expectation):
        return VerifiedConsentOIDCClaims(
            subject="known-user",
            issuer=expectation.issuer,
            audiences=(expectation.audience,),
            nonce=expectation.nonce,
            issued_at=expectation.now - 5,
            expires_at=expectation.now + 120,
            not_before=expectation.now - 5,
            key_id="key-1",
            token_sha256=digest(token),
        )

    deps = ConsentIdentityFederationAPIDependencies(
        public=public,
        pairing_store=pairing,
        settings_for=lambda: identity_settings,
        context_for=lambda resolved_client, _profile: current(
            base[resolved_client.credential_sha256]
        ),
        oidc_verifier_for=lambda _request: oidc_verifier,
        subject_digest_key_for=lambda _request: b"s" * 32,
    )
    app = FastAPI()
    app.include_router(create_consent_public_router(public))
    app.include_router(create_consent_identity_federation_router(deps))
    http = TestClient(app, base_url="http://127.0.0.1")
    identity_paths = {
        path
        for path in app.openapi()["paths"]
        if path.startswith("/api/v1/public/consent/identity/")
    }
    assert identity_paths == {
        "/api/v1/public/consent/identity/pairings",
        "/api/v1/public/consent/identity/pairings/authorize",
        "/api/v1/public/consent/identity/pairings/redeem",
        "/api/v1/public/consent/identity/pairings/revoke",
        "/api/v1/public/consent/identity/link",
        "/api/v1/public/consent/identity/link/unlink",
    }
    identity_schema = str({path: app.openapi()["paths"][path] for path in identity_paths}).lower()
    assert "tenant_id" not in identity_schema
    assert "property_id" not in identity_schema
    assert "profile_id" not in identity_schema
    verifier = "p" * 64
    target_headers = {
        "Authorization": f"ConsentPublic {target_token}",
        "X-Lightwork-Profile-Credential": target_profile_token,
        "X-Lightwork-Consent-Service-Client": "service-target",
    }
    source_headers = {
        "Authorization": f"ConsentPublic {source_token}",
        "X-Lightwork-Profile-Credential": source_profile_token,
        "Origin": "https://consent.example.test",
    }

    preflight = http.options(
        "/api/v1/public/consent/identity/pairings",
        headers={
            "Origin": "https://consent.example.test",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "authorization, content-type, x-lightwork-profile-credential"
            ),
        },
    )
    assert preflight.status_code == 204

    started = http.post(
        "/api/v1/public/consent/identity/pairings",
        headers=target_headers,
        json={"code_challenge": challenge(verifier)},
    )
    assert started.status_code == 200, started.text
    material = started.json()
    assert started.headers["cache-control"] == "no-store, private"
    authorized = http.post(
        "/api/v1/public/consent/identity/pairings/authorize",
        headers=source_headers,
        json={
            "pairing_code": material["pairing_code"],
            "oidc_nonce": material["oidc_nonce"],
            "oidc_token": "signed-token-value-that-is-long-enough-12345",
        },
    )
    assert authorized.status_code == 200
    assert authorized.json()["status"] == "authorized"
    assert authorized.headers["access-control-allow-origin"] == source_client.browser_origin

    redeemed = http.post(
        "/api/v1/public/consent/identity/pairings/redeem",
        headers=target_headers,
        json={"pairing_code": material["pairing_code"], "code_verifier": verifier},
    )
    assert redeemed.status_code == 200
    assert redeemed.json() == {"status": "redeemed", "linked": True}
    assert (
        preferences.get_profile_authority("tenant-a", "profile-target")["linked_known_profile_id"]
        == preferences.get_profile_authority("tenant-a", "profile-source")[
            "linked_known_profile_id"
        ]
    )

    replay = http.post(
        "/api/v1/public/consent/identity/pairings/redeem",
        headers=target_headers,
        json={"pairing_code": material["pairing_code"], "code_verifier": verifier},
    )
    assert replay.status_code == 403
    selectors = http.post(
        "/api/v1/public/consent/identity/pairings",
        headers=target_headers,
        json={
            "code_challenge": challenge(verifier),
            "tenant_id": "tenant-a",
            "profile_id": "profile-target",
        },
    )
    assert selectors.status_code == 422
    wrong_service = http.post(
        "/api/v1/public/consent/identity/pairings",
        headers={**target_headers, "X-Lightwork-Consent-Service-Client": "wrong"},
        json={"code_challenge": challenge(verifier)},
    )
    assert wrong_service.status_code == 401

    current_link = http.get(
        "/api/v1/public/consent/identity/link",
        headers=target_headers,
    )
    assert current_link.status_code == 200
    assert current_link.json()["linked"] is True
    authority = preferences.get_profile_authority("tenant-a", "profile-target")
    unlink_body = {
        "expected_profile_revision": authority["revision"],
        "expected_link_revision": authority["link_revision"],
        "idempotency_key": "public-unlink-1",
        "reason_sha256": digest("consumer-unlink"),
    }
    unlinked = http.post(
        "/api/v1/public/consent/identity/link/unlink",
        headers=target_headers,
        json=unlink_body,
    )
    assert unlinked.status_code == 200, unlinked.text
    assert unlinked.json()["pairing_revoked"] is True
    assert unlinked.json()["receipt_histories_merged"] is False
    replayed = http.post(
        "/api/v1/public/consent/identity/link/unlink",
        headers=target_headers,
        json=unlink_body,
    )
    assert replayed.status_code == 200
    assert replayed.json() == unlinked.json()
    after = http.get(
        "/api/v1/public/consent/identity/link",
        headers=target_headers,
    )
    assert after.status_code == 200
    assert after.json()["status"] == "unlinked"
    forbidden_selector = http.post(
        "/api/v1/public/consent/identity/link/unlink",
        headers=target_headers,
        json={**unlink_body, "tenant_id": "tenant-a"},
    )
    assert forbidden_selector.status_code == 422
