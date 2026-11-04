from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick import privacy_rights_orchestration as rights
from maverick.consent_identity_federation import ConsentIdentityEvidence
from maverick.consent_preferences import ConsentPreferenceStore
from maverick.consumer_trust_center import (
    ConsumerTrustCenterSourceAdapter,
    TrustCenterCapabilityGrant,
    TrustCenterContext,
)
from maverick.privacy_rights_ott_ctv import (
    OTTCTVPrivacyRightsStore,
    build_service_authority,
)
from maverick_dashboard.consent_identity_federation_api import (
    resolve_consent_pairing_context,
)
from maverick_dashboard.consent_public_api import (
    PublicClientBinding,
    PublicConsentCredentialError,
    PublicConsentDependencies,
    PublicProfileBinding,
    PublicRequestContext,
)
from maverick_dashboard.privacy_rights_ott_ctv_api import (
    OTTCTVPrivacyRightsAPIDependencies,
    _account_binding,
    create_ott_ctv_privacy_rights_router,
)

NOW = 1_800_000_000.0


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def object_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


class FakeCredentials:
    def __init__(
        self,
        raw_client: str,
        client: PublicClientBinding,
        raw_profile: str,
        profile: PublicProfileBinding,
    ) -> None:
        self.raw_client = raw_client
        self.client = client
        self.raw_profile = raw_profile
        self.profile = profile
        self.active = True

    def _live(self) -> None:
        if not self.active:
            raise PublicConsentCredentialError("revoked")

    def resolve_client(self, raw: str) -> PublicClientBinding:
        self._live()
        if raw != self.raw_client:
            raise PublicConsentCredentialError("invalid")
        return self.client

    def resolve_profile(
        self,
        raw: str,
        client: PublicClientBinding,
    ) -> PublicProfileBinding:
        self._live()
        if raw != self.raw_profile or client != self.client:
            raise PublicConsentCredentialError("invalid")
        return self.profile

    def resolve_client_authority(self, credential: str) -> PublicClientBinding:
        self._live()
        if credential != self.client.credential_sha256:
            raise PublicConsentCredentialError("invalid")
        return self.client

    def resolve_profile_authority(
        self,
        credential: str,
        client: PublicClientBinding,
    ) -> PublicProfileBinding:
        self._live()
        if credential != self.profile.credential_sha256 or client != self.client:
            raise PublicConsentCredentialError("invalid")
        return self.profile


class Publishing:
    def __init__(self, client: PublicClientBinding) -> None:
        self.client = client

    def preview(self, *_args):
        return {
            "bundle_sha256": self.client.bundle_sha256,
            "bundle": {"property": {"record_sha256": self.client.property_sha256}},
        }

    def resolve_public_configuration(self, *_args, **_kwargs):
        return {
            "allowed": True,
            "property": {"property_id": "property-a", "revision": 1},
            "publication": {
                "property_revision": 1,
                "publication_sha256": self.client.publication_sha256,
                "bundle_sha256": self.client.bundle_sha256,
            },
            "configuration_sha256": digest("configuration"),
            "configuration": {
                "purposes": [{"id": "analytics", "lawful_basis": "consent"}],
                "notice": {"document_sha256": digest("notice")},
            },
        }


def context_identity(context) -> ConsentIdentityEvidence:
    body = {
        "schema": "lightwork.consent.identity-evidence.v1",
        "tenant_id": context.tenant_id,
        "target_fingerprint": context.fingerprint,
        "source_fingerprint": digest("browser-source-fingerprint"),
        "subject_binding_sha256": digest("known-subject"),
        "oidc_verification_sha256": digest("oidc-verification"),
        "source_link_sha256": digest("source-link"),
        "target_link_sha256": digest("target-link"),
        "pairing_revision": 4,
        "valid_until": NOW + 600,
    }
    return ConsentIdentityEvidence(**body, evidence_sha256=object_digest(body))


def trust_context(context) -> TrustCenterContext:
    raw_grant = TrustCenterCapabilityGrant(
        capability="rights_cases",
        grant_ref="grant-rights",
        tenant_sha256=hashlib.sha256(context.tenant_id.encode()).hexdigest(),
        property_id=context.property_id,
        profile_sha256=hashlib.sha256(context.profile_id.encode()).hexdigest(),
        approved_by_sha256=digest("approver-a"),
        second_approved_by_sha256=digest("approver-b"),
        valid_until=NOW + 900,
        grant_sha256=digest("placeholder-grant"),
    )
    grant = replace(
        raw_grant,
        grant_sha256=ConsumerTrustCenterSourceAdapter.capability_grant_sha256(raw_grant),
    )
    raw = TrustCenterContext(
        tenant_id=context.tenant_id,
        property_id=context.property_id,
        profile_id=context.profile_id,
        actor_sha256=digest("service-actor"),
        requested_locale="en-US",
        server_origin=None,
        server_bundle_id="com.example.tv",
        server_platform="tvos",
        jurisdiction="us",
        country_code="US",
        region_code="NY",
        profile_authority=None,
        capability_grants=(grant,),
        rights_authorizations=(),
        publication_history_limit=10,
        receipt_limit=10,
        retained_until=NOW + 3_600,
        revision=3,
        valid_until=NOW + 900,
        context_sha256=digest("placeholder-context"),
    )
    return replace(raw, context_sha256=ConsumerTrustCenterSourceAdapter.context_sha256(raw))


def setup_api(tmp_path: Path):
    raw_client = "raw-service-client-token-123456789"
    raw_profile = "raw-device-profile-token-123456789"
    preferences = ConsentPreferenceStore(
        tmp_path / "preferences.sqlite3",
        clock=lambda: NOW,
    )
    policy = preferences.publish_policy(
        "tenant-a",
        "policy-a",
        1,
        {"analytics": "consent"},
        digest("notice"),
        NOW - 10,
        expected_current_version=0,
    )
    preferences.create_profile(
        "tenant-a",
        "known-profile",
        "known",
        digest("known-subject"),
        "create-known",
    )
    preferences.create_profile(
        "tenant-a",
        "device-profile",
        "anonymous",
        digest("anonymous-subject"),
        "create-device",
    )
    preferences.link_profiles(
        "tenant-a",
        "known-profile",
        "device-profile",
        expected_known_revision=0,
        expected_anonymous_revision=0,
        idempotency_key="link-device-account",
    )
    client = PublicClientBinding(
        credential_id="service-client-record",
        credential_sha256=digest(raw_client),
        tenant_id="tenant-a",
        property_id="property-a",
        client_kind="service",
        browser_origin=None,
        service_client_id="service-tv-1",
        target_origin=None,
        target_bundle_id="com.example.tv",
        target_platform="tvos",
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
        policy_id="policy-a",
        policy_version=1,
        policy_sha256=str(policy["policy_sha256"]),
        expires_at=NOW + 1_200,
        revision=2,
        record_sha256=digest("client-record"),
    )
    profile = PublicProfileBinding(
        credential_sha256=digest(raw_profile),
        client_credential_sha256=client.credential_sha256,
        tenant_id="tenant-a",
        property_id="property-a",
        profile_id="device-profile",
        subject_binding_sha256=digest("anonymous-subject"),
        binding_sha256=digest("profile-binding"),
    )
    credentials = FakeCredentials(raw_client, client, raw_profile, profile)
    public = PublicConsentDependencies(
        credential_store=credentials,
        publishing_store_for=lambda _tenant: Publishing(client),
        preference_store_for=lambda _tenant: preferences,
        gate=lambda: True,
        rate_limit=lambda *_args: None,
        context_resolver=lambda _request, _client: PublicRequestContext(
            "us", "US", "NY", "en-US"
        ),
        clock=lambda: NOW,
    )
    context = resolve_consent_pairing_context(public, client, profile)
    evidence_state = {"value": context_identity(context)}
    trust_state = {"value": trust_context(context)}
    actor = {"value": "device-service"}
    rights_store = rights.PrivacyRightsOrchestrationStore(
        tmp_path / "rights.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        digest_key_resolver=lambda _tenant: b"k" * 32,
        clock=lambda: NOW,
    )
    rights_store.enroll_source(
        "tenant-a",
        "crm",
        adapter_ref="provider-adapter-v1",
        credential_ref="env:RIGHTS_PROVIDER_TOKEN",
        capabilities=sorted(rights.TASK_PHASES),
        expected_revision=0,
        idempotency_key="enroll-crm",
    )
    bridge_path = tmp_path / "ott.sqlite3"

    def bridge_for(_request, _pairing, _rights_store, authority_resolver):
        return OTTCTVPrivacyRightsStore(
            bridge_path,
            rights_store=_rights_store,
            authority_resolver=authority_resolver,
            signing_key_resolver=lambda _tenant, _ref: b"s" * 32,
            config_gate=lambda: None,
            clock=lambda: NOW,
        )

    deps = OTTCTVPrivacyRightsAPIDependencies(
        public=public,
        identity_evidence_for=lambda _request, _pairing: evidence_state["value"],
        trust_context_for=lambda _request, _pairing: trust_state["value"],
        rights_store_for=lambda _request, _pairing: rights_store,
        bridge_store_for=bridge_for,
        gate=lambda: True,
        clock=lambda: NOW,
    )
    app = FastAPI()
    app.include_router(create_ott_ctv_privacy_rights_router(deps))
    expected_authority = build_service_authority(
        context,
        trust_state["value"],
        service_client_id="service-tv-1",
        target_bundle_id="com.example.tv",
        target_platform="tvos",
        account_binding_sha256=_account_binding(public, context),
        identity_evidence=evidence_state["value"],
        client_expires_at=client.expires_at,
        now=NOW,
    )
    return {
        "http": TestClient(app, base_url="http://127.0.0.1"),
        "headers": {
            "Authorization": f"ConsentPublic {raw_client}",
            "X-Lightwork-Consent-Service-Client": "service-tv-1",
            "X-Lightwork-Profile-Credential": raw_profile,
        },
        "authority": expected_authority,
        "credentials": credentials,
        "trust_state": trust_state,
        "bridge_path": bridge_path,
        "raw": (raw_client, raw_profile),
    }


def request_body(authority, *, right: str = "access", key: str = "create-request-1"):
    return {
        "right": right,
        "expected_revision": 0,
        "idempotency_key": key,
        "client_revision": authority.client_revision,
        "profile_revision": authority.profile_revision,
        "identity_evidence_sha256": authority.identity_evidence_sha256,
        "identity_evidence_revision": authority.identity_evidence_revision,
        "identity_evidence_valid_until": authority.identity_evidence_valid_until,
        "publication_sha256": authority.publication_sha256,
        "bundle_sha256": authority.publication_bundle_sha256,
        "configuration_sha256": authority.configuration_sha256,
        "policy_version": authority.policy_version,
        "policy_sha256": authority.policy_sha256,
        "profile_binding_sha256": authority.profile_binding_sha256,
        "trust_context_revision": authority.trust_context_revision,
        "trust_context_sha256": authority.trust_context_sha256,
        "capability_grant_sha256": authority.capability_grant_sha256,
    }


def test_service_api_is_self_authenticating_digest_only_and_fail_closed(tmp_path: Path):
    setup = setup_api(tmp_path)
    http = setup["http"]
    headers = setup["headers"]
    authority = setup["authority"]
    body = request_body(authority)

    created = http.post(
        "/api/v1/public/consent/ott-ctv/rights/requests",
        headers=headers,
        json=body,
    )
    assert created.status_code == 201, created.text
    payload = created.json()
    assert payload["identity_evidence_sha256"] == authority.identity_evidence_sha256
    assert payload["provider_operations_verified"] is False
    assert payload["estate_completeness_claimed"] is False
    assert payload["live_provider_acceptance_verified"] is False
    assert payload["signature"]
    assert payload["evidence_sha256"]
    assert "tenant_id" not in payload

    replay = http.post(
        "/api/v1/public/consent/ott-ctv/rights/requests",
        headers=headers,
        json=body,
    )
    assert replay.status_code == 201
    assert replay.json() == payload
    fetched = http.get(
        f"/api/v1/public/consent/ott-ctv/rights/requests/{payload['case_id']}",
        headers=headers,
    )
    assert fetched.status_code == 200
    assert fetched.json()["case_id"] == payload["case_id"]

    selector = http.post(
        "/api/v1/public/consent/ott-ctv/rights/requests",
        headers={**headers, "X-Lightwork-Device-ID": "raw-device-selector"},
        json=body,
    )
    assert selector.status_code == 401
    stale = http.post(
        "/api/v1/public/consent/ott-ctv/rights/requests",
        headers=headers,
        json={**body, "publication_sha256": digest("stale")},
    )
    assert stale.status_code == 409
    changed_replay = http.post(
        "/api/v1/public/consent/ott-ctv/rights/requests",
        headers=headers,
        json={**body, "right": "deletion"},
    )
    assert changed_replay.status_code == 409

    raw_response = json.dumps(payload)
    persisted = Path(setup["bridge_path"]).read_bytes()
    wal = Path(f"{setup['bridge_path']}-wal")
    if wal.exists():
        persisted += wal.read_bytes()
    for forbidden in (*setup["raw"], "raw-device-selector"):
        assert forbidden not in raw_response
        assert forbidden.encode() not in persisted

    active_trust = setup["trust_state"]["value"]
    setup["trust_state"]["value"] = replace(active_trust, revoked=True)
    grant_revoked = http.get(
        f"/api/v1/public/consent/ott-ctv/rights/requests/{payload['case_id']}",
        headers=headers,
    )
    assert grant_revoked.status_code == 409
    setup["trust_state"]["value"] = active_trust

    setup["credentials"].active = False
    revoked = http.get(
        f"/api/v1/public/consent/ott-ctv/rights/requests/{payload['case_id']}",
        headers=headers,
    )
    assert revoked.status_code == 401


def test_shipped_app_mounts_the_ott_ctv_service_routes() -> None:
    from maverick_dashboard.app import app

    paths = set(app.openapi()["paths"])
    assert "/api/v1/public/consent/ott-ctv/rights/status" in paths
    assert "/api/v1/public/consent/ott-ctv/rights/requests" in paths
    assert "/api/v1/public/consent/ott-ctv/rights/requests/{case_id}" in paths
