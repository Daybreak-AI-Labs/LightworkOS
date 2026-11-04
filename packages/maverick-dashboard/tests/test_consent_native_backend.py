from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
from maverick.consent_native_sdk import (
    NativeApplicationAuthority,
    NativeConsentConflict,
    NativeConsentDenied,
    NativeDeviceAuthority,
)
from maverick_dashboard import consent_native_backend as backend_module
from maverick_dashboard.consent_native_backend import LightworkNativeConsentBackend
from maverick_dashboard.consent_public_api import PublicProfileBinding


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _authority() -> NativeApplicationAuthority:
    return NativeApplicationAuthority(
        application_ref="native-prod",
        tenant_id="tenant-one",
        property_id="property-one",
        application_id="com.example.native",
        platform="android",
        public_client_credential_sha256=_digest("client"),
        public_client_revision=3,
        public_client_record_sha256=_digest("client-record"),
        property_revision=4,
        property_sha256=_digest("property"),
        publication_sha256=_digest("publication"),
        publication_bundle_sha256=_digest("bundle"),
        configuration_sha256=_digest("configuration"),
        policy_id="policy-one",
        policy_version=5,
        policy_sha256=_digest("policy"),
        standards_contract_sha256=_digest("standards"),
        minimum_sdk_version=2,
        default_locale="en-US",
        locales=("en-US",),
    )


def _device(authority: NativeApplicationAuthority) -> NativeDeviceAuthority:
    return NativeDeviceAuthority(
        device_id="CP-DEV-native",
        application_ref=authority.application_ref,
        application_authority_sha256=authority.authority_sha256,
        tenant_id=authority.tenant_id,
        application_id=authority.application_id,
        platform=authority.platform,
        install_subject_sha256=_digest("installation"),
        public_key_hex=_digest("public-key"),
        key_revision=1,
        sdk_version=2,
        revision=1,
        attestation_authority="play-integrity",
        attestation_evidence_sha256=_digest("attestation"),
        attestation_valid_until=2_000,
        created_at=1_000,
    )


class _CredentialStore:
    def __init__(self, client, profile, target) -> None:
        self.client = client
        self.profile = profile
        self.target = target
        self.revocations = []

    def resolve_client_authority(self, _digest_value):
        return self.client

    def resolve_profile_authority(self, digest_value, _client):
        if digest_value == self.profile.credential_sha256:
            return self.profile
        if digest_value == self.target.credential_sha256:
            return self.target
        raise RuntimeError("profile unavailable")

    def bootstrap_profile(self, client, **kwargs):
        created = kwargs["create_profile"]("CP-PUB-new", _digest("subject-binding"), "core-idem")
        return {
            "profile_ref": created["profile_id"],
            "profile_revision": created["revision"],
            "profile_binding_sha256": _digest("new-binding"),
            "created_at": 1_000.0,
        }

    def revoke_profile(self, tenant_id, property_id, profile_id, **kwargs):
        self.revocations.append((tenant_id, property_id, profile_id, kwargs))
        return {"profile_id": profile_id, "status": "revoked"}


class _Preferences:
    def __init__(self, authority: NativeApplicationAuthority) -> None:
        self.authority = authority
        self.records = []
        self.created = []

    def get_active_policy(self, tenant, policy_id, *, at):
        assert tenant == self.authority.tenant_id
        assert policy_id == self.authority.policy_id
        assert at == 1_000.0
        return {
            "policy_id": self.authority.policy_id,
            "version": self.authority.policy_version,
            "policy_sha256": self.authority.policy_sha256,
            "notice_sha256": _digest("notice"),
            "purposes": {"analytics": "consent", "sale": "consent"},
            "effective_at": 1,
            "expires_at": None,
        }

    def create_profile(self, tenant, profile_id, identity_kind, subject, idempotency_key):
        self.created.append((tenant, profile_id, identity_kind, subject, idempotency_key))
        return {"profile_id": profile_id, "revision": 0, "created_at": 1_000.0}

    def record_preferences(self, *args, **kwargs):
        self.records.append((args, kwargs))
        return {
            "receipt_id": f"receipt-{len(self.records)}",
            "receipt_sha256": _digest(f"receipt-{len(self.records)}"),
            "profile_revision": kwargs["expected_revision"] + 1,
            "policy_sha256": self.authority.policy_sha256,
        }

    def decide(self, *_args, **_kwargs):
        return SimpleNamespace(
            as_dict=lambda: {
                "allowed": False,
                "reason": "explicit_deny",
                "receipt_sha256": _digest("receipt"),
                "profile_revision": 2,
            }
        )


class _Publishing:
    def __init__(self, authority: NativeApplicationAuthority) -> None:
        self.authority = authority

    def resolve_public_configuration(self, *_args, **_kwargs):
        return {
            "allowed": True,
            "property": {
                "property_id": self.authority.property_id,
                "revision": self.authority.property_revision,
            },
            "publication": {
                "publication_sha256": self.authority.publication_sha256,
                "bundle_sha256": self.authority.publication_bundle_sha256,
            },
            "configuration_sha256": self.authority.configuration_sha256,
            "configuration": {
                "purposes": [
                    {"id": "analytics", "lawful_basis": "consent"},
                    {"id": "sale", "lawful_basis": "consent"},
                ],
                "notice": {"document_sha256": _digest("notice")},
            },
        }


def _material(monkeypatch):
    authority = _authority()
    client = SimpleNamespace(
        credential_sha256=authority.public_client_credential_sha256,
        tenant_id=authority.tenant_id,
        property_id=authority.property_id,
        client_kind="service",
        service_client_id=authority.application_ref,
        target_origin=None,
        target_bundle_id=authority.application_id,
        target_platform=authority.platform,
        jurisdiction="US-CA",
        country_code="US",
        region_code="US-CA",
        default_locale="en-US",
        revision=authority.public_client_revision,
        record_sha256=authority.public_client_record_sha256,
        property_revision=authority.property_revision,
        property_sha256=authority.property_sha256,
        publication_sha256=authority.publication_sha256,
        bundle_sha256=authority.publication_bundle_sha256,
        policy_id=authority.policy_id,
        policy_version=authority.policy_version,
        policy_sha256=authority.policy_sha256,
    )
    profile = PublicProfileBinding(
        credential_sha256=_digest("profile"),
        client_credential_sha256=client.credential_sha256,
        tenant_id=authority.tenant_id,
        property_id=authority.property_id,
        profile_id="CP-PUB-source",
        subject_binding_sha256=_digest("source-subject"),
        binding_sha256=_digest("source-binding"),
    )
    target = PublicProfileBinding(
        credential_sha256=_digest("target"),
        client_credential_sha256=client.credential_sha256,
        tenant_id=authority.tenant_id,
        property_id=authority.property_id,
        profile_id="CP-PUB-target",
        subject_binding_sha256=_digest("target-subject"),
        binding_sha256=_digest("target-binding"),
    )
    credentials = _CredentialStore(client, profile, target)
    preferences = _Preferences(authority)
    public = SimpleNamespace(
        credential_store=credentials,
        publishing_store_for=lambda _tenant: _Publishing(authority),
        preference_store_for=lambda _tenant: preferences,
    )
    monkeypatch.setattr(
        backend_module,
        "resolve_consent_pairing_context",
        lambda _public, _client, resolved_profile: SimpleNamespace(
            configuration_sha256=authority.configuration_sha256,
            profile_id=resolved_profile.profile_id,
        ),
    )
    return authority, _device(authority), profile, target, credentials, preferences, public


def test_existing_backend_operations_are_exact_and_digest_only(monkeypatch) -> None:
    authority, device, profile, target, credentials, preferences, public = _material(monkeypatch)
    links = []
    rights = []
    backend = LightworkNativeConsentBackend(
        public,
        profile_linker=lambda **kwargs: links.append(kwargs) or {"linked": True},
        rights_requester=lambda **kwargs: rights.append(kwargs) or {"case_id": "PRIV-one"},
        clock=lambda: 1_000.0,
    )
    configuration = backend(authority, device, "configuration", {}, "request-config")
    assert configuration["configuration_sha256"] == authority.configuration_sha256
    bootstrapped = backend(
        authority,
        device,
        "bootstrap_profile",
        {
            "subject_sha256": _digest("anonymous-subject"),
            "profile_credential_sha256": _digest("new-profile"),
            "idempotency_key": "bootstrap-one",
        },
        "request-bootstrap",
    )
    assert bootstrapped["profile_ref"] == "CP-PUB-new"
    current = backend(
        authority,
        device,
        "current_preferences",
        {"profile_credential_sha256": profile.credential_sha256},
        "request-current",
    )
    assert current["profile_revision"] == 2
    preference = backend(
        authority,
        device,
        "record_preferences",
        {
            "profile_credential_sha256": profile.credential_sha256,
            "expected_revision": 2,
            "idempotency_key": "preference-one",
            "choices": [
                {
                    "purpose_id": "analytics",
                    "action": "deny",
                    "channel": "all",
                    "vendor_id": "all",
                    "expires_at": None,
                }
            ],
        },
        "request-preference",
    )
    assert preference["profile_revision"] == 3
    signal = backend(
        authority,
        device,
        "privacy_signals",
        {
            "profile_credential_sha256": profile.credential_sha256,
            "expected_revision": 3,
            "idempotency_key": "signals-one",
            "signals": {
                "gpc": True,
                "do_not_sell_or_share": True,
                "standards_contract_sha256": authority.standards_contract_sha256,
                "purposes": ["sale"],
                "gpp_string_sha256": _digest("gpp-wire"),
            },
        },
        "request-signal",
    )
    assert signal["signal_evidence"]["wire_interpreted"] is False
    assert preferences.records[-1][1]["signal"] == "gpc"
    linked = backend(
        authority,
        device,
        "link_profile",
        {
            "profile_credential_sha256": profile.credential_sha256,
            "target_profile_credential_sha256": target.credential_sha256,
            "pairing_authorization_sha256": _digest("pairing"),
            "scope": "household",
            "idempotency_key": "link-one",
        },
        "request-link",
    )
    assert linked == {"linked": True}
    assert links[0]["source"].profile_id == profile.profile_id
    request = backend(
        authority,
        device,
        "rights_request",
        {
            "profile_credential_sha256": profile.credential_sha256,
            "rights": ["access", "opt_out"],
            "expected_revision": 0,
            "idempotency_key": "rights-one",
        },
        "request-rights",
    )
    assert request == {"case_id": "PRIV-one"}
    assert rights[0]["profile"] == profile
    revoked = backend(
        authority,
        device,
        "revoke_profile",
        {
            "profile_credential_sha256": profile.credential_sha256,
            "evidence_sha256": _digest("revocation"),
            "idempotency_key": "revoke-one",
        },
        "request-revoke",
    )
    assert revoked["status"] == "revoked"
    assert credentials.revocations[0][0:3] == (
        authority.tenant_id,
        authority.property_id,
        profile.profile_id,
    )


def test_stock_publishing_property_shape_uses_the_exact_client_property_pin(monkeypatch) -> None:
    authority, device, _profile, _target, _credentials, _preferences, public = _material(
        monkeypatch
    )
    backend = LightworkNativeConsentBackend(public, clock=lambda: 1_000.0)

    configuration = backend(authority, device, "configuration", {}, "request-stock-shape")

    assert configuration["configuration_sha256"] == authority.configuration_sha256

    class _MismatchedPublishing(_Publishing):
        def resolve_public_configuration(self, *_args, **_kwargs):
            value = super().resolve_public_configuration(*_args, **_kwargs)
            value["property"]["record_sha256"] = _digest("different-property")
            return value

    public.publishing_store_for = lambda _tenant: _MismatchedPublishing(authority)
    with pytest.raises(NativeConsentConflict, match="configuration changed"):
        backend(authority, device, "configuration", {}, "request-mismatched-property")


def test_profile_link_rights_and_standards_fail_closed_without_authority(monkeypatch) -> None:
    authority, device, profile, _target, _credentials, _preferences, public = _material(monkeypatch)
    backend = LightworkNativeConsentBackend(public, clock=lambda: 1_000.0)
    base = {
        "profile_credential_sha256": profile.credential_sha256,
        "idempotency_key": "request-one",
    }
    with pytest.raises(NativeConsentDenied, match="synchronization authority"):
        backend(
            authority,
            device,
            "link_profile",
            {
                **base,
                "target_profile_credential_sha256": _digest("target"),
                "pairing_authorization_sha256": _digest("pairing"),
                "scope": "device",
            },
            "link-request",
        )
    with pytest.raises(NativeConsentDenied, match="rights handoff"):
        backend(
            authority,
            device,
            "rights_request",
            {**base, "rights": ["access"], "expected_revision": 0},
            "rights-request",
        )
    with pytest.raises(NativeConsentConflict, match="standards contract"):
        backend(
            authority,
            device,
            "privacy_signals",
            {
                **base,
                "expected_revision": 0,
                "signals": {
                    "gpc": True,
                    "do_not_sell_or_share": True,
                    "standards_contract_sha256": _digest("stale"),
                    "purposes": ["sale"],
                },
            },
            "signal-request",
        )
    wire = "DBABLA~CPXxRfAPXxRfAAfKABENB-CgAAAAAAAAAAYgAAAAAAAA"
    with pytest.raises(NativeConsentDenied, match="certified consent-string"):
        backend(
            authority,
            device,
            "privacy_signals",
            {
                **base,
                "expected_revision": 0,
                "signals": {
                    "gpc": False,
                    "do_not_sell_or_share": False,
                    "standards_contract_sha256": authority.standards_contract_sha256,
                    "purposes": ["sale"],
                    "gpp_string": wire,
                    "gpp_string_sha256": hashlib.sha256(wire.encode()).hexdigest(),
                },
            },
            "signal-wire-request",
        )
