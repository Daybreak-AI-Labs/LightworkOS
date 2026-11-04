from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, Request
from maverick.consent_identity_federation import (
    ConsentIdentityEvidence,
    ConsentPairingContext,
)
from maverick.consumer_trust_center import TrustCenterIntegrityError
from maverick.consumer_trust_center_authority import (
    ConsumerTrustCenterAuthorityStore,
    ResolvedTrustCenterBinding,
    TrustCenterAuthorityConfigError,
    TrustCenterAuthorityPermissionDenied,
    TrustCenterPrincipalAuthority,
    principal_authority_sha256,
)
from maverick_dashboard import consumer_trust_center_authority_composition as composition
from maverick_dashboard.consent_public_api import (
    PublicClientBinding,
    PublicConsentDependencies,
    PublicProfileBinding,
)

NOW = 2_100_000_000.0
TENANT = "tenant-a"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _object_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _authorities(tenant_id: str = TENANT) -> dict[str, Any]:
    client = PublicClientBinding(
        credential_id=f"public-client-{tenant_id}",
        credential_sha256=_digest(f"client-credential:{tenant_id}"),
        tenant_id=tenant_id,
        property_id="primary-web",
        client_kind="browser",
        browser_origin="https://privacy.example.test",
        service_client_id=None,
        target_origin="https://privacy.example.test",
        target_bundle_id=None,
        target_platform=None,
        jurisdiction="us-ca",
        country_code="US",
        region_code="CA",
        default_locale="en-US",
        property_revision=2,
        property_sha256=_digest(f"property:{tenant_id}"),
        rule_group_id="public-rules",
        rule_group_version=3,
        publication_sha256=_digest(f"publication:{tenant_id}"),
        bundle_sha256=_digest(f"bundle:{tenant_id}"),
        policy_id="privacy-policy",
        policy_version=4,
        policy_sha256=_digest(f"policy:{tenant_id}"),
        expires_at=NOW + 3_600,
        revision=5,
        record_sha256=_digest(f"client-record:{tenant_id}"),
    )
    profile = PublicProfileBinding(
        credential_sha256=_digest(f"profile-credential:{tenant_id}"),
        client_credential_sha256=client.credential_sha256,
        tenant_id=tenant_id,
        property_id=client.property_id,
        profile_id="profile-opaque-a",
        subject_binding_sha256=_digest(f"anonymous-subject:{tenant_id}"),
        binding_sha256=_digest(f"profile-binding:{tenant_id}"),
    )
    channel_sha = _object_digest(
        {
            "client_kind": client.client_kind,
            "browser_origin": client.browser_origin,
            "service_client_id": client.service_client_id,
            "target_origin": client.target_origin,
            "target_bundle_id": client.target_bundle_id,
            "target_platform": client.target_platform,
        }
    )
    pairing = ConsentPairingContext(
        tenant_id=tenant_id,
        property_id=client.property_id,
        profile_id=profile.profile_id,
        profile_revision=6,
        client_credential_sha256=client.credential_sha256,
        client_revision=client.revision,
        client_record_sha256=client.record_sha256,
        profile_credential_sha256=profile.credential_sha256,
        profile_binding_sha256=profile.binding_sha256,
        property_revision=client.property_revision,
        property_sha256=client.property_sha256,
        publication_sha256=client.publication_sha256,
        bundle_sha256=client.bundle_sha256,
        configuration_sha256=_digest(f"configuration:{tenant_id}"),
        policy_id=client.policy_id,
        policy_version=client.policy_version,
        policy_sha256=client.policy_sha256,
        channel_kind="browser-origin",
        channel_binding_sha256=channel_sha,
    ).normalized()
    evidence_body = {
        "schema": "lightwork.consent.identity-evidence.v1",
        "tenant_id": tenant_id,
        "target_fingerprint": pairing.fingerprint,
        "source_fingerprint": _digest(f"source-pairing:{tenant_id}"),
        "subject_binding_sha256": _digest(f"known-subject:{tenant_id}"),
        "oidc_verification_sha256": _digest(f"oidc-verification:{tenant_id}"),
        "source_link_sha256": _digest(f"source-link:{tenant_id}"),
        "target_link_sha256": _digest(f"target-link:{tenant_id}"),
        "pairing_revision": 11,
        "valid_until": NOW + 600,
    }
    evidence = ConsentIdentityEvidence(
        **evidence_body,
        evidence_sha256=_object_digest(evidence_body),
    )
    return {
        "client": client,
        "profile": profile,
        "pairing": pairing,
        "evidence": evidence,
    }


class _Registry:
    def __init__(self, values: dict[str, Any]) -> None:
        self.values = values
        self.mapping_calls: list[tuple[str, str]] = []
        self.client_calls: list[str] = []
        self.profile_calls: list[tuple[str, PublicClientBinding]] = []

    def resolve_rights_intake_context(
        self,
        tenant_id: str,
        context_ref: str,
    ) -> tuple[PublicClientBinding, PublicProfileBinding]:
        self.mapping_calls.append((tenant_id, context_ref))
        return self.values["client"], self.values["profile"]

    def resolve_client_authority(self, credential_sha256: str) -> PublicClientBinding:
        self.client_calls.append(credential_sha256)
        if credential_sha256 != self.values["client"].credential_sha256:
            raise RuntimeError("private client lookup detail")
        return self.values["client"]

    def resolve_profile_authority(
        self,
        credential_sha256: str,
        client: PublicClientBinding,
    ) -> PublicProfileBinding:
        self.profile_calls.append((credential_sha256, client))
        if (
            credential_sha256 != self.values["profile"].credential_sha256
            or client != self.values["client"]
        ):
            raise RuntimeError("private profile lookup detail")
        return self.values["profile"]


class _IdentityStore:
    def __init__(self, evidence: ConsentIdentityEvidence | BaseException) -> None:
        self.evidence = evidence
        self.calls: list[ConsentPairingContext] = []

    def resolve_redeemed_identity_evidence(
        self,
        pairing: ConsentPairingContext,
    ) -> ConsentIdentityEvidence:
        self.calls.append(pairing)
        if isinstance(self.evidence, BaseException):
            raise self.evidence
        return self.evidence


def _request(app: FastAPI, *, principal: str | None = "user:operator") -> Request:
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/api/v1/consent/trust-center-authority",
            "raw_path": b"/api/v1/consent/trust-center-authority",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 443),
            "app": app,
        }
    )
    if principal is not None:
        request.state.principal = SimpleNamespace(principal=principal)
    return request


def _public(registry: _Registry) -> PublicConsentDependencies:
    return PublicConsentDependencies(
        credential_store=registry,  # type: ignore[arg-type]
        publishing_store_for=lambda _tenant: object(),
        preference_store_for=lambda _tenant: object(),
        gate=lambda: True,
        rate_limit=lambda _credential, _action: None,
        context_resolver=lambda _request, _client: None,  # type: ignore[arg-type]
        clock=lambda: NOW,
    )


def _environment(
    monkeypatch: pytest.MonkeyPatch,
    *,
    tenant_id: str = TENANT,
    evidence: ConsentIdentityEvidence | BaseException | None = None,
) -> tuple[FastAPI, Request, dict[str, Any], _Registry, _IdentityStore]:
    values = _authorities(tenant_id)
    registry = _Registry(values)
    public = _public(registry)
    selected = values["evidence"] if evidence is None else evidence
    identity = _IdentityStore(selected)
    app = FastAPI()
    request = _request(app)
    app.state.privacy_rights_intake_public_dependencies_factory = lambda *, request: public
    app.state.consent_identity_federation_store_factory = lambda *, tenant_id, request: identity
    app.state.consumer_trust_center_authority_clock = lambda: NOW
    monkeypatch.setattr(
        composition,
        "resolve_consent_pairing_context",
        lambda selected_public, client, profile: (
            values["pairing"]
            if selected_public is public
            and client == values["client"]
            and profile == values["profile"]
            else (_ for _ in ()).throw(RuntimeError("misbound public authority"))
        ),
    )
    composition.attach_consumer_trust_center_authority_composition(app)
    return app, request, values, registry, identity


def _operator_ref(request: Request, tenant_id: str = TENANT) -> str:
    return composition._operator_principal_ref(request, tenant_id)


def _context_ref(values: dict[str, Any]) -> str:
    return composition._privacy_rights_context_ref(values["pairing"])


def test_attach_is_lazy_idempotent_and_preserves_explicit_injections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()

    def explicit_signer(_tenant: str, _ref: str) -> bytes:
        return b"injected-key-at-least-thirty-two-bytes"

    app.state.consumer_trust_center_authority_signing_key_resolver = explicit_signer
    app.state.consumer_trust_center_authority_signing_key_ref = "vault:tca-key"
    calls = {"public": 0, "identity": 0}

    def public_factory(*, request: Request) -> None:
        del request
        calls["public"] += 1

    def identity_factory(*, tenant_id: str, request: Request) -> None:
        del tenant_id, request
        calls["identity"] += 1

    app.state.privacy_rights_intake_public_dependencies_factory = public_factory
    app.state.consent_identity_federation_store_factory = identity_factory

    composition.attach_consumer_trust_center_authority_composition(app)
    first_binding = app.state.consumer_trust_center_authority_binding_resolver_factory
    first_principal = app.state.consumer_trust_center_authority_principal_resolver_factory
    first_verifier = app.state.consumer_trust_center_authority_pairing_verifier
    composition.attach_consumer_trust_center_authority_composition(app)

    assert calls == {"public": 0, "identity": 0}
    assert app.state.consumer_trust_center_authority_binding_resolver_factory is first_binding
    assert app.state.consumer_trust_center_authority_principal_resolver_factory is first_principal
    assert app.state.consumer_trust_center_authority_pairing_verifier is first_verifier
    assert app.state.consumer_trust_center_authority_signing_key_resolver is explicit_signer
    assert app.state.consumer_trust_center_authority_signing_key_ref == "vault:tca-key"


def test_binding_uses_immutable_registry_mapping_and_full_current_pairing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, request, values, registry, _identity = _environment(monkeypatch)
    factory = app.state.consumer_trust_center_authority_binding_resolver_factory
    resolver = factory(
        tenant_id=TENANT,
        principal_ref=_operator_ref(request),
        request=request,
    )
    context_ref = _context_ref(values)

    binding = resolver(context_ref)

    assert type(binding) is ResolvedTrustCenterBinding
    assert registry.mapping_calls == [(TENANT, context_ref)]
    assert binding.tenant_id == TENANT
    assert binding.property_id == values["pairing"].property_id
    assert binding.profile_id == values["pairing"].profile_id
    assert (
        binding.actor_sha256
        == hashlib.sha256(
            (
                f"public-consent-actor\0{values['client'].credential_sha256}\0"
                f"{values['profile'].credential_sha256}"
            ).encode()
        ).hexdigest()
    )
    assert binding.requested_locale == "en-US"
    assert binding.server_origin == "https://privacy.example.test"
    assert binding.profile_authority is None
    with pytest.raises(TrustCenterIntegrityError, match="context authority changed"):
        resolver("TCA.PRI.00000000000000000000000000000000")


def test_binding_rejects_cross_tenant_and_pairing_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, request, values, registry, _identity = _environment(monkeypatch)
    resolver = app.state.consumer_trust_center_authority_binding_resolver_factory(
        tenant_id=TENANT,
        principal_ref=_operator_ref(request),
        request=request,
    )
    context_ref = _context_ref(values)
    tenant_b = _authorities("tenant-b")
    registry.values = tenant_b
    monkeypatch.setattr(
        composition,
        "resolve_consent_pairing_context",
        lambda _public, _client, _profile: tenant_b["pairing"],
    )
    with pytest.raises(TrustCenterIntegrityError, match="tenant authority changed"):
        resolver(context_ref)

    registry.values = values
    drifted = replace(
        values["pairing"],
        client_record_sha256=_digest("attacker-selected-client-record"),
    )
    monkeypatch.setattr(
        composition,
        "resolve_consent_pairing_context",
        lambda _public, _client, _profile: drifted,
    )
    with pytest.raises(TrustCenterIntegrityError, match="public pairing authority changed"):
        resolver(context_ref)


def test_operator_permissions_match_api_gates_and_bind_exact_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, request, _values, _registry, _identity = _environment(monkeypatch)
    monkeypatch.setattr(
        composition,
        "has_permission",
        lambda _request, permission: permission in {"view", "operate"},
    )
    monkeypatch.setattr(
        composition,
        "has_global_permission",
        lambda _request, _permission: False,
    )
    principal_ref = _operator_ref(request)
    factory = app.state.consumer_trust_center_authority_principal_resolver_factory
    resolver = factory(
        tenant_id=TENANT,
        principal_ref=principal_ref,
        request=request,
    )

    authority = resolver(TENANT)

    assert type(authority) is TrustCenterPrincipalAuthority
    assert authority.principal_sha256 == _digest(principal_ref)
    assert authority.permissions == (
        "authority_read",
        "capability_request",
        "metadata_export",
        "rights_request",
    )
    assert authority.valid_until == NOW + 60
    assert authority.authority_sha256 == principal_authority_sha256(authority)
    with pytest.raises(TrustCenterAuthorityPermissionDenied, match="tenant authority changed"):
        resolver("tenant-b")
    with pytest.raises(TrustCenterAuthorityPermissionDenied, match="principal authority"):
        factory(
            tenant_id=TENANT,
            principal_ref="tca-principal-00000000000000000000000000000000",
            request=request,
        )


def test_auditor_receives_read_not_export_mutation_permission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, request, _values, _registry, _identity = _environment(monkeypatch)
    monkeypatch.setattr(composition, "has_permission", lambda *_args: False)
    monkeypatch.setattr(
        composition,
        "has_global_permission",
        lambda _request, permission: permission == "audit",
    )
    resolver = app.state.consumer_trust_center_authority_principal_resolver_factory(
        tenant_id=TENANT,
        principal_ref=_operator_ref(request),
        request=request,
    )
    assert resolver(TENANT).permissions == ("authority_read",)


def test_public_rights_intake_principal_is_read_only_even_when_auth_is_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _request_with_user, values, _registry, _identity = _environment(monkeypatch)
    public_request = _request(app, principal=None)
    monkeypatch.setattr(composition, "has_permission", lambda *_args: True)
    monkeypatch.setattr(composition, "has_global_permission", lambda *_args: True)
    service_ref = f"pro-rights-intake-{_digest('service')[:32]}"
    resolver = app.state.consumer_trust_center_authority_principal_resolver_factory(
        tenant_id=TENANT,
        principal_ref=service_ref,
        request=public_request,
    )
    authority = resolver(TENANT)

    assert authority.permissions == ("authority_read",)
    store = ConsumerTrustCenterAuthorityStore(
        tmp_path / "authority.sqlite3",
        binding_resolver=lambda _ref: ResolvedTrustCenterBinding(
            tenant_id=TENANT,
            property_id=values["client"].property_id,
            profile_id=values["profile"].profile_id,
            actor_sha256=_digest("consumer-actor"),
            requested_locale="en-US",
            server_origin=values["client"].target_origin,
            server_bundle_id=None,
            server_platform=None,
            jurisdiction="us-ca",
            country_code="US",
            region_code="CA",
            profile_authority=None,
        ),
        principal_authority_resolver=resolver,
        signing_key_resolver=lambda _tenant, _key_ref: b"x" * 32,
        config_gate=lambda: None,
        clock=lambda: NOW,
    )
    assert store._principal(TENANT, "authority_read", NOW) == _digest(service_ref)
    with pytest.raises(TrustCenterAuthorityPermissionDenied):
        store._principal(TENANT, "context_admin", NOW)
    with pytest.raises(TrustCenterAuthorityPermissionDenied):
        store._principal(TENANT, "capability_request", NOW)


def test_environment_signing_key_is_explicit_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    composition.attach_consumer_trust_center_authority_composition(app)
    resolver = app.state.consumer_trust_center_authority_signing_key_resolver
    key_ref = app.state.consumer_trust_center_authority_signing_key_ref
    monkeypatch.delenv("MAVERICK_TRUST_CENTER_AUTHORITY_SIGNING_KEY", raising=False)
    with pytest.raises(TrustCenterAuthorityConfigError, match="absent or too short"):
        resolver(TENANT, key_ref)
    monkeypatch.setenv("MAVERICK_TRUST_CENTER_AUTHORITY_SIGNING_KEY", "short")
    with pytest.raises(TrustCenterAuthorityConfigError, match="absent or too short"):
        resolver(TENANT, key_ref)
    key = "environment-trust-center-signing-key-32-bytes-minimum"
    monkeypatch.setenv("MAVERICK_TRUST_CENTER_AUTHORITY_SIGNING_KEY", key)
    assert resolver(TENANT, key_ref) == key.encode()
    with pytest.raises(TrustCenterAuthorityConfigError, match="unavailable"):
        resolver(TENANT, "env:ATTACKER_SELECTED_KEY")


def test_pairing_verifier_reresolves_public_authority_and_redeemed_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, request, values, registry, identity = _environment(monkeypatch)
    verifier = app.state.consumer_trust_center_authority_pairing_verifier

    evidence = verifier(request=request, pairing=values["pairing"])

    assert evidence is values["evidence"]
    assert registry.client_calls == [values["client"].credential_sha256]
    assert registry.profile_calls == [(values["profile"].credential_sha256, values["client"])]
    assert identity.calls == [values["pairing"]]


@pytest.mark.parametrize("failure", ["pairing", "digest", "expiry"])
def test_pairing_verifier_rejects_stale_or_misbound_evidence(
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _authorities()
    evidence = values["evidence"]
    if failure == "digest":
        evidence = replace(evidence, evidence_sha256=_digest("tampered-evidence"))
    elif failure == "expiry":
        body = asdict(evidence)
        body.pop("evidence_sha256")
        body["valid_until"] = NOW
        evidence = ConsentIdentityEvidence(
            **body,
            evidence_sha256=_object_digest(body),
        )
    app, request, current, _registry, identity = _environment(
        monkeypatch,
        evidence=evidence,
    )
    supplied = current["pairing"]
    if failure == "pairing":
        supplied = replace(
            supplied,
            configuration_sha256=_digest("stale-configuration"),
        )
    verifier = app.state.consumer_trust_center_authority_pairing_verifier

    with pytest.raises(TrustCenterIntegrityError):
        verifier(request=request, pairing=supplied)
    if failure == "pairing":
        assert identity.calls == []


def test_factories_reject_requests_from_another_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _request_one, values, _registry, _identity = _environment(monkeypatch)
    other_request = _request(FastAPI())
    with pytest.raises(TrustCenterAuthorityConfigError, match="request authority"):
        app.state.consumer_trust_center_authority_binding_resolver_factory(
            tenant_id=TENANT,
            principal_ref="tca-principal-00000000000000000000000000000000",
            request=other_request,
        )
    with pytest.raises(TrustCenterAuthorityConfigError, match="request authority"):
        app.state.consumer_trust_center_authority_pairing_verifier(
            request=other_request,
            pairing=values["pairing"],
        )
