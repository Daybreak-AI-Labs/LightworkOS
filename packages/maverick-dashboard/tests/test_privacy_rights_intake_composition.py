from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, Request
from maverick.consent_identity_federation import (
    ConsentIdentityEvidence,
    ConsentIdentitySettings,
    ConsentPairingContext,
)
from maverick.consumer_trust_center import (
    ConsumerTrustCenterSourceAdapter,
    TrustCenterCapabilityGrant,
    TrustCenterContext,
)
from maverick.privacy_rights_intake import (
    IDENTITY_EVIDENCE_SCHEMA,
    ConsumerRightsIdentityEvidence,
    PrivacyRightsIntakeConfigError,
    PrivacyRightsIntakeConflict,
    PrivacyRightsIntakeStore,
)
from maverick_dashboard import privacy_rights_intake_composition as composition
from maverick_dashboard.consent_public_api import (
    PublicClientBinding,
    PublicConsentDependencies,
    PublicProfileBinding,
    PublicRequestContext,
    PublicRightsIntakeMaterial,
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


def _tenant_config(
    issuer: str,
    *,
    enabled: bool = True,
    max_active_requests: int = 100,
    max_active_requests_per_subject: int = 5,
) -> dict[str, Any]:
    return {
        "consent_preferences": {
            "enable": enabled,
            "publishing": {"enable": enabled},
            "public_api": {"enable": enabled},
            "trust_center": {"enable": enabled},
            "identity": {
                "enable": enabled,
                "issuer": issuer,
                "audience": "lightwork-consumer",
                "jwks_origin": issuer,
                "token_ttl_seconds": 600,
            },
        },
        "privacy_automation": {
            "enable": enabled,
            "rights_orchestration": {"enable": enabled},
            "rights_consumer_intake": {
                "enable": enabled,
                "request_ttl_seconds": 600,
                "retention_seconds": 86_400,
                "max_active_requests": max_active_requests,
                "max_active_requests_per_subject": max_active_requests_per_subject,
            },
        },
    }


class _FederationStore:
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


class _TrustStore:
    def __init__(self, context: TrustCenterContext) -> None:
        self.context = context
        self.refs: list[str] = []

    def make_context_resolver(self, context_ref: str):
        self.refs.append(context_ref)
        return lambda: self.context


class _RightsStore:
    def open_case(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def get_case(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def set_identity_verification(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def get_source(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def list_sources(self, *_args: Any, **_kwargs: Any) -> tuple[()]:
        return ()

    def plan_source_tasks(self, *_args: Any, **_kwargs: Any) -> tuple[()]:
        return ()


def _request(app: FastAPI) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/api/v1/public/consent/rights-requests",
            "raw_path": b"/api/v1/public/consent/rights-requests",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 443),
            "app": app,
        }
    )


def _authorities() -> dict[str, Any]:
    client = PublicClientBinding(
        credential_id="public-client-a",
        credential_sha256=_digest("client-credential"),
        tenant_id=TENANT,
        property_id="web-main",
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
        property_sha256=_digest("property-record"),
        rule_group_id="public-rules",
        rule_group_version=3,
        publication_sha256=_digest("publication"),
        bundle_sha256=_digest("bundle"),
        policy_id="privacy-policy",
        policy_version=4,
        policy_sha256=_digest("policy"),
        expires_at=NOW + 1_200,
        revision=5,
        record_sha256=_digest("client-record"),
    )
    profile = PublicProfileBinding(
        credential_sha256=_digest("profile-credential"),
        client_credential_sha256=client.credential_sha256,
        tenant_id=TENANT,
        property_id=client.property_id,
        profile_id="profile-opaque-a",
        subject_binding_sha256=_digest("anonymous-subject"),
        binding_sha256=_digest("profile-binding"),
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
        tenant_id=TENANT,
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
        configuration_sha256=_digest("configuration"),
        policy_id=client.policy_id,
        policy_version=client.policy_version,
        policy_sha256=client.policy_sha256,
        channel_kind="browser-origin",
        channel_binding_sha256=channel_sha,
    ).normalized()
    identity_body = {
        "schema": "lightwork.consent.identity-evidence.v1",
        "tenant_id": TENANT,
        "target_fingerprint": pairing.fingerprint,
        "source_fingerprint": _digest("source-pairing"),
        "subject_binding_sha256": _digest("known-oidc-subject"),
        "oidc_verification_sha256": _digest("verified-oidc-token"),
        "source_link_sha256": _digest("source-link"),
        "target_link_sha256": _digest("target-link"),
        "pairing_revision": 11,
        "valid_until": NOW + 600,
    }
    identity = ConsentIdentityEvidence(
        **identity_body,
        evidence_sha256=_object_digest(identity_body),
    )
    actor_sha = _digest("public-consent-actor")
    grant = TrustCenterCapabilityGrant(
        capability="rights_cases",
        grant_ref="rights-grant-a",
        tenant_sha256=_digest(TENANT),
        property_id=client.property_id,
        profile_sha256=_digest(profile.profile_id),
        approved_by_sha256=_digest("approver-one"),
        second_approved_by_sha256=_digest("approver-two"),
        valid_until=NOW + 900,
        grant_sha256="0" * 64,
        revoked=False,
    )
    grant = replace(
        grant,
        grant_sha256=ConsumerTrustCenterSourceAdapter.capability_grant_sha256(grant),
    )
    trust = TrustCenterContext(
        tenant_id=TENANT,
        property_id=client.property_id,
        profile_id=profile.profile_id,
        actor_sha256=actor_sha,
        requested_locale="en-US",
        server_origin=client.target_origin,
        server_bundle_id=None,
        server_platform=None,
        jurisdiction=client.jurisdiction,
        country_code=client.country_code,
        region_code=client.region_code,
        profile_authority=None,
        capability_grants=(grant,),
        rights_authorizations=(),
        publication_history_limit=25,
        receipt_limit=25,
        retained_until=NOW + 86_400,
        revision=7,
        valid_until=NOW + 900,
        context_sha256="0" * 64,
        revoked=False,
    )
    trust = replace(
        trust,
        context_sha256=ConsumerTrustCenterSourceAdapter.context_sha256(trust),
    )
    configuration = {
        "allowed": True,
        "configuration_sha256": pairing.configuration_sha256,
        "property": {
            "property_id": client.property_id,
            "revision": client.property_revision,
        },
        "publication": {
            "property_revision": client.property_revision,
            "publication_sha256": client.publication_sha256,
            "bundle_sha256": client.bundle_sha256,
        },
    }
    policy = {
        "policy_id": client.policy_id,
        "version": client.policy_version,
        "policy_sha256": client.policy_sha256,
    }
    public_context = PublicRequestContext(
        jurisdiction=client.jurisdiction,
        country_code=client.country_code,
        region_code=client.region_code,
        locale="en-US",
    )
    resolved = SimpleNamespace(
        binding=client,
        profile=profile,
        context=public_context,
        actor_sha256=actor_sha,
    )
    return {
        "client": client,
        "profile": profile,
        "pairing": pairing,
        "identity": identity,
        "trust": trust,
        "configuration": configuration,
        "policy": policy,
        "resolved": resolved,
    }


def _environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    identity: ConsentIdentityEvidence | BaseException | None = None,
    trust: TrustCenterContext | None = None,
    explicit_assurance: bool = True,
) -> tuple[FastAPI, dict[str, Any], _FederationStore, _TrustStore, Path]:
    values = _authorities()
    selected_identity = values["identity"] if identity is None else identity
    selected_trust = values["trust"] if trust is None else trust
    federation = _FederationStore(selected_identity)
    trust_store = _TrustStore(selected_trust)
    rights = _RightsStore()
    path = tmp_path / TENANT / "privacy-rights-intake.sqlite3"
    public = PublicConsentDependencies(
        credential_store=object(),  # type: ignore[arg-type]
        publishing_store_for=lambda _tenant: object(),
        preference_store_for=lambda _tenant: object(),
        gate=lambda: True,
        rate_limit=lambda _credential, _action: None,
        context_resolver=lambda _request, _client: values["resolved"].context,
        clock=lambda: NOW,
    )
    monkeypatch.setattr(
        composition,
        "privacy_rights_intake_composition_enabled",
        lambda _config=None: True,
    )
    tenant_config = _tenant_config("https://id.example.test")
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: tenant_config)
    monkeypatch.setattr(
        composition,
        "_settings",
        lambda _config: composition.PrivacyRightsIntakeCompositionSettings(
            request_ttl_seconds=600,
            retention_seconds=86_400,
            max_active_requests=17,
            max_active_requests_per_subject=3,
        ),
    )
    monkeypatch.setattr(
        composition,
        "resolve_consent_pairing_context",
        lambda _public, client, profile: (
            values["pairing"]
            if client == values["client"] and profile == values["profile"]
            else (_ for _ in ()).throw(RuntimeError("misbound public authority"))
        ),
    )

    app = FastAPI()
    app.state.privacy_rights_intake_gate = lambda: True
    app.state.privacy_rights_intake_public_dependencies_factory = lambda *, request: public
    app.state.privacy_rights_intake_identity_settings_factory = lambda *, request, config: (
        ConsentIdentitySettings(
            enabled=True,
            issuer="https://id.example.test",
            audience="lightwork-consumer",
            jwks_origin="https://id.example.test",
            token_ttl_seconds=600,
        )
    )
    app.state.consent_identity_federation_store_factory = lambda *, tenant_id, request: federation
    if explicit_assurance:

        def assurance_resolver(
            *,
            federation_evidence: ConsentIdentityEvidence,
            pairing_context: ConsentPairingContext,
            identity_settings: ConsentIdentitySettings,
            resolved_at: float,
            request: Request,
        ) -> ConsumerRightsIdentityEvidence:
            del identity_settings, request
            body: dict[str, object] = {
                "schema": IDENTITY_EVIDENCE_SCHEMA,
                "tenant_id": pairing_context.tenant_id,
                "property_sha256": pairing_context.property_sha256,
                "profile_sha256": _digest(pairing_context.profile_id),
                "profile_binding_sha256": pairing_context.profile_binding_sha256,
                "subject_binding_sha256": federation_evidence.subject_binding_sha256,
                "channel": pairing_context.channel_kind,
                "channel_binding_sha256": pairing_context.channel_binding_sha256,
                "verification_authority_sha256": _digest("deployment-aal-policy"),
                "verification_method": "provider-idv",
                "assurance_level": "substantial",
                "evidence_ref": f"CONSENT-OIDC-{federation_evidence.evidence_sha256}",
                "evidence_revision": federation_evidence.pairing_revision,
                "verified_at": resolved_at - 60,
                "valid_until": federation_evidence.valid_until,
                "revoked": False,
            }
            return ConsumerRightsIdentityEvidence(
                **body,
                evidence_sha256=_object_digest(body),
            )

        app.state.privacy_rights_intake_identity_assurance_resolver = assurance_resolver
    app.state.consumer_trust_center_authority_store_factory = lambda **_kwargs: trust_store
    app.state.privacy_rights_orchestration_store_factory = lambda **_kwargs: rights
    app.state.privacy_rights_intake_path_factory = lambda *, tenant_id, request: (
        path.parent / "privacy-rights-intake.sqlite3"
    )
    app.state.privacy_rights_intake_clock = lambda: NOW
    composition.attach_privacy_rights_intake_composition(app)
    return app, values, federation, trust_store, path


def test_tenant_config_snapshot_is_exact_and_does_not_bleed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick import config as config_module

    configs = {
        "tenant-a": _tenant_config(
            "https://id-a.example.test",
            max_active_requests=41,
            max_active_requests_per_subject=4,
        ),
        "tenant-b": _tenant_config(
            "https://id-b.example.test",
            max_active_requests=73,
            max_active_requests_per_subject=7,
        ),
        "tenant-disabled": _tenant_config(
            "https://disabled.example.test",
            enabled=False,
        ),
        "tenant-invalid": _tenant_config("https://invalid.example.test"),
    }
    current = {"tenant": None}

    @contextmanager
    def scope(*, tenant: str, **_kwargs: Any):
        previous = current["tenant"]
        current["tenant"] = tenant
        try:
            yield
        finally:
            current["tenant"] = previous

    monkeypatch.setattr(composition, "tenant_scope", scope)
    monkeypatch.setattr(
        config_module,
        "load_config",
        lambda: configs[str(current["tenant"])],
    )
    monkeypatch.setattr(
        config_module,
        "config_source_errors",
        lambda *, include_tenant: (
            {"tenant-invalid/config.toml": "invalid"}
            if current["tenant"] == "tenant-invalid"
            else {}
        ),
    )

    config_a = composition._load_tenant_config("tenant-a")
    config_b = composition._load_tenant_config("tenant-b")
    settings_a = composition._settings(config_a)
    settings_b = composition._settings(config_b)
    app = FastAPI()
    request = _request(app)

    assert settings_a.max_active_requests == 41
    assert settings_a.max_active_requests_per_subject == 4
    assert settings_b.max_active_requests == 73
    assert settings_b.max_active_requests_per_subject == 7
    assert composition._identity_settings(request, config_a).issuer == ("https://id-a.example.test")
    assert composition._identity_settings(request, config_b).issuer == ("https://id-b.example.test")
    assert current["tenant"] is None
    with pytest.raises(PrivacyRightsIntakeConfigError, match="disabled for this tenant"):
        composition._load_tenant_config("tenant-disabled")
    with pytest.raises(PrivacyRightsIntakeConfigError, match="source is invalid"):
        composition._load_tenant_config("tenant-invalid")


def _material(app: FastAPI, values: dict[str, Any]) -> PublicRightsIntakeMaterial:
    factory = app.state.privacy_rights_intake_store_factory
    return factory(
        tenant_id=TENANT,
        initial_client_binding=values["client"],
        initial_profile_binding=values["profile"],
        active_public_configuration=values["configuration"],
        active_policy=values["policy"],
        public_authority_resolver=lambda: values["resolved"],
        request=_request(app),
    )


def test_attach_is_lazy_and_builds_exact_subject_bound_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, values, federation, trust_store, path = _environment(tmp_path, monkeypatch)
    assert not path.exists()

    material = _material(app, values)

    assert isinstance(material, PublicRightsIntakeMaterial)
    assert isinstance(material.store, PrivacyRightsIntakeStore)
    assert material.store.path == path
    assert material.store._request_ttl_seconds == 600
    assert material.store._retention_seconds == 86_400
    assert material.store._max_active_requests == 17
    assert material.store._max_active_requests_per_subject == 3
    authority = material.authority
    assert isinstance(authority, composition.ConsumerRightsIntakeAuthority)
    assert authority.subject_binding_sha256 == values["identity"].subject_binding_sha256
    assert authority.profile_binding_sha256 == values["profile"].binding_sha256
    assert authority.property_sha256 == values["client"].property_sha256
    assert authority.capability_grant_sha256 == values["trust"].capability_grants[0].grant_sha256
    assert authority.minimum_identity_assurance == "substantial"
    assert material.store._identity_evidence_resolver().assurance_level == "substantial"
    assert authority.valid_until == values["identity"].valid_until
    assert federation.calls
    assert trust_store.refs == [
        composition.privacy_rights_intake_trust_context_ref(values["pairing"])
    ]
    assert path.exists()


def test_factory_fails_closed_without_redeemed_oidc_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, values, _federation, _trust, path = _environment(
        tmp_path,
        monkeypatch,
        identity=RuntimeError("private identity lookup detail"),
    )

    with pytest.raises(
        PrivacyRightsIntakeConflict,
        match="fresh independently verified identity evidence is unavailable",
    ):
        _material(app, values)
    assert not path.exists()


def test_verified_oidc_transport_alone_cannot_open_an_intake_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, values, _federation, _trust, path = _environment(
        tmp_path,
        monkeypatch,
        explicit_assurance=False,
    )
    assert app.state.privacy_rights_intake_gate() is False

    with pytest.raises(
        PrivacyRightsIntakeConfigError,
        match="consumer rights intake is disabled",
    ):
        _material(app, values)
    assert not path.exists()


def test_factory_fails_closed_without_active_rights_cases_grant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _authorities()
    no_grant = replace(values["trust"], capability_grants=(), context_sha256="0" * 64)
    no_grant = replace(
        no_grant,
        context_sha256=ConsumerTrustCenterSourceAdapter.context_sha256(no_grant),
    )
    app, current, _federation, _trust, path = _environment(
        tmp_path,
        monkeypatch,
        trust=no_grant,
    )

    with pytest.raises(
        PrivacyRightsIntakeConflict,
        match="active rights_cases grant is required",
    ):
        _material(app, current)
    assert not path.exists()


def test_factory_rejects_identity_target_misbinding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _authorities()
    body = asdict(values["identity"])
    body.pop("evidence_sha256")
    body["target_fingerprint"] = _digest("attacker-selected-target")
    misbound = ConsentIdentityEvidence(
        **body,
        evidence_sha256=_object_digest(body),
    )
    app, current, _federation, _trust, path = _environment(
        tmp_path,
        monkeypatch,
        identity=misbound,
    )

    with pytest.raises(
        PrivacyRightsIntakeConflict,
        match="fresh OIDC identity evidence changed",
    ):
        _material(app, current)
    assert not path.exists()
