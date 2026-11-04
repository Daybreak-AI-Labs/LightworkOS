from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import maverick_dashboard.consent_public_api as consent_public_api
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick.consent_experiments import (
    ConsentExperimentAuthority,
    ConsentExperimentConfigError,
    ConsentExperimentNotFound,
    ConsentExperimentPermissionDenied,
    ExperimentSpec,
    ExperimentVariant,
)
from maverick.consent_preferences import ConsentPreferenceStore
from maverick.consent_profile_data import ConsentProfileDataStore
from maverick.consent_publishing import ConsentPublishingStore
from maverick.privacy_rights_intake import SignedConsumerRightsStatus
from maverick_dashboard.consent_profile_data_api import (
    PublicPromptAssignmentStore,
    public_profile_data_ids,
)
from maverick_dashboard.consent_public_api import (
    PublicConsentConflict,
    PublicConsentCredentialError,
    PublicConsentCredentialStore,
    PublicConsentDependencies,
    PublicConsentRateLimitExceeded,
    PublicConsentValidationError,
    PublicRightsIntakeMaterial,
    PublicRightsPackageDownload,
    create_consent_public_router,
    default_public_consent_dependencies,
    default_public_consent_gate,
    default_public_experiment_gate,
    default_public_profile_data_gate,
    default_public_request_context,
)

_NOW = 1_800_000_000.0
_ORIGIN = "https://www.example.com"
_CLIENT_CREDENTIAL = "browser-client-credential-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_PROFILE_CREDENTIAL = "profile-capability-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_SERVICE_CREDENTIAL = "service-client-credential-cccccccccccccccccccccccccccccccc"
_NOTICE_SHA256 = hashlib.sha256(b"public notice v1").hexdigest()


def test_browser_rate_key_separates_clients(monkeypatch):
    from maverick_dashboard import ip_allowlist

    monkeypatch.setattr(ip_allowlist, "client_ip", lambda request: request.client.host)
    first = SimpleNamespace(client=SimpleNamespace(host="192.0.2.1"))
    second = SimpleNamespace(client=SimpleNamespace(host="192.0.2.2"))
    assert consent_public_api._browser_rate_key(first, "site") != consent_public_api._browser_rate_key(second, "site")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _json_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


class _ExperimentKeys:
    def key_for(self, tenant_id: str, capability: str) -> bytes:
        assert capability == "lightwork.consent-experiments.v1"
        return hmac.new(b"p" * 32, tenant_id.encode(), hashlib.sha256).digest()


class _ProfileDataKeys:
    def key_for(self, tenant_id: str, capability: str) -> bytes:
        assert capability == "lightwork.consent-profile-assignments.v1"
        return hmac.new(b"d" * 32, tenant_id.encode(), hashlib.sha256).digest()


@dataclass
class _Environment:
    app: FastAPI
    client: TestClient
    registry: PublicConsentCredentialStore
    publishing: ConsentPublishingStore
    preferences: ConsentPreferenceStore
    property_record: dict[str, Any]
    publication: dict[str, Any]
    policy: dict[str, Any]
    experiments: ConsentExperimentAuthority
    profile_data: ConsentProfileDataStore
    profile_assignments: PublicPromptAssignmentStore
    binding: Any
    gate_state: dict[str, bool]
    experiment_gate_state: dict[str, bool]
    profile_data_gate_state: dict[str, bool]
    limiter_state: dict[str, Any]
    clock_state: dict[str, float]


def _seed_authorities(tmp_path: Path, *, mixed_lawful_bases: bool = False) -> _Environment:
    clock_state = {"now": _NOW}
    publishing_ids = itertools.count(1)
    preference_ids = itertools.count(1)
    credential_ids = itertools.count(1)
    publishing = ConsentPublishingStore(
        tmp_path / "publishing" / "publishing.sqlite3",
        clock=lambda: clock_state["now"],
        id_factory=lambda prefix: f"{prefix}-{next(publishing_ids)}",
    )
    preferences = ConsentPreferenceStore(
        tmp_path / "preferences" / "preferences.sqlite3",
        clock=lambda: clock_state["now"],
        id_factory=lambda prefix: f"{prefix}-{next(preference_ids)}",
    )
    registry = PublicConsentCredentialStore(
        tmp_path / "registry" / "credentials.sqlite3",
        clock=lambda: clock_state["now"],
        id_factory=lambda: f"public-client-{next(credential_ids)}",
    )
    experiments = ConsentExperimentAuthority(
        tmp_path / "experiments" / "experiments.sqlite3",
        key_authority=_ExperimentKeys(),
        config_loader=lambda: {
            "consent_preferences": {
                "enable": True,
                "experiments": {"enable": True},
            }
        },
        clock=lambda: clock_state["now"],
    )
    tenant = "tenant-a"
    property_record = publishing.upsert_property(
        tenant,
        "web-main",
        kind="web",
        consent_group_id="consumer-global",
        web_domains=["example.com"],
        origin_allowlist=[_ORIGIN],
        expected_revision=0,
        idempotency_key="property-v1",
    )
    publishing.put_purpose_version(
        tenant,
        "analytics",
        1,
        title_key="purpose.title",
        description_key="purpose.description",
        lawful_basis="consent",
        required=False,
        default_choice="denied",
        expected_current_version=0,
        idempotency_key="purpose-v1",
    )
    if mixed_lawful_bases:
        publishing.put_purpose_version(
            tenant,
            "fulfillment",
            1,
            title_key="fulfillment.title",
            description_key="fulfillment.description",
            lawful_basis="contract",
            required=True,
            default_choice="denied",
            expected_current_version=0,
            idempotency_key="fulfillment-purpose-v1",
        )
    publishing.put_custom_preference_version(
        tenant,
        "required-bool",
        1,
        title_key="profile.required.title",
        description_key="profile.required.description",
        value_type="boolean",
        option_ids=[],
        required=True,
        expected_current_version=0,
        idempotency_key="profile-required-v1",
    )
    publishing.put_custom_preference_version(
        tenant,
        "locale",
        1,
        title_key="profile.locale.title",
        description_key="profile.locale.description",
        value_type="single_select",
        option_ids=["eu", "us"],
        required=False,
        expected_current_version=0,
        idempotency_key="profile-locale-v1",
    )
    publishing.put_custom_preference_version(
        tenant,
        "channels",
        1,
        title_key="profile.channels.title",
        description_key="profile.channels.description",
        value_type="multi_select",
        option_ids=["email", "sms"],
        required=False,
        expected_current_version=0,
        idempotency_key="profile-channels-v1",
    )
    publishing.put_notice_version(
        tenant,
        "privacy-notice",
        1,
        title_key="notice.title",
        body_key="notice.body",
        document_sha256=_NOTICE_SHA256,
        expected_current_version=0,
        idempotency_key="notice-v1",
    )
    publishing.put_translation_version(
        tenant,
        "consumer-copy",
        "en-US",
        1,
        messages={
            "purpose.title": "Analytics",
            "purpose.description": "Measure service performance",
            **(
                {
                    "fulfillment.title": "Order fulfillment",
                    "fulfillment.description": "Fulfill an order",
                }
                if mixed_lawful_bases
                else {}
            ),
            "notice.title": "Your privacy choices",
            "notice.body": "Choose whether analytics may be used.",
            "template.title": "Privacy choices",
            "template.body": "Control analytics.",
            "action.accept": "Accept",
            "action.reject": "Reject",
            "action.save": "Save",
            "profile.required.title": "Required profile choice",
            "profile.required.description": "A required volunteered boolean choice.",
            "profile.locale.title": "Region preference",
            "profile.locale.description": "A volunteered closed region reference.",
            "profile.channels.title": "Contact channel preferences",
            "profile.channels.description": "Volunteered closed channel references.",
        },
        expected_current_version=0,
        idempotency_key="translation-v1",
    )
    publishing.put_template_version(
        tenant,
        "standard-banner",
        1,
        surface="banner",
        title_key="template.title",
        body_key="template.body",
        actions={
            "accept_all": "action.accept",
            "reject_all": "action.reject",
            "save_preferences": "action.save",
        },
        theme_token_id="brand-default",
        expected_current_version=0,
        idempotency_key="template-v1",
    )
    publishing.put_rule_group_version(
        tenant,
        "production-rules",
        1,
        rules=[
            {
                "rule_id": "global",
                "priority": 1,
                "locales": ["en-US"],
                "default_locale": "en-US",
                "purposes": [
                    {"id": "analytics", "version": 1},
                    *(
                        [{"id": "fulfillment", "version": 1}]
                        if mixed_lawful_bases
                        else []
                    ),
                ],
                "custom_preferences": [
                    {"id": "required-bool", "version": 1},
                    {"id": "locale", "version": 1},
                    {"id": "channels", "version": 1},
                ],
                "notice": {"id": "privacy-notice", "version": 1},
                "template": {"id": "standard-banner", "version": 1},
                "translation_catalog_id": "consumer-copy",
                "translation_versions": {"en-US": 1},
            }
        ],
        expected_current_version=0,
        idempotency_key="rules-v1",
    )
    publication = publishing.publish(
        tenant,
        "web-main",
        "production-rules",
        1,
        expected_property_revision=1,
        expected_publication_revision=0,
        idempotency_key="publication-v1",
    )
    policy = preferences.publish_policy(
        tenant,
        "public-consent",
        1,
        {
            "analytics": "consent",
            **({"fulfillment": "contract"} if mixed_lawful_bases else {}),
        },
        _NOTICE_SHA256,
        _NOW - 100,
    )
    resolved = publishing.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin=_ORIGIN,
        jurisdiction="global",
        country_code="US",
        region_code="",
        requested_locale="en-US",
        evaluated_at=_NOW,
    )
    catalog_id, journey_id = public_profile_data_ids(
        tenant_id=tenant,
        property_id="web-main",
        publication_sha256=publication["publication_sha256"],
        bundle_sha256=publication["bundle_sha256"],
        configuration_sha256=resolved["configuration_sha256"],
        policy_id=policy["policy_id"],
        policy_version=policy["version"],
        policy_sha256=policy["policy_sha256"],
    )
    profile_actor = {"value": "profile-catalog-author"}
    profile_data = ConsentProfileDataStore(
        tmp_path / "profile-data" / "consent-profile-data.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: profile_actor["value"],
        clock=lambda: clock_state["now"],
    )
    definitions = [
        {
            "preference_id": "required-bool",
            "definition_version": 1,
            "label_ref": "required-bool",
            "value_type": "boolean",
            "options": [],
            "required": True,
            "expires_after_seconds": None,
            "retention_seconds": 86_400,
        },
        {
            "preference_id": "locale",
            "definition_version": 1,
            "label_ref": "locale",
            "value_type": "single_select",
            "options": [
                {"value_id": "eu", "label_ref": "eu"},
                {"value_id": "us", "label_ref": "us"},
            ],
            "required": False,
            "expires_after_seconds": None,
            "retention_seconds": 86_400,
        },
        {
            "preference_id": "channels",
            "definition_version": 1,
            "label_ref": "channels",
            "value_type": "multi_select",
            "options": [
                {"value_id": "email", "label_ref": "email"},
                {"value_id": "sms", "label_ref": "sms"},
            ],
            "required": False,
            "expires_after_seconds": None,
            "retention_seconds": 86_400,
        },
    ]
    profile_data.create_catalog_version(
        tenant,
        catalog_id,
        property_id="web-main",
        publication_sha256=publication["publication_sha256"],
        bundle_sha256=publication["bundle_sha256"],
        configuration_sha256=resolved["configuration_sha256"],
        policy_id=policy["policy_id"],
        policy_version=policy["version"],
        policy_sha256=policy["policy_sha256"],
        definitions=definitions,
        retention_seconds=86_400,
        expected_latest_version=0,
        idempotency_key="public-profile-catalog-create",
    )
    profile_actor["value"] = "profile-catalog-reviewer"
    profile_data.approve_catalog_version(
        tenant,
        catalog_id,
        1,
        expected_revision=1,
        idempotency_key="public-profile-catalog-approve",
    )
    profile_actor["value"] = "profile-journey-author"
    profile_data.create_journey_version(
        tenant,
        journey_id,
        catalog_id=catalog_id,
        catalog_version=1,
        stages=[
            {
                "stage_id": "foundation",
                "priority": 20,
                "prompt_label_ref": "foundation",
                "preference_ids": ["locale", "required-bool"],
                "condition": None,
            },
            {
                "stage_id": "analytics-follow-up",
                "priority": 10,
                "prompt_label_ref": "analytics-follow-up",
                "preference_ids": ["channels"],
                "condition": {
                    "source": "purpose",
                    "key": "analytics",
                    "operator": "equals",
                    "value": "grant",
                },
            },
        ],
        max_prompts=2,
        cooldown_seconds=60,
        frequency_cap=3,
        frequency_window_seconds=600,
        retention_seconds=86_400,
        expected_latest_version=0,
        idempotency_key="public-profile-journey-create",
    )
    profile_actor["value"] = "profile-journey-reviewer"
    profile_data.approve_journey_version(
        tenant,
        journey_id,
        1,
        expected_revision=1,
        idempotency_key="public-profile-journey-approve",
    )
    profile_actor["value"] = "profile-release-manager"
    profile_data.activate_journey(
        tenant,
        journey_id,
        1,
        expected_revision=2,
        idempotency_key="public-profile-journey-activate",
    )
    profile_assignments = PublicPromptAssignmentStore(
        tmp_path / "profile-data" / "public-assignments.sqlite3",
        tenant_id=tenant,
        key_authority=_ProfileDataKeys(),
        clock=lambda: clock_state["now"],
    )
    binding = registry.enroll_client(
        _CLIENT_CREDENTIAL,
        tenant_id=tenant,
        property_id="web-main",
        client_kind="browser",
        browser_origin=_ORIGIN,
        jurisdiction="global",
        country_code="US",
        region_code="",
        default_locale="en-US",
        property_revision=property_record["revision"],
        property_sha256=property_record["record_sha256"],
        rule_group_id="production-rules",
        rule_group_version=1,
        publication_sha256=publication["publication_sha256"],
        bundle_sha256=publication["bundle_sha256"],
        policy_id=policy["policy_id"],
        policy_version=policy["version"],
        policy_sha256=policy["policy_sha256"],
        expected_revision=0,
    )
    gate_state = {"enabled": True}
    experiment_gate_state = {"enabled": True}
    profile_data_gate_state = {"enabled": True}
    limiter_state: dict[str, Any] = {"blocked": False, "calls": []}

    def rate_limit(credential_sha256: str, action: str) -> None:
        limiter_state["calls"].append((credential_sha256, action))
        if limiter_state["blocked"]:
            raise PublicConsentRateLimitExceeded("blocked")

    dependencies = PublicConsentDependencies(
        credential_store=registry,
        publishing_store_for=lambda requested_tenant: (
            publishing
            if requested_tenant == "tenant-a"
            else ConsentPublishingStore(
                tmp_path / "other" / "publishing.sqlite3",
                clock=lambda: _NOW,
            )
        ),
        preference_store_for=lambda requested_tenant: (
            preferences
            if requested_tenant == "tenant-a"
            else ConsentPreferenceStore(
                tmp_path / "other" / "preferences.sqlite3",
                clock=lambda: _NOW,
            )
        ),
        gate=lambda: gate_state["enabled"],
        rate_limit=rate_limit,
        context_resolver=default_public_request_context,
        clock=lambda: clock_state["now"],
        experiment_gate=lambda: experiment_gate_state["enabled"],
        experiment_authority_for=lambda requested_tenant: (
            experiments if requested_tenant == "tenant-a" else None
        ),
        profile_data_gate=lambda: profile_data_gate_state["enabled"],
        profile_data_store_for=lambda requested_tenant: (
            profile_data if requested_tenant == "tenant-a" else None
        ),
        profile_assignment_store_for=lambda requested_tenant: (
            profile_assignments if requested_tenant == "tenant-a" else None
        ),
    )
    app = FastAPI()
    app.include_router(create_consent_public_router(dependencies))
    client = TestClient(app, base_url="https://consent.lightwork.test")
    return _Environment(
        app=app,
        client=client,
        registry=registry,
        publishing=publishing,
        preferences=preferences,
        property_record=property_record,
        publication=publication,
        policy=policy,
        experiments=experiments,
        profile_data=profile_data,
        profile_assignments=profile_assignments,
        binding=binding,
        gate_state=gate_state,
        experiment_gate_state=experiment_gate_state,
        profile_data_gate_state=profile_data_gate_state,
        limiter_state=limiter_state,
        clock_state=clock_state,
    )


@pytest.fixture
def environment(tmp_path: Path) -> _Environment:
    return _seed_authorities(tmp_path)


def _browser_headers(*, profile: bool = False) -> dict[str, str]:
    headers = {
        "Authorization": f"ConsentPublic {_CLIENT_CREDENTIAL}",
        "Origin": _ORIGIN,
    }
    if profile:
        headers["X-Lightwork-Profile-Credential"] = _PROFILE_CREDENTIAL
    return headers


def _profile_bootstrap_body() -> dict[str, str]:
    return {
        "subject_sha256": _sha256("browser pseudonym"),
        "profile_credential_sha256": _sha256(_PROFILE_CREDENTIAL),
        "idempotency_key": "bootstrap-1",
    }


def _contract_echo(
    configuration: dict[str, Any],
    policy_sha256: str,
) -> dict[str, Any]:
    return {
        "publication_sha256": configuration["publication"]["publication_sha256"],
        "bundle_sha256": configuration["publication"]["bundle_sha256"],
        "configuration_sha256": configuration["configuration_sha256"],
        "policy_version": 1,
        "policy_sha256": policy_sha256,
    }


def _public_assignment(environment: _Environment, **headers: str) -> dict[str, Any]:
    response = environment.client.get(
        "/api/v1/public/consent/experiments/assignment",
        headers={**_browser_headers(profile=True), **headers},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _create_public_experiment(
    environment: _Environment,
    *,
    approve: bool = True,
    unsafe: bool = False,
    max_exposures: int = 10_000,
) -> tuple[dict[str, Any], dict[str, Any]]:
    baseline = _public_assignment(environment)
    inline = json.loads(json.dumps(baseline["render"]))
    inline["layout"] = "inline"
    variants = (
        ExperimentVariant(
            variant_id="control",
            allocation_bps=5_000,
            content_ref="public-layout:stacked",
            content_sha256=baseline["content_sha256"],
            accessibility_evidence_sha256=_sha256("control accessibility review"),
            equal_choice_evidence_sha256=_sha256("control choice parity review"),
            is_control=True,
        ),
        ExperimentVariant(
            variant_id="treatment",
            allocation_bps=5_000,
            content_ref=("public-layout:unsafe" if unsafe else "public-layout:inline"),
            content_sha256=_json_sha256(inline),
            accessibility_evidence_sha256=_sha256("treatment accessibility review"),
            equal_choice_evidence_sha256=_sha256("treatment choice parity review"),
        ),
    )
    spec = ExperimentSpec(
        experiment_id=baseline["experiment_id"],
        metric_id="preference-completion",
        variants=variants,
        starts_at=_NOW - 100,
        ends_at=_NOW + 10_000,
        max_exposures=max_exposures,
        min_sample_per_variant=20,
    )
    created = environment.experiments.create_experiment(
        "tenant-a",
        spec,
        created_by="human:experiment-owner",
        idempotency_key="public-experiment-create",
    )
    if not approve:
        return baseline, created
    with pytest.raises(ConsentExperimentPermissionDenied, match="cannot approve"):
        environment.experiments.approve(
            "tenant-a",
            spec.experiment_id,
            expected_revision=0,
            approved_by="human:experiment-owner",
            idempotency_key="public-experiment-self-approval",
        )
    approved_record = environment.experiments.approve(
        "tenant-a",
        spec.experiment_id,
        expected_revision=0,
        approved_by="human:privacy-reviewer",
        idempotency_key="public-experiment-approval",
    )
    active = environment.experiments.activate(
        "tenant-a",
        spec.experiment_id,
        expected_revision=approved_record["revision"],
        activated_by="human:release-manager",
        idempotency_key="public-experiment-activation",
    )
    return baseline, active


def _foreign_profile_capability(
    environment: _Environment,
    *,
    tenant_id: str,
    property_id: str,
    marker: str,
) -> str:
    client_credential = f"foreign-client-{marker}-" + "c" * 32
    profile_credential = f"foreign-profile-{marker}-" + "p" * 32
    binding = environment.registry.enroll_client(
        client_credential,
        tenant_id=tenant_id,
        property_id=property_id,
        client_kind="browser",
        browser_origin=_ORIGIN,
        jurisdiction="global",
        country_code="US",
        region_code="",
        default_locale="en-US",
        property_revision=environment.property_record["revision"],
        property_sha256=environment.property_record["record_sha256"],
        rule_group_id="production-rules",
        rule_group_version=1,
        publication_sha256=environment.publication["publication_sha256"],
        bundle_sha256=environment.publication["bundle_sha256"],
        policy_id=environment.policy["policy_id"],
        policy_version=environment.policy["version"],
        policy_sha256=environment.policy["policy_sha256"],
        expected_revision=0,
    )
    environment.registry.bootstrap_profile(
        binding,
        subject_sha256=_sha256(f"foreign subject {marker}"),
        profile_credential_sha256=_sha256(profile_credential),
        idempotency_key=f"foreign-bootstrap-{marker}",
        create_profile=lambda profile_id, _subject, _idempotency: {
            "created_at": _NOW,
            "profile_id": profile_id,
            "revision": 0,
        },
    )
    return profile_credential


def test_public_router_is_mounted_at_an_exact_self_auth_boundary() -> None:
    from maverick_dashboard.app import app
    from maverick_dashboard.auth import _self_authenticated_path

    paths = app.openapi()["paths"]
    assert "/api/v1/public/consent/configuration" in paths
    assert "/api/v1/public/consent/preferences" in paths
    assert _self_authenticated_path("/api/v1/public/consent/configuration")
    assert not _self_authenticated_path("/api/v1/public/consent-admin")
    assert callable(app.state.privacy_rights_intake_store_factory)
    assert callable(app.state.consumer_trust_center_authority_binding_resolver_factory)
    assert callable(app.state.consumer_trust_center_authority_principal_resolver_factory)
    assert callable(app.state.consumer_trust_center_authority_signing_key_resolver)
    assert callable(app.state.consumer_trust_center_authority_pairing_verifier)
    public_factory = app.state.privacy_rights_intake_public_dependencies_factory
    assert public_factory(request=object()) is public_factory(request=object())


def test_admin_safe_client_listing_and_id_based_revocation(
    environment: _Environment,
) -> None:
    listed = environment.registry.list_clients("tenant-a")
    assert listed["truncated"] is False
    assert listed["items"][0]["credential_id"] == environment.binding.credential_id
    assert "credential_sha256" not in listed["items"][0]

    revoked = environment.registry.revoke_client_id(
        "tenant-a",
        environment.binding.credential_id,
        expected_revision=1,
    )
    assert revoked["status"] == "revoked"
    assert revoked["revision"] == 2
    assert environment.registry.list_clients("tenant-a")["items"][0]["status"] == "revoked"
    with pytest.raises(PublicConsentCredentialError, match="invalid public consent credential"):
        environment.registry.resolve_client(_CLIENT_CREDENTIAL)


def test_profile_capability_can_be_revoked_without_storing_raw_capability(
    environment: _Environment,
) -> None:
    _bootstrap(environment)
    profile = environment.registry.resolve_profile(
        _PROFILE_CREDENTIAL,
        environment.binding,
    )
    revoked = environment.registry.revoke_profile(
        "tenant-a",
        "web-main",
        profile.profile_id,
        actor_sha256=_sha256("privacy owner"),
        evidence_sha256=_sha256("revocation ticket"),
    )
    assert revoked["profile_id"] == profile.profile_id
    assert "credential_sha256" not in revoked
    with pytest.raises(PublicConsentCredentialError, match="invalid public consent credential"):
        environment.registry.resolve_profile(
            _PROFILE_CREDENTIAL,
            environment.binding,
        )


def test_exact_enrolled_origin_gets_bounded_cors_preflight_and_response(
    environment: _Environment,
) -> None:
    preflight = environment.client.options(
        "/api/v1/public/consent/preferences",
        headers={
            "Origin": _ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": ("authorization,x-lightwork-profile-credential"),
        },
    )
    assert preflight.status_code == 204
    assert preflight.headers["access-control-allow-origin"] == _ORIGIN
    assert "authorization" in preflight.headers["access-control-allow-headers"]

    configuration = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    )
    assert configuration.status_code == 200
    assert environment.limiter_state["calls"][-1][1] == "request"
    assert configuration.headers["access-control-allow-origin"] == _ORIGIN
    assert configuration.headers["vary"] == "Origin"
    assert configuration.json()["policy_sha256"] == environment.policy["policy_sha256"]

    rejected = environment.client.options(
        "/api/v1/public/consent/preferences",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert rejected.status_code == 403


def _bootstrap(environment: _Environment) -> dict[str, Any]:
    response = environment.client.post(
        "/api/v1/public/consent/profiles/bootstrap",
        headers=_browser_headers(),
        json=_profile_bootstrap_body(),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _rights_intake_pair(environment: _Environment):
    _bootstrap(environment)
    client = environment.registry.resolve_client(_CLIENT_CREDENTIAL)
    profile = environment.registry.resolve_profile(_PROFILE_CREDENTIAL, client)
    return client, profile


def _reenroll_client(environment: _Environment, client):
    return environment.registry.enroll_client(
        _CLIENT_CREDENTIAL,
        tenant_id=client.tenant_id,
        property_id=client.property_id,
        client_kind=client.client_kind,
        browser_origin=client.browser_origin,
        service_client_id=client.service_client_id,
        target_origin=client.target_origin,
        target_bundle_id=client.target_bundle_id,
        target_platform=client.target_platform,
        jurisdiction=client.jurisdiction,
        country_code=client.country_code,
        region_code=client.region_code,
        default_locale=client.default_locale,
        property_revision=client.property_revision,
        property_sha256=client.property_sha256,
        rule_group_id=client.rule_group_id,
        rule_group_version=client.rule_group_version,
        publication_sha256=client.publication_sha256,
        bundle_sha256=client.bundle_sha256,
        policy_id=client.policy_id,
        policy_version=client.policy_version,
        policy_sha256=client.policy_sha256,
        expires_at=client.expires_at,
        expected_revision=client.revision,
    )


def test_rights_intake_context_registration_is_exact_idempotent_and_digest_only(
    environment: _Environment,
) -> None:
    client, profile = _rights_intake_pair(environment)
    binding = environment.registry.register_rights_intake_context(
        "rights-context-a",
        client,
        profile,
    )
    environment.clock_state["now"] += 30
    replay = environment.registry.register_rights_intake_context(
        "rights-context-a",
        client,
        profile,
    )

    assert replay == binding
    assert binding.tenant_id == "tenant-a"
    assert binding.client_credential_sha256 == _sha256(_CLIENT_CREDENTIAL)
    assert binding.profile_credential_sha256 == _sha256(_PROFILE_CREDENTIAL)
    assert binding.binding_sha256 == _json_sha256(
        {
            "context_ref": "rights-context-a",
            "tenant_id": "tenant-a",
            "client_credential_sha256": _sha256(_CLIENT_CREDENTIAL),
            "client_revision": client.revision,
            "client_record_sha256": client.record_sha256,
            "profile_credential_sha256": _sha256(_PROFILE_CREDENTIAL),
            "profile_binding_sha256": profile.binding_sha256,
            "created_at": _NOW,
        }
    )
    with sqlite3.connect(environment.registry.path) as connection:
        connection.row_factory = sqlite3.Row
        columns = tuple(
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(public_consent_rights_intake_contexts)"
            )
        )
        rows = connection.execute("SELECT * FROM public_consent_rights_intake_contexts").fetchall()
    assert columns == (
        "context_ref",
        "tenant_id",
        "client_credential_sha256",
        "client_revision",
        "client_record_sha256",
        "profile_credential_sha256",
        "profile_binding_sha256",
        "created_at",
        "binding_sha256",
    )
    assert len(rows) == 1
    assert _CLIENT_CREDENTIAL.encode() not in environment.registry.path.read_bytes()
    assert _PROFILE_CREDENTIAL.encode() not in environment.registry.path.read_bytes()

    with pytest.raises(PublicConsentConflict, match="another authority"):
        environment.registry.register_rights_intake_context(
            "rights-context-rebound",
            client,
            profile,
        )


def test_rights_intake_context_uses_exact_tenant_and_authority_selectors(
    environment: _Environment,
) -> None:
    client, profile = _rights_intake_pair(environment)
    environment.registry.register_rights_intake_context(
        "rights-context-a",
        client,
        profile,
    )
    resolved_client, resolved_profile = environment.registry.resolve_rights_intake_context(
        "tenant-a",
        "rights-context-a",
    )
    assert resolved_client == client
    assert resolved_profile == profile
    with pytest.raises(PublicConsentCredentialError, match="invalid public consent credential"):
        environment.registry.resolve_rights_intake_context(
            "tenant-b",
            "rights-context-a",
        )

    marker = "rights-cross-tenant"
    foreign_profile_credential = _foreign_profile_capability(
        environment,
        tenant_id="tenant-b",
        property_id="web-foreign",
        marker=marker,
    )
    foreign_client = environment.registry.resolve_client(f"foreign-client-{marker}-" + "c" * 32)
    foreign_profile = environment.registry.resolve_profile(
        foreign_profile_credential,
        foreign_client,
    )
    with pytest.raises(PublicConsentConflict, match="another authority"):
        environment.registry.register_rights_intake_context(
            "rights-context-a",
            foreign_client,
            foreign_profile,
        )


@pytest.mark.parametrize("revoked_authority", ["client", "profile"])
def test_rights_intake_context_rechecks_revocation_authority(
    environment: _Environment,
    revoked_authority: str,
) -> None:
    client, profile = _rights_intake_pair(environment)
    environment.registry.register_rights_intake_context(
        "rights-context-a",
        client,
        profile,
    )
    if revoked_authority == "client":
        environment.registry.revoke_client_id(
            client.tenant_id,
            client.credential_id,
            expected_revision=client.revision,
        )
    else:
        environment.registry.revoke_profile(
            profile.tenant_id,
            profile.property_id,
            profile.profile_id,
            actor_sha256=_sha256("privacy owner"),
            evidence_sha256=_sha256("rights context revocation"),
        )

    with pytest.raises(PublicConsentCredentialError, match="invalid public consent credential"):
        environment.registry.resolve_rights_intake_context(
            "tenant-a",
            "rights-context-a",
        )


def test_rights_intake_registration_rejects_a_stale_client_revision(
    environment: _Environment,
) -> None:
    stale_client, profile = _rights_intake_pair(environment)
    current_client = _reenroll_client(environment, stale_client)
    assert current_client.revision == stale_client.revision + 1
    with pytest.raises(PublicConsentConflict, match="pairing authority changed"):
        environment.registry.register_rights_intake_context(
            "rights-context-a",
            stale_client,
            profile,
        )


def test_rights_intake_context_is_invalidated_by_client_revision_change(
    environment: _Environment,
) -> None:
    client, profile = _rights_intake_pair(environment)
    environment.registry.register_rights_intake_context(
        "rights-context-a",
        client,
        profile,
    )
    updated = _reenroll_client(environment, client)
    assert updated.revision == client.revision + 1
    with pytest.raises(PublicConsentCredentialError, match="invalid public consent credential"):
        environment.registry.resolve_rights_intake_context(
            "tenant-a",
            "rights-context-a",
        )


def test_rights_intake_context_schema_two_migrates_exact_authority_pins(
    environment: _Environment,
) -> None:
    client, profile = _rights_intake_pair(environment)
    current = environment.registry.register_rights_intake_context(
        "rights-context-a",
        client,
        profile,
    )
    legacy_body = {
        "context_ref": current.context_ref,
        "tenant_id": current.tenant_id,
        "client_credential_sha256": current.client_credential_sha256,
        "profile_credential_sha256": current.profile_credential_sha256,
        "created_at": current.created_at,
    }
    with sqlite3.connect(environment.registry.path) as connection:
        connection.execute(
            "DROP TRIGGER public_consent_rights_intake_contexts_no_update"
        )
        connection.execute(
            "DROP TRIGGER public_consent_rights_intake_contexts_no_delete"
        )
        connection.execute(
            "ALTER TABLE public_consent_rights_intake_contexts "
            "RENAME TO public_consent_rights_intake_contexts_v3"
        )
        connection.execute(
            "CREATE TABLE public_consent_rights_intake_contexts ("
            "context_ref TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,"
            "client_credential_sha256 TEXT NOT NULL,"
            "profile_credential_sha256 TEXT NOT NULL,created_at REAL NOT NULL,"
            "binding_sha256 TEXT NOT NULL,"
            "UNIQUE (tenant_id,client_credential_sha256,profile_credential_sha256))"
        )
        connection.execute(
            "INSERT INTO public_consent_rights_intake_contexts VALUES(?,?,?,?,?,?)",
            (*legacy_body.values(), _json_sha256(legacy_body)),
        )
        connection.execute("DROP TABLE public_consent_rights_intake_contexts_v3")
        connection.execute(
            "UPDATE public_consent_meta SET value='2' WHERE key='schema_version'"
        )

    migrated = PublicConsentCredentialStore(
        environment.registry.path,
        clock=lambda: environment.clock_state["now"],
    )
    assert migrated.resolve_rights_intake_context("tenant-a", "rights-context-a") == (
        client,
        profile,
    )
    assert migrated.verify_integrity()["rights_intake_contexts"] == 1
    with sqlite3.connect(migrated.path) as connection:
        connection.row_factory = sqlite3.Row
        columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(public_consent_rights_intake_contexts)"
            )
        }
        version = connection.execute(
            "SELECT value FROM public_consent_meta WHERE key='schema_version'"
        ).fetchone()
    assert {
        "client_revision",
        "client_record_sha256",
        "profile_binding_sha256",
    }.issubset(columns)
    assert version is not None and version[0] == "3"


def test_rights_intake_context_is_immutable_and_detects_digest_corruption(
    environment: _Environment,
) -> None:
    client, profile = _rights_intake_pair(environment)
    environment.registry.register_rights_intake_context(
        "rights-context-a",
        client,
        profile,
    )
    with sqlite3.connect(environment.registry.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="bindings are immutable"):
            connection.execute(
                "UPDATE public_consent_rights_intake_contexts SET tenant_id='tenant-b' "
                "WHERE context_ref='rights-context-a'"
            )
        connection.rollback()
        connection.execute("DROP TRIGGER public_consent_rights_intake_contexts_no_update")
        connection.execute(
            "UPDATE public_consent_rights_intake_contexts SET binding_sha256=? "
            "WHERE context_ref='rights-context-a'",
            ("0" * 64,),
        )
        connection.commit()

    with pytest.raises(PublicConsentCredentialError, match="invalid public consent credential"):
        environment.registry.resolve_rights_intake_context(
            "tenant-a",
            "rights-context-a",
        )


@pytest.mark.parametrize("large_history", [False, True])
def test_public_roundtrip_is_digest_bound_idempotent_and_private(
    environment: _Environment, large_history: bool,
) -> None:
    if large_history:
        for version in range(1, 502):
            environment.preferences.publish_policy(
                "tenant-a", "aaa-unrelated", version, {"analytics": "consent"},
                _sha256("unrelated notice"), 1,
                expected_current_version=version - 1,
            )
        assert environment.preferences.list_policies("tenant-a", limit=500)["truncated"]
    configuration_response = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers={**_browser_headers(), "Accept-Language": "en-US"},
    )
    assert configuration_response.status_code == 200, configuration_response.text
    assert configuration_response.headers["cache-control"] == "no-store, private"
    configuration = configuration_response.json()
    assert configuration["allowed"] is True
    assert configuration["property"]["property_id"] == "web-main"
    assert (
        configuration["publication"]["publication_sha256"]
        == (environment.publication["publication_sha256"])
    )
    fallback = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers={**_browser_headers(), "Accept-Language": "fr-FR"},
    )
    assert fallback.status_code == 200
    assert fallback.json()["rule"]["locale"] == "en-US"

    bootstrap = _bootstrap(environment)
    replay = environment.client.post(
        "/api/v1/public/consent/profiles/bootstrap",
        headers=_browser_headers(),
        json=_profile_bootstrap_body(),
    )
    assert replay.status_code == 201
    assert replay.json() == bootstrap
    rebound_bootstrap = environment.client.post(
        "/api/v1/public/consent/profiles/bootstrap",
        headers=_browser_headers(),
        json={
            **_profile_bootstrap_body(),
            "subject_sha256": _sha256("different browser pseudonym"),
        },
    )
    assert rebound_bootstrap.status_code == 409
    assert rebound_bootstrap.json()["detail"] == "preference state changed"
    assert bootstrap["profile_revision"] == 0
    registry_bytes = environment.registry.path.read_bytes()
    assert _CLIENT_CREDENTIAL.encode() not in registry_bytes
    assert _PROFILE_CREDENTIAL.encode() not in registry_bytes

    current = environment.client.get(
        "/api/v1/public/consent/preferences",
        headers=_browser_headers(profile=True),
    )
    assert current.status_code == 200, current.text
    assert current.json()["profile_revision"] == 0
    assert current.json()["preferences"] == [
        {
            "purpose_id": "analytics",
            "granted": False,
            "reason": "no_current_explicit_grant",
            "action": None,
            "receipt_sha256": None,
        }
    ]

    update_body = {
        **_contract_echo(configuration, environment.policy["policy_sha256"]),
        "expected_revision": 0,
        "idempotency_key": "preferences-1",
        "choices": [{"purpose_id": "analytics", "action": "grant"}],
    }
    update = environment.client.put(
        "/api/v1/public/consent/preferences",
        headers=_browser_headers(profile=True),
        json=update_body,
    )
    assert update.status_code == 200, update.text
    assert update.json()["profile_revision"] == 1
    retry = environment.client.put(
        "/api/v1/public/consent/preferences",
        headers=_browser_headers(profile=True),
        json=update_body,
    )
    assert retry.status_code == 200
    assert retry.json()["receipt_sha256"] == update.json()["receipt_sha256"]

    rebound = {
        **update_body,
        "choices": [{"purpose_id": "analytics", "action": "deny"}],
    }
    conflict = environment.client.put(
        "/api/v1/public/consent/preferences",
        headers=_browser_headers(profile=True),
        json=rebound,
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "preference state changed"

    after_grant = environment.client.get(
        "/api/v1/public/consent/preferences",
        headers=_browser_headers(profile=True),
    )
    assert after_grant.json()["preferences"][0]["granted"] is True

    signal_body = {
        **_contract_echo(configuration, environment.policy["policy_sha256"]),
        "signal": "gpc",
        "expected_revision": 1,
        "idempotency_key": "gpc-1",
    }
    signal = environment.client.post(
        "/api/v1/public/consent/privacy-signals",
        headers={**_browser_headers(profile=True), "Sec-GPC": "1"},
        json=signal_body,
    )
    assert signal.status_code == 200, signal.text
    assert signal.json()["profile_revision"] == 2
    after_gpc = environment.client.get(
        "/api/v1/public/consent/preferences",
        headers=_browser_headers(profile=True),
    )
    assert after_gpc.json()["preferences"][0]["granted"] is False
    assert after_gpc.json()["preferences"][0]["reason"] == "explicit_deny"


def test_browser_privacy_signal_skips_non_consent_purposes(tmp_path: Path) -> None:
    environment = _seed_authorities(tmp_path, mixed_lawful_bases=True)
    configuration_response = environment.client.get(
        "/api/v1/public/consent/configuration", headers=_browser_headers()
    )
    assert configuration_response.status_code == 200, configuration_response.text
    configuration = configuration_response.json()
    assert {
        item["id"]: item["lawful_basis"]
        for item in configuration["configuration"]["purposes"]
    } == {"analytics": "consent", "fulfillment": "contract"}
    _bootstrap(environment)
    signal = environment.client.post(
        "/api/v1/public/consent/privacy-signals",
        headers={**_browser_headers(profile=True), "Sec-GPC": "1"},
        json={
            **_contract_echo(configuration, environment.policy["policy_sha256"]),
            "signal": "gpc",
            "expected_revision": 0,
            "idempotency_key": "mixed-purpose-gpc",
        },
    )
    assert signal.status_code == 200, signal.text
    current = environment.client.get(
        "/api/v1/public/consent/preferences", headers=_browser_headers(profile=True)
    )
    assert current.status_code == 200, current.text
    assert current.json()["profile_revision"] == 1
    assert next(
        item for item in current.json()["preferences"] if item["purpose_id"] == "analytics"
    )["reason"] == "explicit_deny"


def test_auth_failures_are_generic_and_authority_cannot_be_client_supplied(
    environment: _Environment,
) -> None:
    cases = [
        {},
        {"Authorization": "ConsentPublic invalid-credential-value"},
        {
            "Authorization": f"ConsentPublic {_CLIENT_CREDENTIAL}",
            "Origin": "https://shop.example.com",
        },
        {"Authorization": f"ConsentPublic {_CLIENT_CREDENTIAL}"},
        {
            **_browser_headers(),
            "X-Lightwork-Tenant": "tenant-b",
        },
        {
            **_browser_headers(),
            "X-Lightwork-Property": "other-property",
        },
    ]
    for headers in cases:
        response = environment.client.get(
            "/api/v1/public/consent/configuration",
            headers=headers,
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid public consent credential"

    query_authority = environment.client.get(
        "/api/v1/public/consent/configuration?tenant_id=tenant-b",
        headers=_browser_headers(),
    )
    assert query_authority.status_code == 401
    assert query_authority.json()["detail"] == "invalid public consent credential"

    bootstrap_body = {**_profile_bootstrap_body(), "tenant_id": "tenant-b"}
    extra_authority = environment.client.post(
        "/api/v1/public/consent/profiles/bootstrap",
        headers=_browser_headers(),
        json=bootstrap_body,
    )
    assert extra_authority.status_code == 422

    _bootstrap(environment)
    wrong_profile = environment.client.get(
        "/api/v1/public/consent/preferences",
        headers={
            **_browser_headers(),
            "X-Lightwork-Profile-Credential": (
                "wrong-profile-capability-dddddddddddddddddddddddddddddddd"
            ),
        },
    )
    assert wrong_profile.status_code == 401
    assert wrong_profile.json()["detail"] == "invalid public consent credential"


def test_public_experiment_assignment_is_sticky_bounded_and_identity_free(
    environment: _Environment,
) -> None:
    _bootstrap(environment)
    _baseline, active = _create_public_experiment(environment)
    assert active["state"] == "active"

    first = _public_assignment(environment)
    second = _public_assignment(environment)
    assert first == second
    assert set(first) == {
        "content_sha256",
        "eligible",
        "experiment_id",
        "is_control",
        "is_holdout",
        "reason",
        "render",
        "variant_id",
    }
    assert first["eligible"] is True
    assert first["reason"] in {"assigned", "holdout"}
    assert first["render"]["layout"] in {"inline", "stacked"}
    assert set(first["render"]) == {"language", "layout", "template"}
    serialized = json.dumps(first, sort_keys=True)
    for secret in (
        _CLIENT_CREDENTIAL,
        _PROFILE_CREDENTIAL,
        _sha256("browser pseudonym"),
        "tenant-a",
        "web-main",
        "profile_id",
        "subject_identity",
        "assignment_receipt_sha256",
    ):
        assert secret not in serialized


def test_public_experiment_falls_back_on_disabled_unapproved_and_legal_signal(
    environment: _Environment,
) -> None:
    _bootstrap(environment)
    environment.experiment_gate_state["enabled"] = False
    disabled = _public_assignment(environment)
    assert disabled["eligible"] is False
    assert disabled["is_control"] is True
    assert disabled["variant_id"] == "published-control"
    assert disabled["reason"] == "experiment_disabled"

    environment.experiment_gate_state["enabled"] = True
    baseline, draft = _create_public_experiment(environment, approve=False)
    assert draft["state"] == "draft"
    unapproved = _public_assignment(environment)
    assert unapproved["eligible"] is False
    assert unapproved["reason"] == "not_active"
    assert unapproved["render"] == baseline["render"]

    approved = environment.experiments.approve(
        "tenant-a",
        draft["definition"]["experiment_id"],
        expected_revision=0,
        approved_by="human:privacy-reviewer",
        idempotency_key="fallback-test-approval",
    )
    environment.experiments.activate(
        "tenant-a",
        draft["definition"]["experiment_id"],
        expected_revision=approved["revision"],
        activated_by="human:release-manager",
        idempotency_key="fallback-test-activation",
    )
    legal = _public_assignment(environment, **{"Sec-GPC": "1"})
    assert legal["eligible"] is False
    assert legal["is_control"] is True
    assert legal["reason"] == "legal_signal_precedence"


def test_public_experiment_rejects_unsafe_variant_catalog(
    environment: _Environment,
) -> None:
    _bootstrap(environment)
    baseline, _active = _create_public_experiment(environment, unsafe=True)
    assignment = _public_assignment(environment)
    assert assignment["eligible"] is False
    assert assignment["is_control"] is True
    assert assignment["reason"] == "unsafe_variant_definition"
    assert assignment["render"] == baseline["render"]


def test_public_experiment_keeps_origin_property_tenant_and_profile_authority_exact(
    environment: _Environment,
) -> None:
    _bootstrap(environment)
    path = "/api/v1/public/consent/experiments/assignment"
    denied_headers = (
        {**_browser_headers(profile=True), "Origin": "https://attacker.example"},
        {**_browser_headers(profile=True), "X-Lightwork-Tenant": "tenant-b"},
        {**_browser_headers(profile=True), "X-Lightwork-Property": "other-property"},
    )
    for headers in denied_headers:
        denied = environment.client.get(path, headers=headers)
        assert denied.status_code == 401
        assert denied.json()["detail"] == "invalid public consent credential"

    foreign_profiles = (
        _foreign_profile_capability(
            environment,
            tenant_id="tenant-b",
            property_id="web-main",
            marker="tenant",
        ),
        _foreign_profile_capability(
            environment,
            tenant_id="tenant-a",
            property_id="other-property",
            marker="property",
        ),
    )
    for profile_credential in foreign_profiles:
        denied = environment.client.get(
            path,
            headers={
                **_browser_headers(),
                "X-Lightwork-Profile-Credential": profile_credential,
            },
        )
        assert denied.status_code == 401
        assert denied.json()["detail"] == "invalid public consent credential"

    query = environment.client.get(
        f"{path}?tenant_id=tenant-b",
        headers=_browser_headers(profile=True),
    )
    assert query.status_code == 401


def test_public_experiment_exposure_and_outcome_are_deduplicated_aggregates(
    environment: _Environment,
) -> None:
    configuration = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    ).json()
    _bootstrap(environment)
    _create_public_experiment(environment)
    assignment = _public_assignment(environment)
    assert assignment["eligible"] is True
    event = _contract_echo(configuration, environment.policy["policy_sha256"])
    first = environment.client.post(
        "/api/v1/public/consent/experiments/exposure",
        headers=_browser_headers(profile=True),
        json={**event, "idempotency_key": "exposure-first"},
    )
    assert first.status_code == 200, first.text
    assert first.json()["recorded"] is True
    assert first.json()["deduplicated"] is False
    second = environment.client.post(
        "/api/v1/public/consent/experiments/exposure",
        headers=_browser_headers(profile=True),
        json={**event, "idempotency_key": "exposure-second"},
    )
    assert second.status_code == 200, second.text
    assert second.json()["recorded"] is True
    assert second.json()["deduplicated"] is True

    outcome = environment.client.post(
        "/api/v1/public/consent/experiments/outcome",
        headers=_browser_headers(profile=True),
        json={**event, "idempotency_key": "outcome-first", "success": True},
    )
    assert outcome.status_code == 200, outcome.text
    assert outcome.json()["recorded"] is True
    replay = environment.client.post(
        "/api/v1/public/consent/experiments/outcome",
        headers=_browser_headers(profile=True),
        json={**event, "idempotency_key": "outcome-second", "success": True},
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["deduplicated"] is True

    rejected_authority = environment.client.post(
        "/api/v1/public/consent/experiments/exposure",
        headers=_browser_headers(profile=True),
        json={
            **event,
            "idempotency_key": "extra-authority",
            "actor": "public-caller",
            "experiment_id": assignment["experiment_id"],
            "profile_context": {"segment": "vip"},
            "tenant_id": "tenant-b",
            "variant_id": assignment["variant_id"],
        },
    )
    assert rejected_authority.status_code == 422
    stored = environment.experiments.path.read_bytes()
    wal_path = Path(str(environment.experiments.path) + "-wal")
    if wal_path.exists():
        stored += wal_path.read_bytes()
    assert _CLIENT_CREDENTIAL.encode() not in stored
    assert _PROFILE_CREDENTIAL.encode() not in stored
    assert _sha256("browser pseudonym").encode() not in stored


def test_public_experiment_preserves_max_exposures_reason(
    environment: _Environment,
) -> None:
    configuration = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    ).json()
    _bootstrap(environment)
    _create_public_experiment(environment, max_exposures=1)
    event = _contract_echo(configuration, environment.policy["policy_sha256"])
    exposure = environment.client.post(
        "/api/v1/public/consent/experiments/exposure",
        headers=_browser_headers(profile=True),
        json={**event, "idempotency_key": "fill-exposure-cap"},
    )
    assert exposure.status_code == 200, exposure.text
    assert exposure.json()["recorded"] is True
    outcome = environment.client.post(
        "/api/v1/public/consent/experiments/outcome",
        headers=_browser_headers(profile=True),
        json={
            **event,
            "idempotency_key": "outcome-after-exposure-cap",
            "success": True,
        },
    )
    assert outcome.status_code == 200, outcome.text
    assert outcome.json()["recorded"] is True

    second_profile = "second-profile-capability-" + "s" * 32
    bootstrap = environment.client.post(
        "/api/v1/public/consent/profiles/bootstrap",
        headers=_browser_headers(),
        json={
            "subject_sha256": _sha256("second browser pseudonym"),
            "profile_credential_sha256": _sha256(second_profile),
            "idempotency_key": "second-profile-bootstrap",
        },
    )
    assert bootstrap.status_code == 201, bootstrap.text
    capped = environment.client.get(
        "/api/v1/public/consent/experiments/assignment",
        headers={
            **_browser_headers(),
            "X-Lightwork-Profile-Credential": second_profile,
        },
    )
    assert capped.status_code == 200, capped.text
    assert capped.json()["eligible"] is False
    assert capped.json()["reason"] == "max_exposures"


def test_service_client_is_explicit_and_cannot_mix_browser_origin(
    environment: _Environment,
) -> None:
    service = environment.registry.enroll_client(
        _SERVICE_CREDENTIAL,
        tenant_id="tenant-a",
        property_id="web-main",
        client_kind="service",
        service_client_id="edge-service",
        target_origin=_ORIGIN,
        jurisdiction="global",
        country_code="US",
        region_code="",
        default_locale="en-US",
        property_revision=environment.property_record["revision"],
        property_sha256=environment.property_record["record_sha256"],
        rule_group_id="production-rules",
        rule_group_version=1,
        publication_sha256=environment.publication["publication_sha256"],
        bundle_sha256=environment.publication["bundle_sha256"],
        policy_id=environment.policy["policy_id"],
        policy_version=environment.policy["version"],
        policy_sha256=environment.policy["policy_sha256"],
        expected_revision=0,
    )
    assert service.client_kind == "service"
    good_headers = {
        "Authorization": f"ConsentPublic {_SERVICE_CREDENTIAL}",
        "X-Lightwork-Consent-Service-Client": "edge-service",
    }
    accepted = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=good_headers,
    )
    assert accepted.status_code == 200, accepted.text
    for headers in (
        {
            **good_headers,
            "X-Lightwork-Consent-Service-Client": "other-service",
        },
        {**good_headers, "Origin": _ORIGIN},
    ):
        denied = environment.client.get(
            "/api/v1/public/consent/configuration",
            headers=headers,
        )
        assert denied.status_code == 401
        assert denied.json()["detail"] == "invalid public consent credential"

    _bootstrap(environment)
    cross_credential = environment.client.get(
        "/api/v1/public/consent/preferences",
        headers={
            **good_headers,
            "X-Lightwork-Profile-Credential": _PROFILE_CREDENTIAL,
        },
    )
    assert cross_credential.status_code == 401

    with pytest.raises(PublicConsentValidationError):
        environment.registry.enroll_client(
            "invalid-hybrid-credential-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            tenant_id="tenant-a",
            property_id="web-main",
            client_kind="service",
            service_client_id="hybrid-service",
            target_origin=_ORIGIN,
            target_platform="ios",
            jurisdiction="global",
            country_code="US",
            region_code="",
            default_locale="en-US",
            property_revision=environment.property_record["revision"],
            property_sha256=environment.property_record["record_sha256"],
            rule_group_id="production-rules",
            rule_group_version=1,
            publication_sha256=environment.publication["publication_sha256"],
            bundle_sha256=environment.publication["bundle_sha256"],
            policy_id=environment.policy["policy_id"],
            policy_version=environment.policy["version"],
            policy_sha256=environment.policy["policy_sha256"],
            expected_revision=0,
        )


def test_publication_property_policy_and_echo_digests_fail_closed(
    environment: _Environment,
) -> None:
    configuration = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    ).json()
    _bootstrap(environment)
    wrong_echo = {
        **_contract_echo(configuration, environment.policy["policy_sha256"]),
        "publication_sha256": "0" * 64,
        "expected_revision": 0,
        "idempotency_key": "wrong-contract",
        "choices": [{"purpose_id": "analytics", "action": "grant"}],
    }
    rejected = environment.client.put(
        "/api/v1/public/consent/preferences",
        headers=_browser_headers(profile=True),
        json=wrong_echo,
    )
    assert rejected.status_code == 409
    assert rejected.json()["detail"] == "consent contract unavailable"

    environment.publishing.publish(
        "tenant-a",
        "web-main",
        "production-rules",
        1,
        expected_property_revision=1,
        expected_publication_revision=1,
        idempotency_key="publication-v2",
    )
    stale_publication = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    )
    assert stale_publication.status_code == 409


def test_property_and_policy_rotation_fail_closed(environment: _Environment) -> None:
    environment.publishing.upsert_property(
        "tenant-a",
        "web-main",
        kind="web",
        consent_group_id="consumer-global",
        web_domains=["example.com"],
        origin_allowlist=[_ORIGIN, "https://shop.example.com"],
        expected_revision=1,
        idempotency_key="property-v2",
    )
    stale_property = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    )
    assert stale_property.status_code == 409

    fresh = _seed_authorities(environment.registry.path.parent.parent / "fresh-policy")
    fresh.preferences.publish_policy(
        "tenant-a",
        "public-consent",
        2,
        {"analytics": "consent"},
        _NOTICE_SHA256,
        _NOW - 10,
        expected_current_version=1,
    )
    stale_policy = fresh.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    )
    assert stale_policy.status_code == 409


def test_rate_body_gate_and_schema_bounds(environment: _Environment) -> None:
    environment.gate_state["enabled"] = False
    disabled = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    )
    assert disabled.status_code == 404
    assert disabled.json()["detail"] == "not found"
    environment.gate_state["enabled"] = True

    environment.limiter_state["blocked"] = True
    limited = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    )
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"
    environment.limiter_state["blocked"] = False

    oversized = environment.client.post(
        "/api/v1/public/consent/profiles/bootstrap",
        headers={
            **_browser_headers(),
            "Content-Length": str(64 * 1024 + 1),
            "Content-Type": "application/json",
        },
        content=b"{}",
    )
    assert oversized.status_code == 413
    invalid_length = environment.client.post(
        "/api/v1/public/consent/profiles/bootstrap",
        headers={
            **_browser_headers(),
            "Content-Length": "not-a-number",
            "Content-Type": "application/json",
        },
        content=b"{}",
    )
    assert invalid_length.status_code == 400


class _FakeTrustCenterStore:
    def __init__(self, *, conflict: bool = False) -> None:
        self.conflict = conflict
        self.export_keys: list[str] = []

    def snapshot(self) -> dict[str, Any]:
        if self.conflict:
            from maverick.consumer_trust_center import TrustCenterConflict

            raise TrustCenterConflict("private source detail")
        return {
            "schema": "lightwork.consumer-trust-center.v1",
            "capabilities": ["consent_history"],
            "sections": {"consent": {"receipts": []}},
            "snapshot_sha256": "a" * 64,
        }

    def export_signed(self, *, idempotency_key: str) -> dict[str, Any]:
        self.export_keys.append(idempotency_key)
        return {
            "payload": {
                "schema": "lightwork.consumer-trust-center-export.v1",
                "snapshot": self.snapshot(),
            },
            "payload_sha256": "b" * 64,
            "signature_sha256": "c" * 64,
        }


class _FakeRightsDeliveryStore:
    def __init__(self, content: bytes, *, denied: bool = False) -> None:
        self.content = content
        self.denied = denied
        self.redeem_calls: list[dict[str, str]] = []
        self.claim_calls: list[str] = []

    def redeem(
        self,
        capability: str,
        *,
        reauthentication_receipt_sha256: str,
        request_context_sha256: str,
    ) -> str:
        if self.denied:
            from maverick.privacy_rights_consumer_delivery import (
                RightsConsumerDeliveryDenied,
            )

            raise RightsConsumerDeliveryDenied
        self.redeem_calls.append(
            {
                "capability": capability,
                "reauthentication_receipt_sha256": (reauthentication_receipt_sha256),
                "request_context_sha256": request_context_sha256,
            }
        )
        return "lwrcg1." + "g" * 43

    def claim_server_grant(self, server_grant: str) -> Any:
        self.claim_calls.append(server_grant)

        @dataclass(frozen=True)
        class Claimed:
            package_sha256: str

        return Claimed(hashlib.sha256(self.content).hexdigest())


def test_public_trust_center_reauthenticates_and_exports_without_selectors(
    environment: _Environment,
) -> None:
    _bootstrap(environment)
    store = _FakeTrustCenterStore()
    resolutions: list[Any] = []
    factory_calls: list[dict[str, Any]] = []

    def factory(**kwargs: Any) -> _FakeTrustCenterStore:
        factory_calls.append(kwargs)
        resolutions.append(kwargs["public_authority_resolver"]())
        resolutions.append(kwargs["public_authority_resolver"]())
        return store

    environment.app.state.consumer_trust_center_gate = lambda: True
    environment.app.state.consumer_trust_center_store_factory = factory
    headers = _browser_headers(profile=True)

    preflight = environment.client.options(
        "/api/v1/public/consent/trust-center",
        headers={
            "Origin": _ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": ("authorization, x-lightwork-profile-credential"),
        },
    )
    assert preflight.status_code == 204
    assert preflight.headers["access-control-allow-origin"] == _ORIGIN

    snapshot = environment.client.get(
        "/api/v1/public/consent/trust-center",
        headers=headers,
    )
    assert snapshot.status_code == 200
    assert snapshot.json()["schema"] == "lightwork.consumer-trust-center.v1"
    assert snapshot.headers["cache-control"] == "no-store, private"
    assert snapshot.headers["pragma"] == "no-cache"
    assert snapshot.headers["access-control-allow-origin"] == _ORIGIN
    assert len(resolutions) == 2
    assert resolutions[0] == resolutions[1]
    assert resolutions[0].binding.tenant_id == "tenant-a"
    assert (
        resolutions[0].profile.profile_id == factory_calls[0]["initial_profile_binding"].profile_id
    )

    exported = environment.client.post(
        "/api/v1/public/consent/trust-center/exports",
        headers=headers,
        json={"idempotency_key": "browser-export-1"},
    )
    assert exported.status_code == 200
    assert set(exported.json()) == {
        "payload",
        "payload_sha256",
        "signature_sha256",
    }
    assert store.export_keys == ["browser-export-1"]

    assert (
        environment.client.get(
            "/api/v1/public/consent/trust-center?tenant_id=tenant-b",
            headers=headers,
        ).status_code
        == 401
    )
    assert (
        environment.client.get(
            "/api/v1/public/consent/trust-center",
            headers=_browser_headers(),
        ).status_code
        == 401
    )
    extra = environment.client.post(
        "/api/v1/public/consent/trust-center/exports",
        headers=headers,
        json={"idempotency_key": "browser-export-2", "tenant_id": "tenant-b"},
    )
    assert extra.status_code == 422

    environment.app.state.consumer_trust_center_store_factory = lambda **_kwargs: (
        _FakeTrustCenterStore(conflict=True)
    )
    conflict = environment.client.get(
        "/api/v1/public/consent/trust-center",
        headers=headers,
    )
    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "trust center state changed"}
    assert "private source detail" not in conflict.text

    environment.app.state.consumer_trust_center_gate = lambda: False
    assert (
        environment.client.get(
            "/api/v1/public/consent/trust-center",
            headers=headers,
        ).status_code
        == 404
    )


def test_public_trust_center_brand_projection_and_asset_are_exactly_bound(
    environment: _Environment,
) -> None:
    from maverick.trust_center_branding import BrandingNotFound

    _bootstrap(environment)
    environment.app.state.consumer_trust_center_gate = lambda: True
    environment.app.state.consumer_trust_center_store_factory = (
        lambda **_kwargs: _FakeTrustCenterStore()
    )
    content = b"bounded-raster-fixture"
    content_sha = hashlib.sha256(content).hexdigest()
    projection = SimpleNamespace(
        projection_id="brand-projection-public",
        projection_revision=2,
        publication_sha256=environment.binding.publication_sha256,
        public_origin=_ORIGIN,
        public_host="www.example.com",
        asset_kind="logo",
        asset_media_type="image/png",
        asset_width=320,
        asset_height=80,
        asset_content_sha256=content_sha,
        domain_claim_id="brand-domain",
        domain_claim_version=1,
        domain_authority_sha256="d" * 64,
        domain_deployment_sha256="e" * 64,
    )

    class BrandStore:
        def resolve_projection(self, exact):
            assert exact.tenant_id == "tenant-a"
            assert exact.client_credential_id == environment.binding.credential_id
            assert exact.client_record_sha256 == environment.binding.record_sha256
            assert exact.public_origin == _ORIGIN
            return projection

        def read_public_asset(self, exact, projection_id, requested_sha):
            self.resolve_projection(exact)
            if projection_id != projection.projection_id or requested_sha != content_sha:
                raise BrandingNotFound("branding_asset_unavailable")
            return SimpleNamespace(projection=projection, content=content)

    environment.app.state.trust_center_branding_gate = lambda: True
    environment.app.state.trust_center_branding_store_factory = (
        lambda **_kwargs: BrandStore()
    )
    headers = _browser_headers(profile=True)
    snapshot = environment.client.get(
        "/api/v1/public/consent/trust-center",
        headers=headers,
    )
    assert snapshot.status_code == 200
    brand = snapshot.json()["brand"]
    assert brand["available"] is True
    assert brand["public_host"] == "www.example.com"
    assert brand["host_header_tenant_inference"] is False
    assert brand["asset"]["url"].endswith(
        f"/{projection.projection_id}/{content_sha}"
    )

    asset = environment.client.get(brand["asset"]["url"], headers=headers)
    assert asset.status_code == 200
    assert asset.content == content
    assert asset.headers["content-type"] == "image/png"
    assert asset.headers["x-content-type-options"] == "nosniff"
    assert asset.headers["cache-control"] == "private, max-age=0, must-revalidate"
    assert asset.headers["x-lightwork-publication-sha256"] == (
        environment.binding.publication_sha256
    )

    wrong = environment.client.get(
        f"/api/v1/public/consent/trust-center/brand-assets/"
        f"{projection.projection_id}/{'f' * 64}",
        headers=headers,
    )
    assert wrong.status_code == 404


def test_public_rights_delivery_claims_server_grant_and_returns_only_bound_bytes(
    environment: _Environment,
) -> None:
    _bootstrap(environment)
    content = b"encrypted governed response package"
    store = _FakeRightsDeliveryStore(content)
    reauth_resolutions: list[Any] = []
    adapter_claims: list[Any] = []

    def reauthentication_resolver(**kwargs: Any) -> str:
        assert kwargs["raw_receipt"] == "reauth-receipt-" + "r" * 32
        reauth_resolutions.append(kwargs["public_authority_resolver"]())
        reauth_resolutions.append(kwargs["public_authority_resolver"]())
        return "e" * 64

    def package_adapter(**kwargs: Any) -> PublicRightsPackageDownload:
        adapter_claims.append(kwargs["claimed_grant"])
        return PublicRightsPackageDownload(
            content=content,
            package_sha256=kwargs["claimed_grant"].package_sha256,
        )

    environment.app.state.rights_consumer_delivery_gate = lambda: True
    environment.app.state.rights_consumer_delivery_store_factory = lambda **_kwargs: store
    environment.app.state.rights_reauthentication_resolver = reauthentication_resolver
    environment.app.state.rights_package_delivery_adapter = package_adapter
    headers = {
        **_browser_headers(profile=True),
        "X-Lightwork-Reauthentication-Receipt": ("reauth-receipt-" + "r" * 32),
    }
    capability = "lwrcd1." + "c" * 43

    preflight = environment.client.options(
        "/api/v1/public/consent/rights-deliveries/redeem",
        headers={
            "Origin": _ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "authorization, content-type, x-lightwork-profile-credential, "
                "x-lightwork-reauthentication-receipt"
            ),
        },
    )
    assert preflight.status_code == 204

    delivered = environment.client.post(
        "/api/v1/public/consent/rights-deliveries/redeem",
        headers=headers,
        json={"capability": capability},
    )
    assert delivered.status_code == 200
    assert delivered.content == content
    assert delivered.headers["content-type"] == "application/octet-stream"
    assert delivered.headers["cache-control"] == "no-store, private"
    assert delivered.headers["access-control-allow-origin"] == _ORIGIN
    assert delivered.headers["content-disposition"] == (
        'attachment; filename="lightwork-rights-response.bin"'
    )
    assert store.redeem_calls == [
        {
            "capability": capability,
            "reauthentication_receipt_sha256": "e" * 64,
            "request_context_sha256": store.redeem_calls[0]["request_context_sha256"],
        }
    ]
    assert len(store.redeem_calls[0]["request_context_sha256"]) == 64
    assert store.claim_calls == ["lwrcg1." + "g" * 43]
    assert len(adapter_claims) == 1
    assert len(reauth_resolutions) == 2
    assert "lwrcg1" not in delivered.text

    extra = environment.client.post(
        "/api/v1/public/consent/rights-deliveries/redeem",
        headers=headers,
        json={"capability": capability, "case_id": "case-attacker"},
    )
    assert extra.status_code == 422
    missing_reauth = environment.client.post(
        "/api/v1/public/consent/rights-deliveries/redeem",
        headers=_browser_headers(profile=True),
        json={"capability": capability},
    )
    assert missing_reauth.status_code == 401

    denied_store = _FakeRightsDeliveryStore(content, denied=True)
    environment.app.state.rights_consumer_delivery_store_factory = lambda **_kwargs: denied_store
    denied = environment.client.post(
        "/api/v1/public/consent/rights-deliveries/redeem",
        headers=headers,
        json={"capability": capability},
    )
    assert denied.status_code == 404
    assert denied.json() == {"detail": "delivery unavailable"}


def test_only_narrow_public_routes_are_exposed(environment: _Environment) -> None:
    paths = set(environment.app.openapi()["paths"])
    assert paths == {
        "/api/v1/public/consent/configuration",
        "/api/v1/public/consent/experiments/assignment",
        "/api/v1/public/consent/experiments/exposure",
        "/api/v1/public/consent/experiments/outcome",
        "/api/v1/public/consent/global-opt-out/configuration",
        "/api/v1/public/consent/global-opt-out/requests",
        "/api/v1/public/consent/preferences",
        "/api/v1/public/consent/profile-data",
        "/api/v1/public/consent/profile-data/export",
        "/api/v1/public/consent/profile-data/preferences/{preference_id}",
        "/api/v1/public/consent/profile-data/preferences/{preference_id}/history",
        "/api/v1/public/consent/profile-data/preferences/{preference_id}/revoke",
        "/api/v1/public/consent/profile-data/preferences/{preference_id}/unset",
        "/api/v1/public/consent/profile-data/prompt",
            "/api/v1/public/consent/profile-data/prompt/interactions",
            "/api/v1/public/consent/rights-deliveries/redeem",
            "/api/v1/public/consent/rights-requests",
            "/api/v1/public/consent/rights-requests/{case_id}",
            "/api/v1/public/consent/privacy-signals",
        "/api/v1/public/consent/profiles/bootstrap",
        "/api/v1/public/consent/sdk.js",
        "/api/v1/public/consent/sessions",
        "/api/v1/public/consent/sessions/renew",
        "/api/v1/public/consent/trust-center",
        "/api/v1/public/consent/trust-center/brand-assets/{projection_id}/{content_sha256}",
        "/api/v1/public/consent/trust-center/exports",
        "/api/v1/public/consent/{resource_path}",
    }
    assert set(environment.app.openapi()["paths"]["/api/v1/public/consent/{resource_path}"]) == {
        "options"
    }
    serialized = str(environment.app.openapi()).lower()
    assert "/profile-data/export" in serialized
    assert "profiles/{" not in serialized
    assert "tenant_id" not in serialized
    assert "property_id" not in serialized


def test_sdk_is_inert_versioned_source_and_gate_controlled(
    environment: _Environment,
) -> None:
    response = environment.client.get("/api/v1/public/consent/sdk.js")
    assert response.status_code == 200
    assert "LightworkConsent" in response.text
    assert "innerHTML" not in response.text
    assert "installAutoBlocker" in response.text
    assert "updateGoogleConsentMode" in response.text
    assert "getProfileData" in response.text
    assert "getProfileValueHistory" in response.text
    assert "exportProfileData" in response.text
    assert "setProfileValue" in response.text
    assert "unsetProfileValue" in response.text
    assert "revokeProfileValue" in response.text
    assert "getTrustCenter" in response.text
    assert "exportTrustCenter" in response.text
    assert "renderTrustCenter" in response.text
    assert "redeemRightsPackage" in response.text
    assert "downloadRightsPackage" in response.text
    assert "getProgressivePrompt" in response.text
    assert "renderProgressivePrompt" in response.text
    assert "beginIdentityPairing" in response.text
    assert "authorizeIdentityPairing" in response.text
    assert "redeemIdentityPairing" in response.text
    assert "revokeIdentityPairing" in response.text
    assert '"/profile-data/prompt"' in response.text
    assert '"/profile-data/prompt/interactions"' in response.text
    assert '"/experiments/assignment"' in response.text
    assert '"/experiments/exposure"' in response.text
    assert '"/experiments/outcome"' in response.text
    assert "certifiedExperimentRender" in response.text
    assert "data-lightwork-purpose" in response.text
    assert "outerHTML" not in response.text
    assert "document.write" not in response.text
    assert "insertAdjacentHTML" not in response.text
    assert "eval(" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    environment.gate_state["enabled"] = False
    assert environment.client.get("/api/v1/public/consent/sdk.js").status_code == 404


def _profile_journey_id(environment: _Environment) -> str:
    configuration = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    )
    assert configuration.status_code == 200, configuration.text
    body = configuration.json()
    _, journey_id = public_profile_data_ids(
        tenant_id="tenant-a",
        property_id="web-main",
        publication_sha256=body["publication"]["publication_sha256"],
        bundle_sha256=body["publication"]["bundle_sha256"],
        configuration_sha256=body["configuration_sha256"],
        policy_id=body["policy_id"],
        policy_version=body["policy_version"],
        policy_sha256=body["policy_sha256"],
    )
    return journey_id


def test_public_profile_roundtrip_prompt_receipts_and_no_authority_leak(
    environment: _Environment,
) -> None:
    _bootstrap(environment)
    headers = _browser_headers(profile=True)
    empty = environment.client.get(
        "/api/v1/public/consent/profile-data",
        headers=headers,
    )
    assert empty.status_code == 200, empty.text
    assert empty.json()["current"] == []
    assert empty.json()["active_values"] == {}
    assert "tenant" not in empty.text.lower()
    assert "profile_id" not in empty.text
    assert "capability" not in empty.text.lower()

    prompt = environment.client.get(
        "/api/v1/public/consent/profile-data/prompt",
        headers=headers,
    )
    assert prompt.status_code == 200, prompt.text
    assignment = prompt.json()
    assert assignment["eligible"] is True
    assert [item["preference_id"] for item in assignment["prompts"]] == [
        "required-bool",
        "locale",
    ]
    assert assignment["prompts"][0]["required"] is True
    assert set(assignment) == {
        "assignment_id",
        "assigned_at",
        "eligible",
        "prompts",
        "reason",
    }
    assert "journey_id" not in prompt.text
    assert "catalog_id" not in prompt.text

    terminal = {
        "assignment_id": assignment["assignment_id"],
        "outcome": "completed",
        "idempotency_key": "prompt-completed-1",
    }
    before_insert = environment.client.post(
        "/api/v1/public/consent/profile-data/prompt/interactions",
        headers=headers,
        json=terminal,
    )
    assert before_insert.status_code == 409
    inserted = environment.client.post(
        "/api/v1/public/consent/profile-data/prompt/interactions",
        headers=headers,
        json={
            "assignment_id": assignment["assignment_id"],
            "outcome": "inserted",
            "idempotency_key": "prompt-inserted-1",
        },
    )
    assert inserted.status_code == 200, inserted.text
    replay = environment.client.post(
        "/api/v1/public/consent/profile-data/prompt/interactions",
        headers=headers,
        json={
            "assignment_id": assignment["assignment_id"],
            "outcome": "inserted",
            "idempotency_key": "prompt-inserted-1",
        },
    )
    assert replay.status_code == 200
    incomplete = environment.client.post(
        "/api/v1/public/consent/profile-data/prompt/interactions",
        headers=headers,
        json=terminal,
    )
    assert incomplete.status_code == 409

    rejected_pii = environment.client.put(
        "/api/v1/public/consent/profile-data/preferences/locale",
        headers=headers,
        json={
            "value": "person@example.com",
            "expected_revision": 0,
            "idempotency_key": "profile-value-pii",
        },
    )
    assert rejected_pii.status_code == 422
    required = environment.client.put(
        "/api/v1/public/consent/profile-data/preferences/required-bool",
        headers=headers,
        json={
            "value": False,
            "expected_revision": 0,
            "idempotency_key": "profile-required-v1",
        },
    )
    assert required.status_code == 200, required.text
    assert required.json()["value"] is False
    assert required.json()["revision"] == 1
    assert (
        environment.client.put(
            "/api/v1/public/consent/profile-data/preferences/required-bool",
            headers=headers,
            json={
                "value": False,
                "expected_revision": 0,
                "idempotency_key": "profile-required-v1",
            },
        ).json()
        == required.json()
    )
    stale = environment.client.put(
        "/api/v1/public/consent/profile-data/preferences/required-bool",
        headers=headers,
        json={
            "value": True,
            "expected_revision": 0,
            "idempotency_key": "profile-required-stale",
        },
    )
    assert stale.status_code == 409
    locale = environment.client.put(
        "/api/v1/public/consent/profile-data/preferences/locale",
        headers=headers,
        json={
            "value": "eu",
            "expected_revision": 0,
            "idempotency_key": "profile-locale-v1",
        },
    )
    assert locale.status_code == 200, locale.text
    completed = environment.client.post(
        "/api/v1/public/consent/profile-data/prompt/interactions",
        headers=headers,
        json=terminal,
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["outcome"] == "completed"

    channels = environment.client.put(
        "/api/v1/public/consent/profile-data/preferences/channels",
        headers=headers,
        json={
            "value": ["sms", "email"],
            "expected_revision": 0,
            "idempotency_key": "profile-channels-v1",
        },
    )
    assert channels.status_code == 200, channels.text
    assert channels.json()["value"] == ["email", "sms"]
    unset = environment.client.post(
        "/api/v1/public/consent/profile-data/preferences/channels/unset",
        headers=headers,
        json={
            "expected_revision": 1,
            "idempotency_key": "profile-channels-unset",
        },
    )
    assert unset.status_code == 200, unset.text
    assert unset.json()["status"] == "unset"
    reset = environment.client.put(
        "/api/v1/public/consent/profile-data/preferences/channels",
        headers=headers,
        json={
            "value": ["email"],
            "expected_revision": 2,
            "idempotency_key": "profile-channels-v2",
        },
    )
    assert reset.status_code == 200, reset.text
    revoked = environment.client.post(
        "/api/v1/public/consent/profile-data/preferences/channels/revoke",
        headers=headers,
        json={
            "expected_revision": 3,
            "idempotency_key": "profile-channels-revoke",
        },
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"

    history = environment.client.get(
        "/api/v1/public/consent/profile-data/preferences/channels/history",
        headers=headers,
    )
    assert history.status_code == 200, history.text
    assert [item["action"] for item in history.json()["history"]] == [
        "set",
        "unset",
        "set",
        "revoked",
    ]
    view = environment.client.get(
        "/api/v1/public/consent/profile-data",
        headers=headers,
    )
    assert view.status_code == 200, view.text
    assert view.json()["active_values"] == {"locale": "eu", "required-bool": False}
    assert {item["event_type"] for item in view.json()["prompt_interactions"]} >= {
        "exposure",
        "completed",
    }
    exported = environment.client.get(
        "/api/v1/public/consent/profile-data/export",
        headers=headers,
    )
    assert exported.status_code == 200, exported.text
    assert exported.json()["schema"] == "lightwork.public-consent-profile-data-export.v1"
    assert "tenant_id" not in exported.text
    assert "profile_id" not in exported.text
    assert _PROFILE_CREDENTIAL not in exported.text
    assert _sha256(_PROFILE_CREDENTIAL) not in exported.text

    database = environment.profile_data.path.read_bytes()
    assert _PROFILE_CREDENTIAL.encode() not in database
    assert _sha256(_PROFILE_CREDENTIAL).encode() not in database
    assert b"person@example.com" not in database


def test_profile_data_gate_selectors_and_catalog_binding_fail_closed(
    environment: _Environment,
) -> None:
    _bootstrap(environment)
    headers = _browser_headers(profile=True)
    environment.profile_data_gate_state["enabled"] = False
    assert (
        environment.client.get(
            "/api/v1/public/consent/profile-data",
            headers=headers,
        ).status_code
        == 404
    )
    environment.profile_data_gate_state["enabled"] = True

    selector_attack = environment.client.put(
        "/api/v1/public/consent/profile-data/preferences/locale",
        headers=headers,
        json={
            "value": "eu",
            "expected_revision": 0,
            "idempotency_key": "selector-attack-1",
            "tenant_id": "tenant-other",
            "profile_id": "profile-other",
            "property_id": "web-other",
            "catalog_id": "catalog-other",
            "journey_id": "journey-other",
            "profile_capability_sha256": "a" * 64,
        },
    )
    assert selector_attack.status_code == 422

    configuration = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    ).json()
    catalog_id, _ = public_profile_data_ids(
        tenant_id="tenant-a",
        property_id="web-main",
        publication_sha256=configuration["publication"]["publication_sha256"],
        bundle_sha256=configuration["publication"]["bundle_sha256"],
        configuration_sha256=configuration["configuration_sha256"],
        policy_id=configuration["policy_id"],
        policy_version=configuration["policy_version"],
        policy_sha256=configuration["policy_sha256"],
    )
    with sqlite3.connect(environment.profile_data.path) as connection:
        payload_text = connection.execute(
            "SELECT payload_json FROM catalogs WHERE tenant_id=? AND catalog_id=? AND version=1",
            ("tenant-a", catalog_id),
        ).fetchone()[0]
        payload = json.loads(payload_text)
        payload["definitions"][0]["label_ref"] = "different-published-label"
        canonical = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        connection.execute(
            "UPDATE catalogs SET payload_json=?,integrity_sha256=? "
            "WHERE tenant_id=? AND catalog_id=? AND version=1",
            (canonical, _json_sha256(payload), "tenant-a", catalog_id),
        )
    changed = environment.client.get(
        "/api/v1/public/consent/profile-data",
        headers=headers,
    )
    assert changed.status_code == 409
    assert "catalog differs" in changed.json()["detail"]


def test_profile_prompt_cooldown_and_frequency_cap(environment: _Environment) -> None:
    _bootstrap(environment)
    headers = _browser_headers(profile=True)
    first = environment.client.get(
        "/api/v1/public/consent/profile-data/prompt",
        headers=headers,
    )
    assert first.status_code == 200, first.text
    assert first.json()["eligible"] is True
    cooldown = environment.client.get(
        "/api/v1/public/consent/profile-data/prompt",
        headers=headers,
    )
    assert cooldown.status_code == 200, cooldown.text
    assert cooldown.json()["eligible"] is False
    assert cooldown.json()["reason"] == "cooldown"
    for exposure in (2, 3):
        environment.clock_state["now"] += 61
        response = environment.client.get(
            "/api/v1/public/consent/profile-data/prompt",
            headers=headers,
        )
        assert response.status_code == 200, response.text
        assert response.json()["eligible"] is True, exposure
    environment.clock_state["now"] += 61
    capped = environment.client.get(
        "/api/v1/public/consent/profile-data/prompt",
        headers=headers,
    )
    assert capped.status_code == 200, capped.text
    assert capped.json()["eligible"] is False
    assert capped.json()["reason"] == "frequency_cap"


@pytest.mark.parametrize("transition", ["kill", "rollback"])
def test_profile_prompt_terminal_lifecycle_fails_to_no_prompt(
    environment: _Environment,
    transition: str,
) -> None:
    _bootstrap(environment)
    journey_id = _profile_journey_id(environment)
    function = getattr(environment.profile_data, f"{transition}_journey")
    function(
        "tenant-a",
        journey_id,
        1,
        expected_revision=3,
        idempotency_key=f"public-journey-{transition}",
    )
    response = environment.client.get(
        "/api/v1/public/consent/profile-data/prompt",
        headers=_browser_headers(profile=True),
    )
    assert response.status_code == 200, response.text
    assert response.json()["eligible"] is False
    assert response.json()["reason"] == "not_active"
    assert response.json()["assignment_id"] is None
    assert response.json()["prompts"] == []


def test_foreign_or_revoked_profile_capability_cannot_read_profile_data(
    environment: _Environment,
) -> None:
    _bootstrap(environment)
    foreign = _foreign_profile_capability(
        environment,
        tenant_id="tenant-other",
        property_id="web-other",
        marker="profile-data-cross-scope",
    )
    rejected = environment.client.get(
        "/api/v1/public/consent/profile-data",
        headers={**_browser_headers(), "X-Lightwork-Profile-Credential": foreign},
    )
    assert rejected.status_code == 401
    profile = environment.registry.resolve_profile(_PROFILE_CREDENTIAL, environment.binding)
    environment.registry.revoke_profile(
        "tenant-a",
        "web-main",
        profile.profile_id,
        actor_sha256=_sha256("privacy owner"),
        evidence_sha256=_sha256("profile-data revocation ticket"),
    )
    revoked = environment.client.get(
        "/api/v1/public/consent/profile-data",
        headers=_browser_headers(profile=True),
    )
    assert revoked.status_code == 401


def test_default_gate_requires_all_three_explicit_sections(monkeypatch) -> None:
    from maverick import config

    enabled = {
        "consent_preferences": {
            "enable": True,
            "publishing": {"enable": True},
            "public_api": {"enable": True},
        },
    }
    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(config, "load_config", lambda: enabled)
    assert default_public_consent_gate() is True
    disabled_paths = (
        ("enable",),
        ("publishing", "enable"),
        ("public_api", "enable"),
    )
    for path in disabled_paths:
        consent = {
            "enable": True,
            "publishing": {"enable": True},
            "public_api": {"enable": True},
        }
        target = consent
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = False
        monkeypatch.setattr(
            config,
            "load_config",
            lambda value={"consent_preferences": consent}: value,
        )
        assert default_public_consent_gate() is False
    monkeypatch.setattr(config, "config_source_errors", lambda: ["invalid"])
    assert default_public_consent_gate() is False


def test_default_public_experiment_gate_requires_exact_nested_boolean(
    monkeypatch,
) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "experiments": {"enable": True},
            }
        },
    )
    assert default_public_experiment_gate() is True
    for value in (False, 1, "true", None):
        monkeypatch.setattr(
            config,
            "load_config",
            lambda selected=value: {
                "consent_preferences": {
                    "enable": True,
                    "experiments": {"enable": selected},
                }
            },
        )
        assert default_public_experiment_gate() is False
    monkeypatch.setattr(config, "config_source_errors", lambda: ["invalid"])
    assert default_public_experiment_gate() is False


def test_default_public_profile_data_gate_requires_exact_nested_boolean(
    monkeypatch,
) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "profile_data": {"enable": True},
            }
        },
    )
    assert default_public_profile_data_gate() is True
    for parent, nested in (
        (False, True),
        (True, False),
        (True, 1),
        (True, "true"),
        (True, None),
    ):
        monkeypatch.setattr(
            config,
            "load_config",
            lambda root=parent, selected=nested: {
                "consent_preferences": {
                    "enable": root,
                    "profile_data": {"enable": selected},
                }
            },
        )
        assert default_public_profile_data_gate() is False
    monkeypatch.setattr(config, "config_source_errors", lambda: ["invalid"])
    assert default_public_profile_data_gate() is False


def test_default_dependencies_share_authoritative_store_paths(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from maverick import config, paths

    calls: list[tuple[str, str, str | None]] = []

    def isolated_data_dir(
        section: str,
        filename: str,
        *,
        tenant: str | None,
    ) -> Path:
        calls.append((section, filename, tenant))
        scope = tenant or "global"
        return tmp_path / section / scope / filename

    monkeypatch.setattr(paths, "data_dir", isolated_data_dir)
    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "experiments": {"enable": True},
            }
        },
    )
    monkeypatch.setenv("MAVERICK_CONSENT_EXPERIMENT_KEY", "ab" * 32)
    dependencies = default_public_consent_dependencies()
    dependencies.publishing_store_for("tenant-a")
    dependencies.preference_store_for("tenant-a")
    assert dependencies.experiment_gate is default_public_experiment_gate
    assert dependencies.experiment_authority_for is None
    experiment_authority = consent_public_api._default_public_experiment_authority_for("tenant-a")
    assert isinstance(experiment_authority, ConsentExperimentAuthority)
    assert experiment_authority.path == (
        tmp_path / "consent_preferences" / "tenant-a" / "consent-experiments.sqlite3"
    )
    with pytest.raises(ConsentExperimentNotFound):
        experiment_authority.get_experiment("tenant-a", "missing")

    assert calls == [
        (
            "consent_public_api",
            "public-consent-credentials.sqlite3",
            None,
        ),
        (
            "consent_preferences",
            "consent-publishing.sqlite3",
            "tenant-a",
        ),
        (
            "consent_preferences",
            "consent-preferences.sqlite3",
            "tenant-a",
        ),
        (
            "consent_preferences",
            "consent-experiments.sqlite3",
            "tenant-a",
        ),
    ]


def test_default_profile_data_dependencies_use_tenant_scoped_stores(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from maverick import config, paths

    calls: list[tuple[str, str, str | None]] = []

    def isolated_data_dir(
        section: str,
        filename: str,
        *,
        tenant: str | None,
    ) -> Path:
        calls.append((section, filename, tenant))
        return tmp_path / section / (tenant or "global") / filename

    monkeypatch.setattr(paths, "data_dir", isolated_data_dir)
    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "profile_data": {"enable": True},
            }
        },
    )
    dependencies = default_public_consent_dependencies()
    assert dependencies.profile_data_gate is default_public_profile_data_gate
    assert dependencies.profile_data_store_for is None
    assert dependencies.profile_assignment_store_for is None
    profile_store = consent_public_api._default_public_profile_data_store_for("tenant-a")
    assignment_store = consent_public_api._default_public_profile_assignment_store_for(
        "tenant-a",
        key_authority=_ProfileDataKeys(),
    )
    assert profile_store.path == (
        tmp_path / "consent_preferences" / "tenant-a" / "consent-profile-data.sqlite3"
    )
    assert assignment_store.path == (
        tmp_path / "consent_preferences" / "tenant-a" / "consent-profile-data-assignments.sqlite3"
    )
    assert calls == [
        ("consent_public_api", "public-consent-credentials.sqlite3", None),
        ("consent_preferences", "consent-profile-data.sqlite3", "tenant-a"),
        (
            "consent_preferences",
            "consent-profile-data-assignments.sqlite3",
            "tenant-a",
        ),
    ]


def test_default_experiment_authority_remains_fail_control_when_config_off(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from maverick import config, paths

    monkeypatch.setattr(
        paths,
        "data_dir",
        lambda section, filename, *, tenant: tmp_path / section / (tenant or "global") / filename,
    )
    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "experiments": {"enable": False},
            }
        },
    )
    monkeypatch.setenv("MAVERICK_CONSENT_EXPERIMENT_KEY", "cd" * 32)
    dependencies = default_public_consent_dependencies()
    assert dependencies.experiment_gate is not None
    assert dependencies.experiment_gate() is False
    authority = consent_public_api._default_public_experiment_authority_for("tenant-a")
    with pytest.raises(ConsentExperimentConfigError):
        authority.get_experiment("tenant-a", "missing")


def test_production_default_preserves_app_state_experiment_factory_precedence(
    environment: _Environment,
    monkeypatch,
) -> None:
    _bootstrap(environment)
    _create_public_experiment(environment)
    factory_calls: list[tuple[str, Any]] = []
    dependencies = PublicConsentDependencies(
        credential_store=environment.registry,
        publishing_store_for=lambda _tenant: environment.publishing,
        preference_store_for=lambda _tenant: environment.preferences,
        gate=lambda: True,
        rate_limit=lambda _credential, _action: None,
        context_resolver=default_public_request_context,
        clock=lambda: _NOW,
        experiment_gate=lambda: True,
    )
    monkeypatch.setattr(
        consent_public_api,
        "default_public_consent_dependencies",
        lambda: dependencies,
    )

    def forbidden_fallback(_tenant_id: str, *, key_authority=None):
        raise AssertionError("production fallback bypassed app-state authority")

    monkeypatch.setattr(
        consent_public_api,
        "_default_public_experiment_authority_for",
        forbidden_fallback,
    )
    app = FastAPI()

    def state_factory(*, tenant_id: str, request):
        factory_calls.append((tenant_id, request.app))
        return environment.experiments

    app.state.consent_experiment_authority_factory = state_factory
    app.include_router(create_consent_public_router())
    client = TestClient(app, base_url="https://consent.lightwork.test")
    response = client.get(
        "/api/v1/public/consent/experiments/assignment",
        headers=_browser_headers(profile=True),
    )
    assert response.status_code == 200, response.text
    assert response.json()["reason"] in {"assigned", "holdout"}
    assert factory_calls == [("tenant-a", app)]


def test_production_default_passes_app_state_experiment_key_authority(
    environment: _Environment,
    monkeypatch,
) -> None:
    _bootstrap(environment)
    _create_public_experiment(environment)
    dependencies = PublicConsentDependencies(
        credential_store=environment.registry,
        publishing_store_for=lambda _tenant: environment.publishing,
        preference_store_for=lambda _tenant: environment.preferences,
        gate=lambda: True,
        rate_limit=lambda _credential, _action: None,
        context_resolver=default_public_request_context,
        clock=lambda: _NOW,
        experiment_gate=lambda: True,
    )
    monkeypatch.setattr(
        consent_public_api,
        "default_public_consent_dependencies",
        lambda: dependencies,
    )
    injected_keys = _ExperimentKeys()
    fallback_calls: list[tuple[str, Any]] = []

    def fallback(tenant_id: str, *, key_authority=None):
        fallback_calls.append((tenant_id, key_authority))
        return environment.experiments

    monkeypatch.setattr(
        consent_public_api,
        "_default_public_experiment_authority_for",
        fallback,
    )
    app = FastAPI()
    app.state.consent_experiment_key_authority = injected_keys
    app.include_router(create_consent_public_router())
    client = TestClient(app, base_url="https://consent.lightwork.test")
    response = client.get(
        "/api/v1/public/consent/experiments/assignment",
        headers=_browser_headers(profile=True),
    )
    assert response.status_code == 200, response.text
    assert response.json()["reason"] in {"assigned", "holdout"}
    assert fallback_calls == [("tenant-a", injected_keys)]


def test_production_default_preserves_app_state_profile_factory_precedence(
    environment: _Environment,
    monkeypatch,
) -> None:
    _bootstrap(environment)
    dependencies = PublicConsentDependencies(
        credential_store=environment.registry,
        publishing_store_for=lambda _tenant: environment.publishing,
        preference_store_for=lambda _tenant: environment.preferences,
        gate=lambda: True,
        rate_limit=lambda _credential, _action: None,
        context_resolver=default_public_request_context,
        clock=lambda: environment.clock_state["now"],
        profile_data_gate=lambda: True,
    )
    monkeypatch.setattr(
        consent_public_api,
        "default_public_consent_dependencies",
        lambda: dependencies,
    )
    calls: list[tuple[str, str, Any]] = []
    app = FastAPI()

    def profile_factory(*, tenant_id: str, request):
        calls.append(("profile", tenant_id, request.app))
        return environment.profile_data

    def assignment_factory(*, tenant_id: str, request):
        calls.append(("assignment", tenant_id, request.app))
        return environment.profile_assignments

    app.state.consent_profile_data_store_factory = profile_factory
    app.state.consent_profile_assignment_store_factory = assignment_factory
    app.include_router(create_consent_public_router())
    client = TestClient(app, base_url="https://consent.lightwork.test")
    response = client.get(
        "/api/v1/public/consent/profile-data/prompt",
        headers=_browser_headers(profile=True),
    )
    assert response.status_code == 200, response.text
    assert response.json()["eligible"] is True
    assert calls == [
        ("profile", "tenant-a", app),
        ("assignment", "tenant-a", app),
    ]


def test_production_default_passes_app_state_profile_data_key_authority(
    environment: _Environment,
    monkeypatch,
) -> None:
    _bootstrap(environment)
    dependencies = PublicConsentDependencies(
        credential_store=environment.registry,
        publishing_store_for=lambda _tenant: environment.publishing,
        preference_store_for=lambda _tenant: environment.preferences,
        gate=lambda: True,
        rate_limit=lambda _credential, _action: None,
        context_resolver=default_public_request_context,
        clock=lambda: environment.clock_state["now"],
        profile_data_gate=lambda: True,
    )
    monkeypatch.setattr(
        consent_public_api,
        "default_public_consent_dependencies",
        lambda: dependencies,
    )
    injected_keys = _ProfileDataKeys()
    fallback_calls: list[tuple[str, Any]] = []

    def assignment_fallback(tenant_id: str, *, key_authority=None):
        fallback_calls.append((tenant_id, key_authority))
        return environment.profile_assignments

    monkeypatch.setattr(
        consent_public_api,
        "_default_public_profile_assignment_store_for",
        assignment_fallback,
    )
    app = FastAPI()
    app.state.consent_profile_data_store_factory = lambda *, tenant_id, request: (
        environment.profile_data
    )
    app.state.consent_profile_data_key_authority = injected_keys
    app.include_router(create_consent_public_router())
    client = TestClient(app, base_url="https://consent.lightwork.test")
    response = client.get(
        "/api/v1/public/consent/profile-data/prompt",
        headers=_browser_headers(profile=True),
    )
    assert response.status_code == 200, response.text
    assert response.json()["eligible"] is True
    assert fallback_calls == [("tenant-a", injected_keys)]


def test_credential_revocation_is_generic(environment: _Environment) -> None:
    environment.registry.revoke_client(
        _CLIENT_CREDENTIAL,
        expected_revision=1,
    )
    response = environment.client.get(
        "/api/v1/public/consent/configuration",
        headers=_browser_headers(),
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid public consent credential"


class _RightsIntakeStore:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.verified = True
        self.status = SignedConsumerRightsStatus(
            payload={
                "schema": "lightwork.privacy-rights-intake-status.v1",
                "tenant_sha256": "d" * 64,
                "case_id": "rights-case-1",
                "rights": ["access", "erasure"],
                "status": "open",
                "identity_status": "verified",
                "destructive_approval_required": True,
                "provider_operations_verified": False,
                "estate_completeness_claimed": False,
            },
            signing_key_ref="kms:rights-status/key-one",
            signing_key_revision=1,
            signing_key_authority_sha256="a" * 64,
            signature="b" * 64,
            evidence_sha256="c" * 64,
        )

    def create_request(
        self,
        authority: Any,
        *,
        rights: list[str],
        expected_revision: int,
        idempotency_key: str,
    ) -> SignedConsumerRightsStatus:
        self.calls.append(
            (
                "create",
                authority,
                tuple(rights),
                expected_revision,
                idempotency_key,
            )
        )
        return self.status

    def get_status(self, authority: Any, case_id: str) -> SignedConsumerRightsStatus:
        self.calls.append(("status", authority, case_id))
        return self.status

    def verify_signed_status(self, status: SignedConsumerRightsStatus) -> bool:
        self.calls.append(("verify", status.evidence_sha256))
        return self.verified and status is self.status


def test_public_rights_intake_is_subject_bound_closed_and_private(
    environment: _Environment,
) -> None:
    _bootstrap(environment)
    gate = {"enabled": True}
    store = _RightsIntakeStore()
    intake_authority = object()
    factory_calls: list[dict[str, Any]] = []

    def factory(**kwargs: Any) -> PublicRightsIntakeMaterial:
        factory_calls.append(kwargs)
        return PublicRightsIntakeMaterial(store=store, authority=intake_authority)

    environment.app.state.privacy_rights_intake_gate = lambda: gate["enabled"]
    environment.app.state.privacy_rights_intake_store_factory = factory

    rejected = environment.client.post(
        "/api/v1/public/consent/rights-requests",
        headers=_browser_headers(profile=True),
        json={
            "rights": ["access"],
            "expected_revision": 0,
            "idempotency_key": "public-rights-raw-key",
            "tenant_id": "tenant-b",
            "source_ids": ["attacker-selected-source"],
            "identity_token": "raw-token",
        },
    )
    assert rejected.status_code == 422
    assert factory_calls == []

    created = environment.client.post(
        "/api/v1/public/consent/rights-requests",
        headers=_browser_headers(profile=True),
        json={
            "rights": ["access", "erasure"],
            "expected_revision": 0,
            "idempotency_key": "public-rights-raw-key",
        },
    )
    assert created.status_code == 201, created.text
    assert created.headers["cache-control"] == "no-store, private"
    assert created.json() == {
        "payload": store.status.payload,
        "signing_key_ref": store.status.signing_key_ref,
        "signing_key_revision": 1,
        "signing_key_authority_sha256": "a" * 64,
        "signature": "b" * 64,
        "evidence_sha256": "c" * 64,
    }
    assert len(factory_calls) == 1
    supplied = factory_calls[0]
    assert supplied["tenant_id"] == "tenant-a"
    assert supplied["initial_client_binding"] == environment.binding
    assert supplied["initial_profile_binding"].subject_binding_sha256
    refreshed = supplied["public_authority_resolver"]()
    assert refreshed.binding.record_sha256 == environment.binding.record_sha256
    assert "tenant_id" not in created.json()["payload"]

    create_call = store.calls[0]
    assert create_call[:4] == (
        "create",
        intake_authority,
        ("access", "erasure"),
        0,
    )
    assert create_call[4] != "public-rights-raw-key"
    assert "public-rights-raw-key" not in create_call[4]

    current = environment.client.get(
        "/api/v1/public/consent/rights-requests/rights-case-1",
        headers=_browser_headers(profile=True),
    )
    assert current.status_code == 200, current.text
    assert current.headers["cache-control"] == "no-store, private"
    assert store.calls[-2:] == [
        ("status", intake_authority, "rights-case-1"),
        ("verify", store.status.evidence_sha256),
    ]

    store.verified = False
    unverifiable = environment.client.get(
        "/api/v1/public/consent/rights-requests/rights-case-1",
        headers=_browser_headers(profile=True),
    )
    assert unverifiable.status_code == 503
    assert unverifiable.json()["detail"] == "privacy-rights intake unavailable"
    store.verified = True

    gate["enabled"] = False
    disabled = environment.client.get(
        "/api/v1/public/consent/rights-requests/rights-case-1",
        headers=_browser_headers(profile=True),
    )
    assert disabled.status_code == 404
    assert disabled.json()["detail"] == "not found"
