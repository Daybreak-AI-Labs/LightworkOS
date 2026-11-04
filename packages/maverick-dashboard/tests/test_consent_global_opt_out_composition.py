from __future__ import annotations

import hashlib
import time
from types import SimpleNamespace

from fastapi import FastAPI
from maverick import consent_global_opt_out as goo
from maverick.privacy_rights_intake import ConsumerRightsIntakeAuthority
from maverick_dashboard import consent_global_opt_out_composition as composition
from maverick_dashboard.consent_public_api import (
    PublicClientBinding,
    PublicProfileBinding,
    PublicRightsIntakeMaterial,
)
from starlette.requests import Request


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _config() -> dict:
    return {
        "consent_preferences": {
            "enable": True,
            "global_opt_out": {
                "enable": True,
                "retention_seconds": 3_600,
                "submission_ttl_seconds": 300,
                "max_records": 100,
            },
        }
    }


def _request(app: FastAPI) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/api/v1/public/consent/global-opt-out/configuration",
            "raw_path": b"/api/v1/public/consent/global-opt-out/configuration",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 443),
            "app": app,
        }
    )


class _RightsStore:
    def __init__(self) -> None:
        self.calls = []

    def create_request(self, authority, **kwargs):
        self.calls.append((authority, kwargs))
        return SimpleNamespace(
            payload={"case_id": "PRI-composed-case", "rights": ["opt_out"]},
            evidence_sha256=_digest("signed-intake-status"),
        )

    @staticmethod
    def verify_signed_status(_status):
        return True


def test_public_composition_binds_exact_authorities_and_invokes_real_intake(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config())
    now = time.time()
    client = PublicClientBinding(
        credential_id="public-client-main",
        credential_sha256=_digest("client-credential"),
        tenant_id="alpha",
        property_id="web-main",
        client_kind="browser",
        browser_origin="https://example.test",
        service_client_id=None,
        target_origin="https://example.test",
        target_bundle_id=None,
        target_platform=None,
        jurisdiction="global",
        country_code="US",
        region_code="",
        default_locale="en-US",
        property_revision=3,
        property_sha256=_digest("property"),
        rule_group_id="production",
        rule_group_version=2,
        publication_sha256=_digest("publication"),
        bundle_sha256=_digest("bundle"),
        policy_id="public-consent",
        policy_version=4,
        policy_sha256=_digest("policy"),
        expires_at=now + 3_600,
        revision=5,
        record_sha256=_digest("client-record"),
    )
    profile = PublicProfileBinding(
        credential_sha256=_digest("profile-credential"),
        client_credential_sha256=client.credential_sha256,
        tenant_id="alpha",
        property_id="web-main",
        profile_id="profile-main",
        subject_binding_sha256=_digest("subject-binding"),
        binding_sha256=_digest("profile-binding"),
    )
    configuration = {
        "configuration_sha256": _digest("configuration"),
        "configuration": {
            "purposes": [{"id": "analytics", "lawful_basis": "consent"}],
            "notice": {"document_sha256": _digest("notice")},
        },
        "property": {"property_id": "web-main", "revision": 3},
        "publication": {
            "property_revision": 3,
            "publication_sha256": client.publication_sha256,
            "bundle_sha256": client.bundle_sha256,
        },
    }
    policy = {
        "policy_id": client.policy_id,
        "version": client.policy_version,
        "policy_sha256": client.policy_sha256,
        "purposes": {"analytics": "consent"},
        "notice_sha256": _digest("notice"),
    }
    intake = ConsumerRightsIntakeAuthority(
        tenant_id="alpha",
        property_sha256=client.property_sha256,
        property_revision=client.property_revision,
        profile_sha256=_digest("profile"),
        profile_credential_sha256=profile.credential_sha256,
        profile_binding_sha256=profile.binding_sha256,
        profile_revision=6,
        subject_binding_sha256=profile.subject_binding_sha256,
        client_credential_sha256=client.credential_sha256,
        client_record_sha256=client.record_sha256,
        client_revision=client.revision,
        publication_sha256=client.publication_sha256,
        publication_bundle_sha256=client.bundle_sha256,
        configuration_sha256=configuration["configuration_sha256"],
        policy_sha256=client.policy_sha256,
        policy_version=client.policy_version,
        trust_context_sha256=_digest("trust"),
        trust_context_revision=2,
        capability_grant_sha256=_digest("grant"),
        channel="browser-origin",
        channel_binding_sha256=_digest("channel"),
        identity_authority_sha256=_digest("identity-authority"),
        minimum_identity_assurance="substantial",
        valid_until=now + 1_800,
        revoked=False,
    ).normalized()
    rights_store = _RightsStore()
    app = FastAPI()
    app.state.global_opt_out_clock = lambda: now
    request = _request(app)
    resolved = SimpleNamespace(binding=client, profile=profile)
    material = composition.global_opt_out_public_material_factory(
        app,
        tenant_id="alpha",
        initial_client_binding=client,
        initial_profile_binding=profile,
        active_public_configuration=configuration,
        active_policy=policy,
        public_authority_resolver=lambda: resolved,
        rights_intake_material=PublicRightsIntakeMaterial(
            store=rights_store,
            authority=intake,
        ),
        request=request,
    )
    assert material.authority.application_ref == client.credential_id
    assert material.authority.profile_sha256 == intake.profile_sha256
    assert material.authority.public_client_record_sha256 == client.record_sha256
    assert material.authority.intake_authority_sha256 == goo.authority_material_sha256(
        intake
    )

    created = material.store.create_configuration(
        client.credential_id,
        locale="en-US",
        mobile_ui={
            "enabled": True,
            "title": "Privacy choice",
            "body": "Submit an opt-out request.",
            "submit_label": "Opt out",
            "success_message": "Request accepted.",
        },
        email_ui={
            "enabled": True,
            "title": "Privacy request",
            "body": "Submit a verified request.",
            "submit_label": "Submit",
            "success_message": "Request accepted.",
        },
        supported_devices=["browser"],
        supported_services=["website", "email"],
        expires_at=None,
        expected_revision=0,
        idempotency_key="create-composed-global-opt-out",
    )
    material.store.activate_configuration(
        created["configuration_id"],
        expected_revision=created["revision"],
        idempotency_key="activate-composed-global-opt-out",
    )
    public_config = material.store.get_public_configuration(material.authority)
    submitted = material.store.submit(
        material.authority,
        configuration_version=public_config["configuration_version"],
        configuration_sha256=public_config["configuration_sha256"],
        authority_revision=public_config["authority_revision"],
        authority_sha256=public_config["authority_sha256"],
        idempotency_key="submit-composed-global-opt-out",
    )
    assert submitted["state"] == "submitted"
    assert submitted["case_reference_sha256"] == _digest("PRI-composed-case")
    assert rights_store.calls[0][1]["rights"] == ["opt_out"]
    assert rights_store.calls[0][1]["expected_revision"] == 0


def test_attach_installs_lazy_factories_and_closed_readiness(monkeypatch):
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config())
    app = FastAPI()
    app.state.privacy_rights_intake_gate = lambda: True
    app.state.privacy_rights_intake_store_factory = lambda **_kwargs: object()
    composition.attach_consent_global_opt_out_composition(app)
    assert callable(app.state.global_opt_out_admin_store_factory)
    assert callable(app.state.global_opt_out_public_material_factory)
    assert app.state.global_opt_out_enabled_probe("alpha") is True
    readiness = app.state.global_opt_out_readiness_probe("alpha")
    assert readiness == {
        "ready": True,
        "configured_authority": True,
        "privacy_rights_intake_available": True,
        "live_device_acceptance": False,
        "live_customer_acceptance": False,
    }
