from __future__ import annotations

import hashlib
import itertools
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import consumer_trust_center as trust_center
from maverick import consumer_trust_center_authority as authority
from maverick.consent_identity_federation import (
    ConsentIdentityEvidence,
    ConsentPairingContext,
)
from maverick_dashboard import consent_identity_federation_api as identity_api
from maverick_dashboard import consumer_trust_center_authority_api as api
from maverick_dashboard.consent_public_api import (
    PublicClientBinding,
    PublicConsentDependencies,
    PublicProfileBinding,
)

API = "/api/v1/consent/trust-center-authority"
TENANT = "tenant-a"
PROPERTY = "primary-web"
PROFILE = "profile-opaque"
CONTEXT = "trust-context-a"
NOW = 2_100_000_000.0
SIGNING_KEY = b"trust-center-authority-api-test-key-32-bytes-minimum"
CLIENT_CREDENTIAL_ID = "public-client-rights-intake"
CLIENT_REVISION = 5
PROFILE_REVISION = 6
_DEFAULT_VERIFIER_RESULT = object()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


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


def _privacy_rights_authorities() -> tuple[
    PublicClientBinding,
    PublicProfileBinding,
    ConsentPairingContext,
    ConsentIdentityEvidence,
]:
    client = PublicClientBinding(
        credential_id=CLIENT_CREDENTIAL_ID,
        credential_sha256=_digest("privacy-rights-client-credential"),
        tenant_id=TENANT,
        property_id=PROPERTY,
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
        property_sha256=_digest("privacy-rights-property"),
        rule_group_id="public-rules",
        rule_group_version=3,
        publication_sha256=_digest("privacy-rights-publication"),
        bundle_sha256=_digest("privacy-rights-bundle"),
        policy_id="privacy-policy",
        policy_version=4,
        policy_sha256=_digest("privacy-rights-policy"),
        expires_at=NOW + 3_600,
        revision=CLIENT_REVISION,
        record_sha256=_digest("privacy-rights-client-record"),
    )
    profile = PublicProfileBinding(
        credential_sha256=_digest("privacy-rights-profile-credential"),
        client_credential_sha256=client.credential_sha256,
        tenant_id=TENANT,
        property_id=PROPERTY,
        profile_id=PROFILE,
        subject_binding_sha256=_digest("privacy-rights-anonymous-subject"),
        binding_sha256=_digest("privacy-rights-profile-binding"),
    )
    channel_sha256 = _object_digest(
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
        property_id=PROPERTY,
        profile_id=PROFILE,
        profile_revision=PROFILE_REVISION,
        client_credential_sha256=client.credential_sha256,
        client_revision=CLIENT_REVISION,
        client_record_sha256=client.record_sha256,
        profile_credential_sha256=profile.credential_sha256,
        profile_binding_sha256=profile.binding_sha256,
        property_revision=client.property_revision,
        property_sha256=client.property_sha256,
        publication_sha256=client.publication_sha256,
        bundle_sha256=client.bundle_sha256,
        configuration_sha256=_digest("privacy-rights-configuration"),
        policy_id=client.policy_id,
        policy_version=client.policy_version,
        policy_sha256=client.policy_sha256,
        channel_kind="browser-origin",
        channel_binding_sha256=channel_sha256,
    ).normalized()
    evidence_body = {
        "schema": "lightwork.consent.identity-evidence.v1",
        "tenant_id": TENANT,
        "target_fingerprint": pairing.fingerprint,
        "source_fingerprint": _digest("privacy-rights-source-pairing"),
        "subject_binding_sha256": _digest("privacy-rights-known-subject"),
        "oidc_verification_sha256": _digest("privacy-rights-oidc-verification"),
        "source_link_sha256": _digest("privacy-rights-source-link"),
        "target_link_sha256": _digest("privacy-rights-target-link"),
        "pairing_revision": 11,
        "valid_until": NOW + 600,
    }
    evidence = ConsentIdentityEvidence(
        **evidence_body,
        evidence_sha256=_object_digest(evidence_body),
    )
    return client, profile, pairing, evidence


def _privacy_rights_prepare_body() -> dict[str, object]:
    return {
        "client_credential_id": CLIENT_CREDENTIAL_ID,
        "property_id": PROPERTY,
        "profile_id": PROFILE,
        "expected_client_revision": CLIENT_REVISION,
        "expected_profile_revision": PROFILE_REVISION,
        "valid_until": NOW + 5_000,
        "retained_until": NOW + 10_000,
        "publication_history_limit": 20,
        "receipt_limit": 15,
        "idempotency_key": "privacy-rights-context-prepare",
    }


class _PrivacyRightsRegistry:
    def __init__(
        self,
        state: dict[str, object],
        client: PublicClientBinding,
        profile: PublicProfileBinding,
    ) -> None:
        self.state = state
        self.client = client
        self.profile = profile
        self.resolve_calls: list[dict[str, object]] = []
        self.registration_calls: list[tuple[str, PublicClientBinding, PublicProfileBinding]] = []

    def resolve_pairing_authority_by_admin_refs(
        self,
        tenant_id: str,
        client_credential_id: str,
        property_id: str,
        profile_id: str,
        *,
        expected_client_revision: int,
    ) -> tuple[PublicClientBinding, PublicProfileBinding]:
        self.resolve_calls.append(
            {
                "tenant_id": tenant_id,
                "client_credential_id": client_credential_id,
                "property_id": property_id,
                "profile_id": profile_id,
                "expected_client_revision": expected_client_revision,
            }
        )
        if (
            tenant_id != TENANT
            or client_credential_id != self.client.credential_id
            or property_id != self.client.property_id
            or profile_id != self.profile.profile_id
            or expected_client_revision != self.client.revision
        ):
            raise RuntimeError("private selector or revision mismatch")
        return self.client, self.profile

    def register_rights_intake_context(
        self,
        context_ref: str,
        client: PublicClientBinding,
        profile: PublicProfileBinding,
    ) -> None:
        if client is not self.client or profile is not self.profile:
            raise RuntimeError("private pairing changed")
        self.registration_calls.append((context_ref, client, profile))
        self.state["prepared_context_ref"] = context_ref


def _install_privacy_rights_preparation(
    client: TestClient,
    state: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    *,
    verifier_result: object = _DEFAULT_VERIFIER_RESULT,
) -> SimpleNamespace:
    client_binding, profile, pairing, evidence = _privacy_rights_authorities()
    registry = _PrivacyRightsRegistry(state, client_binding, profile)
    public = PublicConsentDependencies(
        credential_store=registry,  # type: ignore[arg-type]
        publishing_store_for=lambda _tenant: None,
        preference_store_for=lambda _tenant: None,
        gate=lambda: True,
        rate_limit=lambda _credential, _action: None,
        context_resolver=lambda _request, _client: None,  # type: ignore[arg-type]
        clock=lambda: NOW,
    )
    public_factory_calls: list[Request] = []
    pairing_resolution_calls: list[
        tuple[PublicConsentDependencies, PublicClientBinding, PublicProfileBinding]
    ] = []
    verifier_calls: list[tuple[Request, ConsentPairingContext]] = []

    def public_factory(*, request: Request) -> PublicConsentDependencies:
        public_factory_calls.append(request)
        return public

    def resolve_pairing(
        supplied_public: PublicConsentDependencies,
        supplied_client: PublicClientBinding,
        supplied_profile: PublicProfileBinding,
    ) -> ConsentPairingContext:
        pairing_resolution_calls.append((supplied_public, supplied_client, supplied_profile))
        if (
            supplied_public is not public
            or supplied_client is not client_binding
            or supplied_profile is not profile
        ):
            raise RuntimeError("private pairing authority mismatch")
        return pairing

    selected_result = evidence if verifier_result is _DEFAULT_VERIFIER_RESULT else verifier_result

    def pairing_verifier(
        *,
        request: Request,
        pairing: ConsentPairingContext,
    ) -> object:
        verifier_calls.append((request, pairing))
        if isinstance(selected_result, BaseException):
            raise selected_result
        return selected_result

    monkeypatch.setattr(identity_api, "resolve_consent_pairing_context", resolve_pairing)
    client.app.state.privacy_rights_intake_public_dependencies_factory = public_factory
    client.app.state.consumer_trust_center_authority_pairing_verifier = pairing_verifier
    return SimpleNamespace(
        client=client_binding,
        profile=profile,
        pairing=pairing,
        evidence=evidence,
        registry=registry,
        public=public,
        public_factory_calls=public_factory_calls,
        pairing_resolution_calls=pairing_resolution_calls,
        verifier_calls=verifier_calls,
    )


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state: dict[str, object] = {
        "enabled": True,
        "now": NOW,
        "subject": "context-admin",
        "factory_calls": [],
        "permission_calls": [],
        "factory_error": None,
        "store_override": None,
        "prepared_context_ref": None,
    }
    database = tmp_path / "trust-center-authority.sqlite3"
    ids = itertools.count(1)

    def gate() -> None:
        if not state["enabled"]:
            raise trust_center.TrustCenterDisabled("private disabled configuration")

    monkeypatch.setattr(trust_center, "require_trust_center_enabled", gate)
    monkeypatch.setattr(api, "_enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: TENANT)

    def tenant_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("tenant", permission))

    def global_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("global", permission))

    monkeypatch.setattr(api, "require_permission", tenant_permission)
    monkeypatch.setattr(api, "require_global_permission", global_permission)

    def store_for(request: Request, tenant_id: str, principal_ref: str):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append(
            {
                "request": request,
                "tenant_id": tenant_id,
                "principal_ref": principal_ref,
            }
        )
        error = state["factory_error"]
        if isinstance(error, BaseException):
            raise error
        override = state["store_override"]
        if override is not None:
            return override

        def binding_resolver(context_ref: str):
            if context_ref not in {CONTEXT, state["prepared_context_ref"]}:
                raise RuntimeError("private binding lookup detail")
            return authority.ResolvedTrustCenterBinding(
                tenant_id=TENANT,
                property_id=PROPERTY,
                profile_id=PROFILE,
                actor_sha256=_digest("consumer-actor"),
                requested_locale="en-US",
                server_origin="https://private.example/path?credential=never-store-this",
                server_bundle_id=None,
                server_platform=None,
                jurisdiction="US-CA",
                country_code="US",
                region_code="CA",
                profile_authority=None,
            )

        def principal_resolver(tenant: str):
            raw = authority.TrustCenterPrincipalAuthority(
                tenant_sha256=_digest(tenant),
                principal_sha256=_digest(principal_ref),
                permissions=tuple(sorted(authority.PRINCIPAL_PERMISSIONS)),
                valid_until=float(state["now"]) + 50_000,
                authority_sha256="0" * 64,
                revoked=False,
            )
            return replace(
                raw,
                authority_sha256=authority.principal_authority_sha256(raw),
            )

        return authority.ConsumerTrustCenterAuthorityStore(
            database,
            binding_resolver=binding_resolver,
            principal_authority_resolver=principal_resolver,
            signing_key_resolver=lambda _tenant, _key_ref: SIGNING_KEY,
            signing_key_ref="env:TRUST_CENTER_AUTHORITY_API_TEST_KEY",
            config_gate=gate,
            clock=lambda: float(state["now"]),
            id_factory=lambda prefix: f"{prefix}-{next(ids)}",
        )

    dependencies = api.ConsumerTrustCenterAuthorityDependencies(store_for=store_for)
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        if request.headers.get("X-Test-No-Principal") != "1":
            selected = request.headers.get("X-Test-Subject")
            subject = selected if selected is not None else str(state["subject"])
            request.state.principal = SimpleNamespace(principal=f"user:{subject}")
        return await call_next(request)

    app.include_router(
        api.create_consumer_trust_center_authority_router(dependencies),
        prefix="/api/v1",
    )
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    return client, database, state


def _create(client: TestClient) -> dict:
    response = client.put(
        f"{API}/contexts/{CONTEXT}",
        json={
            "valid_until": NOW + 5_000,
            "retained_until": NOW + 10_000,
            "publication_history_limit": 20,
            "receipt_limit": 15,
            "idempotency_key": "context-create",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _activate_capability(
    client: TestClient,
    capability: str,
    context_revision: int,
    prefix: str,
) -> tuple[dict, int]:
    proposed_response = client.post(
        f"{API}/contexts/{CONTEXT}/capability-grants",
        headers={"X-Test-Subject": f"{prefix}-requestor"},
        json={
            "capability": capability,
            "expected_context_revision": context_revision,
            "valid_until": NOW + 4_000,
            "idempotency_key": f"{prefix}-propose",
        },
    )
    assert proposed_response.status_code == 201, proposed_response.text
    proposed = proposed_response.json()
    first_response = client.post(
        f"{API}/capability-grants/{proposed['grant_ref']}/approve",
        headers={"X-Test-Subject": f"{prefix}-approver-one"},
        json={
            "expected_revision": proposed["revision"],
            "expected_context_revision": context_revision + 1,
            "idempotency_key": f"{prefix}-approve-one",
        },
    )
    assert first_response.status_code == 200, first_response.text
    first = first_response.json()
    second_response = client.post(
        f"{API}/capability-grants/{proposed['grant_ref']}/approve",
        headers={"X-Test-Subject": f"{prefix}-approver-two"},
        json={
            "expected_revision": first["revision"],
            "expected_context_revision": context_revision + 2,
            "idempotency_key": f"{prefix}-approve-two",
        },
    )
    assert second_response.status_code == 200, second_response.text
    return second_response.json(), context_revision + 3


def test_status_is_store_free_default_off_and_server_scoped(
    environment, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _database, state = environment
    response = client.get(f"{API}/status")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private"
    status = response.json()
    assert status["enabled"] is True
    assert set(status["supported_capabilities"]) == set(authority.CAPABILITIES)
    assert status["four_eyes_capability_grants"] is True
    assert status["four_eyes_case_authorizations"] is True
    assert status["raw_identity_persisted"] is False
    assert status["tenant_or_principal_selector_accepted"] is False
    assert status["status_request_opens_tenant_storage"] is False
    assert state["factory_calls"] == []
    assert TENANT not in json.dumps(status)

    expected_principal = (
        "tca-principal-"
        + hashlib.sha256(
            f"lightwork.consumer-trust-center-authority.identity.v1:{TENANT}:user:context-admin".encode()
        ).hexdigest()[:32]
    )
    assert status["principal_ref"] == expected_principal

    state["enabled"] = False
    assert client.get(f"{API}/status").json()["enabled"] is False
    blocked = client.put(
        f"{API}/contexts/{CONTEXT}",
        json={
            "valid_until": NOW + 100,
            "retained_until": NOW + 200,
            "idempotency_key": "disabled",
        },
    )
    assert blocked.status_code == 403
    assert blocked.json() == {"detail": "consumer Trust Center authority is disabled"}
    assert "private" not in blocked.text
    assert state["factory_calls"] == []

    state["enabled"] = True
    monkeypatch.setattr("maverick_dashboard.auth.anonymous_local_access_allowed", lambda: False)
    monkeypatch.setattr("maverick_dashboard.auth._dashboard_token_authenticated", lambda _r: False)
    unauthenticated = client.get(
        f"{API}/status",
        headers={"X-Test-No-Principal": "1"},
    )
    assert unauthenticated.status_code == 401


def test_status_grants_a_synthetic_operator_ref_under_genuine_auth_off(environment) -> None:
    """A missing principal is not ALWAYS a 401: genuine local auth-off mode
    and a valid static dashboard bearer are both already-authenticated
    shapes require_permission() itself accepts."""
    client, _database, _state = environment
    response = client.get(
        f"{API}/status",
        headers={"X-Test-No-Principal": "1"},
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "field",
    [
        "tenant",
        "tenant_id",
        "principal",
        "principal_ref",
        "property_id",
        "profile_id",
        "consumer_identity",
        "credential",
        "signing_key",
        "binding",
        "server_origin",
    ],
)
def test_closed_bodies_reject_browser_authority_and_secret_fields_generically(
    environment,
    field: str,
) -> None:
    client, _database, state = environment
    response = client.put(
        f"{API}/contexts/{CONTEXT}",
        json={
            "valid_until": NOW + 1_000,
            "retained_until": NOW + 2_000,
            "idempotency_key": "unsafe-field",
            field: "private value that must not be reflected",
        },
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "Trust Center authority request is invalid"}
    assert "private value" not in response.text
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert state["factory_calls"] == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("client_credential_sha256", _digest("must-not-be-accepted")),
        ("profile_credential_sha256", _digest("must-not-be-accepted")),
        ("capability", "rights_cases"),
        ("approval", "must-not-be-accepted"),
    ],
)
def test_privacy_rights_prepare_strictly_rejects_secret_and_grant_fields(
    environment,
    field: str,
    value: object,
) -> None:
    client, database, state = environment
    body = _privacy_rights_prepare_body()
    body[field] = value

    response = client.post(f"{API}/privacy-rights-contexts/prepare", json=body)

    assert response.status_code == 422
    assert response.json() == {"detail": "Trust Center authority request is invalid"}
    assert str(value) not in response.text
    assert response.headers["cache-control"] == "no-store, private"
    assert state["factory_calls"] == []
    assert not database.exists()


def test_privacy_rights_prepare_requires_server_composition(environment) -> None:
    client, database, state = environment

    response = client.post(
        f"{API}/privacy-rights-contexts/prepare",
        json=_privacy_rights_prepare_body(),
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "privacy-rights context preparation is unavailable"}
    assert response.headers["cache-control"] == "no-store, private"
    assert state["factory_calls"] == []
    assert not database.exists()


@pytest.mark.parametrize(
    ("field", "stale_value"),
    [
        ("client_credential_id", "public-client-stale"),
        ("property_id", "other-property"),
        ("profile_id", "other-profile"),
        ("expected_client_revision", CLIENT_REVISION - 1),
        ("expected_profile_revision", PROFILE_REVISION - 1),
    ],
)
def test_privacy_rights_prepare_requires_exact_selectors_and_current_revisions(
    environment,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    stale_value: object,
) -> None:
    client, database, state = environment
    prepared = _install_privacy_rights_preparation(client, state, monkeypatch)
    body = _privacy_rights_prepare_body()
    body[field] = stale_value

    response = client.post(f"{API}/privacy-rights-contexts/prepare", json=body)

    assert response.status_code == 409
    assert response.json() == {"detail": "privacy-rights context authority is not current"}
    assert str(stale_value) not in response.text
    assert prepared.registry.registration_calls == []
    assert prepared.verifier_calls == []
    assert state["factory_calls"] == []
    assert not database.exists()


def test_privacy_rights_prepare_requires_current_redeemed_identity_evidence(
    environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, database, state = environment
    prepared = _install_privacy_rights_preparation(
        client,
        state,
        monkeypatch,
        verifier_result=None,
    )

    response = client.post(
        f"{API}/privacy-rights-contexts/prepare",
        json=_privacy_rights_prepare_body(),
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "privacy-rights context authority is not current"}
    assert len(prepared.verifier_calls) == 1
    assert prepared.verifier_calls[0][1] is prepared.pairing
    assert prepared.registry.registration_calls == []
    assert state["factory_calls"] == []
    assert not database.exists()


def test_privacy_rights_prepare_creates_only_one_context_and_is_idempotent(
    environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, database, state = environment
    prepared = _install_privacy_rights_preparation(client, state, monkeypatch)
    body = _privacy_rights_prepare_body()

    first = client.post(f"{API}/privacy-rights-contexts/prepare", json=body)
    replay = client.post(f"{API}/privacy-rights-contexts/prepare", json=body)

    assert first.status_code == 201, first.text
    assert replay.status_code == 201, replay.text
    assert replay.json() == first.json()
    result = first.json()
    assert result == {
        "schema": "lightwork.privacy-rights-context-preparation.v1",
        "context_ref": prepared.registry.registration_calls[0][0],
        "context_revision": 1,
        "status": "active",
        "required_capability": "rights_cases",
        "capability_grant_created": False,
        "distinct_approvals_required": 2,
        "next_action": "propose_rights_cases_capability_grant",
    }
    assert prepared.registry.resolve_calls == [
        {
            "tenant_id": TENANT,
            "client_credential_id": CLIENT_CREDENTIAL_ID,
            "property_id": PROPERTY,
            "profile_id": PROFILE,
            "expected_client_revision": CLIENT_REVISION,
        },
        {
            "tenant_id": TENANT,
            "client_credential_id": CLIENT_CREDENTIAL_ID,
            "property_id": PROPERTY,
            "profile_id": PROFILE,
            "expected_client_revision": CLIENT_REVISION,
        },
    ]
    assert prepared.pairing_resolution_calls == [
        (prepared.public, prepared.client, prepared.profile),
        (prepared.public, prepared.client, prepared.profile),
    ]
    assert [pairing for _request, pairing in prepared.verifier_calls] == [
        prepared.pairing,
        prepared.pairing,
    ]
    assert len(prepared.registry.registration_calls) == 2
    assert {call[0] for call in prepared.registry.registration_calls} == {result["context_ref"]}
    assert len(state["factory_calls"]) == 2

    serialized = json.dumps(result, sort_keys=True)
    assert not any("sha256" in key or "digest" in key for key in result)
    for private_value in (
        prepared.client.credential_sha256,
        prepared.client.record_sha256,
        prepared.profile.credential_sha256,
        prepared.profile.binding_sha256,
        prepared.pairing.channel_binding_sha256,
        prepared.evidence.evidence_sha256,
    ):
        assert private_value not in serialized

    with sqlite3.connect(database) as connection:
        context_count = connection.execute(
            "SELECT COUNT(*) FROM trust_center_authority_contexts"
        ).fetchone()[0]
        grant_count = connection.execute(
            "SELECT COUNT(*) FROM trust_center_authority_grants"
        ).fetchone()[0]
        rights_count = connection.execute(
            "SELECT COUNT(*) FROM trust_center_authority_rights"
        ).fetchone()[0]
    assert (context_count, grant_count, rights_count) == (1, 0, 0)


def test_privacy_rights_prepare_failure_never_proposes_or_approves_a_grant(
    environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _database, state = environment
    prepared = _install_privacy_rights_preparation(client, state, monkeypatch)

    class FailingStore:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def __getattr__(self, name: str):
            def operation(*_args, **_kwargs):
                self.calls.append(name)
                if name == "create_context":
                    raise RuntimeError("private context storage failure")
                raise AssertionError(f"unexpected authority operation: {name}")

            return operation

    failing = FailingStore()
    state["store_override"] = failing

    response = client.post(
        f"{API}/privacy-rights-contexts/prepare",
        json=_privacy_rights_prepare_body(),
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Trust Center authority operation failed"}
    assert "private context storage failure" not in response.text
    assert failing.calls == ["create_context"]
    assert prepared.registry.registration_calls


def test_context_revision_get_revocation_and_strict_types(environment) -> None:
    client, _database, _state = environment
    created = _create(client)
    assert created["revision"] == 1
    assert client.get(f"{API}/contexts/{CONTEXT}").json() == created
    revised_response = client.patch(
        f"{API}/contexts/{CONTEXT}",
        headers={"X-Test-Subject": "context-reviser"},
        json={
            "expected_revision": 1,
            "valid_until": NOW + 4_000,
            "retained_until": NOW + 9_000,
            "publication_history_limit": 10,
            "receipt_limit": 10,
            "idempotency_key": "context-revise",
        },
    )
    assert revised_response.status_code == 200, revised_response.text
    revised = revised_response.json()
    assert revised["revision"] == 2
    revoked = client.post(
        f"{API}/contexts/{CONTEXT}/revoke",
        headers={"X-Test-Subject": "context-revoker"},
        json={"expected_revision": 2, "idempotency_key": "context-revoke"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    invalid_path = client.get(f"{API}/contexts/%20private%20value")
    assert invalid_path.status_code == 422
    assert invalid_path.json() == {"detail": "Trust Center authority request is invalid"}
    wrong_type = client.post(
        f"{API}/contexts/{CONTEXT}/revoke",
        json={"expected_revision": "3", "idempotency_key": "wrong-type"},
    )
    assert wrong_type.status_code == 422
    assert wrong_type.json() == {"detail": "Trust Center authority request is invalid"}


def test_full_four_eyes_rights_export_history_integrity_and_retention(environment) -> None:
    client, database, state = environment
    created = _create(client)
    proposed = client.post(
        f"{API}/contexts/{CONTEXT}/capability-grants",
        headers={"X-Test-Subject": "publication-requestor"},
        json={
            "capability": "active_publication",
            "expected_context_revision": created["revision"],
            "valid_until": NOW + 4_000,
            "idempotency_key": "publication-propose",
        },
    ).json()
    self_approval = client.post(
        f"{API}/capability-grants/{proposed['grant_ref']}/approve",
        headers={"X-Test-Subject": "publication-requestor"},
        json={
            "expected_revision": proposed["revision"],
            "expected_context_revision": 2,
            "idempotency_key": "publication-self-approve",
        },
    )
    assert self_approval.status_code == 409
    assert self_approval.json() == {"detail": "Trust Center authority state conflict"}

    first = client.post(
        f"{API}/capability-grants/{proposed['grant_ref']}/approve",
        headers={"X-Test-Subject": "publication-approver-one"},
        json={
            "expected_revision": 1,
            "expected_context_revision": 2,
            "idempotency_key": "publication-approve-one",
        },
    ).json()
    active_response = client.post(
        f"{API}/capability-grants/{proposed['grant_ref']}/approve",
        headers={"X-Test-Subject": "publication-approver-two"},
        json={
            "expected_revision": first["revision"],
            "expected_context_revision": 3,
            "idempotency_key": "publication-approve-two",
        },
    )
    assert active_response.status_code == 200, active_response.text
    assert active_response.json()["status"] == "active"

    rights_capability, context_revision = _activate_capability(
        client,
        "rights_cases",
        4,
        "rights-capability",
    )
    assert rights_capability["status"] == "active"
    assert context_revision == 7

    rights_proposal_response = client.post(
        f"{API}/contexts/{CONTEXT}/rights-authorizations",
        headers={"X-Test-Subject": "rights-requestor"},
        json={
            "case_id": "case-7",
            "expected_case_sha256": _digest("case-7-record"),
            "expected_context_revision": context_revision,
            "valid_until": NOW + 3_000,
            "idempotency_key": "rights-propose",
        },
    )
    assert rights_proposal_response.status_code == 201, rights_proposal_response.text
    rights_proposal = rights_proposal_response.json()
    rights_first = client.post(
        f"{API}/rights-authorizations/{rights_proposal['authorization_ref']}/approve",
        headers={"X-Test-Subject": "rights-approver-one"},
        json={
            "expected_revision": 1,
            "expected_context_revision": 8,
            "idempotency_key": "rights-approve-one",
        },
    ).json()
    rights_active_response = client.post(
        f"{API}/rights-authorizations/{rights_proposal['authorization_ref']}/approve",
        headers={"X-Test-Subject": "rights-approver-two"},
        json={
            "expected_revision": rights_first["revision"],
            "expected_context_revision": 9,
            "idempotency_key": "rights-approve-two",
        },
    )
    assert rights_active_response.status_code == 200, rights_active_response.text
    rights_active = rights_active_response.json()
    assert rights_active["status"] == "active"

    history = client.get(f"{API}/history/rights_authorization/{rights_active['authorization_ref']}")
    assert history.status_code == 200
    assert history.json()["count"] == 3
    assert history.json()["items"][0]["record"]["status"] == "active"

    exported_response = client.post(
        f"{API}/contexts/{CONTEXT}/exports",
        headers={"X-Test-Subject": "metadata-exporter"},
        json={"idempotency_key": "context-export"},
    )
    assert exported_response.status_code == 201, exported_response.text
    exported = exported_response.json()
    assert exported["valid"] is True
    assert SIGNING_KEY.decode() not in exported_response.text
    verified = client.post(
        f"{API}/exports/verify",
        headers={"X-Test-Subject": "metadata-auditor"},
        json=exported["export"],
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["valid"] is True
    read = client.get(
        f"{API}/exports/{exported['export']['export_id']}",
        headers={"X-Test-Subject": "metadata-reader"},
    )
    assert read.status_code == 200, read.text
    assert read.json() == exported
    assert read.headers["cache-control"] == "no-store, private"
    tampered = dict(exported["export"])
    tampered["signature_sha256"] = _digest("tampered")
    assert client.post(f"{API}/exports/verify", json=tampered).json()["valid"] is False

    integrity = client.get(f"{API}/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is True
    assert integrity.json()["contexts"] == 1
    due = client.get(
        f"{API}/retention/due",
        params={"before": NOW + 20_000, "limit": 100},
    )
    assert due.status_code == 200
    assert due.json() == {"contexts": [CONTEXT], "count": 1}

    state["now"] = NOW + 20_000
    purged = client.post(
        f"{API}/retention/purge",
        headers={"X-Test-Subject": "retention-admin"},
        json={
            "before": NOW + 20_000,
            "limit": 100,
            "idempotency_key": "retention-purge",
        },
    )
    assert purged.status_code == 200, purged.text
    assert purged.json()["contexts_purged"] == [CONTEXT]
    assert purged.json()["count"] == 1

    persisted = database.read_bytes()
    wal = Path(f"{database}-wal")
    if wal.exists():
        persisted += wal.read_bytes()
    for forbidden in (
        TENANT.encode(),
        PROPERTY.encode(),
        PROFILE.encode(),
        b"never-store-this",
        SIGNING_KEY,
        b"publication-requestor",
    ):
        assert forbidden not in persisted
    permission_calls = state["permission_calls"]
    assert isinstance(permission_calls, list)
    assert ("tenant", "view") in permission_calls
    assert ("tenant", "operate") in permission_calls
    assert ("global", "admin") in permission_calls
    assert ("global", "audit") in permission_calls


def test_revocation_lifecycle_and_unsupported_capability_are_generic(environment) -> None:
    client, _database, _state = environment
    _create(client)
    unsupported = client.post(
        f"{API}/contexts/{CONTEXT}/capability-grants",
        json={
            "capability": "browser-invented-capability",
            "expected_context_revision": 1,
            "valid_until": NOW + 500,
            "idempotency_key": "unsupported-capability",
        },
    )
    assert unsupported.status_code == 422
    assert unsupported.json() == {"detail": "Trust Center authority request is invalid"}

    grant, context_revision = _activate_capability(
        client,
        "active_publication",
        1,
        "revoke",
    )
    revoked = client.post(
        f"{API}/capability-grants/{grant['grant_ref']}/revoke",
        headers={"X-Test-Subject": "grant-revoker"},
        json={
            "expected_revision": grant["revision"],
            "expected_context_revision": context_revision,
            "idempotency_key": "grant-revoke",
        },
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"


def test_failures_and_unsafe_store_outputs_are_generic(environment) -> None:
    client, _database, state = environment

    class UnsafeStore:
        @staticmethod
        def get_context_authority(_tenant: str, _context: str):
            return {"url": "https://private.example/credential"}

        def __getattr__(self, _name):
            return lambda *_args, **_kwargs: None

    state["store_override"] = UnsafeStore()
    unsafe = client.get(f"{API}/contexts/{CONTEXT}")
    assert unsafe.status_code == 503
    assert unsafe.json() == {"detail": "Trust Center authority returned an invalid contract"}
    assert "private.example" not in unsafe.text

    state["store_override"] = None
    state["factory_error"] = RuntimeError("database password and private path")
    unavailable = client.get(f"{API}/contexts/{CONTEXT}")
    assert unavailable.status_code == 503
    assert unavailable.json() == {"detail": "Trust Center authority is unavailable"}
    assert "password" not in unavailable.text


def test_all_core_operations_are_mounted_and_adapter_has_no_network_client(environment) -> None:
    client, _database, _state = environment
    paths = set(client.app.openapi()["paths"])
    assert {
        f"{API}/status",
        f"{API}/privacy-rights-contexts/prepare",
        f"{API}/contexts/{{context_ref}}",
        f"{API}/contexts/{{context_ref}}/revoke",
        f"{API}/contexts/{{context_ref}}/capability-grants",
        f"{API}/capability-grants/{{grant_ref}}/approve",
        f"{API}/capability-grants/{{grant_ref}}/revoke",
        f"{API}/contexts/{{context_ref}}/rights-authorizations",
        f"{API}/rights-authorizations/{{authorization_ref}}/approve",
        f"{API}/rights-authorizations/{{authorization_ref}}/revoke",
        f"{API}/history/{{object_kind}}/{{object_ref}}",
        f"{API}/contexts/{{context_ref}}/exports",
        f"{API}/exports/{{export_id}}",
        f"{API}/exports/verify",
        f"{API}/retention/due",
        f"{API}/retention/purge",
        f"{API}/integrity",
    } <= paths
    source = Path(api.__file__).read_text(encoding="utf-8")
    for method in (
        "create_context",
        "revise_context",
        "revoke_context",
        "propose_capability_grant",
        "approve_capability_grant",
        "revoke_capability_grant",
        "propose_rights_authorization",
        "approve_rights_authorization",
        "revoke_rights_authorization",
        "get_context_authority",
        "history",
        "export_signed_metadata",
        "get_signed_metadata",
        "verify_signed_metadata",
        "retention_due",
        "purge_expired",
        "verify_integrity",
    ):
        assert f"store.{method}" in source
    for primitive in ("requests.", "httpx.", "urllib.request", "socket."):
        assert primitive not in source


def test_default_authority_fails_closed_without_server_resolvers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "_enabled", lambda: True)
    monkeypatch.setattr(api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(trust_center, "require_trust_center_enabled", lambda: None)
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="user:operator")
        return await call_next(request)

    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.get(f"{API}/contexts/{CONTEXT}")
    assert response.status_code == 503
    assert response.json() == {"detail": "Trust Center authority is unavailable"}


def test_overview_lists_every_record_with_the_viewers_role_and_no_digests(
    environment,
) -> None:
    client, _database, state = environment
    created = _create(client)
    proposed = client.post(
        f"{API}/contexts/{CONTEXT}/capability-grants",
        headers={"X-Test-Subject": "overview-requestor"},
        json={
            "capability": "consent_history",
            "expected_context_revision": created["revision"],
            "valid_until": NOW + 4_000,
            "idempotency_key": "overview-propose",
        },
    )
    assert proposed.status_code == 201, proposed.text
    approved = client.post(
        f"{API}/capability-grants/{proposed.json()['grant_ref']}/approve",
        headers={"X-Test-Subject": "overview-approver"},
        json={
            "expected_revision": 1,
            "expected_context_revision": created["revision"] + 1,
            "idempotency_key": "overview-approve-one",
        },
    )
    assert approved.status_code == 200, approved.text

    as_requestor = client.get(f"{API}/overview", headers={"X-Test-Subject": "overview-requestor"})
    assert as_requestor.status_code == 200, as_requestor.text
    body = as_requestor.json()
    assert [item["context_ref"] for item in body["contexts"]] == [CONTEXT]
    assert body["contexts"][0]["revision"] == created["revision"] + 2
    grant = body["grants"][0]
    assert grant["capability"] == "consent_history"
    assert grant["status"] == "first_approved"
    assert grant["approval_count"] == 1
    assert grant["requested_by_me"] is True and grant["approved_by_me"] is False
    as_approver = client.get(
        f"{API}/overview", headers={"X-Test-Subject": "overview-approver"}
    ).json()
    assert as_approver["grants"][0]["approved_by_me"] is True
    assert as_approver["grants"][0]["requested_by_me"] is False
    assert "sha256" not in json.dumps(body)
    assert ("tenant", "view") in state["permission_calls"]


def test_rights_request_is_chosen_from_a_list_and_pinned_on_the_server(
    environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick_dashboard import privacy_rights_orchestration_api as rights_api

    client, _database, _state = environment
    created = _create(client)
    _grant, context_revision = _activate_capability(
        client, "rights_cases", created["revision"], "pick-case"
    )

    class _NotFound(Exception):
        pass

    case = SimpleNamespace(
        case_id="case-7",
        rights=("access", "deletion"),
        status="open",
        created_at=NOW - 100,
        retained_until=NOW + 50_000,
        integrity_sha256=_digest("case-7-record"),
    )

    class _Cases:
        def list_cases(self, tenant_id, *, limit):
            assert tenant_id == TENANT
            return (case,)

        def get_case(self, tenant_id, case_id):
            if case_id != "case-7":
                raise _NotFound(case_id)
            return case

    monkeypatch.setattr(
        rights_api, "_ops", lambda: SimpleNamespace(PrivacyRightsNotFound=_NotFound)
    )
    client.app.state.privacy_rights_orchestration_store_factory = (
        lambda **_kwargs: _Cases()
    )
    try:
        listed = client.get(f"{API}/rights-cases")
        assert listed.status_code == 200, listed.text
        assert listed.json()["items"] == [
            {
                "case_id": "case-7",
                "rights": ["access", "deletion"],
                "status": "open",
                "created_at": NOW - 100,
                "retained_until": NOW + 50_000,
            }
        ]
        proposed = client.post(
            f"{API}/contexts/{CONTEXT}/rights-authorizations/for-case",
            headers={"X-Test-Subject": "case-requestor"},
            json={
                "case_id": "case-7",
                "expected_context_revision": context_revision,
                "valid_until": NOW + 3_000,
                "idempotency_key": "case-for-context",
            },
        )
        assert proposed.status_code == 201, proposed.text
        assert proposed.json()["expected_case_sha256"] == _digest("case-7-record")
        missing = client.post(
            f"{API}/contexts/{CONTEXT}/rights-authorizations/for-case",
            json={
                "case_id": "case-unknown",
                "expected_context_revision": context_revision + 1,
                "valid_until": NOW + 3_000,
                "idempotency_key": "case-missing",
            },
        )
        assert missing.status_code == 404
        forged = client.post(
            f"{API}/contexts/{CONTEXT}/rights-authorizations/for-case",
            json={
                "case_id": "case-7",
                "expected_case_sha256": "0" * 64,
                "expected_context_revision": context_revision + 1,
                "valid_until": NOW + 3_000,
                "idempotency_key": "case-forged",
            },
        )
        assert forged.status_code == 422
    finally:
        del client.app.state.privacy_rights_orchestration_store_factory
