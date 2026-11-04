from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from maverick import privacy_rights_orchestration as rights
from maverick.consent_identity_federation import (
    ConsentIdentityEvidence,
    ConsentPairingContext,
)
from maverick.consumer_trust_center import (
    ConsumerTrustCenterSourceAdapter,
    TrustCenterCapabilityGrant,
    TrustCenterContext,
)
from maverick.privacy_rights_ott_ctv import (
    OTTCTVPrivacyRightsConfigError,
    OTTCTVPrivacyRightsConflict,
    OTTCTVPrivacyRightsNotFound,
    OTTCTVPrivacyRightsStore,
    build_service_authority,
    enabled,
)


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def object_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def pairing(*, tenant: str = "tenant-a", profile_revision: int = 2):
    channel = {
        "client_kind": "service",
        "browser_origin": None,
        "service_client_id": "service-tv-1",
        "target_origin": None,
        "target_bundle_id": "com.example.television",
        "target_platform": "tvos",
    }
    return ConsentPairingContext(
        tenant_id=tenant,
        property_id="property-a",
        profile_id="profile-tv-1",
        profile_revision=profile_revision,
        client_credential_sha256=digest(f"{tenant}:client-capability"),
        client_revision=4,
        client_record_sha256=digest(f"{tenant}:client-record"),
        profile_credential_sha256=digest(f"{tenant}:profile-capability"),
        profile_binding_sha256=digest(f"{tenant}:profile-binding:{profile_revision}"),
        property_revision=3,
        property_sha256=digest(f"{tenant}:property"),
        publication_sha256=digest(f"{tenant}:publication"),
        bundle_sha256=digest(f"{tenant}:publication-bundle"),
        configuration_sha256=digest(f"{tenant}:configuration"),
        policy_id="policy-a",
        policy_version=5,
        policy_sha256=digest(f"{tenant}:policy"),
        channel_kind="service-client",
        channel_binding_sha256=object_digest(channel),
    )


def identity_evidence(context: ConsentPairingContext, clock: Clock):
    body = {
        "schema": "lightwork.consent.identity-evidence.v1",
        "tenant_id": context.tenant_id,
        "target_fingerprint": context.fingerprint,
        "source_fingerprint": digest("fresh-browser-source"),
        "subject_binding_sha256": digest("known-subject-binding"),
        "oidc_verification_sha256": digest("fresh-oidc-verification"),
        "source_link_sha256": digest("source-account-link"),
        "target_link_sha256": digest("target-account-link"),
        "pairing_revision": 4,
        "valid_until": clock() + 600,
    }
    return ConsentIdentityEvidence(**body, evidence_sha256=object_digest(body))


def trust_context(
    context: ConsentPairingContext,
    clock: Clock,
    *,
    grant_revoked: bool = False,
    grant_valid_until: float | None = None,
):
    raw_grant = TrustCenterCapabilityGrant(
        capability="rights_cases",
        grant_ref="grant-rights-cases",
        tenant_sha256=hashlib.sha256(context.tenant_id.encode()).hexdigest(),
        property_id=context.property_id,
        profile_sha256=hashlib.sha256(context.profile_id.encode()).hexdigest(),
        approved_by_sha256=digest("privacy-approver-one"),
        second_approved_by_sha256=digest("privacy-approver-two"),
        valid_until=(grant_valid_until if grant_valid_until is not None else clock() + 900),
        grant_sha256=digest("placeholder-grant"),
        revoked=grant_revoked,
    )
    grant = replace(
        raw_grant,
        grant_sha256=ConsumerTrustCenterSourceAdapter.capability_grant_sha256(raw_grant),
    )
    raw_context = TrustCenterContext(
        tenant_id=context.tenant_id,
        property_id=context.property_id,
        profile_id=context.profile_id,
        actor_sha256=digest("device-service-actor"),
        requested_locale="en-US",
        server_origin=None,
        server_bundle_id="com.example.television",
        server_platform="tvos",
        jurisdiction="US-NY",
        country_code="US",
        region_code="NY",
        profile_authority=None,
        capability_grants=(grant,),
        rights_authorizations=(),
        publication_history_limit=10,
        receipt_limit=10,
        retained_until=clock() + 3_600,
        revision=3,
        valid_until=clock() + 900,
        context_sha256=digest("placeholder-context"),
        revoked=False,
    )
    return replace(
        raw_context,
        context_sha256=ConsumerTrustCenterSourceAdapter.context_sha256(raw_context),
    )


def service_authority(clock: Clock, *, tenant: str = "tenant-a"):
    context = pairing(tenant=tenant)
    return build_service_authority(
        context,
        trust_context(context, clock),
        service_client_id="service-tv-1",
        target_bundle_id="com.example.television",
        target_platform="tvos",
        account_binding_sha256=digest(f"{tenant}:linked-account"),
        identity_evidence=identity_evidence(context, clock),
        client_expires_at=clock() + 1_200,
        now=clock(),
    )


def rights_store(path: Path, clock: Clock, actor: dict[str, str]):
    return rights.PrivacyRightsOrchestrationStore(
        path,
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        digest_key_resolver=lambda _tenant: b"k" * 32,
        clock=clock,
        token_factory=lambda: "fixed-lease-token",
    )


def enroll(store, tenant: str, source: str, key: str) -> None:
    store.enroll_source(
        tenant,
        source,
        adapter_ref="provider-adapter-v1",
        credential_ref="env:RIGHTS_PROVIDER_TOKEN",
        capabilities=sorted(rights.TASK_PHASES),
        expected_revision=0,
        idempotency_key=key,
    )


def bridge(
    path: Path,
    store,
    current: dict[str, object],
    clock: Clock,
    *,
    retention_seconds: int = 600,
    maintenance: bool = False,
):
    return OTTCTVPrivacyRightsStore(
        path,
        rights_store=store,
        authority_resolver=lambda _expected: current["authority"],
        signing_key_resolver=lambda _tenant, _ref: b"s" * 32,
        retention_seconds=retention_seconds,
        maintenance_authorizer=lambda: maintenance,
        config_gate=lambda: None,
        clock=clock,
    )


def test_feature_gate_requires_every_parent_and_exact_boolean() -> None:
    complete = {
        "consent_preferences": {
            "enable": True,
            "publishing": {"enable": True},
            "public_api": {"enable": True},
            "identity": {"enable": True},
            "trust_center": {"enable": True},
        },
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {"enable": True},
            "ott_ctv_rights": {"enable": True},
        },
    }
    assert enabled(complete)
    assert not enabled({})
    assert not enabled(
        {
            **complete,
            "privacy_automation": {
                **complete["privacy_automation"],
                "ott_ctv_rights": {"enable": 1},
            },
        }
    )


def test_access_creation_is_signed_idempotent_and_digest_only(tmp_path: Path) -> None:
    clock = Clock()
    actor = {"value": "device-service"}
    store = rights_store(tmp_path / "rights.sqlite3", clock, actor)
    enroll(store, "tenant-a", "crm", "enroll-crm")
    authority = service_authority(clock)
    current = {"authority": authority}
    integration = bridge(tmp_path / "ott.sqlite3", store, current, clock)

    status = integration.create_request(
        authority,
        right="access",
        expected_revision=0,
        idempotency_key="raw-device-request-key-12345",
    )
    replay = integration.create_request(
        authority,
        right="access",
        expected_revision=0,
        idempotency_key="raw-device-request-key-12345",
    )
    assert replay == status
    assert integration.verify_signed_status(status)
    assert status.payload["identity_status"] == "verified"
    assert status.payload["planned_source_count"] == 1
    assert status.payload["provider_operations_verified"] is False
    assert status.payload["estate_completeness_claimed"] is False
    assert status.payload["native_sdk_implemented"] is False
    assert status.payload["retrieved_payload_included"] is False
    assert "tenant_id" not in status.payload

    with sqlite3.connect(store.path) as connection:
        phases = {
            json.loads(row[0])["phase"]
            for row in connection.execute(
                "SELECT payload_json FROM rights_tasks WHERE case_id=?",
                (status.payload["case_id"],),
            )
        }
    assert phases == {"discover", "retrieve", "redact"}
    persisted = integration.path.read_bytes()
    wal = Path(f"{integration.path}-wal")
    if wal.exists():
        persisted += wal.read_bytes()
    for forbidden in (
        b"raw-device-request-key-12345",
        b"raw-device-id-should-never-appear",
        b"raw-oidc-token-should-never-appear",
        b"raw-consumer-selector-should-never-appear",
        b"literal-provider-credential-should-never-appear",
        b"retrieved-personal-payload-should-never-appear",
    ):
        assert forbidden not in persisted
        assert forbidden.decode() not in json.dumps(dict(status.payload))


def test_cross_tenant_replay_transition_and_grant_drift_fail_closed(tmp_path: Path) -> None:
    clock = Clock()
    actor = {"value": "device-service"}
    store = rights_store(tmp_path / "rights.sqlite3", clock, actor)
    enroll(store, "tenant-a", "crm", "enroll-crm")
    authority = service_authority(clock)
    current = {"authority": authority}
    integration = bridge(tmp_path / "ott.sqlite3", store, current, clock)
    status = integration.create_request(
        authority,
        right="access",
        expected_revision=0,
        idempotency_key="create-access-1",
    )

    other = service_authority(clock, tenant="tenant-b")
    current["authority"] = other
    with pytest.raises(OTTCTVPrivacyRightsNotFound):
        integration.get_status(other, str(status.payload["case_id"]))
    current["authority"] = authority
    with pytest.raises(OTTCTVPrivacyRightsConflict, match="idempotency"):
        integration.create_request(
            authority,
            right="deletion",
            expected_revision=0,
            idempotency_key="create-access-1",
        )

    transitioned = replace(authority, profile_revision=authority.profile_revision + 1)
    current["authority"] = transitioned
    with pytest.raises(OTTCTVPrivacyRightsConflict, match="changed"):
        integration.get_status(authority, str(status.payload["case_id"]))

    context = pairing()
    evidence = identity_evidence(context, clock)
    for changed in (
        trust_context(context, clock, grant_revoked=True),
        trust_context(context, clock, grant_valid_until=clock()),
    ):
        with pytest.raises(OTTCTVPrivacyRightsConflict, match="capability"):
            build_service_authority(
                context,
                changed,
                service_client_id="service-tv-1",
                target_bundle_id="com.example.television",
                target_platform="tvos",
                account_binding_sha256=digest("linked-account"),
                identity_evidence=evidence,
                client_expires_at=clock() + 1_200,
                now=clock(),
            )


def test_deletion_remains_under_legal_hold_and_distinct_approval(tmp_path: Path) -> None:
    clock = Clock()
    actor = {"value": "device-service"}
    store = rights_store(tmp_path / "rights.sqlite3", clock, actor)
    enroll(store, "tenant-a", "crm", "enroll-crm")
    authority = service_authority(clock)
    current = {"authority": authority}
    integration = bridge(tmp_path / "ott.sqlite3", store, current, clock)
    status = integration.create_request(
        authority,
        right="deletion",
        expected_revision=0,
        idempotency_key="create-deletion-1",
    )
    case_id = str(status.payload["case_id"])
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT payload_json FROM rights_tasks WHERE case_id=? AND phase='delete'",
            (case_id,),
        ).fetchone()
    delete_task = json.loads(str(row[0]))

    actor["value"] = "legal-operator"
    case = store.get_case("tenant-a", case_id)
    held = store.set_legal_hold(
        "tenant-a",
        case_id,
        active=True,
        evidence_sha256=digest("legal-hold-order"),
        evidence_ref="legal-hold-order-1",
        expected_revision=case.revision,
        idempotency_key="hold-deletion-1",
    )
    actor["value"] = "destructive-approver"
    with pytest.raises(rights.PrivacyRightsConflict, match="legal hold"):
        store.approve_destructive_work(
            "tenant-a",
            delete_task["task_id"],
            expected_revision=delete_task["revision"],
            idempotency_key="approve-held-deletion",
        )

    actor["value"] = "legal-operator"
    store.set_legal_hold(
        "tenant-a",
        case_id,
        active=False,
        evidence_sha256=digest("legal-hold-release"),
        evidence_ref="legal-hold-release-1",
        expected_revision=held.revision,
        idempotency_key="release-deletion-1",
    )
    actor["value"] = "destructive-approver"
    approved = store.approve_destructive_work(
        "tenant-a",
        delete_task["task_id"],
        expected_revision=delete_task["revision"],
        idempotency_key="approve-released-deletion",
    )
    assert approved.approved_by == "destructive-approver"
    assert approved.planned_by == "device-service"


def test_partial_planning_recovers_after_restart(tmp_path: Path) -> None:
    clock = Clock()
    actor = {"value": "device-service"}
    store = rights_store(tmp_path / "rights.sqlite3", clock, actor)
    enroll(store, "tenant-a", "crm", "enroll-crm")
    enroll(store, "tenant-a", "lake", "enroll-lake")
    authority = service_authority(clock)
    current = {"authority": authority}
    path = tmp_path / "ott.sqlite3"
    integration = bridge(path, store, current, clock)
    original = store.plan_source_tasks
    calls = {"value": 0}

    def interrupted(*args, **kwargs):
        calls["value"] += 1
        if calls["value"] == 2:
            raise RuntimeError("simulated crash after first source plan")
        return original(*args, **kwargs)

    store.plan_source_tasks = interrupted
    with pytest.raises(RuntimeError, match="simulated crash"):
        integration.create_request(
            authority,
            right="access",
            expected_revision=0,
            idempotency_key="restartable-access",
        )
    store.plan_source_tasks = original

    restarted = bridge(path, store, current, clock)
    status = restarted.create_request(
        authority,
        right="access",
        expected_revision=0,
        idempotency_key="restartable-access",
    )
    assert status.payload["planned_source_count"] == 2
    assert status.payload["orchestration_revision"] == 4


def test_retention_expiry_and_controlled_atomic_purge(tmp_path: Path) -> None:
    clock = Clock()
    actor = {"value": "device-service"}
    store = rights_store(tmp_path / "rights.sqlite3", clock, actor)
    enroll(store, "tenant-a", "crm", "enroll-crm")
    authority = service_authority(clock)
    current = {"authority": authority}
    path = tmp_path / "ott.sqlite3"
    integration = bridge(path, store, current, clock, retention_seconds=60)
    status = integration.create_request(
        authority,
        right="access",
        expected_revision=0,
        idempotency_key="expiring-access",
    )
    clock.value += 61
    with pytest.raises(OTTCTVPrivacyRightsNotFound):
        integration.get_status(authority, str(status.payload["case_id"]))
    with pytest.raises(OTTCTVPrivacyRightsConfigError, match="maintenance"):
        integration.purge_expired()

    maintainer = bridge(
        path,
        store,
        current,
        clock,
        retention_seconds=60,
        maintenance=True,
    )
    assert maintainer.purge_expired() == {
        "requests_deleted": 1,
        "operations_deleted": 1,
    }
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM ott_ctv_rights_requests"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM ott_ctv_rights_operations"
        ).fetchone()[0] == 0

    boundaries = maintainer.product_boundaries()
    assert boundaries["network_io"] is False
    assert boundaries["provider_writes"] is False
    assert boundaries["fresh_identity_proof_required"] is True
    assert boundaries["identity_proof_valid_until_pinned"] is True
    assert boundaries["identity_proof_max_ttl_seconds"] == 600
    assert boundaries["estate_completeness_claimed"] is False
    assert boundaries["live_provider_acceptance_verified"] is False
