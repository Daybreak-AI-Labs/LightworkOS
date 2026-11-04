from __future__ import annotations

import hashlib
import inspect
import sqlite3
from dataclasses import replace

import pytest
from maverick import config as maverick_config
from maverick.consent_profile_data import PublicProfileAuthority
from maverick.consumer_trust_center import (
    TrustCenterConflict,
    TrustCenterDisabled,
    TrustCenterIntegrityError,
)
from maverick.consumer_trust_center_authority import (
    CAPABILITIES,
    PRINCIPAL_PERMISSIONS,
    ConsumerTrustCenterAuthorityStore,
    ResolvedTrustCenterBinding,
    TrustCenterAuthorityNotFound,
    TrustCenterAuthorityPermissionDenied,
    TrustCenterPrincipalAuthority,
    principal_authority_sha256,
)

NOW = 1_900_000_000.0
TENANT = "tenant-a"
PROPERTY = "property-a"
PROFILE = "profile-a"
CONTEXT = "context-a"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _profile_authority() -> PublicProfileAuthority:
    return PublicProfileAuthority(
        tenant_id=TENANT,
        profile_id=PROFILE,
        property_id=PROPERTY,
        catalog_id="catalog-a",
        catalog_version=2,
        publication_sha256=_digest("publication"),
        bundle_sha256=_digest("bundle"),
        configuration_sha256=_digest("configuration"),
        policy_id="policy-a",
        policy_version=3,
        policy_sha256=_digest("policy"),
        profile_capability_sha256=_digest("profile-capability"),
    )


def _binding(**changes: object) -> ResolvedTrustCenterBinding:
    raw = ResolvedTrustCenterBinding(
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
        profile_authority=_profile_authority(),
    )
    return replace(raw, **changes)


class Harness:
    def __init__(self) -> None:
        self.now = NOW
        self.principal = "context-admin"
        self.permissions = tuple(sorted(PRINCIPAL_PERMISSIONS))
        self.binding = _binding()
        self.counter = 0
        self.gate_calls = 0

    def gate(self) -> None:
        self.gate_calls += 1

    def resolve_binding(self, context_ref: str) -> ResolvedTrustCenterBinding:
        if context_ref != CONTEXT:
            raise RuntimeError("unknown server binding")
        return self.binding

    def resolve_principal(self, tenant_id: str) -> TrustCenterPrincipalAuthority:
        raw = TrustCenterPrincipalAuthority(
            tenant_sha256=_digest(tenant_id),
            principal_sha256=_digest(self.principal),
            permissions=self.permissions,
            valid_until=self.now + 10_000,
            authority_sha256="0" * 64,
            revoked=False,
        )
        return replace(raw, authority_sha256=principal_authority_sha256(raw))

    @staticmethod
    def resolve_key(tenant_id: str, key_ref: str) -> bytes:
        assert tenant_id == TENANT
        assert key_ref == "env:TRUST_CENTER_TEST_KEY"
        return b"trust-center-test-signing-key-32-bytes-minimum"

    def new_id(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}-{self.counter}"


@pytest.fixture
def authority(tmp_path):
    harness = Harness()
    store = ConsumerTrustCenterAuthorityStore(
        tmp_path / "trust-center-authority.db",
        binding_resolver=harness.resolve_binding,
        principal_authority_resolver=harness.resolve_principal,
        signing_key_resolver=harness.resolve_key,
        signing_key_ref="env:TRUST_CENTER_TEST_KEY",
        config_gate=harness.gate,
        clock=lambda: harness.now,
        id_factory=harness.new_id,
    )
    return store, harness


def _create(store: ConsumerTrustCenterAuthorityStore):
    return store.create_context(
        context_ref=CONTEXT,
        valid_until=NOW + 5_000,
        retained_until=NOW + 10_000,
        publication_history_limit=20,
        receipt_limit=15,
        idempotency_key="create-context",
    )


def _context_revision(store: ConsumerTrustCenterAuthorityStore, harness: Harness) -> int:
    harness.principal = "authority-reader"
    return store.get_context_authority(TENANT, CONTEXT).revision


def _activate_capability(
    store: ConsumerTrustCenterAuthorityStore,
    harness: Harness,
    capability: str,
    prefix: str,
):
    revision = _context_revision(store, harness)
    harness.principal = f"{prefix}-requestor"
    proposed = store.propose_capability_grant(
        TENANT,
        CONTEXT,
        capability,
        expected_context_revision=revision,
        valid_until=NOW + 3_000,
        idempotency_key=f"{prefix}-propose",
    )
    harness.principal = f"{prefix}-approver-one"
    first = store.approve_capability_grant(
        TENANT,
        proposed.grant_ref,
        expected_revision=proposed.revision,
        expected_context_revision=revision + 1,
        idempotency_key=f"{prefix}-approve-one",
    )
    harness.principal = f"{prefix}-approver-two"
    return store.approve_capability_grant(
        TENANT,
        proposed.grant_ref,
        expected_revision=first.revision,
        expected_context_revision=revision + 2,
        idempotency_key=f"{prefix}-approve-two",
    )


def test_default_gate_is_closed_without_explicit_config(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(maverick_config, "config_source_errors", list)
    monkeypatch.setattr(
        maverick_config,
        "load_config",
        lambda: {"consent_preferences": {"enable": True, "trust_center": {"enable": False}}},
    )
    harness = Harness()
    with pytest.raises(TrustCenterDisabled):
        ConsumerTrustCenterAuthorityStore(
            tmp_path / "closed.db",
            binding_resolver=harness.resolve_binding,
            principal_authority_resolver=harness.resolve_principal,
            signing_key_resolver=harness.resolve_key,
        )


def test_context_persists_only_exact_digests(authority) -> None:
    store, harness = authority
    context = _create(store)
    assert context.tenant_sha256 == _digest(TENANT)
    assert context.property_sha256 == _digest(PROPERTY)
    assert context.profile_sha256 == _digest(PROFILE)
    assert context.binding_sha256 != context.profile_authority_sha256
    assert context.revision == 1
    raw = store.path.read_bytes()
    for secret in (
        TENANT,
        PROPERTY,
        PROFILE,
        "never-store-this",
        "catalog-a",
        "context-admin",
        "trust-center-test-signing-key",
    ):
        assert secret.encode() not in raw
    assert harness.gate_calls >= 2
    history = store.history(TENANT, "context", CONTEXT)
    assert len(history) == 1
    assert history[0]["record"]["binding_sha256"] == context.binding_sha256


def test_capability_requires_distinct_requestor_and_two_approvers(authority) -> None:
    store, harness = authority
    _create(store)
    harness.principal = "grant-requestor"
    proposed = store.propose_capability_grant(
        TENANT,
        CONTEXT,
        "active_publication",
        expected_context_revision=1,
        valid_until=NOW + 1_000,
        idempotency_key="grant-propose",
    )
    assert proposed.status == "proposed"
    assert _context_revision(store, harness) == 2

    harness.principal = "grant-requestor"
    with pytest.raises(TrustCenterConflict):
        store.approve_capability_grant(
            TENANT,
            proposed.grant_ref,
            expected_revision=1,
            expected_context_revision=2,
            idempotency_key="self-approve",
        )

    harness.principal = "approver-one"
    first = store.approve_capability_grant(
        TENANT,
        proposed.grant_ref,
        expected_revision=1,
        expected_context_revision=2,
        idempotency_key="approve-one",
    )
    assert first.status == "first_approved"
    assert first.approved_by_sha256 == _digest("approver-one")

    with pytest.raises(TrustCenterConflict):
        store.approve_capability_grant(
            TENANT,
            proposed.grant_ref,
            expected_revision=2,
            expected_context_revision=3,
            idempotency_key="same-approver-twice",
        )

    harness.principal = "approver-two"
    active = store.approve_capability_grant(
        TENANT,
        proposed.grant_ref,
        expected_revision=2,
        expected_context_revision=3,
        idempotency_key="approve-two",
    )
    assert active.status == "active"
    assert active.second_approved_by_sha256 == _digest("approver-two")
    assert _context_revision(store, harness) == 4


def test_zero_argument_resolver_returns_exact_active_authority(authority) -> None:
    store, harness = authority
    _create(store)
    grant = _activate_capability(store, harness, "profile_data", "profile")
    resolver = store.make_context_resolver(CONTEXT)
    assert list(inspect.signature(resolver).parameters) == []
    context = resolver()
    assert context.tenant_id == TENANT
    assert context.property_id == PROPERTY
    assert context.profile_id == PROFILE
    assert context.profile_authority == harness.binding.profile_authority
    assert context.revision == 4
    assert len(context.capability_grants) == 1
    public = context.capability_grants[0]
    assert public.capability == "profile_data"
    assert public.grant_ref == grant.grant_ref
    assert public.grant_sha256 != "0" * 64
    assert context.context_sha256 != "0" * 64


def test_resolver_fails_closed_on_binding_drift_expiry_and_revocation(authority) -> None:
    store, harness = authority
    _create(store)
    grant = _activate_capability(store, harness, "active_publication", "publication")
    resolver = store.make_context_resolver(CONTEXT)
    assert resolver().capability_grants

    harness.binding = replace(harness.binding, requested_locale="fr-FR")
    with pytest.raises(TrustCenterConflict, match="binding drifted"):
        resolver()
    harness.binding = _binding()

    harness.principal = "context-admin-two"
    store.revoke_capability_grant(
        TENANT,
        grant.grant_ref,
        expected_revision=grant.revision,
        expected_context_revision=4,
        idempotency_key="revoke-grant",
    )
    with pytest.raises(TrustCenterConflict, match="unavailable"):
        resolver()


def test_rights_case_authorization_is_explicit_four_eyes_and_revocable(authority) -> None:
    store, harness = authority
    _create(store)
    _activate_capability(store, harness, "rights_cases", "rights-capability")
    assert _context_revision(store, harness) == 4
    harness.principal = "rights-requestor"
    proposed = store.propose_rights_authorization(
        TENANT,
        CONTEXT,
        "case-7",
        _digest("case-7-exact-record"),
        expected_context_revision=4,
        valid_until=NOW + 2_000,
        idempotency_key="rights-propose",
    )
    harness.principal = "rights-approver-one"
    first = store.approve_rights_authorization(
        TENANT,
        proposed.authorization_ref,
        expected_revision=1,
        expected_context_revision=5,
        idempotency_key="rights-approve-one",
    )
    harness.principal = "rights-approver-two"
    active = store.approve_rights_authorization(
        TENANT,
        proposed.authorization_ref,
        expected_revision=first.revision,
        expected_context_revision=6,
        idempotency_key="rights-approve-two",
    )
    context = store.make_context_resolver(CONTEXT)()
    assert len(context.rights_authorizations) == 1
    assert context.rights_authorizations[0].case_id == "case-7"
    assert context.rights_authorizations[0].expected_case_sha256 == _digest("case-7-exact-record")

    harness.principal = "rights-revoker"
    revoked = store.revoke_rights_authorization(
        TENANT,
        active.authorization_ref,
        expected_revision=active.revision,
        expected_context_revision=7,
        idempotency_key="rights-revoke",
    )
    assert revoked.status == "revoked"
    assert store.make_context_resolver(CONTEXT)().rights_authorizations == ()


def test_rights_authorization_requires_active_rights_capability(authority) -> None:
    store, harness = authority
    _create(store)
    harness.principal = "rights-requestor"
    with pytest.raises(TrustCenterConflict, match="not active"):
        store.propose_rights_authorization(
            TENANT,
            CONTEXT,
            "case-1",
            _digest("case"),
            expected_context_revision=1,
            valid_until=NOW + 500,
            idempotency_key="rights-without-grant",
        )


def test_revoking_rights_capability_cascades_case_authority(authority) -> None:
    store, harness = authority
    _create(store)
    rights_grant = _activate_capability(store, harness, "rights_cases", "cascade-rights")
    harness.principal = "rights-requestor"
    proposed = store.propose_rights_authorization(
        TENANT,
        CONTEXT,
        "case-cascade",
        _digest("case-cascade-record"),
        expected_context_revision=4,
        valid_until=NOW + 2_000,
        idempotency_key="cascade-case-propose",
    )
    harness.principal = "rights-approver-one"
    first = store.approve_rights_authorization(
        TENANT,
        proposed.authorization_ref,
        expected_revision=1,
        expected_context_revision=5,
        idempotency_key="cascade-case-approve-one",
    )
    harness.principal = "rights-approver-two"
    store.approve_rights_authorization(
        TENANT,
        proposed.authorization_ref,
        expected_revision=first.revision,
        expected_context_revision=6,
        idempotency_key="cascade-case-approve-two",
    )
    harness.principal = "capability-revoker"
    store.revoke_capability_grant(
        TENANT,
        rights_grant.grant_ref,
        expected_revision=rights_grant.revision,
        expected_context_revision=7,
        idempotency_key="cascade-rights-grant-revoke",
    )
    history = store.history(TENANT, "rights_authorization", proposed.authorization_ref)
    assert history[0]["record"]["status"] == "revoked"
    with pytest.raises(TrustCenterConflict, match="unavailable"):
        store.make_context_resolver(CONTEXT)()


def test_idempotency_and_cas_are_exact(authority) -> None:
    store, harness = authority
    first = _create(store)
    replay = _create(store)
    assert replay == first
    with pytest.raises(TrustCenterConflict, match="another exact request"):
        store.create_context(
            context_ref=CONTEXT,
            valid_until=NOW + 4_000,
            retained_until=NOW + 10_000,
            idempotency_key="create-context",
        )

    harness.principal = "grant-requestor"
    with pytest.raises(TrustCenterConflict):
        store.propose_capability_grant(
            TENANT,
            CONTEXT,
            "active_publication",
            expected_context_revision=99,
            valid_until=NOW + 500,
            idempotency_key="stale-context-cas",
        )


def test_principal_authority_is_exact_tenant_scoped_and_permissioned(authority) -> None:
    store, harness = authority
    harness.permissions = ("authority_read",)
    with pytest.raises(TrustCenterAuthorityPermissionDenied):
        _create(store)
    harness.permissions = tuple(sorted(PRINCIPAL_PERMISSIONS))
    harness.binding = replace(harness.binding, actor_sha256=_digest("context-admin"))
    with pytest.raises(TrustCenterAuthorityPermissionDenied, match="cannot administer"):
        _create(store)


def test_signed_export_is_safe_verifiable_and_idempotent(authority) -> None:
    store, harness = authority
    _create(store)
    _activate_capability(store, harness, "active_publication", "export-capability")
    harness.principal = "exporter"
    exported = store.export_signed_metadata(TENANT, CONTEXT, idempotency_key="authority-export")
    replay = store.export_signed_metadata(TENANT, CONTEXT, idempotency_key="authority-export")
    assert replay == exported
    assert store.verify_signed_metadata(exported) is True
    assert exported.payload["tenant_sha256"] == _digest(TENANT)
    rendered = repr(exported)
    for forbidden in (
        TENANT,
        PROPERTY,
        PROFILE,
        "never-store-this",
        "context-admin",
        "trust-center-test-signing-key",
    ):
        assert forbidden not in rendered
    assert (
        store.verify_signed_metadata(replace(exported, signature_sha256=_digest("tampered")))
        is False
    )


def test_signed_export_read_is_tenant_bound_and_integrity_verifying(authority) -> None:
    store, harness = authority
    _create(store)
    _activate_capability(store, harness, "active_publication", "read-export-capability")
    harness.principal = "exporter"
    exported = store.export_signed_metadata(TENANT, CONTEXT, idempotency_key="read-export")
    harness.principal = "authority-reader"
    assert store.get_signed_metadata(TENANT, exported.export_id) == exported
    with pytest.raises(TrustCenterAuthorityNotFound):
        store.get_signed_metadata("tenant-b", exported.export_id)
    with pytest.raises(TrustCenterAuthorityNotFound):
        store.get_signed_metadata(TENANT, "TCX-missing")

    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER trust_center_authority_export_no_update")
        connection.execute(
            "UPDATE trust_center_authority_exports SET payload_json='{}' WHERE export_id=?",
            (exported.export_id,),
        )
    with pytest.raises(TrustCenterIntegrityError):
        store.get_signed_metadata(TENANT, exported.export_id)


def test_context_revision_can_refresh_exact_binding_but_not_truncate_grants(authority) -> None:
    store, harness = authority
    _create(store)
    harness.binding = replace(harness.binding, requested_locale="es-US")
    harness.principal = "context-reviser"
    revised = store.revise_context(
        TENANT,
        CONTEXT,
        expected_revision=1,
        valid_until=NOW + 4_000,
        retained_until=NOW + 9_000,
        publication_history_limit=10,
        receipt_limit=10,
        idempotency_key="refresh-binding",
    )
    assert revised.revision == 2
    _activate_capability(store, harness, "active_publication", "revise-capability")
    harness.principal = "context-reviser"
    with pytest.raises(TrustCenterConflict, match="cannot truncate"):
        store.revise_context(
            TENANT,
            CONTEXT,
            expected_revision=5,
            valid_until=NOW + 500,
            retained_until=NOW + 9_000,
            publication_history_limit=10,
            receipt_limit=10,
            idempotency_key="truncate-context",
        )
    assert store.make_context_resolver(CONTEXT)().requested_locale == "es-US"
    harness.binding = replace(harness.binding, requested_locale="fr-FR")
    with pytest.raises(TrustCenterConflict, match="revoking child authorities"):
        store.revise_context(
            TENANT,
            CONTEXT,
            expected_revision=5,
            valid_until=NOW + 4_000,
            retained_until=NOW + 9_000,
            publication_history_limit=10,
            receipt_limit=10,
            idempotency_key="drift-live-binding",
        )


def test_integrity_detects_tamper_and_history_is_immutable(authority) -> None:
    store, harness = authority
    _create(store)
    _activate_capability(store, harness, "active_publication", "integrity-capability")
    harness.principal = "auditor"
    counts = store.verify_integrity(TENANT)
    assert counts["contexts"] == 1
    assert counts["grants"] == 1
    assert counts["history"] == 7
    assert counts["audit_events"] == 4
    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE trust_center_authority_history SET payload_json='{}'")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE trust_center_authority_grants SET integrity_sha256=?",
            (_digest("tampered"),),
        )
    with pytest.raises(TrustCenterIntegrityError):
        store.verify_integrity(TENANT)


def test_retention_purge_removes_payloads_but_preserves_audit_chain(authority) -> None:
    store, harness = authority
    _create(store)
    _activate_capability(store, harness, "active_publication", "purge-capability")
    harness.now = NOW + 20_000
    harness.principal = "retention-operator"
    assert store.retention_due(TENANT, before=harness.now) == (CONTEXT,)
    result = store.purge_expired(
        TENANT,
        before=harness.now,
        idempotency_key="purge-expired-contexts",
    )
    assert result["count"] == 1
    assert result["contexts_purged"] == (CONTEXT,)
    assert store.retention_due(TENANT, before=harness.now) == ()
    counts = store.verify_integrity(TENANT)
    assert counts["contexts"] == 0
    assert counts["grants"] == 0
    assert counts["history"] == 0
    assert counts["audit_events"] == 5
    replay = store.purge_expired(
        TENANT,
        before=harness.now,
        idempotency_key="purge-expired-contexts",
    )
    assert replay["count"] == 1


def test_context_revocation_cascades_live_children(authority) -> None:
    store, harness = authority
    _create(store)
    grant = _activate_capability(store, harness, "active_publication", "cascade-capability")
    harness.principal = "context-revoker"
    revoked = store.revoke_context(
        TENANT,
        CONTEXT,
        expected_revision=4,
        idempotency_key="revoke-context",
    )
    assert revoked.status == "revoked"
    with pytest.raises(TrustCenterConflict):
        store.make_context_resolver(CONTEXT)()
    history = store.history(TENANT, "grant", grant.grant_ref)
    assert history[0]["record"]["status"] == "revoked"


def test_product_boundaries_are_explicit() -> None:
    boundaries = ConsumerTrustCenterAuthorityStore.product_boundaries()
    assert boundaries["persisted_bindings"] == "sha256_only"
    assert boundaries["zero_argument_context_resolver"] is True
    assert boundaries["raw_identity_persisted"] is False
    assert boundaries["signing_keys_persisted"] is False
    assert boundaries["completeness_inferred"] is False
    assert boundaries["network_io"] is False
    assert boundaries["provider_writes"] is False
    assert {
        "active_publication",
        "consent_history",
        "profile_data",
        "rights_cases",
    } == CAPABILITIES
