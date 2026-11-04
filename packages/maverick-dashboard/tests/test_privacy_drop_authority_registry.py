from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick.privacy_drop_management import (
    DROPDSARReceipt,
    DROPManagementConfigError,
    DROPManagementConflict,
    DROPManagementNotFound,
    DROPRecordAuthority,
)
from maverick_dashboard.privacy_drop_authority_registry import DROPAuthorityRegistry
from maverick_dashboard.privacy_drop_principal_authority import DROPPrincipalKeyAuthority

TENANT = "tenant-drop-registry"
NOW = 2_100_000_000.0
TEMPLATE = "550e8400-e29b-41d4-a716-446655440000"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _binding(tenant_id: str, principal_ref: str) -> str:
    return _digest(f"binding:{tenant_id}:{principal_ref}")


def _registry(
    path: Path,
    *,
    now: list[float] | None = None,
    maintenance: bool = False,
) -> DROPAuthorityRegistry:
    current = now if now is not None else [NOW]
    return DROPAuthorityRegistry(
        path,
        tenant_id=TENANT,
        principal_binding_resolver=_binding,
        retention_seconds=86_400,
        maintenance_authorizer=lambda: maintenance,
        config_gate=lambda: None,
        clock=lambda: current[0],
    )


def _enroll(registry: DROPAuthorityRegistry):
    return registry.enroll_broker(
        broker_ref="broker-ca-001",
        registration_sha256=_digest("broker-registration"),
        evidence_sha256=_digest("broker-enrollment-evidence"),
        valid_until=NOW + 3_600,
        expected_version=0,
        actor_ref="broker-enroller",
        reviewer_ref="broker-reviewer",
        idempotency_key="enroll-broker-ca-001",
    )


def _authority(*, revision: int = 1) -> DROPRecordAuthority:
    return DROPRecordAuthority(
        tenant_id=TENANT,
        drop_id=41_001,
        broker_registration_sha256=_digest("broker-registration"),
        subject_binding_sha256=_digest("external-subject-binding"),
        request_type="DataDeletion",
        template_id=TEMPLATE,
        language="en-us",
        record_revision=revision,
        valid_until=NOW + 1_800,
    ).normalized()


def _import(registry: DROPAuthorityRegistry, authority: DROPRecordAuthority | None = None):
    return registry.import_record(
        authority or _authority(),
        broker_ref="broker-ca-001",
        import_evidence_sha256=_digest("drop-record-import-evidence"),
        expected_version=0,
        actor_ref="record-importer",
        reviewer_ref="record-reviewer",
        idempotency_key="import-drop-41001",
    )


def _receipt(authority: DROPRecordAuthority) -> DROPDSARReceipt:
    return DROPDSARReceipt(
        tenant_id=TENANT,
        drop_id=authority.drop_id,
        authority_sha256=authority.authority_sha256,
        subject_binding_sha256=authority.subject_binding_sha256,
        request_type=authority.request_type,
        request_queue_id="8af319f0-38a5-4ddd-bc0b-bb2d00c9a011",
        request_queue_ref_id="privacy-rights-orchestration",
        internal_case_id="DROP-41001-case",
        created_at=NOW,
    ).normalized()


def test_registry_enrolls_imports_resolves_and_replays(tmp_path: Path) -> None:
    registry = _registry(tmp_path / "registry.sqlite3")

    first_broker = _enroll(registry)
    replayed_broker = _enroll(registry)
    imported = _import(registry)
    replayed_import = _import(registry)
    resolved = registry.resolve_record(
        drop_id=41_001,
        request_type="DataDeletion",
        template_id=TEMPLATE,
        language="en-US",
    )

    assert replayed_broker == first_broker
    assert replayed_import == imported
    assert resolved == imported
    assert first_broker.approved_by_binding_sha256 != (
        first_broker.reviewed_by_binding_sha256
    )
    assert registry.verify_integrity() is True
    report = registry.reconcile()
    assert report.integrity_valid is True
    assert (report.active_brokers, report.active_records, report.approved_outcomes) == (1, 1, 0)
    boundaries = registry.product_boundaries()
    assert boundaries["network_io"] is False
    assert boundaries["live_drop_authority_verified"] is False
    assert boundaries["legal_acceptance_verified"] is False
    assert boundaries["raw_subject_identity_accepted"] is False


def test_registry_rejects_same_person_approval_and_broker_misbinding(tmp_path: Path) -> None:
    registry = _registry(tmp_path / "registry.sqlite3")

    with pytest.raises(DROPManagementConflict, match="independent"):
        registry.enroll_broker(
            broker_ref="broker-ca-001",
            registration_sha256=_digest("broker-registration"),
            evidence_sha256=_digest("broker-enrollment-evidence"),
            valid_until=NOW + 3_600,
            expected_version=0,
            actor_ref="same-person",
            reviewer_ref="same-person",
            idempotency_key="bad-enrollment",
        )

    _enroll(registry)
    bad = DROPRecordAuthority(
        **{
            **_authority().__dict__,
            "broker_registration_sha256": _digest("attacker-broker"),
            "authority_sha256": "",
        }
    ).normalized()
    with pytest.raises(DROPManagementConflict, match="broker registration"):
        _import(registry, bad)


def test_terminal_outcome_requires_independent_bound_evidence(tmp_path: Path) -> None:
    registry = _registry(tmp_path / "registry.sqlite3")
    _enroll(registry)
    authority = _import(registry)
    receipt = _receipt(authority)

    outcome = registry.approve_outcome(
        authority,
        receipt,
        status="DELETED",
        reviewer_ref="outcome-reviewer",
        evidence_sha256=_digest("deletion-evidence"),
        evidence_revision=1,
        observed_at=NOW,
        valid_until=NOW + 600,
        deletion_verified=True,
        search_complete=True,
        provider_operations_complete=True,
        expected_version=0,
        actor_ref="outcome-proposer",
        idempotency_key="approve-deleted-41001",
    )

    assert registry.resolve_outcome(authority, receipt, "DELETED") == outcome
    with pytest.raises(DROPManagementConflict, match="independent"):
        registry.approve_outcome(
            authority,
            receipt,
            status="NOT_FOUND",
            reviewer_ref="same-person",
            evidence_sha256=_digest("not-found-evidence"),
            evidence_revision=1,
            observed_at=NOW,
            valid_until=NOW + 600,
            search_complete=True,
            expected_version=0,
            actor_ref="same-person",
            idempotency_key="bad-outcome",
        )
    assert registry.verify_integrity() is True


def test_broker_revocation_invalidates_record_resolution(tmp_path: Path) -> None:
    registry = _registry(tmp_path / "registry.sqlite3")
    _enroll(registry)
    _import(registry)

    revoked = registry.revoke_broker(
        "broker-ca-001",
        expected_version=1,
        evidence_sha256=_digest("broker-revocation-evidence"),
        actor_ref="broker-revoker",
        reviewer_ref="broker-revocation-reviewer",
        idempotency_key="revoke-broker-ca-001",
    )

    assert revoked.state == "revoked"
    with pytest.raises(DROPManagementNotFound):
        registry.resolve_record(drop_id=41_001)
    assert registry.verify_integrity() is True


def test_concurrent_record_import_has_one_winner(tmp_path: Path) -> None:
    registry = _registry(tmp_path / "registry.sqlite3")
    _enroll(registry)
    authority = _authority()

    def import_once(index: int):
        return registry.import_record(
            authority,
            broker_ref="broker-ca-001",
            import_evidence_sha256=_digest("drop-record-import-evidence"),
            expected_version=0,
            actor_ref="record-importer",
            reviewer_ref="record-reviewer",
            idempotency_key=f"concurrent-import-{index}",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(import_once, index) for index in range(2)]
    outcomes = []
    for future in futures:
        try:
            outcomes.append(future.result())
        except DROPManagementConflict:
            outcomes.append("conflict")

    assert sum(isinstance(value, DROPRecordAuthority) for value in outcomes) == 1
    assert outcomes.count("conflict") == 1
    assert registry.verify_integrity() is True


def test_retention_purge_is_authorized_and_preserves_link_order(tmp_path: Path) -> None:
    now = [NOW]
    path = tmp_path / "registry.sqlite3"
    registry = _registry(path, now=now)
    _enroll(registry)
    _import(registry)
    now[0] = NOW + 90_000
    unauthorized = _registry(path, now=now)
    with pytest.raises(DROPManagementConfigError, match="maintenance"):
        unauthorized.purge_expired()

    authorized = _registry(path, now=now, maintenance=True)
    first = authorized.purge_expired(limit=100)
    second = authorized.purge_expired(limit=100)

    assert first == 1  # record first; its broker is still referenced during this pass
    assert second == 1
    assert authorized.verify_integrity() is True


def test_outcome_survives_principal_key_rotation_by_pinned_revision(tmp_path: Path) -> None:
    secrets = {
        "kms://drop/one": b"1" * 32,
        "kms://drop/two": b"2" * 32,
    }
    keys = DROPPrincipalKeyAuthority(
        tmp_path / "keyring.sqlite3",
        tenant_id=TENANT,
        initial_key_ref="kms://drop/one",
        secret_resolver=lambda _tenant, ref: secrets[ref],
        config_gate=lambda: None,
        clock=lambda: NOW,
    )
    registry = DROPAuthorityRegistry(
        tmp_path / "registry.sqlite3",
        tenant_id=TENANT,
        principal_binding_resolver=keys.bind,
        principal_binding_verifier=keys.verify,
        retention_seconds=86_400,
        config_gate=lambda: None,
        clock=lambda: NOW,
    )
    _enroll(registry)
    authority = _import(registry)
    receipt = _receipt(authority)
    outcome = registry.approve_outcome(
        authority,
        receipt,
        status="DELETED",
        reviewer_ref="outcome-reviewer",
        evidence_sha256=_digest("deletion-evidence"),
        evidence_revision=1,
        observed_at=NOW,
        valid_until=NOW + 600,
        deletion_verified=True,
        search_complete=True,
        provider_operations_complete=True,
        expected_version=0,
        actor_ref="outcome-proposer",
        idempotency_key="approve-before-rotation",
    )

    keys.rotate(
        new_key_ref="kms://drop/two",
        expected_current_revision=1,
        actor_ref="key-operator",
        reviewer_ref="key-reviewer",
        idempotency_key="rotate-after-outcome",
    )

    assert registry.resolve_outcome(authority, receipt, "DELETED") == outcome
    assert registry.verify_integrity() is True
    counts = registry.retained_key_revision_counts()
    assert counts[1] >= 6
