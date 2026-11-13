from __future__ import annotations

import hashlib
import sqlite3

import pytest
from maverick.ai_governance_loop import AIGovernanceLoopStore
from maverick.consent_preferences import ConsentPreferenceStore
from maverick.data_use_governance import DataUseGovernanceStore
from maverick.third_party_lifecycle import ThirdPartyLifecycleStore
from maverick.trc_continuous_evidence import ContinuousEvidenceStore
from maverick.unified_audit import GENESIS_SHA256, SourceRecord


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _assert_chain(records: tuple[SourceRecord, ...]) -> None:
    previous = GENESIS_SHA256
    for sequence, record in enumerate(records, start=1):
        assert record.sequence == sequence
        assert record.previous_sha256 == previous
        previous = record.record_sha256


def test_canonical_source_exports_are_digest_only_and_contiguous(tmp_path) -> None:
    consent = ConsentPreferenceStore(
        tmp_path / "consent.sqlite3",
        clock=lambda: 1_800_000_001.0,
        id_factory=lambda prefix: f"{prefix}-fixed",
    )
    consent.create_profile(
        "tenant-a",
        "profile-a",
        "known",
        _sha("subject-private"),
        "profile-create-1",
    )
    consent_records = consent.unified_audit_records("tenant-a")
    _assert_chain(consent_records)
    assert consent_records[0].action == "record_created"
    assert "profile-a" not in repr(consent_records)
    with sqlite3.connect(tmp_path / "consent.sqlite3") as connection:
        with pytest.raises(sqlite3.IntegrityError, match="outbox is immutable"):
            connection.execute(
                "UPDATE consent_outbox SET event_type='profile.linked' "
                "WHERE tenant='tenant-a'"
            )

    data_use = DataUseGovernanceStore(
        tmp_path / "data-use.sqlite3",
        clock=lambda: 1_800_000_002.0,
    )
    data_use.put_asset(
        "tenant-a",
        "asset-private",
        asset_type="table",
        catalog_binding_sha256=_sha("catalog-private"),
        expected_revision=0,
        idempotency_key="asset-create-1",
    )
    data_use_records = data_use.unified_audit_records("tenant-a")
    _assert_chain(data_use_records)
    assert data_use_records[0].action == "record_changed"
    assert "asset-private" not in repr(data_use_records)


def test_consent_unified_audit_export_survives_an_unlink(tmp_path) -> None:
    """profile.unlinked has no entry in the unified-audit action map used to
    crash unified_audit_records() with "stored consent outbox event type is
    unsupported" for any tenant that had ever unlinked a profile. The outbox
    is immutable (no-update/no-delete triggers), so that export stayed broken
    forever for that tenant once it happened -- silently breaking the
    platform-level Operating Record capture (stock_suite_audit_capture.py
    calls this method)."""
    import time

    consent = ConsentPreferenceStore(tmp_path / "consent-unlink.sqlite3")
    tenant = "tenant-a"
    consent.create_profile(tenant, "known-1", "known", _sha("known"), "create-known")
    consent.create_profile(
        tenant, "anon-1", "anonymous", _sha("anon"), "create-anon"
    )
    consent.link_profiles(
        tenant, "known-1", "anon-1",
        expected_known_revision=0, expected_anonymous_revision=0,
        idempotency_key="link-1",
    )
    consent.unlink_profile(
        tenant, "anon-1",
        expected_anonymous_revision=1, expected_known_revision=1,
        expected_link_revision=1,
        idempotency_key="unlink-1",
        identity_evidence_sha256=_sha("identity-evidence"),
        audit_evidence_sha256=_sha("audit-evidence"),
        actor_sha256=_sha("actor"),
        reason_sha256=_sha("reason"),
        retention_until=time.time() + 86400,
    )

    records = consent.unified_audit_records(tenant)
    _assert_chain(records)
    assert [r.action for r in records] == [
        "record_created",
        "record_created",
        "relationship_changed",  # profile.linked
        "relationship_changed",  # profile.unlinked
    ]


def test_hash_chained_suite_stores_export_verified_source_records(tmp_path) -> None:
    ai = AIGovernanceLoopStore(
        tmp_path / "ai.sqlite3",
        tenant_id="tenant-a",
        config_gate=lambda: None,
    )
    assert ai.verify_unified_audit_history()["valid"] is True
    assert ai.unified_audit_records() == ()

    trc = ContinuousEvidenceStore(
        tmp_path / "trc.sqlite3",
        tenant_id="tenant-a",
        principal_resolver=lambda: "service:test",
        config_gate=lambda: None,
        clock=lambda: 1_800_000_003.0,
    )
    with trc._connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        trc._audit(
            connection,
            "definition_registered",
            _sha("trc-subject"),
            _sha("trc-actor"),
            1_800_000_003.0,
        )
        connection.commit()
    trc_records = trc.unified_audit_records()
    _assert_chain(trc_records)
    assert trc_records[0].action == "control_evaluated"

    lifecycle = ThirdPartyLifecycleStore(
        tmp_path / "lifecycle.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: "service:test",
        clock=lambda: 1_800_000_004.0,
    )
    with lifecycle._connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        lifecycle._audit(
            connection,
            "tenant-a",
            "assessment_created",
            "vendor-private",
            "service:test",
            {"private": "not-exported"},
            1_800_000_004.0,
        )
        connection.commit()
    lifecycle_records = lifecycle.unified_audit_records("tenant-a")
    _assert_chain(lifecycle_records)
    assert lifecycle_records[0].action == "record_created"
    assert "vendor-private" not in repr(lifecycle_records)
    assert "not-exported" not in repr(lifecycle_records)
