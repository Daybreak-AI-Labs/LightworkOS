from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import asdict

import maverick.privacy_drop_management as drop_module
import pytest
from maverick.privacy_drop_management import (
    DROPDSARReceipt,
    DROPManagementConflict,
    DROPManagementIntegrityError,
    DROPManagementNotFound,
    DROPManagementStore,
    DROPRecordAuthority,
    DROPStatusEvidence,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Harness:
    def __init__(
        self, tmp_path, *, request_type: str = "DataDeletion", tenant: str = "tenant-a",
    ) -> None:
        self.now = 1_800_000_000.0
        self.submit_calls = 0
        self.fail_after_submit = False
        self.receipt_created_offset = 0.0
        self.principal_aliases: dict[str, str] = {}
        self.authority = DROPRecordAuthority(
            tenant_id=tenant,
            drop_id=12345,
            broker_registration_sha256=_digest("broker-registration"),
            subject_binding_sha256=_digest("subject-binding"),
            request_type=request_type,
            template_id="550e8400-e29b-41d4-a716-446655440000",
            language="en-us",
            record_revision=1,
            valid_until=self.now + 3_600,
        ).normalized()
        self.current_authority = self.authority
        self.receipts: dict[str, DROPDSARReceipt] = {}

        def authority_resolver(expected):
            if expected.drop_id != self.current_authority.drop_id:
                raise LookupError("not enrolled")
            return self.current_authority

        def submitter(authority, key):
            self.submit_calls += 1
            receipt = self.receipts.setdefault(
                key,
                DROPDSARReceipt(
                    tenant_id=authority.tenant_id,
                    drop_id=authority.drop_id,
                    authority_sha256=authority.authority_sha256,
                    subject_binding_sha256=authority.subject_binding_sha256,
                    request_type=authority.request_type,
                    request_queue_id=str(uuid.uuid5(uuid.NAMESPACE_URL, key)),
                    request_queue_ref_id="SL244HWD6D",
                    internal_case_id=f"drop-case-{authority.drop_id}",
                    created_at=self.now + self.receipt_created_offset,
                ).normalized(),
            )
            if self.fail_after_submit:
                self.fail_after_submit = False
                raise ConnectionError("lost acknowledgement")
            return receipt

        def evidence_resolver(authority, receipt, status):
            return DROPStatusEvidence(
                tenant_id=authority.tenant_id,
                drop_id=authority.drop_id,
                authority_sha256=authority.authority_sha256,
                request_queue_id=receipt.request_queue_id,
                internal_case_id=receipt.internal_case_id,
                status=status,
                reviewer_ref="reviewer-independent",
                evidence_sha256=_digest(f"evidence:{status}"),
                evidence_revision=1,
                observed_at=self.now,
                valid_until=self.now + 300,
                deletion_verified=status == "DELETED",
                opt_out_verified=status == "OPTED_OUT",
                search_complete=status in {"DELETED", "NOT_FOUND"},
                exemption_approved=status == "EXEMPTED",
                provider_operations_complete=status in {"DELETED", "OPTED_OUT"},
            ).normalized()

        self.evidence_resolver = evidence_resolver

        def principal_binding_resolver(tenant_id, principal_ref):
            canonical = self.principal_aliases.get(principal_ref, principal_ref)
            return _digest(f"drop-principal-binding:{tenant_id}:{canonical}")

        self.principal_binding_resolver = principal_binding_resolver
        self.store = DROPManagementStore(
            tmp_path / "drop.sqlite3",
            tenant_id=tenant,
            authority_resolver=authority_resolver,
            dsar_submitter=submitter,
            status_evidence_resolver=lambda *args: self.evidence_resolver(*args),
            principal_binding_resolver=principal_binding_resolver,
            maintenance_authorizer=lambda: True,
            config_gate=lambda: None,
            clock=lambda: self.now,
        )


def test_create_is_minimized_idempotent_and_integrity_checked(tmp_path) -> None:
    h = Harness(tmp_path)
    created = h.store.create_request(
        h.authority,
        expected_revision=0,
        idempotency_key="create-12345",
    )
    replay = h.store.create_request(
        h.authority,
        expected_revision=0,
        idempotency_key="create-12345",
    )
    assert created == replay
    assert created.status == "PENDING"
    assert created.revision == 1
    assert h.submit_calls == 1
    assert h.store.verify_integrity() is True

    with sqlite3.connect(h.store.path) as connection:
        payload = connection.execute("SELECT payload_json FROM drop_requests").fetchone()[0]
    assert "firstName" not in payload
    assert "lastName" not in payload
    assert "email" not in payload
    assert "subject-binding" not in payload


def test_lost_acknowledgement_recovers_with_same_dsar_idempotency_key(tmp_path) -> None:
    h = Harness(tmp_path)
    h.fail_after_submit = True
    with pytest.raises(DROPManagementConflict, match="intake is unavailable"):
        h.store.create_request(
            h.authority,
            expected_revision=0,
            idempotency_key="lost-ack",
        )
    recovered = h.store.create_request(
        h.authority,
        expected_revision=0,
        idempotency_key="lost-ack",
    )
    assert recovered.status == "PENDING"
    assert h.submit_calls == 2
    assert len(h.receipts) == 1


def test_future_dated_dsar_receipt_is_not_committed_and_can_recover(tmp_path) -> None:
    h = Harness(tmp_path)
    h.receipt_created_offset = 30

    with pytest.raises(DROPManagementConflict, match="receipt time is invalid"):
        h.store.create_request(
            h.authority,
            expected_revision=0,
            idempotency_key="future-receipt",
        )
    assert h.store.verify_integrity() is True

    h.now += 31
    recovered = h.store.create_request(
        h.authority,
        expected_revision=0,
        idempotency_key="future-receipt",
    )
    assert recovered.status == "PENDING"
    assert h.submit_calls == 2
    assert len(h.receipts) == 1


def test_delete_status_requires_independent_complete_evidence_and_replays(tmp_path) -> None:
    h = Harness(tmp_path)
    pending = h.store.create_request(h.authority, expected_revision=0, idempotency_key="create")
    deleted = h.store.update_status(
        h.authority,
        status="DELETED",
        expected_revision=pending.revision,
        idempotency_key="delete",
        actor_ref="operator-a",
    )
    replay = h.store.update_status(
        h.authority,
        status="DELETED",
        expected_revision=pending.revision,
        idempotency_key="delete",
        actor_ref="operator-a",
    )
    assert deleted == replay
    assert deleted.status == "DELETED"
    assert deleted.revision == 2
    assert deleted.outcome_evidence_sha256
    assert h.store.verify_integrity() is True


@pytest.mark.parametrize(
    "missing", ["deletion_verified", "search_complete", "provider_operations_complete"]
)
def test_delete_fails_closed_when_required_evidence_is_missing(tmp_path, missing) -> None:
    h = Harness(tmp_path)
    pending = h.store.create_request(h.authority, expected_revision=0, idempotency_key="create")
    base = h.evidence_resolver

    def incomplete(authority, receipt, status):
        evidence = base(authority, receipt, status)
        values = evidence.__dict__.copy()
        values[missing] = False
        values["evidence_binding_sha256"] = ""
        return DROPStatusEvidence(**values).normalized()

    h.evidence_resolver = incomplete
    with pytest.raises(DROPManagementConflict, match="not independently verified"):
        h.store.update_status(
            h.authority,
            status="DELETED",
            expected_revision=pending.revision,
            idempotency_key=f"missing-{missing}",
            actor_ref="operator-a",
        )


def test_terminal_evidence_must_be_observed_after_the_created_dsar(tmp_path) -> None:
    h = Harness(tmp_path)
    pending = h.store.create_request(h.authority, expected_revision=0, idempotency_key="create")
    base = h.evidence_resolver

    def predated(authority, receipt, status):
        evidence = base(authority, receipt, status)
        values = evidence.__dict__.copy()
        values["observed_at"] = receipt.created_at - 1
        values["evidence_binding_sha256"] = ""
        return DROPStatusEvidence(**values).normalized()

    h.evidence_resolver = predated
    with pytest.raises(DROPManagementConflict, match="binding changed"):
        h.store.update_status(
            h.authority,
            status="DELETED",
            expected_revision=pending.revision,
            idempotency_key="predated-evidence",
            actor_ref="operator-a",
        )


def test_request_type_and_four_eyes_are_enforced(tmp_path) -> None:
    h = Harness(tmp_path, request_type="OptOut")
    pending = h.store.create_request(h.authority, expected_revision=0, idempotency_key="create")
    with pytest.raises(DROPManagementConflict, match="deletion outcome"):
        h.store.update_status(
            h.authority,
            status="DELETED",
            expected_revision=pending.revision,
            idempotency_key="wrong-type",
            actor_ref="operator-a",
        )

    base = h.evidence_resolver

    def same_reviewer(authority, receipt, status):
        evidence = base(authority, receipt, status)
        values = evidence.__dict__.copy()
        values["reviewer_ref"] = "operator-a"
        values["evidence_binding_sha256"] = ""
        return DROPStatusEvidence(**values).normalized()

    h.evidence_resolver = same_reviewer
    with pytest.raises(DROPManagementConflict, match="binding changed"):
        h.store.update_status(
            h.authority,
            status="OPTED_OUT",
            expected_revision=pending.revision,
            idempotency_key="same-reviewer",
            actor_ref="operator-a",
        )


def test_four_eyes_rejects_aliases_bound_to_the_same_principal(tmp_path) -> None:
    h = Harness(tmp_path, request_type="OptOut")
    h.principal_aliases.update(
        {
            "operator-alias": "human-123",
            "reviewer-alias": "human-123",
        }
    )
    pending = h.store.create_request(h.authority, expected_revision=0, idempotency_key="create")
    base = h.evidence_resolver

    def aliased_reviewer(authority, receipt, status):
        evidence = base(authority, receipt, status)
        values = evidence.__dict__.copy()
        values["reviewer_ref"] = "reviewer-alias"
        values["evidence_binding_sha256"] = ""
        return DROPStatusEvidence(**values).normalized()

    h.evidence_resolver = aliased_reviewer
    with pytest.raises(DROPManagementConflict, match="binding changed"):
        h.store.update_status(
            h.authority,
            status="OPTED_OUT",
            expected_revision=pending.revision,
            idempotency_key="aliased-reviewer",
            actor_ref="operator-alias",
        )


def test_authority_drift_after_untrusted_status_resolver_is_rejected(tmp_path) -> None:
    h = Harness(tmp_path)
    pending = h.store.create_request(h.authority, expected_revision=0, idempotency_key="create")
    base = h.evidence_resolver

    def drift(authority, receipt, status):
        result = base(authority, receipt, status)
        h.current_authority = DROPRecordAuthority(
            **{
                **h.authority.__dict__,
                "record_revision": 2,
                "authority_sha256": "",
            }
        ).normalized()
        return result

    h.evidence_resolver = drift
    with pytest.raises(DROPManagementConflict, match="authority changed"):
        h.store.update_status(
            h.authority,
            status="DELETED",
            expected_revision=pending.revision,
            idempotency_key="drift",
            actor_ref="operator-a",
        )


def test_tenant_binding_mirror_tamper_and_retention_purge(tmp_path) -> None:
    h = Harness(tmp_path)
    h.store.create_request(h.authority, expected_revision=0, idempotency_key="create")
    other = DROPRecordAuthority(
        **{
            **h.authority.__dict__,
            "tenant_id": "tenant-b",
            "authority_sha256": "",
        }
    ).normalized()
    h.current_authority = other
    with pytest.raises(DROPManagementNotFound):
        h.store.get_request(other)
    h.current_authority = h.authority

    with sqlite3.connect(h.store.path) as connection:
        connection.execute("UPDATE drop_requests SET revision=99")
    assert h.store.verify_integrity() is False

    # Restore by recreating a clean harness, then expire and purge all bindings.
    clean = Harness(tmp_path / "clean")
    clean.store.create_request(clean.authority, expected_revision=0, idempotency_key="create")
    clean.now += 366 * 24 * 3_600
    assert clean.store.purge_expired() == 1
    with sqlite3.connect(clean.store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM drop_requests").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM drop_operations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM drop_audit").fetchone()[0] == 0


def test_get_rejects_semantically_forged_receipt_even_with_recomputed_hashes(tmp_path) -> None:
    h = Harness(tmp_path)
    h.store.create_request(h.authority, expected_revision=0, idempotency_key="create")
    with sqlite3.connect(h.store.path) as connection:
        raw = connection.execute("SELECT payload_json FROM drop_requests").fetchone()[0]
        payload = json.loads(raw)
        receipt_values = dict(payload["receipt"])
        receipt_values["subject_binding_sha256"] = _digest("forged-subject")
        receipt_values["receipt_sha256"] = ""
        forged_receipt = DROPDSARReceipt(**receipt_values).normalized()
        payload["receipt"] = asdict(forged_receipt)
        connection.execute(
            "UPDATE drop_requests SET payload_json=?,integrity_sha256=?",
            (
                drop_module._canonical(payload).decode("ascii"),
                drop_module._sha256(payload),
            ),
        )

    with pytest.raises(DROPManagementIntegrityError, match="receipt is misbound"):
        h.store.get_request(h.authority)
    assert h.store.verify_integrity() is False


def test_database_cannot_be_reopened_for_another_tenant(tmp_path) -> None:
    h = Harness(tmp_path)
    with pytest.raises(DROPManagementIntegrityError, match="another tenant"):
        DROPManagementStore(
            h.store.path,
            tenant_id="tenant-b",
            authority_resolver=lambda authority: authority,
            dsar_submitter=lambda _authority, _key: None,
            status_evidence_resolver=lambda _authority, _receipt, _status: None,
            principal_binding_resolver=lambda tenant, principal: _digest(f"{tenant}:{principal}"),
            maintenance_authorizer=lambda: True,
            config_gate=lambda: None,
            clock=lambda: h.now,
        )


@pytest.mark.parametrize("table", ["drop_requests", "drop_operations", "drop_audit"])
def test_direct_deletion_requires_maintenance_authority(tmp_path, table) -> None:
    h = Harness(tmp_path)
    h.store.create_request(h.authority, expected_revision=0, idempotency_key="create")
    with sqlite3.connect(h.store.path) as connection:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute(f"DELETE FROM {table}")
        assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] > 0
    assert h.store.verify_integrity() is True


def test_missing_audit_or_trigger_fails_integrity_and_blocks_purge(tmp_path) -> None:
    h = Harness(tmp_path)
    h.store.create_request(h.authority, expected_revision=0, idempotency_key="create")
    with sqlite3.connect(h.store.path) as connection:
        connection.execute("DROP TRIGGER drop_audit_no_delete")
        connection.execute("DELETE FROM drop_audit")
    assert h.store.verify_integrity() is False
    h.now += 366 * 24 * 3_600
    with pytest.raises(DROPManagementIntegrityError, match="integrity must pass"):
        h.store.purge_expired()
    with sqlite3.connect(h.store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM drop_requests").fetchone()[0] == 1


def test_non_ascii_tenant_ids_are_compared_not_crashed(tmp_path) -> None:
    # Tenant ids may be any NFC text. A workspace named with an accent works,
    # and an accented id from another workspace is the normal not-found.
    accented = Harness(tmp_path / "accented", tenant="atelier-café")
    created = accented.store.create_request(
        accented.authority, expected_revision=0, idempotency_key="create",
    )
    assert created.status == "PENDING"
    assert accented.store.verify_integrity() is True

    h = Harness(tmp_path / "plain")
    foreign = DROPRecordAuthority(
        **{**asdict(h.authority), "tenant_id": "tenant-é", "authority_sha256": ""}
    )
    with pytest.raises(DROPManagementNotFound):
        h.store.create_request(foreign, expected_revision=0, idempotency_key="foreign")


def test_product_boundaries_do_not_claim_external_acceptance(tmp_path) -> None:
    h = Harness(tmp_path)
    boundaries = h.store.product_boundaries()
    assert boundaries["network_io"] is False
    assert boundaries["live_drop_interoperability_verified"] is False
    assert boundaries["legal_acceptance_verified"] is False
    assert boundaries["permanent_external_effect_claimed"] is False
