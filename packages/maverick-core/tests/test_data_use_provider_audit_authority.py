"""Focused no-network tests for durable provider-audit authority projection."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from maverick.data_use_provider_adapters import ProviderBindingStore
from maverick.data_use_provider_audit import DataUseProviderAuditStore
from maverick.data_use_provider_audit_authority import (
    DataUseProviderAuditAuthorityConflict,
    DataUseProviderAuditAuthorityIntegrityError,
    DataUseProviderAuditAuthorityNotFound,
    DataUseProviderAuditAuthorityStore,
    DataUseProviderAuditAuthorityValidationError,
)

from tests.test_data_use_governance import TENANT, Clock, _digest
from tests.test_data_use_provider_adapters import _enroll, _prepared


def _authority_store(
    tmp_path: Path,
    bindings: ProviderBindingStore,
    *,
    clock: Clock | None = None,
    name: str = "provider-audit-authority.sqlite",
) -> tuple[DataUseProviderAuditAuthorityStore, Clock]:
    selected_clock = clock or Clock()
    return (
        DataUseProviderAuditAuthorityStore(
            tmp_path / name,
            tenant_id=TENANT,
            binding_store=bindings,
            config_gate=lambda: None,
            clock=selected_clock,
        ),
        selected_clock,
    )


def _issue_read(
    authority: DataUseProviderAuditAuthorityStore,
    bindings: ProviderBindingStore,
    provider: str,
    **kwargs,
):
    binding = bindings.get_binding(TENANT, "native-customers")
    assert binding is not None
    return authority.issue_read_grant(
        provider_id=provider,
        binding_id="native-customers",
        expected_binding_revision=binding["revision"],
        expected_binding_sha256=binding["binding_sha256"],
        **kwargs,
    )


@pytest.mark.parametrize("provider", ["snowflake", "databricks"])
def test_real_adapter_result_finalizes_and_feeds_existing_audit_store(
    tmp_path: Path,
    provider: str,
) -> None:
    adapter, ir, bindings, _owner, _transport = _prepared(tmp_path, provider)
    authority, clock = _authority_store(tmp_path, bindings)
    forged_ir = json.loads(json.dumps(ir))
    forged_ir["desired_state"][0]["control_id"] = "forged-control"
    with pytest.raises(DataUseProviderAuditAuthorityValidationError, match="digest"):
        authority.stage_operation(
            provider_id=provider,
            binding_id="native-customers",
            operation_idempotency_sha256=_digest(f"{provider}-forged-ir"),
            control_ir=forged_ir,
            operation="apply",
            authority_revision=1,
            valid_until=4_000.0,
            retained_until=8_000.0,
            idempotency_key=f"stage-forged-{provider}",
        )
    operation_idem = _digest(f"{provider}-authority-real-adapter")
    staged = authority.stage_operation(
        provider_id=provider,
        binding_id="native-customers",
        operation_idempotency_sha256=operation_idem,
        control_ir=ir,
        operation="apply",
        authority_revision=7,
        valid_until=4_000.0,
        retained_until=8_000.0,
        idempotency_key=f"stage-{provider}",
    )
    assert staged == authority.stage_operation(
        provider_id=provider,
        binding_id="native-customers",
        operation_idempotency_sha256=operation_idem,
        control_ir=ir,
        operation="apply",
        authority_revision=7,
        valid_until=4_000.0,
        retained_until=8_000.0,
        idempotency_key=f"stage-{provider}",
    )
    assert (
        authority.get_control_authority_for_operation(
            provider,
            "native-customers",
            operation_idem,
        ).authority_id
        == staged.authority_id
    )

    result = adapter.apply_control_ir(ir, idempotency_sha256=operation_idem)
    assert result["adapter_id"] == f"{provider}-native"
    finalized = authority.finalize_operation(
        staged.authority_id,
        expected_revision=1,
        idempotency_key=f"finalize-{provider}",
    )
    assert finalized.state == "finalized"
    assert finalized.operation_result_sha256 is not None
    assert finalized.control_authority_sha256 is not None

    read_grant = _issue_read(
        authority,
        bindings,
        provider,
        capability_revision=4,
        valid_until=4_000.0,
        retained_until=8_000.0,
        expected_revision=0,
        idempotency_key=f"read-{provider}",
    )
    assert read_grant.capability == "provider_audit_read"
    assert (
        authority.get_current_read_grant(provider, "native-customers").grant_id
        == read_grant.grant_id
    )
    control = authority.resolve_control_authority(
        provider,
        "native-customers",
        operation_idem,
        result,
    )
    read = authority.resolve_read_authority(provider, "native-customers")
    assert control.authority_sha256 == finalized.control_authority_sha256
    assert read.authority_sha256 == read_grant.authority_sha256
    forged_result = dict(result)
    forged_result["result_sha256"] = _digest("forged-result")
    with pytest.raises(DataUseProviderAuditAuthorityConflict, match="not bound"):
        authority.resolve_control_authority(
            provider,
            "native-customers",
            operation_idem,
            forged_result,
        )

    audit_store = DataUseProviderAuditStore(
        tmp_path / f"provider-audit-{provider}.sqlite",
        tenant_id=TENANT,
        binding_store=bindings,
        control_authority_resolver=authority.resolve_control_authority,
        read_authority_resolver=authority.resolve_read_authority,
        config_gate=lambda: None,
        clock=clock,
    )
    expectation = audit_store.register_operation(
        provider_id=provider,
        binding_id="native-customers",
        operation_idempotency_sha256=operation_idem,
        audit_deadline=2_000.0,
        retained_until=6_000.0,
        idempotency_key=f"register-{provider}",
    )
    assert expectation.control_authority_sha256 == control.authority_sha256
    registered = authority.mark_registered(
        finalized.authority_id,
        expected_revision=finalized.revision,
        idempotency_key=f"registered-{provider}",
    )
    assert registered.state == "registered"
    assert registered.control_authority_sha256 == finalized.control_authority_sha256
    assert registered == authority.mark_registered(
        finalized.authority_id,
        expected_revision=finalized.revision,
        idempotency_key=f"registered-{provider}",
    )
    assert (
        authority.resolve_control_authority(
            provider,
            "native-customers",
            operation_idem,
            result,
        ).authority_sha256
        == control.authority_sha256
    )

    revoked = authority.revoke_control_authority(
        registered.authority_id,
        expected_revision=registered.revision,
        idempotency_key=f"revoke-control-{provider}",
    )
    assert revoked.state == "revoked"
    assert revoked == authority.revoke_control_authority(
        registered.authority_id,
        expected_revision=registered.revision,
        idempotency_key=f"revoke-control-{provider}",
    )
    with pytest.raises(DataUseProviderAuditAuthorityConflict, match="unavailable"):
        authority.resolve_control_authority(
            provider,
            "native-customers",
            operation_idem,
            result,
        )

    verification = authority.verify_integrity()
    assert verification.control_authorities == 1
    assert verification.read_grants == 1
    assert verification.history_records == 5
    stored = (tmp_path / "provider-audit-authority.sqlite").read_bytes()
    for raw in (
        TENANT.encode(),
        b"snowflakecomputing.com",
        b"ANALYST_ROLE",
        b"analyst-group",
        b"credential-key-1",
        b"Bearer ",
    ):
        assert raw not in stored


def test_recovery_skips_pending_and_recovers_later_complete_operation(
    tmp_path: Path,
) -> None:
    adapter, ir, bindings, _owner, _transport = _prepared(tmp_path, "snowflake")
    authority, _clock = _authority_store(tmp_path, bindings)
    pending_idem = _digest("pending-before-complete")
    complete_idem = _digest("complete-after-pending")
    pending = authority.stage_operation(
        provider_id="snowflake",
        binding_id="native-customers",
        operation_idempotency_sha256=pending_idem,
        control_ir=ir,
        operation="apply",
        authority_revision=1,
        valid_until=4_000.0,
        retained_until=8_000.0,
        idempotency_key="stage-pending",
    )
    bindings.claim_operation(
        tenant_id=TENANT,
        provider_id="snowflake",
        binding_id="native-customers",
        idempotency_sha256=pending_idem,
        request_sha256=_digest("pending-request"),
    )
    complete = authority.stage_operation(
        provider_id="snowflake",
        binding_id="native-customers",
        operation_idempotency_sha256=complete_idem,
        control_ir=ir,
        operation="apply",
        authority_revision=2,
        valid_until=4_001.0,
        retained_until=8_001.0,
        idempotency_key="stage-complete",
    )
    adapter.apply_control_ir(ir, idempotency_sha256=complete_idem)

    restarted, _ = _authority_store(tmp_path, bindings)
    recovered = restarted.recover_finalizable(limit=10)
    assert [item.authority_id for item in recovered] == [complete.authority_id]
    assert restarted.get_control_authority_record(pending.authority_id).state == "staged"
    assert restarted.recover_finalizable(limit=10) == ()


def test_recovery_cursor_prevents_persistent_pending_prefix_starvation(
    tmp_path: Path,
) -> None:
    adapter, ir, bindings, _owner, _transport = _prepared(tmp_path, "snowflake")
    authority, _clock = _authority_store(tmp_path, bindings)
    for index in range(2):
        operation_idem = _digest(f"persistent-pending-{index}")
        authority.stage_operation(
            provider_id="snowflake",
            binding_id="native-customers",
            operation_idempotency_sha256=operation_idem,
            control_ir=ir,
            operation="apply",
            authority_revision=index + 1,
            valid_until=4_000.0 + index,
            retained_until=8_000.0 + index,
            idempotency_key=f"stage-persistent-{index}",
        )
        bindings.claim_operation(
            tenant_id=TENANT,
            provider_id="snowflake",
            binding_id="native-customers",
            idempotency_sha256=operation_idem,
            request_sha256=_digest(f"pending-request-{index}"),
        )
    complete_idem = _digest("recoverable-after-persistent-prefix")
    complete = authority.stage_operation(
        provider_id="snowflake",
        binding_id="native-customers",
        operation_idempotency_sha256=complete_idem,
        control_ir=ir,
        operation="apply",
        authority_revision=3,
        valid_until=4_002.0,
        retained_until=8_002.0,
        idempotency_key="stage-after-prefix",
    )
    adapter.apply_control_ir(ir, idempotency_sha256=complete_idem)

    assert authority.recover_finalizable(limit=2) == ()
    restarted, _ = _authority_store(tmp_path, bindings)
    recovered = restarted.recover_finalizable(limit=2)
    assert [item.authority_id for item in recovered] == [complete.authority_id]
    assert restarted.verify_integrity().control_authorities == 3


def test_no_change_recovery_empties_expected_changes(tmp_path: Path) -> None:
    adapter, ir, bindings, _owner, transport = _prepared(tmp_path, "databricks")
    authority, _clock = _authority_store(tmp_path, bindings)
    operation_idem = _digest("no-change-recovery")
    staged = authority.stage_operation(
        provider_id="databricks",
        binding_id="native-customers",
        operation_idempotency_sha256=operation_idem,
        control_ir=ir,
        operation="apply",
        authority_revision=3,
        valid_until=4_000.0,
        retained_until=8_000.0,
        idempotency_key="stage-no-change",
    )
    transport.state = ir["desired_state_sha256"]
    result = adapter.apply_control_ir(ir, idempotency_sha256=operation_idem)
    restarted, clock = _authority_store(tmp_path, bindings)
    recovered = restarted.recover_finalizable()
    assert len(recovered) == 1
    assert recovered[0].authority_id == staged.authority_id
    assert recovered[0].no_change is True
    assert recovered[0].expected_changes == ()
    assert (
        restarted.resolve_control_authority(
            "databricks",
            "native-customers",
            operation_idem,
            result,
        ).expected_changes
        == ()
    )
    clock.value = 4_001.0
    with pytest.raises(DataUseProviderAuditAuthorityConflict, match="expired"):
        restarted.resolve_control_authority(
            "databricks",
            "native-customers",
            operation_idem,
            result,
        )


def test_read_grant_cas_revocation_rotation_expiry_and_binding_drift(
    tmp_path: Path,
) -> None:
    _adapter, _ir, bindings, _owner, _transport = _prepared(tmp_path, "snowflake")
    authority, clock = _authority_store(tmp_path, bindings)
    binding = bindings.get_binding(TENANT, "native-customers")
    assert binding is not None
    with pytest.raises(DataUseProviderAuditAuthorityConflict, match="issuance pins"):
        authority.issue_read_grant(
            provider_id="snowflake",
            binding_id="native-customers",
            expected_binding_revision=binding["revision"],
            expected_binding_sha256=_digest("wrong-binding"),
            capability_revision=1,
            valid_until=1_100.0,
            retained_until=2_000.0,
            expected_revision=0,
            idempotency_key="wrong-binding-pin",
        )
    grant = _issue_read(
        authority,
        bindings,
        "snowflake",
        capability_revision=1,
        valid_until=1_100.0,
        retained_until=2_000.0,
        expected_revision=0,
        idempotency_key="issue-read-1",
    )
    assert grant == _issue_read(
        authority,
        bindings,
        "snowflake",
        capability_revision=1,
        valid_until=1_100.0,
        retained_until=2_000.0,
        expected_revision=0,
        idempotency_key="issue-read-1",
    )
    with pytest.raises(DataUseProviderAuditAuthorityConflict, match="active"):
        _issue_read(
            authority,
            bindings,
            "snowflake",
            capability_revision=2,
            valid_until=1_200.0,
            retained_until=2_000.0,
            expected_revision=0,
            idempotency_key="issue-read-active-conflict",
        )
    with pytest.raises(DataUseProviderAuditAuthorityConflict, match="expected"):
        authority.revoke_read_grant(
            grant.grant_id,
            expected_revision=2,
            expected_integrity_sha256=grant.integrity_sha256,
            reason_sha256=_digest("bad-read-revision"),
            idempotency_key="bad-read-revision",
        )
    with pytest.raises(DataUseProviderAuditAuthorityConflict, match="expected"):
        authority.revoke_read_grant(
            grant.grant_id,
            expected_revision=1,
            expected_integrity_sha256=_digest("wrong-read-integrity"),
            reason_sha256=_digest("bad-read-integrity"),
            idempotency_key="bad-read-integrity",
        )
    revoked = authority.revoke_read_grant(
        grant.grant_id,
        expected_revision=1,
        expected_integrity_sha256=grant.integrity_sha256,
        reason_sha256=_digest("operator-revoked-read-1"),
        idempotency_key="revoke-read-1",
    )
    assert revoked.revoked is True
    assert revoked.revocation_reason_sha256 == _digest("operator-revoked-read-1")
    assert revoked == authority.revoke_read_grant(
        grant.grant_id,
        expected_revision=1,
        expected_integrity_sha256=grant.integrity_sha256,
        reason_sha256=_digest("operator-revoked-read-1"),
        idempotency_key="revoke-read-1",
    )
    with pytest.raises(DataUseProviderAuditAuthorityConflict, match="unavailable"):
        authority.resolve_read_authority("snowflake", "native-customers")
    with pytest.raises(DataUseProviderAuditAuthorityNotFound, match="does not exist"):
        authority.get_current_read_grant("snowflake", "native-customers")

    rotated = _issue_read(
        authority,
        bindings,
        "snowflake",
        capability_revision=2,
        valid_until=1_200.0,
        retained_until=2_000.0,
        expected_revision=0,
        idempotency_key="issue-read-2",
    )
    assert (
        authority.resolve_read_authority("snowflake", "native-customers").capability_revision == 2
    )
    _enroll(
        bindings,
        "snowflake",
        expected_revision=1,
        idempotency_key="rotate-binding-for-read-drift",
        credential_revision=2,
        key_id="credential-key-2",
    )
    with pytest.raises(DataUseProviderAuditAuthorityConflict, match="stale"):
        authority.resolve_read_authority("snowflake", "native-customers")
    assert authority.get_read_grant(rotated.grant_id).binding_revision == 1

    second_binding_store = ProviderBindingStore(tmp_path / "expiry-bindings.sqlite", clock=clock)
    _enroll(second_binding_store, "databricks", idempotency_key="enroll-expiry")
    expiry_store, _ = _authority_store(
        tmp_path,
        second_binding_store,
        clock=clock,
        name="expiry-authority.sqlite",
    )
    _issue_read(
        expiry_store,
        second_binding_store,
        "databricks",
        capability_revision=1,
        valid_until=1_010.0,
        retained_until=1_100.0,
        expected_revision=0,
        idempotency_key="issue-expiring",
    )
    clock.value = 1_011.0
    with pytest.raises(DataUseProviderAuditAuthorityConflict, match="unavailable"):
        expiry_store.resolve_read_authority("databricks", "native-customers")


def test_cross_tenant_integrity_tamper_and_retention_guards(tmp_path: Path) -> None:
    _adapter, _ir, bindings, _owner, _transport = _prepared(tmp_path, "snowflake")
    authority, clock = _authority_store(tmp_path, bindings)
    grant = _issue_read(
        authority,
        bindings,
        "snowflake",
        capability_revision=1,
        valid_until=1_010.0,
        retained_until=1_060.0,
        expected_revision=0,
        idempotency_key="issue-retained",
    )
    with pytest.raises(DataUseProviderAuditAuthorityIntegrityError, match="another tenant"):
        DataUseProviderAuditAuthorityStore(
            tmp_path / "provider-audit-authority.sqlite",
            tenant_id="tenant-beta",
            binding_store=bindings,
            config_gate=lambda: None,
            clock=clock,
        )
    with sqlite3.connect(tmp_path / "provider-audit-authority.sqlite") as connection:
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute(
                "DELETE FROM provider_audit_read_grants WHERE grant_id=?",
                (grant.grant_id,),
            )

    clock.value = 1_060.0
    purged = authority.purge_expired(cutoff=1_060.0)
    assert purged.read_grants == 1
    with pytest.raises(DataUseProviderAuditAuthorityNotFound):
        authority.get_read_grant(grant.grant_id)
    assert authority.verify_integrity().audit_events == 2

    second = _issue_read(
        authority,
        bindings,
        "snowflake",
        capability_revision=2,
        valid_until=1_100.0,
        retained_until=1_200.0,
        expected_revision=0,
        idempotency_key="issue-after-purge",
    )
    with sqlite3.connect(tmp_path / "provider-audit-authority.sqlite") as connection:
        connection.execute(
            "UPDATE provider_audit_read_grants SET payload_json='{}' WHERE grant_id=?",
            (second.grant_id,),
        )
    with pytest.raises(DataUseProviderAuditAuthorityIntegrityError, match="integrity"):
        authority.verify_integrity()
