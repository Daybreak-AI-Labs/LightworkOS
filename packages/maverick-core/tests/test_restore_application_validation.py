"""Signed, byte-valid archives must also pass supported reference checks."""
from __future__ import annotations

import hashlib
import json

import pytest
from maverick import backup, file_lock

KEY = bytes(range(32))


def _write(root, namespace, record):
    directory = file_lock.ensure_private_directory(root / namespace)
    file_lock.atomic_write_text(directory / (record["id"] + ".json"), json.dumps(record))


def _seed(root, tenant="acme"):
    _write(root, "vendor_management", {"id": "VMR-vendor", "schema": "lightwork.vendor-record.v1",
                                       "owner": "buyer", "name": "Synthetic Acme"})
    _write(root, "ai_vendor_risk", {"id": "AIV-assessment", "schema": "lightwork.ai-vendor-risk.v1",
                                   "tenant_sha256": hashlib.sha256(tenant.encode()).hexdigest(), "vendor": "Synthetic Acme"})
    case = {"id": "VON-case", "schema": "lightwork.vendor-onboarding.v1", "tenant": tenant,
            "owner": "buyer", "vendor_id": "VMR-vendor", "vendor_name": "Synthetic Acme",
            "assessment": {"id": "AIV-assessment"},
            "renewal_of": None}
    _write(root, "vendor_onboarding", case)
    return case


def _archive(root, path, *, whole_home=False):
    with backup.recovery_scope(root, "acme", KEY, whole_home=whole_home):
        archive = backup.create_backup(path)
        assert backup.verify_backup(archive)["files"]
        return archive


@pytest.mark.parametrize(("field", "value", "reference"), [
    ("vendor_id", "VMR-missing", "vendor_id -> vendor_management/VMR-missing"),
    ("assessment", {"id": "AIV-missing"}, "assessment.id -> ai_vendor_risk/AIV-missing"),
    ("renewal_of", "VON-missing", "renewal_of -> vendor_onboarding/VON-missing"),
])
def test_valid_hash_restore_rejects_missing_reference_before_live_mutation(tmp_path, monkeypatch, field, value, reference):
    source, live = tmp_path / "source", tmp_path / "live"
    case = _seed(source)
    case[field] = value
    _write(source, "vendor_onboarding", case)
    archive = _archive(source, tmp_path / "snapshot.tgz")
    file_lock.ensure_private_directory(live)
    sentinel = live / "important.txt"
    file_lock.atomic_write_text(sentinel, "current live state")

    def forbidden(*args, **kwargs):
        raise AssertionError("invalid application state reached live recovery/application")

    monkeypatch.setattr(backup, "_recover_transactions", forbidden)
    monkeypatch.setattr(backup, "_apply_transaction", forbidden)
    with backup.recovery_scope(live, "acme", KEY), pytest.raises(backup.BackupError, match="application validation") as error:
        backup.restore_backup(archive, replace_existing=True, force=True)
    assert "vendor_onboarding/VON-case.json" in str(error.value)
    assert reference in str(error.value)
    assert sentinel.read_text() == "current live state"
    assert not (live / backup._RESTORE_TX_ROOT).exists()


def test_supported_reference_graph_restores(tmp_path):
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    archive = _archive(source, tmp_path / "snapshot.tgz")
    with backup.recovery_scope(live, "acme", KEY):
        backup.restore_backup(archive, replace_existing=True)
    assert json.loads((live / "vendor_onboarding/VON-case.json").read_text())["vendor_id"] == "VMR-vendor"


@pytest.mark.parametrize("namespace", ["vendor_management", "ai_vendor_risk"])
def test_existing_different_vendor_target_is_rejected_even_with_same_owner_and_tenant(tmp_path, namespace):
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    if namespace == "vendor_management":
        _write(source, namespace, {"id": "VMR-vendor", "schema": "lightwork.vendor-record.v1",
                                   "owner": "buyer", "name": "Different vendor"})
    else:
        _write(source, namespace, {"id": "AIV-assessment", "schema": "lightwork.ai-vendor-risk.v1",
                                   "tenant_sha256": hashlib.sha256(b"acme").hexdigest(), "vendor": "Different vendor"})
    archive = _archive(source, tmp_path / "snapshot.tgz")
    with backup.recovery_scope(live, "acme", KEY), pytest.raises(backup.BackupError, match="vendor.*binding"):
        backup.restore_backup(archive, replace_existing=True)
    assert not (live / "vendor_onboarding").exists()


def test_service_created_accepted_case_and_renewal_restore_and_reopen(tmp_path, monkeypatch):
    from maverick import audit, client, config
    from maverick.governed_operations import ServiceContext
    from maverick.paths import data_dir, tenant_scope
    from maverick.vendor_onboarding import VendorOnboardingService
    from maverick.vendor_onboarding_adapters import (
        EvidenceDocument,
        FakeGoogleDriveEvidence,
        FakeJiraTickets,
    )

    original_home = tmp_path / "original-home"
    file_lock.ensure_private_directory(original_home)
    config_path = original_home / "config.toml"
    config_path.write_text("[vendor_onboarding]\nenable=true\n[vendor_management]\nenable=true\n"
                           "[ai_vendor_risk]\nenable=true\n[model_risk_assurance]\nenable=true\n")
    monkeypatch.setenv("MAVERICK_HOME", str(original_home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(audit, "record", lambda *a, **kw: True)
    monkeypatch.setattr(audit, "record_global", lambda *a, **kw: True)
    config.reset_config_cache()
    client.reset_client_cache()
    now = 1_800_000_000.0
    ctx = ServiceContext("acme", "reviewer@example.test", "procurement", "reviewer@example.test", "jira",
                         human=True, authorization_role="operator", authorization_policy="operator-policy-v1",
                         budget_authority="tenant-budget-v1", workspace_authority="workspace-generation-1")
    docs = FakeGoogleDriveEvidence({("acme", "security-paper"): EvidenceDocument(
        "security-paper", "1", now - 86400,
        b"We do not train models on customer data. Data is encrypted at rest and in transit.",
    )})
    tickets = FakeJiraTickets()
    service = VendorOnboardingService(docs, tickets, lambda *a: True, clock=lambda: now)
    try:
        case = service.intake(ctx, "Synthetic Acme", "security-paper", "VEND", "Review limited pilot")
        case = service.collect_evidence(ctx, case["id"], case["revision"])
        case = service.assess(ctx, case["id"], case["revision"])
        case = service.review(ctx, case["id"], case["revision"], "approved", "Approved synthetic pilot")
        case = service.prepare_action(ctx, case["id"], case["revision"])
        case = service.approve_action(
            ctx,
            case["id"],
            case["revision"],
            case["operation"]["approval_card"]["binding_sha256"],
        )
        case = service.execute(ctx, case["id"])
        accepted = service.accept(ctx, case["id"], case["revision"], True, "Accepted synthetic deliverable")
        renewal = service.intake(ctx, "Synthetic Acme", "security-paper", "VEND", "Annual renewal",
                                 renewal_of=accepted["id"])
        with tenant_scope(tenant="acme"):
            archive = _archive(data_dir(), tmp_path / "snapshot.tgz")
        restored_home = tmp_path / "restored-home"
        with backup.recovery_scope(restored_home / "tenants/acme", "acme", KEY):
            report = backup.validate_backup_application(archive)
            assert report["cases_checked"] == 2 and report["coverage_complete"] is False
            backup.restore_backup(archive, replace_existing=True)
        monkeypatch.setenv("MAVERICK_HOME", str(restored_home))
        config.reset_config_cache()
        client.reset_client_cache()
        reopened = VendorOnboardingService(docs, tickets, lambda *a: True, clock=lambda: now)
        assert reopened.get(ctx, accepted["id"])["work_item"]["business_outcome"] == "accepted"
        assert reopened.get(ctx, renewal["id"])["renewal_of"] == accepted["id"]
        assert tickets.creates == 1  # Restore/reopening never repeats the external create.
    finally:
        config.reset_config_cache()
        client.reset_client_cache()


@pytest.mark.parametrize("location", ["archive", "live"])
def test_additive_restore_refuses_supported_stores_even_if_only_live_has_records(tmp_path, location):
    source, live = tmp_path / "source", tmp_path / "live"
    file_lock.ensure_private_directory(source)
    file_lock.atomic_write_text(source / "plain.txt", "snapshot")
    _seed(source if location == "archive" else live)
    archive = _archive(source, tmp_path / "snapshot.tgz")
    with backup.recovery_scope(live, "acme", KEY), pytest.raises(backup.BackupError, match="additive restore"):
        backup.restore_backup(archive)
    assert not (live / "plain.txt").exists()


@pytest.mark.parametrize("change", ["tenant", "schema", "owner", "assessment_tenant"])
def test_incompatible_reference_scope_fails_before_restore(tmp_path, change):
    source, live = tmp_path / "source", tmp_path / "live"
    case = _seed(source)
    if change == "assessment_tenant":
        _write(source, "ai_vendor_risk", {"id": "AIV-assessment", "schema": "lightwork.ai-vendor-risk.v1",
                                          "tenant_sha256": hashlib.sha256(b"other").hexdigest()})
    else:
        case[{"tenant": "tenant", "schema": "schema", "owner": "owner"}[change]] = "other"
        _write(source, "vendor_onboarding", case)
    archive = _archive(source, tmp_path / "snapshot.tgz")
    with backup.recovery_scope(live, "acme", KEY), pytest.raises(backup.BackupError, match="application validation"):
        backup.restore_backup(archive, replace_existing=True)
    assert not (live / "vendor_onboarding/VON-case.json").exists()


@pytest.mark.parametrize("marker", [b"MVKAR1\n", b"MVKAR2\n", b"MVKTEN1\n", b'"MVKAR1:'])
def test_encrypted_supported_record_requires_reviewed_decryption_validation(tmp_path, marker):
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    file_lock.atomic_write_bytes(source / "vendor_onboarding/VON-case.json", marker + b"sealed fixture")
    archive = _archive(source, tmp_path / "snapshot.tgz")
    with backup.recovery_scope(live, "acme", KEY), pytest.raises(backup.BackupError, match="encrypted.*custody"):
        backup.restore_backup(archive, replace_existing=True)
    assert not (live / "vendor_onboarding/VON-case.json").exists()


def test_whole_home_cannot_resolve_a_reference_from_another_tenant(tmp_path):
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source / "tenants/acme")
    _seed(source / "tenants/other", tenant="other")
    (source / "tenants/acme/vendor_management/VMR-vendor.json").unlink()
    archive = _archive(source, tmp_path / "snapshot.tgz", whole_home=True)
    with backup.recovery_scope(live, "acme", KEY, whole_home=True), pytest.raises(backup.BackupError) as error:
        backup.restore_backup(archive, replace_existing=True)
    assert "tenants/acme/vendor_onboarding/VON-case.json" in str(error.value)
    assert "VMR-vendor" in str(error.value)
    assert not (live / "tenants").exists()


@pytest.mark.parametrize("payload", [
    b'{"id":"VON-case","id":"VON-other","sensitive":"private fixture value"}',
    b'{"id":"VON-case","sensitive":NaN}',
    b'{"id":"VON-case","vendor_id":',
])
def test_unreadable_or_ambiguous_json_is_rejected_without_disclosing_payload(tmp_path, payload):
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    file_lock.atomic_write_bytes(source / "vendor_onboarding/VON-case.json", payload)
    archive = _archive(source, tmp_path / "snapshot.tgz")
    with backup.recovery_scope(live, "acme", KEY), pytest.raises(backup.BackupError, match="unambiguous JSON") as error:
        backup.restore_backup(archive, replace_existing=True)
    assert "private fixture value" not in str(error.value)
    assert not (live / "vendor_onboarding").exists()
