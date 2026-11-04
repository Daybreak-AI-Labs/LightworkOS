"""End-to-end evidence for restoring a workspace into a virgin installation."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

import pytest
from maverick import backup, client, config, crypto_at_rest, file_lock
from maverick import workspace_recovery as recovery
from maverick.job_queue import JobQueue
from maverick.paths import data_dir
from maverick.tenant.kms import seal_text_for_tenant

_CREDENTIAL_DOCUMENTS = {
    "connections/connections.sealed": {
        "salesforce": {
            "name": "salesforce",
            "connector": "salesforce",
            "base_url": "https://example.salesforce.com",
            "token": "synthetic-source-token",
            "created": 1.0,
            "owner": "user:buyer",
            "access": "owner",
            "allowed_principals": [],
            "revision": "1" * 32,
        }
    },
    "connections/oauth-setup.sealed": {"applications": {}, "consents": {}},
    "oauth/tokens.sealed": {
        "synthetic": {
            "access_token": "synthetic-access-token",
            "refresh_token": "synthetic-refresh-token",
            "obtained_at": 1.0,
        }
    },
    "partner/tenants.sealed": [
        {
            "id": "tenant-a",
            "name": "Synthetic tenant",
            "base_url": "https://tenant.example",
            "token": "synthetic-partner-token",
        }
    ],
    "privacy_automation/evidence-keys.sealed": {"keys": {}, "operations": {}},
}


@pytest.fixture(autouse=True)
def isolated_bootstrap_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in (
        "MAVERICK_BACKUP_SIGNING_KEY",
        "MAVERICK_TENANT",
        "MAVERICK_WORLD_BACKEND",
        "MAVERICK_GOVERNED_RECORDS_BACKEND",
        "MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES",
        "MAVERICK_GRPC_DISPATCH_TARGET",
        "MAVERICK_PG_DSN",
        "MAVERICK_KNOWLEDGE_DSN",
        "MAVERICK_QUEUE_REDIS_DSN",
        "MAVERICK_ENCRYPTION_KEY",
        "MAVERICK_KMS_KEK",
        "QDRANT_URL",
        "REDIS_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(config, "config_source_errors", lambda **_: [])
    monkeypatch.setattr(crypto_at_rest, "per_tenant_at_rest", lambda: False)
    client.reset_client_cache()
    yield
    client.reset_client_cache()


def _select_home(monkeypatch, home: Path) -> Path:
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setattr(crypto_at_rest, "_KEY_PATH", home / "shared-keys" / "at_rest.key")
    client.reset_client_cache()
    root = data_dir()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _record(root: Path, namespace: str, value: dict, *, encrypted: bool = False) -> None:
    directory = file_lock.ensure_private_directory(root / namespace)
    payload = json.dumps(value, sort_keys=True).encode()
    destination = directory / f"{value['id']}.json"
    if encrypted:
        file_lock.atomic_create_bytes(destination, crypto_at_rest.seal(payload))
    else:
        file_lock.atomic_create_text(destination, payload.decode())


def _source_snapshot(
    monkeypatch, tmp_path: Path,
) -> tuple[Path, str, bytes, int, int, dict[str, str], str]:
    source = _select_home(monkeypatch, tmp_path / "source-home")
    key = bytes(range(32))
    file_lock.ensure_private_directory(crypto_at_rest._KEY_PATH.parent)
    file_lock.atomic_create_text(crypto_at_rest._KEY_PATH, key.hex())
    recovery_key = recovery.configure_key()["key"]

    _record(source, "vendor_management", {
        "id": "VMR-vendor",
        "schema": "lightwork.vendor-record.v1",
        "owner": "buyer",
        "name": "Synthetic Acme",
    })
    _record(source, "ai_vendor_risk", {
        "id": "AIV-assessment",
        "schema": "lightwork.ai-vendor-risk.v1",
        "tenant_sha256": hashlib.sha256(b"acme").hexdigest(),
        "vendor": "Synthetic Acme",
    }, encrypted=True)
    _record(source, "vendor_onboarding", {
        "id": "VON-case",
        "schema": "lightwork.vendor-onboarding.v1",
        "tenant": "acme",
        "owner": "buyer",
        "vendor_id": "VMR-vendor",
        "vendor_name": "Synthetic Acme",
        "assessment": {"id": "AIV-assessment"},
        "renewal_of": None,
    })
    credential_hashes = {}
    for relative, document in _CREDENTIAL_DOCUMENTS.items():
        credential = source.joinpath(*relative.split("/"))
        file_lock.ensure_private_directory(credential.parent)
        ciphertext = seal_text_for_tenant(
            "acme", json.dumps(document, sort_keys=True)
        )
        file_lock.atomic_create_bytes(
            credential,
            ciphertext,
        )
        credential_hashes[relative] = hashlib.sha256(ciphertext).hexdigest()
    wrapped_dek_sha256 = backup._sha256(source / "keys" / "dek.wrapped")

    queue = JobQueue()
    running_id = queue.enqueue("external-running", {"request": "may-have-run"})
    assert queue.claim() is not None
    pending_id = queue.enqueue("external-pending", {"request": "not-started"})

    snapshot = recovery.create()
    exported = tmp_path / "source-snapshot.tgz"
    file_lock.atomic_create_bytes(exported, recovery.download_path(snapshot["id"]).read_bytes())
    custody = recovery.export_encryption_keys()
    return (
        exported,
        recovery_key,
        custody,
        running_id,
        pending_id,
        credential_hashes,
        wrapped_dek_sha256,
    )


def test_virgin_bootstrap_restores_encrypted_links_and_reconciles_jobs(
    monkeypatch, tmp_path,
):
    (
        exported,
        recovery_key,
        custody,
        running_id,
        pending_id,
        credential_hashes,
        wrapped_dek_sha256,
    ) = _source_snapshot(monkeypatch, tmp_path)
    target = _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key(imported=recovery_key)
    imported = recovery.import_archive(exported)

    prepared = recovery.prepare_bootstrap(
        isolated=True, actor="admin-a", source_offline=True
    )
    assert prepared["state"] == "prepared"
    assert prepared["empty_state_sha256"] == recovery._live_state()["state_sha256"]
    custody_report = recovery.test_key_custody(
        imported["id"], custody,
        expected_sha256=imported["sha256"], actor="admin-a",
    )
    assert custody_report["outcome"] == "verified_supported_formats"
    installed = recovery.install_retained_keys(
        imported["id"], custody,
        expected_sha256=imported["sha256"],
        report_id=custody_report["report_id"],
        isolated=True,
        actor="admin-a",
    )
    assert installed["state"] == "installed" and installed["file_count"] == 1

    review = recovery.prepare_restore(imported["id"], isolated=True, actor="admin-a")
    assert review["restore_mode"] == "virgin_bootstrap"
    assert review["safety_snapshot"] is None
    restored = recovery.apply_restore(
        review["review"], review["target"], isolated=True, actor="admin-a"
    )
    assert restored["state"] == "reconciliation_required"
    assert restored["post_restore_verified"] is True
    marker = recovery._read_bootstrap(actor="admin-a")
    decryptor = recovery._bootstrap_record_decryptor(marker)
    for relative, expected in _CREDENTIAL_DOCUMENTS.items():
        credential = target.joinpath(*relative.split("/"))
        raw = credential.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == credential_hashes[relative]
        assert raw.startswith(crypto_at_rest._TENANT_MAGIC)
        assert json.loads(decryptor(raw, "acme", target)) == expected
    credential_report = restored["reconciliation"]["credentials"]
    assert credential_report["preserved_count"] == len(_CREDENTIAL_DOCUMENTS)
    assert credential_report["exact_ciphertext_preserved"] is True
    assert all(
        item["disposition"] == "preserved_exact_authenticated"
        for item in credential_report["items"]
    )
    assert {
        item["path"]: item["sha256"] for item in credential_report["items"]
    } == credential_hashes
    wrapped_dek = target / "keys" / "dek.wrapped"
    assert backup._sha256(wrapped_dek) == wrapped_dek_sha256
    assert credential_report["wrapped_dek_count"] == 1
    assert credential_report["wrapped_dek_authenticated_count"] == 1
    wrapped_receipt = next(
        item for item in restored["reconciliation"]["items"]
        if item["source"] == "keys/dek.wrapped"
    )
    assert wrapped_receipt["content_sha256"] == wrapped_dek_sha256
    assert wrapped_receipt["safe_source"] == {
        "kind": "file_sha256", "sha256": wrapped_dek_sha256,
    }
    assert wrapped_receipt["disposition"] == "preserved_exact_authenticated"
    assert recovery.bootstrap_reconciliation_pending() is True

    assessment = crypto_at_rest.unseal(
        (target / "ai_vendor_risk" / "AIV-assessment.json").read_bytes()
    )
    assert json.loads(assessment)["vendor"] == "Synthetic Acme"
    with backup.recovery_scope(target, "acme", recovery._key()):
        checked = backup.validate_backup_application(
            recovery.download_path(imported["id"]),
            _record_decryptor=recovery._bootstrap_record_decryptor(
                recovery._read_bootstrap(actor="admin-a")
            ),
        )
    assert checked["cases_checked"] == 1

    with pytest.raises(recovery.RecoveryError, match="reconciliation is unfinished"):
        JobQueue().claim()
    status = recovery.reconciliation_status(actor="admin-a")
    queued = [item for item in status["items"] if item["category"] == "queued_work"]
    assert status["unresolved"] == 2 and len(queued) == 2
    pending = next(item for item in queued if item["record_id"] == str(pending_id))
    running = next(item for item in queued if item["record_id"] == str(running_id))
    assert pending["requires_external_readback"] is False
    assert running["requires_external_readback"] is True

    with pytest.raises(recovery.RecoveryError, match="external readback"):
        recovery.resolve_reconciliation(
            running["id"], "external_effect_absent", evidence_reference="short",
            isolated=True, actor="admin-a",
        )
    recovery.resolve_reconciliation(
        pending["id"], "retire_and_create_new_request", evidence_reference=None,
        isolated=True, actor="admin-a",
    )
    recovery.resolve_reconciliation(
        running["id"], "external_effect_recorded",
        evidence_reference="provider receipt fixture 2026-09-09",
        isolated=True, actor="admin-a",
    )
    completed = recovery.complete_reconciliation(isolated=True, actor="admin-a")
    assert completed["state"] == "completed"
    assert completed["reconciliation"]["resolved_count"] == (
        3 + len(_CREDENTIAL_DOCUMENTS)
    )
    assert recovery.bootstrap_reconciliation_pending() is False
    recovery.assert_bootstrap_start_allowed()
    with sqlite3.connect(target / "jobs.db") as connection:
        rows = dict(connection.execute("SELECT id, status FROM jobs"))
    assert rows == {running_id: "failed", pending_id: "failed"}


def test_bootstrap_refuses_plaintext_or_unopenable_credential_stores(tmp_path):
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    credential = file_lock.ensure_private_directory(stage / "oauth") / "tokens.sealed"
    plaintext = json.dumps(_CREDENTIAL_DOCUMENTS["oauth/tokens.sealed"]).encode()
    file_lock.atomic_create_bytes(credential, plaintext)

    with pytest.raises(recovery.RecoveryError, match="not tenant encrypted"):
        recovery._reconcile_bootstrap_stage(
            stage,
            decryptor=lambda raw, tenant, workspace: raw,
            tenant="acme",
        )
    assert credential.read_bytes() == plaintext

    opaque = crypto_at_rest._TENANT_MAGIC + b"synthetic-invalid-ciphertext"
    file_lock.atomic_write_bytes(credential, opaque)

    def reject(_raw, _tenant, _workspace):
        raise recovery.RecoveryError(
            "An encrypted recovery record did not authenticate under the reviewed retained keys."
        )

    with pytest.raises(recovery.RecoveryError, match="did not authenticate"):
        recovery._reconcile_bootstrap_stage(
            stage,
            decryptor=reject,
            tenant="acme",
        )
    assert credential.read_bytes() == opaque


def test_wrapped_tenant_key_rotates_without_authenticated_ciphertext(
    tmp_path: Path,
) -> None:
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    wrapped = file_lock.ensure_private_directory(stage / "keys") / "dek.wrapped"
    payload = b"synthetic-untrusted-wrapped-key"
    file_lock.atomic_create_bytes(wrapped, payload)

    removed, report = recovery._reconcile_bootstrap_stage(stage)

    assert removed == {"keys/dek.wrapped"}
    assert not wrapped.exists()
    item = next(
        row for row in report["items"] if row["source"] == "keys/dek.wrapped"
    )
    assert item["content_sha256"] == hashlib.sha256(payload).hexdigest()
    assert item["state"] == "resolved"
    assert item["safe_state"] == "discarded_rotation_required"
    assert item["disposition"] == "fresh_rotation_required"
    assert item["safe_source"] == {"kind": "absent"}
    assert report["credentials"]["wrapped_dek_count"] == 1
    assert report["credentials"]["wrapped_dek_authenticated_count"] == 0


def test_wrapped_tenant_key_cannot_be_authenticated_by_an_injected_plaintext_reader(
    tmp_path: Path,
) -> None:
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    wrapped = file_lock.ensure_private_directory(stage / "keys") / "dek.wrapped"
    file_lock.atomic_create_bytes(wrapped, b"synthetic-untrusted-wrapped-key")
    credential = file_lock.ensure_private_directory(stage / "oauth") / "tokens.sealed"
    file_lock.atomic_create_bytes(
        credential,
        crypto_at_rest._TENANT_MAGIC + b"synthetic-untrusted-ciphertext",
    )
    plaintext = json.dumps(_CREDENTIAL_DOCUMENTS["oauth/tokens.sealed"]).encode()

    with pytest.raises(recovery.RecoveryError, match="wrapped tenant key did not authenticate"):
        recovery._reconcile_bootstrap_stage(
            stage,
            decryptor=lambda _raw, _tenant, _workspace: plaintext,
            tenant="acme",
        )

    assert wrapped.exists()
    assert credential.exists()


@pytest.mark.parametrize(
    "relative",
    ["partner/tenants.json", "partner/tenants.json.migrated-plaintext"],
)
def test_bootstrap_never_publishes_legacy_partner_plaintext(
    monkeypatch, tmp_path, relative,
):
    source = _select_home(monkeypatch, tmp_path / "source-home")
    source_credential = source.joinpath(*relative.split("/"))
    file_lock.ensure_private_directory(source_credential.parent)
    plaintext = json.dumps([
        {
            "id": "legacy-tenant",
            "base_url": "https://tenant.example",
            "token": "synthetic-plaintext-token",
        }
    ])
    file_lock.atomic_create_text(source_credential, plaintext)
    recovery_key = recovery.configure_key()["key"]
    snapshot = recovery.create()
    exported = tmp_path / (source_credential.name + ".tgz")
    file_lock.atomic_create_bytes(
        exported,
        recovery.download_path(snapshot["id"]).read_bytes(),
    )

    target = _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key(imported=recovery_key)
    imported = recovery.import_archive(exported)
    recovery.prepare_bootstrap(
        isolated=True,
        actor="admin-a",
        source_offline=True,
    )

    review = recovery.prepare_restore(
        imported["id"],
        isolated=True,
        actor="admin-a",
    )
    with pytest.raises(recovery.RecoveryError, match="legacy plaintext"):
        recovery.apply_restore(
            review["review"],
            review["target"],
            isolated=True,
            actor="admin-a",
        )
    target_credential = target.joinpath(*relative.split("/"))
    assert not target_credential.exists()
    assert recovery._live_state()["file_count"] == 0
    from maverick_dashboard import partner_store

    assert partner_store.list_tenants() == []


def test_bootstrap_completion_receipt_is_durable_before_start_gate_release(
    monkeypatch, tmp_path,
):
    _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key()
    prepared = recovery.prepare_bootstrap(
        isolated=True, actor="admin-a", source_offline=True
    )
    marker = recovery._read_bootstrap(actor="admin-a")
    recovery._write_bootstrap({
        **{key: value for key, value in marker.items() if key != "authentication"},
        "state": "reconciliation_required",
        "snapshot": "a" * 32,
        "safety_snapshot": None,
        "reconciliation": {
            "schema": 2,
            "items": [],
            "protected_authority": {
                "file_count": 0,
                "classified_count": 0,
                "classification_complete": True,
                "state_sha256": hashlib.sha256().hexdigest(),
            },
        },
    })
    original = recovery._write_bootstrap

    def fail_release(record):
        if record.get("state") == "completed":
            raise OSError("injected marker failure")
        return original(record)

    monkeypatch.setattr(recovery, "_write_bootstrap", fail_release)
    with pytest.raises(OSError, match="marker failure"):
        recovery.complete_reconciliation(isolated=True, actor="admin-a")
    assert recovery._last_restore()["state"] == "completed"
    assert recovery.bootstrap_reconciliation_pending() is True
    assert prepared["bootstrap_id"] == recovery._read_bootstrap()["bootstrap_id"]


def test_bootstrap_discards_task_file_resume_and_blocks_unknown_database(
    monkeypatch, tmp_path,
):
    _select_home(monkeypatch, tmp_path / "target-home")
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    task = file_lock.ensure_private_directory(
        stage / "task-file-recovery" / ("a" * 64)
    )
    manifest = task / "manifest.sealed"
    original = task / (("b" * 32) + "-" + ("c" * 64) + ".sealed")
    file_lock.atomic_create_bytes(manifest, b"MVKTEN1\napplying fixture")
    file_lock.atomic_create_bytes(original, b"MVKTEN1\noriginal fixture")
    mixed_case = file_lock.ensure_private_directory(
        stage / "Vendor_Onboarding"
    ) / (("d" * 32) + ".json")
    file_lock.atomic_create_text(mixed_case, json.dumps({
        "id": "d" * 32,
        "operation": {"state": "approved", "attempts": 0},
        "operation_history": [],
        "stage": "review_approved",
    }))
    unknown = stage / "future-authority.db"
    with sqlite3.connect(unknown) as connection:
        # A product database can use a table named jobs without being the
        # canonical JobQueue authority. It must be blocked as unknown rather
        # than parsed or mutated under the queue schema.
        connection.execute("CREATE TABLE jobs(value TEXT)")
        connection.execute("INSERT INTO jobs VALUES('pending')")

    removed, report = recovery._reconcile_bootstrap_stage(stage)
    assert removed == {
        "task-file-recovery/" + ("a" * 64) + "/manifest.sealed",
        "task-file-recovery/" + ("a" * 64) + "/" + ("b" * 32)
        + "-" + ("c" * 64) + ".sealed",
    }
    assert not task.exists() or not any(task.iterdir())
    retired = next(
        item for item in report["items"]
        if item["category"] == "task_file_recovery"
    )
    assert retired["state"] == "resolved"
    assert retired["safe_state"] == "discarded_before_publication"
    mixed_record = json.loads(mixed_case.read_text())
    assert mixed_record["operation"] is None
    assert mixed_record["stage"] == "review_approved"
    mixed_item = next(
        item for item in report["items"]
        if item["category"] == "vendor_operation"
    )
    assert mixed_item["safe_state"] == "invalidated"
    blocked = next(
        item for item in report["items"]
        if item["category"] == "unclassified_protected_authority"
    )
    assert blocked["source"] == "future-authority.db"
    assert blocked["safe_state"] == "global_start_blocked"
    assert blocked["state"] == "unresolved"
    assert report["protected_authority"]["classification_complete"] is True
    assert report["protected_authority"]["classified_count"] == 2


def test_completed_bootstrap_does_not_block_a_later_application_update(
    monkeypatch, tmp_path,
):
    _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key()
    recovery.prepare_bootstrap(isolated=True, actor="admin-a", source_offline=True)
    marker = recovery._read_bootstrap(actor="admin-a")
    recovery._write_bootstrap({
        **{key: value for key, value in marker.items() if key != "authentication"},
        "state": "completed",
        "completed_at": 1_800_000_000.0,
        "reconciliation_sha256": "d" * 64,
    })
    monkeypatch.setattr(recovery, "version", lambda: "later-version")
    monkeypatch.setattr(recovery, "application_identity", lambda: "later-build")
    assert recovery.bootstrap_reconciliation_pending() is False
    recovery.assert_bootstrap_start_allowed()


def test_bootstrap_never_admits_a_nonempty_target(monkeypatch, tmp_path):
    root = _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key()
    file_lock.atomic_create_text(root / "customer-work.json", "{}")
    with pytest.raises(recovery.RecoveryError, match="only before this workspace contains"):
        recovery.prepare_bootstrap(
            isolated=True, actor="admin-a", source_offline=True
        )
    assert not recovery._bootstrap_path().exists()


def test_retained_key_install_resumes_exact_bytes_after_completion_receipt_failure(
    monkeypatch, tmp_path,
):
    exported, recovery_key, custody, _, _, _, _ = _source_snapshot(monkeypatch, tmp_path)
    _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key(imported=recovery_key)
    imported = recovery.import_archive(exported)
    recovery.prepare_bootstrap(isolated=True, actor="admin-a", source_offline=True)
    report = recovery.test_key_custody(
        imported["id"], custody,
        expected_sha256=imported["sha256"], actor="admin-a",
    )
    original = recovery._write_bootstrap

    def fail_installed(record):
        retained = record.get("retained_keys")
        if isinstance(retained, dict) and retained.get("state") == "installed":
            raise OSError("injected installed-receipt failure")
        return original(record)

    monkeypatch.setattr(recovery, "_write_bootstrap", fail_installed)
    with pytest.raises(OSError, match="installed-receipt"):
        recovery.install_retained_keys(
            imported["id"], custody,
            expected_sha256=imported["sha256"],
            report_id=report["report_id"], isolated=True, actor="admin-a",
        )
    marker = recovery._read_bootstrap(actor="admin-a")
    assert marker["retained_keys"]["state"] == "installing"
    installed_sha256 = backup._sha256(crypto_at_rest._KEY_PATH)

    monkeypatch.setattr(recovery, "_write_bootstrap", original)
    result = recovery.install_retained_keys(
        imported["id"], custody,
        expected_sha256=imported["sha256"], report_id=report["report_id"],
        isolated=True, actor="admin-a",
    )
    assert result["state"] == "installed"
    assert backup._sha256(crypto_at_rest._KEY_PATH) == installed_sha256
    assert recovery._read_bootstrap(actor="admin-a")["retained_keys"]["state"] == "installed"


def test_hand_edited_non_ascii_key_file_is_refused_not_crashed(monkeypatch, tmp_path):
    exported, recovery_key, custody, _, _, _, _ = _source_snapshot(monkeypatch, tmp_path)
    _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key(imported=recovery_key)
    imported = recovery.import_archive(exported)
    recovery.prepare_bootstrap(isolated=True, actor="admin-a", source_offline=True)
    report = recovery.test_key_custody(
        imported["id"], custody,
        expected_sha256=imported["sha256"], actor="admin-a",
    )
    original = recovery._write_bootstrap

    def fail_installed(record):
        retained = record.get("retained_keys")
        if isinstance(retained, dict) and retained.get("state") == "installed":
            raise OSError("injected installed-receipt failure")
        return original(record)

    monkeypatch.setattr(recovery, "_write_bootstrap", fail_installed)
    with pytest.raises(OSError, match="installed-receipt"):
        recovery.install_retained_keys(
            imported["id"], custody,
            expected_sha256=imported["sha256"],
            report_id=report["report_id"], isolated=True, actor="admin-a",
        )
    monkeypatch.setattr(recovery, "_write_bootstrap", original)
    # An operator re-saves the key in an editor that adds a byte-order mark.
    key_text = crypto_at_rest._KEY_PATH.read_text(encoding="utf-8").strip()
    crypto_at_rest._KEY_PATH.write_text("﻿" + key_text, encoding="utf-8")

    with pytest.raises(recovery.RecoveryError, match="differs from the reviewed custody copy"):
        recovery.install_retained_keys(
            imported["id"], custody,
            expected_sha256=imported["sha256"], report_id=report["report_id"],
            isolated=True, actor="admin-a",
        )
    assert recovery._read_bootstrap(actor="admin-a")["retained_keys"]["state"] == "installing"


def test_retained_key_install_expiry_is_safe_and_reauthorization_preserves_receipt(
    monkeypatch, tmp_path,
):
    exported, recovery_key, custody, _, _, _, _ = _source_snapshot(monkeypatch, tmp_path)
    _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key(imported=recovery_key)
    imported = recovery.import_archive(exported)
    prepared = recovery.prepare_bootstrap(
        isolated=True, actor="admin-a", source_offline=True
    )
    report = recovery.test_key_custody(
        imported["id"], custody,
        expected_sha256=imported["sha256"], actor="admin-a",
    )
    monkeypatch.setattr(recovery.time, "time", lambda: prepared["expires_at"] + 1)
    with pytest.raises(recovery.RecoveryError, match="expired before key installation"):
        recovery.install_retained_keys(
            imported["id"], custody,
            expected_sha256=imported["sha256"], report_id=report["report_id"],
            isolated=True, actor="admin-a",
        )
    assert not crypto_at_rest._KEY_PATH.exists()

    now = time.time()
    monkeypatch.setattr(recovery.time, "time", lambda: now)
    recovery.prepare_bootstrap(isolated=True, actor="admin-a", source_offline=True)
    recovery.install_retained_keys(
        imported["id"], custody,
        expected_sha256=imported["sha256"], report_id=report["report_id"],
        isolated=True, actor="admin-a",
    )
    installed = recovery._read_bootstrap(actor="admin-a")
    expired = {
        **{key: value for key, value in installed.items() if key != "authentication"},
        "expires_at": now - 1,
    }
    recovery._write_bootstrap(expired)
    renewed = recovery.prepare_bootstrap(
        isolated=True, actor="admin-a", source_offline=True
    )
    assert renewed["expires_at"] > now
    assert renewed["retained_keys"]["state"] == "installed"
    assert recovery._installed_key_material(
        recovery._read_bootstrap(actor="admin-a")
    )["at_rest.key"]


@pytest.mark.parametrize("tampered_relative", [
    "vendor_management/.record-lookup-rebuild", "vendor_management/VMR-vendor.json",
])
def test_interrupted_bootstrap_restore_finalizes_only_exact_committed_state(
    monkeypatch, tmp_path, tampered_relative,
):
    exported, recovery_key, custody, _, _, _, _ = _source_snapshot(monkeypatch, tmp_path)
    target = _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key(imported=recovery_key)
    imported = recovery.import_archive(exported)
    recovery.prepare_bootstrap(isolated=True, actor="admin-a", source_offline=True)
    custody_report = recovery.test_key_custody(
        imported["id"], custody,
        expected_sha256=imported["sha256"], actor="admin-a",
    )
    recovery.install_retained_keys(
        imported["id"], custody,
        expected_sha256=imported["sha256"],
        report_id=custody_report["report_id"], isolated=True, actor="admin-a",
    )
    review = recovery.prepare_restore(imported["id"], isolated=True, actor="admin-a")
    original = recovery._write_bootstrap

    def lose_final_marker(record):
        if record.get("state") == "reconciliation_required":
            raise OSError("injected post-publication marker failure")
        return original(record)

    monkeypatch.setattr(recovery, "_write_bootstrap", lose_final_marker)
    with pytest.raises(OSError, match="post-publication"):
        recovery.apply_restore(
            review["review"], review["target"], isolated=True, actor="admin-a"
        )
    pending = recovery._read_bootstrap(actor="admin-a")
    assert pending["state"] == "restore_pending"
    assert pending["expected_live_state"] == recovery._live_state()
    assert pending["reconciliation"]["protected_authority"]["classification_complete"]
    assert recovery.bootstrap_reconciliation_pending() is True

    monkeypatch.setattr(recovery, "_write_bootstrap", original)
    changed = target.joinpath(*tampered_relative.split("/"))
    committed_bytes = changed.read_bytes()
    file_lock.atomic_write_bytes(changed, b"changed after signed publication")
    with pytest.raises(recovery.RecoveryError, match="neither the signed empty state nor the exact staged state"):
        recovery.resume_bootstrap_restore(isolated=True, actor="admin-a")
    assert recovery._read_bootstrap(actor="admin-a")["state"] == "restore_pending"
    file_lock.atomic_write_bytes(changed, committed_bytes)
    resumed = recovery.resume_bootstrap_restore(isolated=True, actor="admin-a")
    assert resumed["state"] == "reconciliation_required"
    assert resumed["outcome"] == "committed_state_verified"
    assert recovery.reconciliation_status(actor="admin-a")["unresolved"] == 2


@pytest.mark.parametrize("relative,marker_relative", [
    ("vendor_management/VMR-test.json", "vendor_management/.record-lookup-rebuild"),
    ("flows/runs/test.json", "flows/.run-index-rebuild"),
])
@pytest.mark.parametrize("existing_marker", [False, True])
def test_bootstrap_fingerprint_binds_actual_derived_marker_publication(
    monkeypatch, tmp_path, relative, marker_relative, existing_marker,
):
    root = _select_home(monkeypatch, tmp_path / "target-home")
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    source = stage.joinpath(*relative.split("/"))
    file_lock.ensure_private_directory(source.parent)
    file_lock.atomic_create_text(source, '{"id":"synthetic-canonical-row"}')
    staged_marker = stage.joinpath(*marker_relative.split("/"))
    if existing_marker:
        file_lock.ensure_private_directory(staged_marker.parent)
        file_lock.atomic_create_text(staged_marker, "retained marker bytes\n")
    signed_expected = recovery._staged_live_state(stage)
    expected = {
        path.relative_to(stage).as_posix(): (backup._sha256(path), path.stat().st_size)
        for path in stage.rglob("*") if path.is_file()
    }
    key = b"k" * 32
    with backup.recovery_scope(root, "acme", key):
        backup._apply_transaction(root, stage, expected, key=key, replace_existing=True)
    assert recovery._live_state() == signed_expected
    marker = root.joinpath(*marker_relative.split("/"))
    assert marker.read_bytes() == (
        staged_marker.read_bytes() if existing_marker else backup._DERIVED_REBUILD_MARKER_BYTES
    )
    file_lock.atomic_write_text(marker, "tampered derived marker\n")
    assert recovery._live_state() != signed_expected


def test_interrupted_bootstrap_restore_rolls_exact_empty_state_back_to_prepared(
    monkeypatch, tmp_path,
):
    _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key()
    recovery.prepare_bootstrap(isolated=True, actor="admin-a", source_offline=True)
    marker = recovery._read_bootstrap(actor="admin-a")
    pending = {
        **{key: value for key, value in marker.items() if key != "authentication"},
        "state": "restore_pending",
        "snapshot": "a" * 32,
        "archive_sha256": "b" * 64,
        "safety_snapshot": None,
        "review": "c" * 32,
        "restore_pending_at": time.time(),
    }
    recovery._write_bootstrap(pending)
    file_lock.atomic_create_text(recovery._store() / "review.json", "stale review")

    result = recovery.resume_bootstrap_restore(isolated=True, actor="admin-a")
    assert result == {
        "state": "prepared",
        "outcome": "rolled_back_to_empty",
        "retry_required": True,
    }
    assert recovery._read_bootstrap(actor="admin-a")["state"] == "prepared"
    assert not (recovery._store() / "review.json").exists()
    assert recovery._last_restore()["state"] == "rolled_back_to_empty"


@pytest.mark.parametrize("namespace,state", [
    ("starter_team_setups", "active"),
    ("starter_team_reviews", "confirmed"),
    ("starter_team_cases", "completed"),
    ("starter_team_schedules", "active"),
    ("starter_team_inbox", "approved"),
    ("starter_team_ticks", "started"),
    ("starter_team_runtime", "running"),
    ("starter_team_runtime_reviews", "approved"),
    ("starter_team_goal_bindings", "worker_admitted"),
])
def test_restored_starter_team_authority_cannot_release_normal_start(
    monkeypatch, tmp_path, namespace, state,
):
    """A signed old backup grants neither fresh approval nor replay permission."""
    root = _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key()
    recovery.prepare_bootstrap(isolated=True, actor="admin-a", source_offline=True)
    _record(root, namespace, {
        "id": "restored", "status": state, "owner": "user:alice",
        "idempotency_key": "already-dispatched", "goal_id": "native-goal-a",
        "approved_at": 1_800_000_000.0, "committed_usd": 5.0,
    })
    source = root / namespace / "restored.json"
    original = source.read_bytes()
    removed, reconciliation = recovery._reconcile_bootstrap_stage(root)
    assert removed == set()
    marker = recovery._read_bootstrap(actor="admin-a")
    recovery._write_bootstrap({
        **{key: value for key, value in marker.items() if key != "authentication"},
        "state": "reconciliation_required",
        "snapshot": "a" * 32,
        "safety_snapshot": None,
        "reconciliation": reconciliation,
    })
    item, = recovery.reconciliation_status(actor="admin-a")["items"]
    assert item["safe_state"] == "global_start_blocked"
    assert item["requires_external_readback"] is True
    assert recovery.bootstrap_reconciliation_pending() is True
    with pytest.raises(recovery.RecoveryError, match="reconciliation is unfinished"):
        recovery.assert_bootstrap_start_allowed()
    # No starter-team adapter exists; a generic evidence reference must not
    # release a restored approval, native-goal binding or occurrence receipt.
    for disposition in (
        "external_effect_absent", "external_effect_recorded", "retire_and_create_new_request",
    ):
        with pytest.raises(recovery.RecoveryError, match="cannot be safely rewritten"):
            recovery.resolve_reconciliation(
                item["id"], disposition,
                evidence_reference="synthetic current readback reference",
                isolated=True, actor="admin-a",
            )
    with pytest.raises(recovery.RecoveryError, match="Resolve all restored work"):
        recovery.complete_reconciliation(isolated=True, actor="admin-a")
    assert recovery.bootstrap_reconciliation_pending() is True
    assert recovery.reconciliation_status(actor="admin-a")["unresolved"] == 1
    assert source.read_bytes() == original


def test_reconciliation_refuses_source_tampering_before_and_after_disposition(
    monkeypatch, tmp_path,
):
    root = _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key()
    recovery.prepare_bootstrap(isolated=True, actor="admin-a", source_offline=True)
    case = file_lock.ensure_private_directory(root / "vendor_onboarding") / "case.json"
    file_lock.atomic_create_text(case, json.dumps({
        "id": "case-a",
        "operation": {
            "state": "executing",
            "attempts": 1,
            "idempotency_key": "operation-a",
        },
        "operation_history": [],
        "stage": "executing",
    }))
    _removed, reconciliation = recovery._reconcile_bootstrap_stage(root)
    marker = recovery._read_bootstrap(actor="admin-a")
    recovery._write_bootstrap({
        **{key: value for key, value in marker.items() if key != "authentication"},
        "state": "reconciliation_required",
        "snapshot": "a" * 32,
        "safety_snapshot": None,
        "reconciliation": reconciliation,
    })
    item = next(
        row for row in recovery.reconciliation_status(actor="admin-a")["items"]
        if row["category"] == "vendor_operation"
    )
    safe_bytes = case.read_bytes()

    file_lock.atomic_write_text(case, '{"tampered":true}')
    with pytest.raises(recovery.RecoveryError, match="changed after quarantine"):
        recovery.resolve_reconciliation(
            item["id"], "external_effect_recorded",
            evidence_reference="provider receipt 123",
            isolated=True, actor="admin-a",
        )
    assert recovery.reconciliation_status(actor="admin-a")["unresolved"] == 1

    file_lock.atomic_write_bytes(case, safe_bytes)
    recovery.resolve_reconciliation(
        item["id"], "external_effect_recorded",
        evidence_reference="provider receipt 123",
        isolated=True, actor="admin-a",
    )
    file_lock.atomic_write_text(case, '{"tampered_after_review":true}')
    with pytest.raises(recovery.RecoveryError, match="changed after quarantine"):
        recovery.complete_reconciliation(isolated=True, actor="admin-a")
    assert recovery.bootstrap_reconciliation_pending() is True


def test_interrupted_multi_key_install_resumes_only_the_exact_reviewed_set(
    monkeypatch, tmp_path,
):
    source = _select_home(monkeypatch, tmp_path / "source-home")
    primary = bytes(range(32))
    file_lock.ensure_private_directory(crypto_at_rest._KEY_PATH.parent)
    file_lock.atomic_create_text(crypto_at_rest._KEY_PATH, primary.hex())
    ring = file_lock.ensure_private_directory(crypto_at_rest._keyring_dir())
    rotation_material = [bytes([41]) * 32, bytes([73]) * 32]
    for material in rotation_material:
        name = crypto_at_rest._key_fingerprint(material).hex() + ".key"
        file_lock.atomic_create_text(ring / name, material.hex())
    recovery_key = recovery.configure_key()["key"]
    _record(source, "ai_vendor_risk", {
        "id": "AIV-rotated",
        "schema": "lightwork.ai-vendor-risk.v1",
        "tenant_sha256": hashlib.sha256(b"acme").hexdigest(),
        "vendor": "Synthetic rotated-key record",
    }, encrypted=True)
    snapshot = recovery.create()
    exported = tmp_path / "multi-key-source.tgz"
    file_lock.atomic_create_bytes(
        exported, recovery.download_path(snapshot["id"]).read_bytes()
    )
    custody = recovery.export_encryption_keys()

    _select_home(monkeypatch, tmp_path / "target-home")
    recovery.configure_key(imported=recovery_key)
    imported = recovery.import_archive(exported)
    recovery.prepare_bootstrap(isolated=True, actor="admin-a", source_offline=True)
    report = recovery.test_key_custody(
        imported["id"], custody,
        expected_sha256=imported["sha256"], actor="admin-a",
    )
    original_create = file_lock.atomic_create_text
    writes = 0

    def interrupt_second_key(path, content, *args, **kwargs):
        nonlocal writes
        candidate = Path(path)
        if candidate.name == "at_rest.key" or (
            candidate.parent.name == "at_rest.d" and candidate.suffix == ".key"
        ):
            writes += 1
            if writes == 2:
                raise OSError("injected second-key interruption")
        return original_create(path, content, *args, **kwargs)

    monkeypatch.setattr(file_lock, "atomic_create_text", interrupt_second_key)
    with pytest.raises(OSError, match="second-key interruption"):
        recovery.install_retained_keys(
            imported["id"], custody,
            expected_sha256=imported["sha256"], report_id=report["report_id"],
            isolated=True, actor="admin-a",
        )
    interrupted = recovery._read_bootstrap(actor="admin-a")
    assert interrupted["retained_keys"]["state"] == "installing"
    assert len(list(crypto_at_rest._KEY_PATH.parent.rglob("*.key"))) == 1

    monkeypatch.setattr(file_lock, "atomic_create_text", original_create)
    completed = recovery.install_retained_keys(
        imported["id"], custody,
        expected_sha256=imported["sha256"], report_id=report["report_id"],
        isolated=True, actor="admin-a",
    )
    assert completed["state"] == "installed" and completed["file_count"] == 3
    installed = recovery._installed_key_material(
        recovery._read_bootstrap(actor="admin-a")
    )
    assert set(installed) == {
        "at_rest.key",
        *(crypto_at_rest._key_fingerprint(value).hex() + ".key"
          for value in rotation_material),
    }
    assert installed["at_rest.key"] == primary
    for material in rotation_material:
        assert installed[crypto_at_rest._key_fingerprint(material).hex() + ".key"] == material
