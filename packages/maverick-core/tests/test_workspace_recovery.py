from __future__ import annotations

import io
import json
import os
import sqlite3
import subprocess
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick import backup, client, config, crypto_at_rest, file_lock, quotas
from maverick import workspace_recovery as recovery
from maverick.paths import data_dir, tenant_scope


@pytest.fixture(autouse=True)
def isolated_workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    for key in ("MAVERICK_BACKUP_SIGNING_KEY", "MAVERICK_TENANT", "MAVERICK_WORLD_BACKEND",
                "MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES",
                "MAVERICK_GRPC_DISPATCH_TARGET", "MAVERICK_PG_DSN", "MAVERICK_KNOWLEDGE_DSN",
                "MAVERICK_QUEUE_REDIS_DSN", "QDRANT_URL", "REDIS_URL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(config, "config_source_errors", lambda **_: [])
    monkeypatch.setattr(recovery, "application_identity", lambda: "test-build-one")
    monkeypatch.setattr(crypto_at_rest, "_KEY_PATH", tmp_path / "shared-keys" / "at_rest.key")
    client.reset_client_cache()
    root = data_dir()
    root.mkdir(parents=True)
    (root / "record.json").write_text('{"value":"original"}', encoding="utf-8")
    with sqlite3.connect(root / "world.db") as connection:
        connection.execute("CREATE TABLE evidence(value TEXT)")
        connection.execute("INSERT INTO evidence VALUES('original')")
    connection.close()
    yield root
    client.reset_client_cache()


def ready_snapshot():
    recovery.configure_key()
    return recovery.create()


@pytest.mark.parametrize("operation", ["drill", "prepare"])
def test_application_reference_failure_never_reports_accepted_or_prepares_live_restore(isolated_workspace, operation):
    directory = file_lock.ensure_private_directory(isolated_workspace / "vendor_onboarding")
    file_lock.atomic_write_text(directory / "VON-broken.json", json.dumps({
        "id": "VON-broken", "schema": "lightwork.vendor-onboarding.v1", "tenant": "acme",
        "owner": "buyer", "vendor_id": "VMR-missing", "assessment": None, "renewal_of": None,
    }))
    snapshot = ready_snapshot()
    assert snapshot["authenticated"] and snapshot["payload_verified"]
    before = (isolated_workspace / "record.json").read_bytes()
    with pytest.raises(backup.BackupError, match="vendor_id -> vendor_management/VMR-missing"):
        if operation == "drill":
            recovery.drill(snapshot["id"])
        else:
            recovery.prepare_restore(snapshot["id"], isolated=True, actor="administrator")
    assert (isolated_workspace / "record.json").read_bytes() == before
    assert len(recovery.list_snapshots()) == 1
    assert not (recovery._store() / "review.json").exists()
    assert not (recovery._store() / "last-restore.json").exists()
    assert recovery.drill_report(snapshot["id"], actor="local-operator")["state"] == "not_recorded"


def test_signed_comparison_is_paged_bound_and_does_not_authorize_restore(isolated_workspace):
    snapshot = ready_snapshot()
    quotas.UsageLedger().record("buyer", 35, 0, 0)
    for number in range(60):
        (isolated_workspace / f"added-{number:03d}.txt").write_text("private content")
    report = recovery.compare_snapshot(snapshot["id"], actor="admin-one", isolated=True)
    assert report["total_changes"] == 62 and report["protected_changes"] == 1
    assert report["restore_authorized"] is False and report["isolated"] is True
    assert len(report["items"]) == 50 and report["has_more"] is True
    page = recovery.comparison_page(snapshot["id"], report["report_id"], actor="admin-one", offset=50)
    assert len(page["items"]) == 12 and page["has_more"] is False
    assert next(row for row in page["items"] if row["path"] == "usage/ledger.json.lock")["protected"] is False
    payload = recovery.export_comparison(snapshot["id"], report["report_id"], actor="admin-one")
    document = json.loads(payload)
    with backup.recovery_scope(recovery._root(), "acme", recovery._key()):
        backup._verify_authentication(document, allow_unsigned=False, label="test comparison")
    assert len(document["items"]) == 62 and b"private content" not in payload
    assert not (recovery._store() / "review.json").exists()
    assert quotas.UsageLedger().usage("buyer")["dollars"] == 35
    with pytest.raises(backup.BackupError, match="reconciliation"):
        recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-one")
    assert len(recovery.list_snapshots()) == 1


def test_comparison_rejects_other_actor_replaced_report_and_modified_snapshot(isolated_workspace):
    snapshot = ready_snapshot()
    first = recovery.compare_snapshot(snapshot["id"], actor="admin-one", isolated=False)
    with pytest.raises(recovery.RecoveryError, match="account"):
        recovery.export_comparison(snapshot["id"], first["report_id"], actor="admin-two")
    second = recovery.compare_snapshot(snapshot["id"], actor="admin-one", isolated=False)
    with pytest.raises(recovery.RecoveryError, match="comparison changed"):
        recovery.comparison_page(snapshot["id"], first["report_id"], actor="admin-one")
    (isolated_workspace / "record.json").write_text("new current content")
    # Download remains explicitly historical evidence; it never refreshes its
    # timestamp/fingerprint or turns the previous observation into authority.
    saved = json.loads(recovery.export_comparison(snapshot["id"], second["report_id"], actor="admin-one"))
    assert saved["compared_at"] == second["compared_at"]
    assert saved["live_state_sha256"] == second["live_state_sha256"]
    assert saved["restore_authorized"] is False
    with recovery._archive(snapshot["id"]).open("ab") as stream:
        stream.write(b"changed archive bytes")
    with pytest.raises(recovery.RecoveryError, match="snapshot"):
        recovery.export_comparison(snapshot["id"], second["report_id"], actor="admin-one")


def test_comparison_refuses_tampering_wrong_build_and_oversize_without_losing_evidence(monkeypatch):
    snapshot = ready_snapshot()
    first = recovery.compare_snapshot(snapshot["id"], actor="admin-one", isolated=False)
    path = recovery._comparison_path(snapshot["id"])
    before = path.read_bytes()
    monkeypatch.setattr(recovery, "MAX_COMPARISON_BYTES", 1)
    with pytest.raises(recovery.RecoveryError, match="size limit"):
        recovery.compare_snapshot(snapshot["id"], actor="admin-one", isolated=False)
    assert path.read_bytes() == before
    monkeypatch.setattr(recovery, "MAX_COMPARISON_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(recovery, "application_identity", lambda: "another-build")
    with pytest.raises(recovery.RecoveryError, match="build"):
        recovery.export_comparison(snapshot["id"], first["report_id"], actor="admin-one")
    monkeypatch.setattr(recovery, "application_identity", lambda: "test-build-one")
    report = json.loads(before)
    report["restore_authorized"] = True
    path.write_text(json.dumps(report))
    with pytest.raises(recovery.RecoveryError, match="signed comparison"):
        recovery.export_comparison(snapshot["id"], first["report_id"], actor="admin-one")


def test_retiring_snapshot_removes_its_comparison():
    snapshot = ready_snapshot()
    recovery.compare_snapshot(snapshot["id"], actor="admin-one", isolated=False)
    comparison = recovery._comparison_path(snapshot["id"])
    recovery.retire(snapshot["id"], snapshot["sha256"])
    assert not comparison.exists()


@pytest.mark.parametrize("tampered", ["[]", '{"nested":' * 1500 + "null" + "}" * 1500])
def test_malformed_comparison_remains_a_recoverable_error(tampered):
    snapshot = ready_snapshot()
    report = recovery.compare_snapshot(snapshot["id"], actor="admin-one", isolated=False)
    recovery._comparison_path(snapshot["id"]).write_text(tampered)
    with pytest.raises(recovery.RecoveryError, match="comparison"):
        recovery.export_comparison(snapshot["id"], report["report_id"], actor="admin-one")


def test_setup_key_is_not_in_archive_and_cannot_accidentally_rotate():
    result = recovery.configure_key()
    assert len(result["key"]) == 64
    assert recovery.export_key() == result["key"]
    with pytest.raises(recovery.RecoveryError, match="already exists"):
        recovery.configure_key()
    snapshot = recovery.create()
    with backup.recovery_scope(recovery._root(), "acme", recovery._key()):
        manifest = backup.verify_backup(recovery._archive(snapshot["id"]))
    assert not any(name.startswith("backups/") for name in manifest["files"])
    assert manifest["recovery"]["tenant_id"] == "acme"


def test_operator_environment_key_cannot_be_downloaded(monkeypatch):
    monkeypatch.setenv("MAVERICK_BACKUP_SIGNING_KEY", bytes(range(32)).hex())
    with pytest.raises(recovery.RecoveryError, match="custodian"):
        recovery.export_key()


def test_shared_encryption_keys_require_separate_explicit_export(isolated_workspace):
    key = crypto_at_rest._KEY_PATH
    key.parent.mkdir()
    key.write_text(bytes(range(32)).hex())
    ring = key.parent / "at_rest.d"
    ring.mkdir()
    (ring / "0123456789abcdef.key").write_text(bytes(reversed(range(32))).hex())
    snapshot = ready_snapshot()
    assert not snapshot["contains_encryption_key"]
    assert recovery.encryption_custody()["local_key_files"] == 2
    with zipfile.ZipFile(io.BytesIO(recovery.export_encryption_keys())) as archive:
        assert archive.read("keys/at_rest.key") == key.read_bytes()
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["shared_key_material"] is True
        with backup.recovery_scope(isolated_workspace, "acme", recovery._key()):
            backup._verify_authentication(manifest, allow_unsigned=False, label="key export")
        assert len(manifest["files"]) == 2


def test_key_custody_export_never_creates_missing_key_material():
    recovery.configure_key()
    assert recovery.encryption_custody()["local_export_available"] is False
    with pytest.raises(recovery.RecoveryError, match="No readable local encryption"):
        recovery.export_encryption_keys()
    assert not crypto_at_rest._KEY_PATH.exists()


def test_unbound_root_never_exports_shared_administration(monkeypatch):
    monkeypatch.delenv("MAVERICK_CLIENT_ID")
    client.reset_client_cache()
    with pytest.raises(recovery.RecoveryError, match="named workspace"):
        recovery.status()


def test_drill_checks_real_restore_without_changing_live_data(isolated_workspace):
    snapshot = ready_snapshot()
    record = isolated_workspace / "record.json"
    record.write_text("changed", encoding="utf-8")
    result = recovery.drill(snapshot["id"])
    assert result["restored"] and result["post_restore_verified"]
    assert result["elapsed_seconds"] > 0
    assert result["file_count"] == 2
    assert result["live_workspace_changed"] is False
    assert record.read_text() == "changed"


def test_drill_retains_signed_historical_evidence_without_claiming_current_readiness(isolated_workspace, monkeypatch):
    snapshot = ready_snapshot()
    assert recovery.drill_report(snapshot["id"], actor="admin-one")["state"] == "not_recorded"
    performed = recovery.drill(snapshot["id"], actor="admin-one")
    loaded = recovery.drill_report(snapshot["id"], actor="admin-one")
    assert loaded["report_id"] == performed["report_id"] and loaded["current_build_matches"] is True
    assert loaded["completed_at"] == performed["completed_at"]
    assert loaded["snapshot_created_at"] == snapshot["created_at"]
    (isolated_workspace / "record.json").write_text("new current work")
    monkeypatch.setattr(recovery, "application_identity", lambda: "later-build")
    historical = recovery.drill_report(snapshot["id"], actor="admin-one")
    assert historical["current_build_matches"] is False
    assert historical["restore_authorized"] is False
    assert historical["completed_at"] == performed["completed_at"]
    payload = recovery.export_drill_report(snapshot["id"], performed["report_id"], actor="admin-one")
    signed = json.loads(payload)
    with backup.recovery_scope(recovery._root(), "acme", recovery._key()):
        backup._verify_authentication(signed, allow_unsigned=False, label="test drill report")
    assert signed["application_identity"] == "test-build-one"
    assert signed["external_stores_tested"] is False and "decryption" in signed["verification_scope"]
    assert (isolated_workspace / "record.json").read_text() == "new current work"
    assert not (recovery._store() / "review.json").exists()


def test_drill_evidence_rejects_other_actor_tampering_and_superseded_report():
    snapshot = ready_snapshot()
    first = recovery.drill(snapshot["id"], actor="admin-one")
    with pytest.raises(recovery.RecoveryError, match="account"):
        recovery.drill_report(snapshot["id"], actor="admin-two")
    recovery.drill(snapshot["id"], actor="admin-one")
    with pytest.raises(recovery.RecoveryError, match="report changed"):
        recovery.export_drill_report(snapshot["id"], first["report_id"], actor="admin-one")
    path = recovery._store() / (snapshot["id"] + ".drill.json")
    path.write_text('{"nested":' * 1500 + "null" + "}" * 1500)
    with pytest.raises(recovery.RecoveryError, match="signed drill report"):
        recovery.drill_report(snapshot["id"], actor="admin-one")


def test_retiring_snapshot_also_retires_its_drill_evidence():
    snapshot = ready_snapshot()
    recovery.drill(snapshot["id"])
    path = recovery._store() / (snapshot["id"] + ".drill.json")
    assert path.exists()
    recovery.retire(snapshot["id"], snapshot["sha256"])
    assert not path.exists()


def test_encrypted_draft_survives_restore_with_its_separately_custodied_key(isolated_workspace, monkeypatch):
    monkeypatch.setattr(crypto_at_rest, "per_tenant_at_rest", lambda: False)
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    crypto_at_rest._KEY_PATH.parent.mkdir()
    crypto_at_rest._KEY_PATH.write_text(bytes(range(32)).hex())
    draft = backup._filesystem_path(isolated_workspace / "draft-recovery" / ("a" * 64) / ("b" * 64 + ".draft"))
    draft.parent.mkdir(parents=True)
    draft.write_bytes(crypto_at_rest.seal(b'{"payload":{"title":"Unfinished fixture"}}'))
    snapshot = ready_snapshot()
    assert snapshot["contains_drafts"] and not snapshot["contains_encryption_key"]
    assert recovery.drill(snapshot["id"])["post_restore_verified"]
    draft.write_bytes(crypto_at_rest.seal(b'{"payload":{"title":"Later fixture"}}'))
    review = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin-a")
    assert json.loads(crypto_at_rest.unseal(draft.read_bytes()))["payload"]["title"] == "Unfinished fixture"


def test_live_restore_requires_real_isolated_mode():
    snapshot = ready_snapshot()
    with pytest.raises(recovery.RecoveryError, match="local recovery mode"):
        recovery.prepare_restore(snapshot["id"], isolated=False, actor="admin-a")


def custody_worker_fixture(monkeypatch):
    """Protocol-only fixture; actual fresh-process decryption is tested separately."""
    directories = []
    def execute(command, **kwargs):
        directory = Path(command[-1])
        directories.append(directory)
        assert kwargs["cwd"] == directory and kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["timeout"] == 90
        assert file_lock.private_path_is_restricted(directory, 0o700)
        for filename in ("request.json", "snapshot.tgz", "custody.zip", "recovery.key"):
            assert file_lock.private_path_is_restricted(directory / filename, 0o600)
        environment = kwargs["env"]
        assert environment["MAVERICK_HOME"] == str(directory / "home")
        assert not any(name.startswith("LIGHTWORK_") or name.endswith("_API_KEY") for name in environment)
        assert "MAVERICK_ENCRYPTION_KEY" not in environment and "MAVERICK_KMS_KEK" not in environment
        request = json.loads((directory / "request.json").read_text())
        assert backup._sha256(directory / "snapshot.tgz") == request["archive_sha256"]
        assert backup._sha256(directory / "custody.zip") == request["custody_sha256"]
        result = {"schema": 1, "application_identity": request["application_identity"],
                  "checks": [{"format": "binary-v1", "detected": 1, "verified": 1, "failed": 0, "unsupported": 0}],
                  "files_scanned": 1, "sqlite_columns_scanned": 0, "unexamined_files": 0,
                  "outcome": "verified_supported_formats", "fresh_process": True, "key_source": "uploaded-custody-copy",
                  "coverage_complete": False, "live_workspace_changed": False, "external_stores_tested": False,
                  "limits": ["Protocol fixture only; not a decryption acceptance result."]}
        file_lock.atomic_create_text(directory / "result.json", json.dumps(result))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(recovery.subprocess, "run", execute)
    return directories


def test_custody_permission_checks_distinguish_directories_from_files(tmp_path, monkeypatch):
    # Windows verifies owner-only ACLs without POSIX execute bits. Enforce the
    # caller's mode contract too so a directory checked as a 0600 file cannot
    # silently pass here and fail only on Linux.
    restricted = file_lock.private_path_is_restricted
    checked = set()

    def check_mode(path, mode=0o600):
        kind = "directory" if Path(path).is_dir() else "file"
        assert mode == (0o700 if kind == "directory" else 0o600)
        checked.add(kind)
        return restricted(path, mode)

    monkeypatch.setattr(file_lock, "private_path_is_restricted", check_mode)
    snapshot = ready_snapshot()
    upload = tmp_path / "uploaded.zip"
    upload.write_bytes(b"protocol-only-worker-fixture")
    directories = custody_worker_fixture(monkeypatch)
    recovery.test_key_custody(snapshot["id"], upload, expected_sha256=snapshot["sha256"], actor="admin-a")
    assert checked == {"directory", "file"}
    assert len(directories) == 1 and not directories[0].exists()


@pytest.mark.parametrize("memory_upload", [False, True])
def test_custody_report_bound_to_snapshot_actor_and_historical_build(tmp_path, monkeypatch, isolated_workspace, memory_upload):
    monkeypatch.setenv("LIGHTWORK_ENCRYPTION_KEY", "inherited-fixture-must-not-be-used")
    monkeypatch.setenv("MAVERICK_KMS_KEK", "inherited-fixture-must-not-be-used")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "inherited-fixture-must-not-be-used")
    snapshot = ready_snapshot()
    upload = tmp_path / "uploaded.zip"
    upload.write_bytes(b"protocol-only-worker-fixture")
    directories = custody_worker_fixture(monkeypatch)
    report = recovery.test_key_custody(snapshot["id"], upload.read_bytes() if memory_upload else upload,
                                      expected_sha256=snapshot["sha256"], actor="admin-a")
    assert report["restore_authorized"] is False and report["current_build_matches"] is True
    assert report["coverage_complete"] is False
    assert len(directories) == 1 and not directories[0].exists()
    assert (isolated_workspace / "record.json").read_text() == '{"value":"original"}'
    assert not (recovery._store() / "review.json").exists()
    saved = recovery.custody_test_report(snapshot["id"], actor="admin-a")
    assert saved["report_id"] == report["report_id"] and saved["completed_at"] == report["completed_at"]
    payload = json.loads(recovery.export_custody_test(snapshot["id"], report["report_id"], actor="admin-a"))
    with backup.recovery_scope(recovery._root(), "acme", recovery._key()):
        backup._verify_authentication(payload, allow_unsigned=False, label="test custody")
    with pytest.raises(recovery.RecoveryError, match="account"):
        recovery.custody_test_report(snapshot["id"], actor="admin-b")
    monkeypatch.setattr(recovery, "application_identity", lambda: "different-build")
    assert recovery.custody_test_report(snapshot["id"], actor="admin-a")["current_build_matches"] is False
    assert json.loads(recovery.export_custody_test(snapshot["id"], report["report_id"], actor="admin-a"))["completed_at"] == report["completed_at"]


@pytest.mark.parametrize("failure", ["timeout", "exit", "malformed", "forged_counts"])
def test_custody_failure_keeps_previous_report_and_cleans_private_job(tmp_path, monkeypatch, failure):
    snapshot = ready_snapshot()
    upload = tmp_path / "uploaded.zip"
    upload.write_bytes(b"protocol-only-worker-fixture")
    directories = custody_worker_fixture(monkeypatch)
    initial = recovery.test_key_custody(snapshot["id"], upload, expected_sha256=snapshot["sha256"], actor="admin-a")
    previous = (recovery._store() / (snapshot["id"] + ".custody-test.json")).read_bytes()
    execute = recovery.subprocess.run
    def fail(command, **kwargs):
        directory = Path(command[-1])
        if failure == "timeout":
            directories.append(directory)
            raise subprocess.TimeoutExpired(command, 90)
        result = execute(command, **kwargs)
        if failure == "exit":
            return SimpleNamespace(returncode=1)
        path = directory / "result.json"
        if failure == "malformed":
            path.write_text("[]")
        else:
            value = json.loads(path.read_text())
            value["checks"][0]["verified"] = 5
            path.write_text(json.dumps(value))
        return result
    monkeypatch.setattr(recovery.subprocess, "run", fail)
    with pytest.raises(recovery.RecoveryError):
        recovery.test_key_custody(snapshot["id"], upload, expected_sha256=snapshot["sha256"], actor="admin-a")
    assert len(directories) == 2 and not any(path.exists() for path in directories)
    assert (recovery._store() / (snapshot["id"] + ".custody-test.json")).read_bytes() == previous
    assert recovery.custody_test_report(snapshot["id"], actor="admin-a")["report_id"] == initial["report_id"]


def test_custody_changed_snapshot_replacement_and_retirement(tmp_path, monkeypatch):
    snapshot = ready_snapshot()
    upload = tmp_path / "uploaded.zip"
    upload.write_bytes(b"protocol-only-worker-fixture")
    directories = custody_worker_fixture(monkeypatch)
    with pytest.raises(recovery.RecoveryError, match="snapshot"):
        recovery.test_key_custody(snapshot["id"], upload, expected_sha256="0" * 64, actor="admin-a")
    assert not directories
    assert recovery.custody_test_report(snapshot["id"], actor="admin-a")["state"] == "not_recorded"
    first = recovery.test_key_custody(snapshot["id"], upload, expected_sha256=snapshot["sha256"], actor="admin-a")
    recovery.test_key_custody(snapshot["id"], upload, expected_sha256=snapshot["sha256"], actor="admin-a")
    with pytest.raises(recovery.RecoveryError, match="changed"):
        recovery.export_custody_test(snapshot["id"], first["report_id"], actor="admin-a")
    report_path = recovery._store() / (snapshot["id"] + ".custody-test.json")
    recovery.retire(snapshot["id"], snapshot["sha256"])
    assert not report_path.exists()


def test_custody_cleanup_failure_cannot_replace_previous_evidence(tmp_path, monkeypatch):
    snapshot = ready_snapshot()
    upload = tmp_path / "uploaded.zip"
    upload.write_bytes(b"protocol-only-worker-fixture")
    custody_worker_fixture(monkeypatch)
    recovery.test_key_custody(snapshot["id"], upload, expected_sha256=snapshot["sha256"], actor="admin-a")
    path = recovery._store() / (snapshot["id"] + ".custody-test.json")
    previous = path.read_bytes()
    temporary = backup._temporary_directory

    @contextmanager
    def refused_cleanup(*args, **kwargs):
        with temporary(*args, **kwargs) as directory:
            yield directory
        # The fixture removes its real files, then reproduces cleanup refusal.
        if kwargs.get("prefix") == "lw-custody-":
            raise OSError("synthetic cleanup refusal")

    monkeypatch.setattr(backup, "_temporary_directory", refused_cleanup)
    with pytest.raises(OSError, match="cleanup refusal"):
        recovery.test_key_custody(snapshot["id"], upload, expected_sha256=snapshot["sha256"], actor="admin-a")
    assert path.read_bytes() == previous


@pytest.mark.parametrize("field,value", [("items", None), ("snapshot", []), ("total_changes", "0")])
def test_signed_comparison_schema_errors_are_recoverable(field, value):
    snapshot = ready_snapshot()
    report = recovery.compare_snapshot(snapshot["id"], actor="admin-a", isolated=False)
    path = recovery._comparison_path(snapshot["id"])
    saved = json.loads(file_lock.atomic_read_text(path))
    saved[field] = value
    file_lock.atomic_write_text(path, json.dumps(backup._authenticate_for_write(saved, recovery._key())))
    with pytest.raises(recovery.RecoveryError, match="malformed"):
        recovery.comparison_page(snapshot["id"], report["report_id"], actor="admin-a")
    with pytest.raises(recovery.RecoveryError, match="malformed"):
        recovery.export_comparison(snapshot["id"], report["report_id"], actor="admin-a")


@pytest.mark.parametrize("field", ["application_identity", "report_id", "completed_at", "verification_scope"])
def test_signed_drill_missing_required_metadata_is_recoverable(field):
    snapshot = ready_snapshot()
    report = recovery.drill(snapshot["id"], actor="admin-a")
    path = recovery._store() / (snapshot["id"] + ".drill.json")
    saved = json.loads(file_lock.atomic_read_text(path))
    saved.pop(field)
    file_lock.atomic_write_text(path, json.dumps(backup._authenticate_for_write(saved, recovery._key())))
    with pytest.raises(recovery.RecoveryError, match="malformed"):
        recovery.drill_report(snapshot["id"], actor="admin-a")
    with pytest.raises(recovery.RecoveryError, match="malformed"):
        recovery.export_drill_report(snapshot["id"], report["report_id"], actor="admin-a")


def test_old_snapshot_cannot_refund_newer_usage_or_create_restore_review(monkeypatch):
    ledger = quotas.UsageLedger()
    ledger.record("buyer", 10, 0, 0)
    snapshot = ready_snapshot()
    ledger.record("buyer", 25, 0, 0)
    monkeypatch.setattr(quotas, "_quota_config", lambda: {
        "enforce": True, "max_dollars_per_day": 20, "max_tokens_per_day": 0,
    })
    assert quotas.over_quota("buyer") is not None
    with pytest.raises(backup.BackupError, match="accounting"):
        recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    assert not (recovery._store() / "review.json").exists()
    assert len(recovery.list_snapshots()) == 1
    assert ledger.usage("buyer")["dollars"] == 35
    assert quotas.over_quota("buyer") is not None
    assert recovery.drill(snapshot["id"])["restored"] is True
    assert ledger.usage("buyer")["dollars"] == 35


def test_apply_rechecks_accounting_before_consuming_review():
    ledger = quotas.UsageLedger()
    ledger.record("buyer", 10, 0, 0)
    snapshot = ready_snapshot()
    review = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    ledger.record("buyer", 25, 0, 0)
    with pytest.raises(backup.BackupError, match="accounting"):
        recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin-a")
    assert (recovery._store() / "review.json").exists()
    assert not (recovery._store() / "last-restore.json").exists()
    assert ledger.usage("buyer")["dollars"] == 35


def test_restore_bound_to_actor_target_and_single_review(isolated_workspace):
    snapshot = ready_snapshot()
    (isolated_workspace / "record.json").write_text("changed")
    extra = isolated_workspace / "after-snapshot.json"
    extra.write_text("must be rolled back")
    review = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    for actor, target in (("admin-b", review["target"]), ("admin-a", "wrong-target")):
        with pytest.raises(recovery.RecoveryError, match="review changed"):
            recovery.apply_restore(review["review"], target, isolated=True, actor=actor)
    result = recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin-a")
    assert result["restored"] and result["post_restore_verified"] and result["restart_required"]
    assert json.loads((isolated_workspace / "record.json").read_text()) == {"value": "original"}
    assert not extra.exists()
    assert recovery.inspect(result["safety_snapshot"])["payload_verified"]
    with pytest.raises(recovery.RecoveryError, match="unavailable"):
        recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin-a")


def test_restore_rejects_target_drift_before_any_change(isolated_workspace):
    snapshot = ready_snapshot()
    review = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    (isolated_workspace / "record.json").write_text("late writer")
    with pytest.raises(recovery.RecoveryError, match="files changed"):
        recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin-a")
    assert (isolated_workspace / "record.json").read_text() == "late writer"


def test_concurrent_restore_attempts_have_one_winner():
    snapshot = ready_snapshot()
    review = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    def restore():
        try:
            return recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin-a")["restored"]
        except recovery.RecoveryError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: restore(), range(2))) == [False, True]


def test_expired_review_and_changed_snapshot_do_not_touch_live_data(isolated_workspace, monkeypatch):
    snapshot = ready_snapshot()
    review = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    with monkeypatch.context() as patch:
        patch.setattr(recovery.time, "time", lambda: review["expires_at"] + 1)
        with pytest.raises(recovery.RecoveryError, match="review changed"):
            recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin-a")
    recovery._archive(snapshot["id"]).write_bytes(b"changed archive")
    with pytest.raises(backup.BackupError):
        recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin-a")
    assert (isolated_workspace / "record.json").read_text() == '{"value":"original"}'


def test_different_tenant_cannot_import_even_with_same_operator_key(monkeypatch):
    monkeypatch.setenv("MAVERICK_BACKUP_SIGNING_KEY", bytes(range(32)).hex())
    snapshot = recovery.create()
    path = recovery._archive(snapshot["id"])
    with tenant_scope(tenant="other"):
        with pytest.raises(recovery.RecoveryError, match="different workspace"):
            recovery.import_archive(path)


@pytest.mark.parametrize("operation", ["drill", "prepare"])
@pytest.mark.parametrize("changed", ["version", "application_identity"])
def test_cross_version_or_build_restore_blocks_before_application_mutation(isolated_workspace, monkeypatch, operation, changed):
    snapshot = ready_snapshot()
    before = {name: (isolated_workspace / name).read_bytes() for name in ("world.db", "record.json")}
    monkeypatch.setattr(recovery, changed, lambda: "unsupported-other-release")

    def forbidden(*args, **kwargs):
        raise AssertionError("incompatible snapshot reached restore publication")

    monkeypatch.setattr(backup, "_apply_transaction", forbidden)
    with pytest.raises(recovery.RecoveryError, match="different application.*reviewed"):
        if operation == "drill":
            recovery.drill(snapshot["id"])
        else:
            recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    assert {name: (isolated_workspace / name).read_bytes() for name in before} == before
    assert len(recovery.list_snapshots()) == 1
    assert not (recovery._store() / "review.json").exists()
    assert not (recovery._store() / "last-restore.json").exists()
    assert not (recovery._store() / (snapshot["id"] + ".drill.json")).exists()


@pytest.mark.parametrize("schema", [True, 2])
@pytest.mark.parametrize("operation", ["drill", "prepare"])
def test_unknown_recovery_binding_schema_blocks_before_review_or_drill(isolated_workspace, monkeypatch, schema, operation):
    metadata = recovery._metadata
    monkeypatch.setattr(recovery, "_metadata", lambda **kwargs: {**metadata(**kwargs), "schema": schema})
    snapshot = ready_snapshot()
    before = (isolated_workspace / "world.db").read_bytes()
    with pytest.raises(recovery.RecoveryError, match="verified workspace/version binding.*legacy administrator"):
        if operation == "drill":
            recovery.drill(snapshot["id"])
        else:
            recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    assert (isolated_workspace / "world.db").read_bytes() == before
    assert len(recovery.list_snapshots()) == 1
    assert not (recovery._store() / "review.json").exists()
    assert not (recovery._store() / "last-restore.json").exists()
    assert not (recovery._store() / (snapshot["id"] + ".drill.json")).exists()


def test_changed_build_after_review_blocks_with_actionable_diagnostic(isolated_workspace, monkeypatch):
    snapshot = ready_snapshot()
    review = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    before = (isolated_workspace / "world.db").read_bytes()
    review_bytes = (recovery._store() / "review.json").read_bytes()
    monkeypatch.setattr(recovery, "application_identity", lambda: "test-build-two")
    with pytest.raises(recovery.RecoveryError, match="different application build.*exact build.*reviewed"):
        recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin-a")
    assert (isolated_workspace / "world.db").read_bytes() == before
    assert (recovery._store() / "review.json").read_bytes() == review_bytes
    assert not (recovery._store() / "last-restore.json").exists()


def test_retirement_needs_current_bytes_and_protects_restore_safety_snapshot():
    snapshot = ready_snapshot()
    with pytest.raises(recovery.RecoveryError, match="changed"):
        recovery.retire(snapshot["id"], "0" * 64)
    review = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    safety = recovery.inspect(review["safety_snapshot"])
    with pytest.raises(recovery.RecoveryError, match="retained"):
        recovery.retire(safety["id"], safety["sha256"])
    another = recovery.create()
    assert recovery.retire(another["id"], another["sha256"])["retired"]


def test_full_payload_verification_rejects_truncated_archive():
    snapshot = ready_snapshot()
    path = recovery._archive(snapshot["id"])
    path.write_bytes(path.read_bytes()[:100])
    with pytest.raises(backup.BackupError):
        recovery.inspect(snapshot["id"])


def test_web_expansion_limit_is_enforced_without_changing_cli_limits(monkeypatch):
    snapshot = ready_snapshot()
    monkeypatch.setattr(recovery, "MAX_EXPANDED_BYTES", 64)
    with pytest.raises(backup.BackupError, match="expanded-size limit"):
        recovery.inspect(snapshot["id"])
    with backup.recovery_scope(recovery._root(), "acme", recovery._key()):
        assert backup.verify_backup(recovery._archive(snapshot["id"]))["files"]


def test_failed_post_restore_check_rolls_back_replaced_and_removed_files(isolated_workspace, monkeypatch):
    snapshot = ready_snapshot()
    (isolated_workspace / "record.json").write_text("new value")
    extra = isolated_workspace / "late.json"
    extra.write_text("new file")
    review = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    def fail_check(*_):
        raise backup.BackupError("injected post-restore failure")
    monkeypatch.setattr(backup, "_verify_restored", fail_check)
    with pytest.raises(backup.BackupError, match="injected"):
        recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin-a")
    assert (isolated_workspace / "record.json").read_text() == "new value"
    assert extra.read_text() == "new file"


def test_interrupted_confirmation_remains_visible_with_safety_snapshot(isolated_workspace, monkeypatch):
    snapshot = ready_snapshot()
    (isolated_workspace / "record.json").write_text("new value")
    review = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin-a")
    original = recovery.file_lock.atomic_write_text
    def lose_confirmation(path, value, **kwargs):
        if path.name == "last-restore.json" and json.loads(value).get("restored") is True:
            raise OSError("injected confirmation write failure")
        return original(path, value, **kwargs)
    monkeypatch.setattr(recovery.file_lock, "atomic_write_text", lose_confirmation)
    with pytest.raises(OSError, match="confirmation"):
        recovery.apply_restore(review["review"], review["target"], isolated=True, actor="admin-a")
    assert (isolated_workspace / "record.json").read_text() == '{"value":"original"}'
    receipt = recovery.status()["last_restore"]
    assert receipt["state"] == "completion_unconfirmed"
    assert receipt["safety_snapshot"] == review["safety_snapshot"]


@pytest.mark.parametrize("settings", [
    {"queue": {"backend": "arq"}}, {"knowledge": {"store": "pgvector"}},
    {"grpc_dispatch": {"target": "worker.example.test:7443"}},
])
def test_independent_workers_and_stores_block_restore(settings, monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: settings)
    assert recovery.restore_blockers()


def test_the_fresh_rehearsal_process_runs_the_same_application_code(tmp_path, monkeypatch):
    """The retained-key rehearsal child must import the code that is running,
    not another installed copy, or its identity check refuses every test.
    It still inherits no operator settings or credentials."""
    import importlib.util
    from pathlib import Path

    from maverick import workspace_recovery as recovery

    monkeypatch.setenv("PYTHONPATH", "/somewhere/else")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "00" * 32)
    environment = recovery._custody_environment(tmp_path, "tenant-a")
    roots = environment["PYTHONPATH"].split(os.pathsep)
    assert str(Path(importlib.util.find_spec("maverick").origin).parent.parent) in roots
    assert "/somewhere/else" not in roots
    assert "MAVERICK_ENCRYPTION_KEY" not in environment
