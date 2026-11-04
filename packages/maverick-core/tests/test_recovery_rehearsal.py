"""Real subprocess custody checks; every archive, key and home is synthetic."""
from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

TENANT = "rehearsal-fixture"
PAYLOAD = "Synthetic private text never included in reports"


def _alter_snapshot(root, store, variant):
    from maverick import file_lock

    if variant == "tampered-ciphertext":
        path = store._path("1" * 64)
        raw = bytearray(file_lock.atomic_read_bytes(path))
        raw[-1] ^= 1
        file_lock.atomic_write_bytes(path, raw)
    if variant == "unknown-envelope":
        file_lock.atomic_create_bytes(root / "future.bin", b"MVKAR9\nunsupported")
    if variant == "malformed-text":
        with sqlite3.connect(root / "world.db") as database:
            database.execute("INSERT INTO turns VALUES ('MVKAR1:not-base64!')")
    if variant == "plaintext-only":
        for index in range(1, 4):
            store._path(str(index) * 64).unlink()
        with sqlite3.connect(root / "world.db") as database:
            database.execute("UPDATE turns SET content=?", (PAYLOAD,))


def _producer(directory: Path, variant: str) -> None:
    from maverick import backup, file_lock
    from maverick import crypto_at_rest as crypto
    from maverick import workspace_recovery as recovery
    from maverick.paths import data_dir
    from maverick_dashboard.draft_store import DraftStore

    source = directory / "source"
    file_lock.ensure_private_directory(source)
    os.environ.update(MAVERICK_HOME=str(source), MAVERICK_CONFIG=str(source / "config.toml"),
                      MAVERICK_CLIENT_ID=TENANT, MAVERICK_ENCRYPT_AT_REST="1")
    file_lock.atomic_create_text(source / "config.toml", "[encryption]\nat_rest=true\n")
    crypto._KEY_PATH = source / "separate-custody" / "at_rest.key"
    root = file_lock.ensure_private_directory(data_dir())
    store = DraftStore("a" * 64)
    rows = []
    for index, kind in enumerate(("v1", "v2", "tenant"), 1):
        if kind == "v2":
            crypto.rotate_at_rest_key()
        if kind == "tenant":
            os.environ["MAVERICK_ENCRYPT_PER_TENANT"] = "1"
        store.save(str(index) * 64, {"title": PAYLOAD}, expected_revision=0, operation_id="fixture-" + kind)
        rows.append((crypto.seal_to_str(PAYLOAD),))
    with sqlite3.connect(root / "world.db") as database:
        if variant == "wal-database":
            database.execute("PRAGMA journal_mode=WAL")
        database.execute("CREATE TABLE turns(content TEXT)")
        database.executemany("INSERT INTO turns VALUES (?)", rows)
    # A restored primary and provider configuration must never become custody.
    file_lock.atomic_create_text(root / "keys" / "at_rest.key", "00" * 32)
    file_lock.atomic_create_text(root / "config.toml", "[kms]\nprovider='aws'\n")
    file_lock.atomic_create_text(root / "plain.json", json.dumps({"value": PAYLOAD}))
    _alter_snapshot(root, store, variant)
    recovery.configure_key()
    signed_key = recovery._key()
    archive = recovery.create()
    custody = recovery.export_encryption_keys()
    if variant in {"missing-primary", "missing-rotation", "wrong-primary", "wrong-tenant", "bad-fingerprint", "bad-key-size", "duplicate-member", "extra-member", "bad-hmac", "oversize-member"}:
        with zipfile.ZipFile(io.BytesIO(custody)) as source_zip:
            members = {name: source_zip.read(name) for name in source_zip.namelist()}
        manifest = json.loads(members["manifest.json"])
        if variant == "wrong-tenant":
            manifest["workspace"] = "different-workspace"
        for name in list(manifest["files"]):
            if (variant == "missing-primary" and name == "at_rest.key") or (variant == "missing-rotation" and name != "at_rest.key"):
                del manifest["files"][name]
                del members["keys/" + name]
            elif (variant == "wrong-primary" and name == "at_rest.key") or (variant == "bad-fingerprint" and name != "at_rest.key") or variant == "bad-key-size":
                raw = (b"00" * 32) if variant != "bad-key-size" else b"00"
                members["keys/" + name] = raw
                manifest["files"][name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        manifest = backup._authenticate_for_write(manifest, signed_key)
        if variant == "bad-hmac":
            manifest["authentication"]["signature"] = "0" * 64
        members["manifest.json"] = json.dumps(manifest).encode()
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as destination:
            for name, raw in members.items():
                destination.writestr(name, raw)
            if variant == "duplicate-member":
                destination.writestr("README.txt", b"duplicate")
            if variant == "extra-member":
                destination.writestr("../unexpected.key", b"outside")
            if variant == "oversize-member":
                destination.writestr("oversize", b"x" * (5 * 1024 * 1024))
        custody = output.getvalue()
    job = file_lock.ensure_private_directory(directory / "job")
    environment = recovery._custody_environment(job, TENANT)
    file_lock.atomic_create_bytes(job / "snapshot.tgz", file_lock.atomic_read_bytes(recovery._archive(archive["id"])))
    file_lock.atomic_create_bytes(job / "custody.zip", custody)
    file_lock.atomic_create_text(job / "recovery.key", signed_key.hex())
    request = {"schema": 1, "tenant": TENANT, "archive_sha256": backup._sha256(job / "snapshot.tgz"),
               "custody_sha256": hashlib.sha256(custody).hexdigest(), "application_identity": recovery.application_identity(),
               "application_version": recovery.version()}
    if variant == "bad-archive-digest":
        request["archive_sha256"] = "0" * 64
    if variant == "bad-custody-digest":
        request["custody_sha256"] = "0" * 64
    if variant == "wrong-build":
        request["application_identity"] = "source-sha256:" + "0" * 64
    file_lock.atomic_create_text(job / "request.json", json.dumps(request))
    file_lock.atomic_create_text(directory / "environment.json", json.dumps(environment))


@pytest.fixture
def run_worker(tmp_path):
    def run(variant="complete"):
        directory = tmp_path / variant
        directory.mkdir()
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("MAVERICK_", "LIGHTWORK_"))}
        # Keep producer imports from resolving any existing operator home.
        environment.update(MAVERICK_HOME=str(directory / "bootstrap"),
                           MAVERICK_CONFIG=str(directory / "bootstrap" / "config.toml"),
                           MAVERICK_CLIENT_ID=TENANT)
        producer = subprocess.run([sys.executable, str(Path(__file__).absolute()), "--produce", str(directory), variant],
                                  env=environment, capture_output=True, timeout=60)
        assert producer.returncode == 0, producer.stderr.decode(errors="replace")
        job = directory / "job"
        before = {p.relative_to(directory / "source").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in (directory / "source").rglob("*") if p.is_file()}
        child_env = json.loads((directory / "environment.json").read_text())
        if variant == "inherited-key":
            child_env["LIGHTWORK_ENCRYPTION_KEY"] = "00" * 32
        if variant == "hardlinked-custody":
            os.link(job / "custody.zip", directory / "custody-alias.zip")
        if variant == "nonempty-home":
            from maverick import file_lock

            file_lock.atomic_create_text(job / "home" / "operator-state.txt", "synthetic")
        result = subprocess.run([sys.executable, "-m", "maverick.recovery_rehearsal", str(job)],
                                cwd=job, env=child_env, capture_output=True, timeout=60)
        assert result.stdout == b"" and result.stderr == b""
        report = json.loads((job / "result.json").read_text())
        assert PAYLOAD not in json.dumps(report) and str(directory) not in json.dumps(report)
        assert before == {p.relative_to(directory / "source").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in (directory / "source").rglob("*") if p.is_file()}
        return result.returncode, report, job
    return run


@pytest.mark.parametrize("variant", ["missing-primary", "missing-rotation", "wrong-primary", "tampered-ciphertext"])
def test_missing_or_wrong_keys_and_tampering_fail_without_generating_custody(run_worker, variant):
    code, report, job = run_worker(variant)
    assert code == 0 and report["outcome"] == "failed"
    expected_failures = {"missing-primary": 4, "missing-rotation": 2, "wrong-primary": 4, "tampered-ciphertext": 1}
    assert sum(row["failed"] for row in report["checks"]) == expected_failures[variant]
    assert sum(row["verified"] for row in report["checks"]) == 6 - expected_failures[variant]
    if variant == "missing-primary":
        assert not (job / "encryption-keys" / "at_rest.key").exists()
    if variant == "missing-rotation":
        assert not list((job / "encryption-keys").rglob("at_rest.d/*.key"))


@pytest.mark.parametrize("variant", ["wrong-tenant", "bad-fingerprint", "bad-key-size", "duplicate-member", "extra-member",
                                    "bad-hmac", "oversize-member", "bad-archive-digest", "bad-custody-digest", "wrong-build",
                                    "inherited-key", "hardlinked-custody", "nonempty-home"])
def test_invalid_inputs_are_generic_failures_before_custody_install(run_worker, variant):
    code, report, job = run_worker(variant)
    assert code == 1 and report["outcome"] == "failed"
    assert not (job / "encryption-keys").exists()


def test_complete_custody_decrypts_actual_drafts_and_world_text_in_fresh_process(run_worker):
    from maverick import workspace_recovery as recovery

    code, report, job = run_worker()
    assert code == 0 and report["outcome"] == "verified_supported_formats"
    recovery._validate_custody_result(report)
    assert report["fresh_process"] is True and report["coverage_complete"] is False
    assert report["live_workspace_changed"] is False and report["external_stores_tested"] is False
    assert report["key_source"] == "uploaded-custody-copy"
    by_format = {row["format"]: row for row in report["checks"]}
    for label in ("raw-v1", "raw-v2", "raw-tenant-local", "world-text-v1", "world-text-v2", "world-text-tenant-local"):
        assert by_format[label]["verified"] == 1
    assert report["sqlite_columns_scanned"] == 1 and report["unexamined_files"] > 0
    assert (job / "encryption-keys" / "at_rest.key").read_text().strip() != "00" * 32


def test_real_wal_restore_generated_sidecars_remain_private_and_decryption_completes(run_worker):
    from maverick import backup, file_lock

    code, report, job = run_worker("wal-database")
    assert code == 0 and report["outcome"] == "verified_supported_formats"
    assert sum(row["verified"] for row in report["checks"]) == 6
    root = backup._filesystem_path(job / "home" / "tenants" / TENANT)
    sidecars = list(root.glob("world.db-?*"))
    assert sidecars, "The fixture must exercise real SQLite-generated WAL or SHM files"
    assert all(file_lock.private_path_is_restricted(path) for path in sidecars)


@pytest.mark.parametrize("variant", ["unknown-envelope", "malformed-text"])
def test_unrecognized_markers_are_not_counted_as_plaintext_success(run_worker, variant):
    code, report, _ = run_worker(variant)
    assert code == 0 and report["outcome"] == "incomplete"
    assert sum(row["unsupported"] for row in report["checks"]) == 1


def test_plaintext_and_wrapped_keys_are_not_encrypted_record_verification(run_worker):
    code, report, _ = run_worker("plaintext-only")
    assert code == 0 and report["outcome"] == "no_encrypted_records"
    assert sum(row["detected"] for row in report["checks"]) == 0
    assert report["unexamined_files"] > 0


def test_audit_hook_rejects_socket_creation_and_process_launch_in_a_real_child():
    script = """
import json, socket, subprocess, sys
from maverick.recovery_rehearsal import _deny_external
sys.addaudithook(_deny_external)
rejected = []
for operation in (lambda: socket.socket(), lambda: subprocess.run([sys.executable, '-c', 'pass'])):
    try:
        operation()
    except PermissionError:
        rejected.append(True)
    else:
        rejected.append(False)
print(json.dumps(rejected))
"""
    completed = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=10)
    assert completed.returncode == 0 and completed.stderr == b""
    assert json.loads(completed.stdout) == [True, True]


def test_scan_limit_yields_incomplete_without_attempting_decryption(tmp_path, monkeypatch):
    from maverick import file_lock
    from maverick import recovery_rehearsal as worker

    file_lock.ensure_private_directory(tmp_path)
    file_lock.atomic_create_bytes(tmp_path / "encrypted.bin", b"MVKAR1\ntruncated")
    scanner = worker._Scanner(tmp_path, TENANT, {}, worker._result("fixture"))
    monkeypatch.setattr(worker, "MAX_FILES", 0)
    result = scanner.scan()
    assert result["outcome"] == "incomplete" and result["files_scanned"] == 0
    assert next(row for row in result["checks"] if row["format"] == "scan-limit")["unsupported"] == 1


def test_world_reader_never_executes_an_archived_view(tmp_path):
    from maverick import file_lock
    from maverick import recovery_rehearsal as worker

    file_lock.ensure_private_directory(tmp_path)
    path = tmp_path / "world.db"
    file_lock.atomic_create_bytes(path, b"")
    with sqlite3.connect(path) as database:
        database.execute("CREATE VIEW turns AS SELECT load_extension('must-never-be-loaded') AS content")
    before = path.read_bytes()
    result = worker._Scanner(tmp_path, TENANT, {}, worker._result("fixture")).scan()
    assert result["outcome"] == "incomplete" and result["sqlite_columns_scanned"] == 0
    assert path.read_bytes() == before


if __name__ == "__main__" and len(sys.argv) == 4 and sys.argv[1] == "--produce":
    _producer(Path(sys.argv[2]), sys.argv[3])
