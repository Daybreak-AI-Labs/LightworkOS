"""Measured synthetic restore and separately retained key custody rehearsal."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="lw-drill-") as temporary:
        # Standalone acceptance process: remove inherited deployment overrides
        # before importing modules that cache paths or credentials.
        for name in list(os.environ):
            if name.startswith(("MAVERICK_", "LIGHTWORK_")) or name in {"QDRANT_URL", "REDIS_URL"}:
                os.environ.pop(name)
        os.environ["MAVERICK_HOME"] = temporary
        os.environ["MAVERICK_CONFIG"] = str(Path(temporary, "config.toml"))
        os.environ["MAVERICK_CLIENT_ID"] = "recovery-fixture"
        os.environ["MAVERICK_ENCRYPT_AT_REST"] = "1"
        os.environ["MAVERICK_ENCRYPT_PER_TENANT"] = "0"
        Path(temporary, "config.toml").write_text(
            "[features]\nworkspace_recovery = true\n[encryption]\nat_rest = true\nper_tenant = false\n[kms]\nprovider = 'local'\n",
            encoding="utf-8",
        )
        from maverick import crypto_at_rest
        from maverick import workspace_recovery as recovery
        from maverick.paths import data_dir
        from maverick_dashboard.draft_store import DraftStore

        root = data_dir()
        root.mkdir(parents=True, exist_ok=True)
        crypto_at_rest._KEY_PATH = Path(temporary, "shared-keys", "at_rest.key")
        store = DraftStore("a" * 64)
        slot = "b" * 64
        draft = store.save(slot, {"title": "Synthetic unfinished work"}, expected_revision=0, operation_id="initial-fixture")
        if not (crypto_at_rest._KEY_PATH.is_file()):
            raise RuntimeError("The fixture must use its own local encryption key")
        database = sqlite3.connect(root / "world.db")
        try:
            database.execute("CREATE TABLE turns(content TEXT)")
            database.execute("INSERT INTO turns VALUES (?)", (crypto_at_rest.seal_to_str("Synthetic prior conversation"),))
            database.commit()
        finally:
            database.close()
        recovery.configure_key()
        snapshot = recovery.create()
        drill = recovery.drill(snapshot["id"])
        store.save(slot, {"title": "Later synthetic work"}, expected_revision=draft["revision"], operation_id="later-fixture")
        # Core fixture authority only. Actual startup/lease admission is covered
        # by test_workspace_recovery_api and the browser acceptance journey.
        review = recovery.prepare_restore(snapshot["id"], isolated=True, actor="synthetic-drill")
        restored = recovery.apply_restore(review["review"], review["target"], isolated=True, actor="synthetic-drill")
        if not (store.read(slot)["payload"]["title"] == "Synthetic unfinished work"):
            raise RuntimeError("Restored draft verification failed")
        database = sqlite3.connect(root / "world.db")
        try:
            if not (crypto_at_rest.unseal_from_str(database.execute("SELECT content FROM turns").fetchone()[0]) == "Synthetic prior conversation"):
                raise RuntimeError("Restored conversation verification failed")
        finally:
            database.close()
        # The controlled restore above deliberately retains its original local
        # key. The independent custody phase below must not have that fallback.
        custody = Path(temporary, "separately-retained-keys.zip")
        custody.write_bytes(recovery.export_encryption_keys())
        key_path = crypto_at_rest._KEY_PATH.resolve()
        if not (key_path.is_relative_to(Path(temporary).resolve())):
            raise RuntimeError("Fixture key location verification failed")
        key_path.unlink()
        if not (not key_path.exists()):
            raise RuntimeError("Deleted fixture key verification failed")
        custody_report = recovery.test_key_custody(
            snapshot["id"], custody, expected_sha256=snapshot["sha256"], actor="synthetic-drill",
        )
        if not (not key_path.exists()):
            raise RuntimeError("The rehearsal must not regenerate or restore the original shared key")
        checks = {row["format"]: row for row in custody_report["checks"]}
        if not (custody_report["outcome"] == "verified_supported_formats"):
            raise RuntimeError("Custody outcome verification failed")
        if custody_report["fresh_process"] is not True:
            raise RuntimeError("Custody process verification failed")
        if not (custody_report["key_source"] == "uploaded-custody-copy"):
            raise RuntimeError("Custody key-source verification failed")
        if custody_report["coverage_complete"] is not False:
            raise RuntimeError("Custody coverage verification failed")
        if not (custody_report["sqlite_columns_scanned"] == 1):
            raise RuntimeError("Custody SQLite coverage verification failed")
        for name in ("raw-v1", "world-text-v1"):
            if not (checks[name]["verified"] == 1):
                raise RuntimeError("Custody format verification failed")
        if not (all(row["failed"] == row["unsupported"] == 0 for row in checks.values())):
            raise RuntimeError("Custody failure-count verification failed")
        signed_custody = json.loads(recovery.export_custody_test(
            snapshot["id"], custody_report["report_id"], actor="synthetic-drill",
        ))
        print(json.dumps({"fixture": "synthetic-local-only", "files": snapshot["file_count"],
                          "archive_bytes": snapshot["bytes"], "expanded_bytes": snapshot["expanded_bytes"],
                          "application_version": recovery.version(), "application_identity": recovery.application_identity(),
                          "temporary_restore_seconds": drill["elapsed_seconds"], "controlled_restore_seconds": restored["elapsed_seconds"],
                          "post_restore_verified": restored["post_restore_verified"], "fixture_draft_decrypted": True,
                          "controlled_restore_key_source": "original-synthetic-local-key",
                          "original_encryption_key_deleted_before_custody_test": True,
                          "original_encryption_key_absent_after_custody_test": True,
                          "retained_key_custody": {
                              key: custody_report[key] for key in (
                                  "outcome", "fresh_process", "key_source", "checks", "files_scanned",
                                  "sqlite_columns_scanned", "unexamined_files", "elapsed_seconds", "coverage_complete",
                                  "live_workspace_changed", "external_stores_tested", "restore_authorized",
                              )
                          },
                          "retained_key_custody_signed_report": signed_custody,
                          "real_workspace_changed": False, "native_runtime_verified": False,
                          "external_stores_tested": False}, indent=2))


if __name__ == "__main__":
    main()
