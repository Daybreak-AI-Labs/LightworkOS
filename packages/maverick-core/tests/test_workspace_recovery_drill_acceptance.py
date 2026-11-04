"""Run the actual synthetic drill without inherited deployment authority."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def test_actual_drill_ignores_inherited_aliases_and_uses_only_retained_custody(tmp_path):
    repo = Path(__file__).resolve().parents[3]
    foreign = tmp_path / "inherited-home"
    foreign.mkdir()
    configuration = foreign / "config.toml"
    configuration.write_text("[encryption]\nat_rest = false\n", encoding="utf-8")
    marker = foreign / "unrelated-work.txt"
    marker.write_text("Unrelated workspace must not be read or changed.", encoding="utf-8")
    before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in foreign.iterdir()}
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(("MAVERICK_", "LIGHTWORK_"))}
    environment.update(
        LIGHTWORK_HOME=str(foreign), LIGHTWORK_CONFIG=str(configuration), LIGHTWORK_TENANT="foreign-fixture",
        LIGHTWORK_ENCRYPTION_KEY="00" * 32, LIGHTWORK_BACKUP_SIGNING_KEY="11" * 32,
        LIGHTWORK_ENCRYPT_AT_REST="0", LIGHTWORK_ENCRYPT_PER_TENANT="1",
        MAVERICK_ENCRYPTION_KEY="22" * 32, PYTHONUTF8="1",
    )
    completed = subprocess.run(
        [sys.executable, str(repo / "scripts/acceptance/workspace_recovery_drill.py")],
        cwd=tmp_path, env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["fixture"] == "synthetic-local-only"
    assert report["post_restore_verified"] is True and report["fixture_draft_decrypted"] is True
    assert report["controlled_restore_key_source"] == "original-synthetic-local-key"
    assert report["original_encryption_key_deleted_before_custody_test"] is True
    assert report["original_encryption_key_absent_after_custody_test"] is True
    custody = report["retained_key_custody"]
    assert custody["outcome"] == "verified_supported_formats"
    assert custody["fresh_process"] is True and custody["key_source"] == "uploaded-custody-copy"
    assert custody["coverage_complete"] is False and custody["restore_authorized"] is False
    assert custody["live_workspace_changed"] is False and custody["external_stores_tested"] is False
    checks = {row["format"]: row for row in custody["checks"]}
    assert checks["raw-v1"]["verified"] == checks["world-text-v1"]["verified"] == 1
    assert custody["sqlite_columns_scanned"] == 1
    signed = report["retained_key_custody_signed_report"]
    assert len(signed["authentication"]["signature"]) == 64
    assert signed["outcome"] == custody["outcome"] and signed["checks"] == custody["checks"]
    assert signed["restore_authorized"] is False
    assert before == {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in foreign.iterdir()}
