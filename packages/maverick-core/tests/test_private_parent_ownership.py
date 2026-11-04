"""Caller-selected storage must never silently claim a shared directory."""
from __future__ import annotations

import os
import sqlite3
import subprocess

import pytest
from maverick import (
    attachments,
    failure_telemetry,
    shield_updates,
    supply_chain,
)
from maverick import benchmark_reproducibility as benchmark
from maverick.encryption_migrate import backup_world_db
from maverick.file_lock import private_path_is_restricted
from maverick.world_model import WorldModel


def _make_shared_directory(path):
    path.mkdir(mode=0o777)
    if os.name == "nt":
        subprocess.run(
            ["icacls", str(path), "/grant", "*S-1-1-0:(OI)(CI)RX"],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        path.chmod(0o755)
    assert not private_path_is_restricted(path, 0o700)


def _security_snapshot(path):
    if os.name == "nt":
        import maverick.file_lock as file_lock

        return file_lock._windows_private_sddl(path)[0]
    return path.stat().st_mode & 0o777


def _shared_fixture(tmp_path):
    shared = tmp_path / "shared"
    _make_shared_directory(shared)
    unrelated = shared / "team-file.txt"
    unrelated.write_text("keep-access", encoding="utf-8")
    return shared, unrelated, _security_snapshot(shared)


def _assert_shared_unchanged(shared, unrelated, before):
    assert _security_snapshot(shared) == before
    assert not private_path_is_restricted(shared, 0o700)
    assert unrelated.read_text(encoding="utf-8") == "keep-access"


def test_world_db_refuses_shared_custom_parent_without_mutation(tmp_path):
    shared, unrelated, before = _shared_fixture(tmp_path)

    with pytest.raises(PermissionError, match="must already be private"):
        WorldModel(shared / "world.db")

    _assert_shared_unchanged(shared, unrelated, before)
    assert not (shared / "world.db").exists()


def test_world_default_override_refuses_shared_parent_without_mutation(
    tmp_path, monkeypatch,
):
    import maverick.world_model as world_model

    shared, unrelated, before = _shared_fixture(tmp_path)
    monkeypatch.setattr(world_model, "DEFAULT_DB", shared / "world.db")

    with pytest.raises(PermissionError, match="must already be private"):
        world_model.open_world()

    _assert_shared_unchanged(shared, unrelated, before)
    assert not (shared / "world.db").exists()


def test_attachments_refuse_shared_custom_root_without_mutation(tmp_path):
    shared, unrelated, before = _shared_fixture(tmp_path)

    with pytest.raises(
        attachments.AttachmentRejected,
        match="storage directory is not private",
    ):
        attachments.store(
            7,
            "private.txt",
            "text/plain",
            b"tenant secret",
            root=shared,
        )

    _assert_shared_unchanged(shared, unrelated, before)
    assert not (shared / "7").exists()


def test_plaintext_backup_refuses_shared_db_parent_without_mutation(tmp_path):
    shared, unrelated, _ = _shared_fixture(tmp_path)
    db = shared / "world.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE records (value TEXT)")
        conn.execute("INSERT INTO records VALUES ('plaintext')")
    before = _security_snapshot(shared)

    with pytest.raises(PermissionError, match="must already be private"):
        backup_world_db(db)

    _assert_shared_unchanged(shared, unrelated, before)
    assert not list(shared.glob("*.pre-encrypt-*.bak"))


def test_best_effort_failure_telemetry_preserves_shared_parent(
    tmp_path, monkeypatch,
):
    shared, unrelated, before = _shared_fixture(tmp_path)
    path = shared / "failure-modes.jsonl"
    monkeypatch.setenv("MAVERICK_FAILURE_TELEMETRY", "1")
    monkeypatch.setattr(
        "maverick.learning_guard.learning_write_allowed", lambda _name: True,
    )

    assert failure_telemetry.record("timeout", path=path)

    _assert_shared_unchanged(shared, unrelated, before)
    assert private_path_is_restricted(path)


def test_shield_rules_refuse_shared_custom_parent_without_mutation(
    tmp_path, monkeypatch,
):
    shared, unrelated, before = _shared_fixture(tmp_path)
    path = shared / "shield-rules.json"
    monkeypatch.setattr(
        shield_updates,
        "verify_bundle",
        lambda _bundle, _key: (2, [{"id": "signed-rule"}]),
    )

    with pytest.raises(PermissionError, match="must already be private"):
        shield_updates.apply_update(
            {"sig": "verified"}, pubkey_hex="publisher", path=path,
        )

    _assert_shared_unchanged(shared, unrelated, before)
    assert not path.exists()
    assert not (shared / "shield-rules.json.lock").exists()


def test_supply_chain_pins_refuse_shared_custom_parent_without_mutation(
    tmp_path, monkeypatch,
):
    shared, unrelated, before = _shared_fixture(tmp_path)
    path = shared / "pins.json"
    monkeypatch.setattr(supply_chain, "snapshot", lambda: {"example": "1.0"})

    with pytest.raises(PermissionError, match="must already be private"):
        supply_chain.write_pins(path)

    _assert_shared_unchanged(shared, unrelated, before)
    assert not path.exists()


def test_manifest_refuses_preexisting_shared_manifest_directory(
    tmp_path, monkeypatch,
):
    root = tmp_path / "benchmark-root"
    root.mkdir()
    manifests = root / "manifests"
    _make_shared_directory(manifests)
    unrelated = manifests / "team-file.txt"
    unrelated.write_text("keep-access", encoding="utf-8")
    before = _security_snapshot(manifests)
    monkeypatch.setattr(benchmark, "host_info", lambda: {"os": "test"})

    with pytest.raises(PermissionError, match="must already be private"):
        benchmark.record_with_manifest(
            "suite",
            0.9,
            history_path=root / "history.json",
            write_manifest=True,
            now=1000.0,
        )

    _assert_shared_unchanged(manifests, unrelated, before)
    assert not list(manifests.glob("suite-*.json"))
