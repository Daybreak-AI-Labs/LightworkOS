"""Source-bound prior-schema restore and pre-publication compatibility checks."""
from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import tarfile
from contextlib import closing

import pytest
from maverick import backup, config, file_lock, world_model

KEY = bytes(range(32))


def _seed_v33_goal(world, title):
    """Write a historical row without invoking the current-schema writer."""
    assert world.schema_version == 33
    columns = {row[1] for row in world.conn.execute("PRAGMA table_info(goals)")}
    assert "connection_selection" not in columns
    cursor = world.conn.execute(
        "INSERT INTO goals(title, description, status, created_at, updated_at, owner) "
        "VALUES(?, '', 'pending', ?, ?, 'operator')",
        (title, 1_700_000_000.0, 1_700_000_000.0),
    )
    world.conn.commit()
    return cursor.lastrowid


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setattr(config, "load_config", lambda *a, **kw: {})


def _versioned_archive(tmp_path, versions, *, declared, relative="world.db", schema=2, version_view=False, extra_files=None, signed=True):
    source = file_lock.ensure_private_directory(tmp_path / "source")
    database = source / "fixture.sqlite"
    with closing(sqlite3.connect(database)) as connection:
        if version_view:
            connection.execute("CREATE VIEW schema_version AS SELECT 34 AS version")
        else:
            connection.execute("CREATE TABLE schema_version(version)")
            connection.executemany("INSERT INTO schema_version VALUES(?)", [(version,) for version in versions])
        connection.execute("CREATE TABLE evidence(id TEXT PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO evidence VALUES('preserved-id','prior persisted value')")
        connection.commit()
    payload = database.read_bytes()
    payloads = {relative: payload, **(extra_files or {})}
    manifest = backup._authenticate_for_write({
        "schema": schema, "client_id": "acme", "world_schema_version": declared,
        "files": {name: {"sha256": hashlib.sha256(value).hexdigest(), "size": len(value)} for name, value in payloads.items()},
    }, KEY if signed else None)
    archive = tmp_path / "fixture.tgz"
    with tarfile.open(archive, "w:gz") as stream:
        for name, content in [("manifest.json", json.dumps(manifest).encode()), *[("data/" + name, value) for name, value in payloads.items()]]:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            stream.addfile(info, io.BytesIO(content))
    return archive


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_staged_world_sidecars_cannot_escape_checkpointed_schema_inspection(tmp_path, suffix):
    archive = _versioned_archive(tmp_path, [34], declared=34, extra_files={"world.db" + suffix: b"uncheckpointed state"})
    with backup.recovery_scope(tmp_path / "live", "acme", KEY):
        assert backup.verify_backup(archive)["files"]
        with pytest.raises(backup.BackupError, match="checkpointed.*reviewed"):
            backup.validate_backup_application(archive)


@pytest.mark.parametrize("schema", [3, True, 2.0])
def test_unknown_or_malformed_archive_schema_requires_actionable_migration(tmp_path, schema):
    archive = _versioned_archive(tmp_path, [34], declared=34, schema=schema)
    with backup.recovery_scope(tmp_path / "live", "acme", KEY), pytest.raises(backup.BackupError, match="schema.*upgrade.*reviewed"):
        backup.restore_backup(archive, force=True)


@pytest.mark.parametrize("operation", ["validate", "restore", "force_restore"])
@pytest.mark.parametrize("declared", [None, "prior", "current", "future"])
def test_future_payload_never_reaches_live_transaction_even_with_old_or_missing_metadata(tmp_path, monkeypatch, operation, declared):
    current = world_model.SCHEMA_VERSION
    declared = {None: None, "prior": current - 1, "current": current, "future": current + 1}[declared]
    archive = _versioned_archive(tmp_path, [current + 1], declared=declared)
    live = file_lock.ensure_private_directory(tmp_path / "live")
    sentinel = live / "keep.txt"
    file_lock.atomic_write_text(sentinel, "newer live data")

    def forbidden(*args, **kwargs):
        raise AssertionError("incompatible archive reached live transaction")

    monkeypatch.setattr(backup, "_recover_transactions", forbidden)
    monkeypatch.setattr(backup, "_apply_transaction", forbidden)
    with backup.recovery_scope(live, "acme", KEY):
        assert backup.verify_backup(archive)["files"]  # Authentication/hashes are valid.
        with pytest.raises(backup.BackupError, match="newer than this binary.*upgrade"):
            if operation == "validate":
                backup.validate_backup_application(archive)
            else:
                backup.restore_backup(archive, force=operation == "force_restore", replace_existing=True)
    assert sentinel.read_text() == "newer live data"
    assert not (live / "world.db").exists()
    assert not (live / backup._RESTORE_TX_ROOT).exists()


@pytest.mark.parametrize("versions", [[0], [-1], ["35"], [35.5], [None], [34, 35], [35, 35]])
def test_malformed_payload_schema_is_actionable_before_restore(tmp_path, versions):
    archive = _versioned_archive(tmp_path, versions, declared=35)
    live = tmp_path / "live"
    with backup.recovery_scope(live, "acme", KEY), pytest.raises(backup.BackupError, match="schema.*reviewed"):
        backup.restore_backup(archive, replace_existing=True, force=True)
    assert not (live / "world.db").exists()


def test_schema_version_view_cannot_masquerade_as_supported_metadata(tmp_path):
    archive = _versioned_archive(tmp_path, [], declared=35, version_view=True)
    with backup.recovery_scope(tmp_path / "live", "acme", KEY), pytest.raises(backup.BackupError, match="schema.*reviewed"):
        backup.validate_backup_application(archive)


@pytest.mark.parametrize("declared", [True, "35", 35.0, 0, -1, {}, []])
def test_malformed_signed_schema_metadata_is_not_a_compatibility_override(tmp_path, declared):
    archive = _versioned_archive(tmp_path, [35], declared=declared)
    with backup.recovery_scope(tmp_path / "live", "acme", KEY), pytest.raises(backup.BackupError, match="schema.*reviewed"):
        backup.restore_backup(archive, replace_existing=True, force=True)


def test_whole_home_restore_checks_each_tenant_world_schema(tmp_path):
    archive = _versioned_archive(tmp_path, [world_model.SCHEMA_VERSION + 1], declared=None, relative="tenants/acme/world.db")
    live = tmp_path / "live"
    with backup.recovery_scope(live, "acme", KEY, whole_home=True), pytest.raises(backup.BackupError, match="newer than this binary.*upgrade"):
        backup.restore_backup(archive, replace_existing=True, force=True)
    assert not (live / "tenants/acme/world.db").exists()


@pytest.mark.parametrize("declared", [None, 34])
def test_signed_root_metadata_must_match_the_staged_database(tmp_path, declared):
    archive = _versioned_archive(tmp_path, [35], declared=declared)
    with backup.recovery_scope(tmp_path / "live", "acme", KEY), pytest.raises(backup.BackupError, match="schema.*match.*reviewed"):
        backup.restore_backup(archive, replace_existing=True, force=True)


def test_empty_version_table_remains_supported_legacy_restore(tmp_path):
    archive = _versioned_archive(tmp_path, [], declared=None)
    live = tmp_path / "live"
    with backup.recovery_scope(live, "acme", KEY):
        backup.restore_backup(archive, replace_existing=True)
    with closing(sqlite3.connect(live / "world.db")) as connection:
        assert connection.execute("SELECT id,value FROM evidence").fetchall() == [("preserved-id", "prior persisted value")]
        assert connection.execute("SELECT version FROM schema_version").fetchall() == []


@pytest.mark.parametrize("actual", [34, world_model.SCHEMA_VERSION + 1])
def test_explicit_unsigned_v1_still_checks_actual_schema_without_a_declaration(tmp_path, actual):
    archive = _versioned_archive(tmp_path, [actual], declared=None, schema=1, signed=False)
    live = tmp_path / "legacy-live"
    with backup.recovery_scope(live, "acme", KEY):
        if actual > world_model.SCHEMA_VERSION:
            with pytest.raises(backup.BackupError, match="newer than this binary.*upgrade"):
                backup.restore_backup(archive, allow_unsigned=True, force=True)
            assert not (live / "world.db").exists()
        else:
            backup.restore_backup(archive, allow_unsigned=True)
            with closing(sqlite3.connect(live / "world.db")) as connection:
                assert connection.execute("SELECT id,value FROM evidence").fetchall() == [("preserved-id", "prior persisted value")]
                assert connection.execute("SELECT version FROM schema_version").fetchone()[0] == actual


def test_snapshot_schema_metadata_is_bound_to_the_copied_database(tmp_path, monkeypatch):
    source = file_lock.ensure_private_directory(tmp_path / "source")
    with closing(sqlite3.connect(source / "world.db")) as connection:
        connection.execute("CREATE TABLE schema_version(version)")
        connection.execute("INSERT INTO schema_version VALUES(33)")
        connection.commit()
    stage_original = backup._stage

    def stage_changed_source(root, stage, **kwargs):
        with closing(sqlite3.connect(root / "world.db")) as connection:
            connection.execute("UPDATE schema_version SET version=34")
            connection.commit()
        return stage_original(root, stage, **kwargs)

    monkeypatch.setattr(backup, "_stage", stage_changed_source)
    with backup.recovery_scope(source, "acme", KEY):
        archive = backup.create_backup(tmp_path / "snapshot.tgz")
        assert backup.verify_backup(archive)["world_schema_version"] == 34


def test_prior_v33_record_survives_upgrade_restore_and_repeat_upgrade(tmp_path, monkeypatch):
    current = world_model.SCHEMA_VERSION
    source = file_lock.ensure_private_directory(tmp_path / "source")
    # Reconstruct the v33 database using the released SQL ladder through v33.
    # This is a prior-schema fixture, not execution of a historical installer.
    with monkeypatch.context() as prior:
        prior.setattr(world_model, "SCHEMA_VERSION", 33)
        with world_model.WorldModel(source / "world.db") as world:
            goal_id = _seed_v33_goal(world, "Prior schema customer record")
            assert world.schema_version == 33
    with backup.recovery_scope(source, "acme", KEY):
        archive = backup.create_backup(tmp_path / "v33.tgz")
        assert backup.verify_backup(archive)["world_schema_version"] == 33
    with world_model.WorldModel(source / "world.db") as upgraded:
        assert upgraded.schema_version == current
        assert upgraded.get_goal(goal_id).title == "Prior schema customer record"
        assert upgraded.goal_connection_selection(goal_id) == ""
        assert upgraded.conn.execute("SELECT name FROM sqlite_master WHERE name='provider_cap_receipts'").fetchone()
        assert upgraded.conn.execute("SELECT name FROM sqlite_master WHERE name='provider_operation_attempts'").fetchone()
    live = tmp_path / "restored"
    with backup.recovery_scope(live, "acme", KEY):
        backup.restore_backup(archive, replace_existing=True)
    with closing(sqlite3.connect(live / "world.db")) as connection:
        assert connection.execute("SELECT version FROM schema_version").fetchone()[0] == 33
    with world_model.WorldModel(live / "world.db") as reopened:
        assert reopened.schema_version == current
        assert reopened.get_goal(goal_id).title == "Prior schema customer record"
        assert reopened.get_goal(goal_id).owner == "operator"
        assert reopened.goal_connection_selection(goal_id) == ""


@pytest.mark.parametrize("relative", ["customer-world.sqlite", "tenants/acme/customer-state.data"])
@pytest.mark.parametrize("operation", ["validate", "restore"])
def test_custom_named_future_world_blocks_before_publication(tmp_path, monkeypatch, relative, operation):
    source = file_lock.ensure_private_directory(tmp_path / "source")
    path = source / relative
    file_lock.ensure_private_directory(path.parent)
    with world_model.WorldModel(path) as world:
        world.create_goal("Customer future schema record")
        world.conn.execute("UPDATE schema_version SET version=?", (world_model.SCHEMA_VERSION + 1,))
        world.conn.commit()
    with backup.recovery_scope(source, "acme", KEY, whole_home=relative.startswith("tenants/")):
        archive = backup.create_backup(tmp_path / "custom.tgz")
        assert backup.verify_backup(archive)["world_schema_version"] is None

    def forbidden(*args, **kwargs):
        raise AssertionError("custom incompatible world reached publication")

    monkeypatch.setattr(backup, "_recover_transactions", forbidden)
    monkeypatch.setattr(backup, "_apply_transaction", forbidden)
    live = tmp_path / "live"
    with backup.recovery_scope(live, "acme", KEY, whole_home=relative.startswith("tenants/")):
        with pytest.raises(backup.BackupError, match="newer than this binary.*upgrade"):
            if operation == "validate":
                backup.validate_backup_application(archive)
            else:
                backup.restore_backup(archive, force=True, replace_existing=True)
    assert not live.exists()


@pytest.mark.parametrize("relative", ["customer-world.sqlite", "tenants/acme/customer-state.data"])
def test_custom_named_prior_world_restores_and_reopens(tmp_path, monkeypatch, relative):
    source = file_lock.ensure_private_directory(tmp_path / "source")
    path = source / relative
    file_lock.ensure_private_directory(path.parent)
    with monkeypatch.context() as prior:
        prior.setattr(world_model, "SCHEMA_VERSION", 33)
        with world_model.WorldModel(path) as world:
            goal_id = _seed_v33_goal(world, "Custom prior record")
    with backup.recovery_scope(source, "acme", KEY, whole_home=relative.startswith("tenants/")):
        archive = backup.create_backup(tmp_path / "custom-prior.tgz")
    live = tmp_path / "restored"
    with backup.recovery_scope(live, "acme", KEY, whole_home=relative.startswith("tenants/")):
        backup.restore_backup(archive, replace_existing=True)
    with world_model.WorldModel(live / relative) as reopened:
        assert reopened.schema_version == world_model.SCHEMA_VERSION
        assert reopened.get_goal(goal_id).title == "Custom prior record"
        assert reopened.get_goal(goal_id).owner == "operator"
        assert reopened.goal_connection_selection(goal_id) == ""


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_custom_sqlite_sidecars_cannot_hide_native_metadata(tmp_path, suffix):
    archive = _versioned_archive(tmp_path, [35], declared=None, relative="tenant-world.data",
                                 extra_files={"tenant-world.data" + suffix: b"uncheckpointed state"})
    with backup.recovery_scope(tmp_path / "live", "acme", KEY):
        with pytest.raises(backup.BackupError, match="checkpointed.*reviewed"):
            backup.validate_backup_application(archive)


def test_other_sqlite_stores_are_not_assigned_a_world_schema(tmp_path):
    source = file_lock.ensure_private_directory(tmp_path / "source")
    with closing(sqlite3.connect(source / "other-component.sqlite3")) as connection:
        connection.execute("CREATE TABLE component_metadata(schema_version INTEGER)")
        connection.execute("INSERT INTO component_metadata VALUES(999)")
        connection.execute("PRAGMA user_version=999")
        connection.commit()
    with backup.recovery_scope(source, "acme", KEY):
        archive = backup.create_backup(tmp_path / "unclassified.tgz")
    live = tmp_path / "live"
    with backup.recovery_scope(live, "acme", KEY):
        backup.restore_backup(archive, replace_existing=True)
    with closing(sqlite3.connect(live / "other-component.sqlite3")) as connection:
        assert connection.execute("SELECT schema_version FROM component_metadata").fetchone()[0] == 999
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 999
