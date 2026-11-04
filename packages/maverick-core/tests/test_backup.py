"""Backup / restore / DR for a single-client deployment: consistent snapshot of
the client data root, round-trip restore, the cross-client fail-closed guard,
and path-traversal-safe extraction."""
from __future__ import annotations

import io
import os
import sqlite3
import tarfile
import time
from pathlib import Path

import pytest
from maverick import backup, client, file_lock


@pytest.fixture(autouse=True)
def _bound_client(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    monkeypatch.setenv("MAVERICK_BACKUP_SIGNING_KEY", bytes(range(32)).hex())
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    client.reset_client_cache()
    yield
    client.reset_client_cache()


def _seed(root):
    """Write a tiny world DB + audit-ish files into the client data root."""
    root.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(root / "world.db"))
    con.execute("CREATE TABLE t (v TEXT)")
    con.execute("INSERT INTO t VALUES ('secret-data')")
    con.commit()
    con.close()
    (root / "audit").mkdir(exist_ok=True)
    (root / "audit" / "2026-06-18.ndjson").write_text('{"kind":"x"}\n')
    (root / "agent_trust.json").write_text('[{"id":"vega"}]')


def test_create_and_restore_round_trip():
    from maverick.paths import data_dir
    root = data_dir()
    _seed(root)
    tar = backup.create_backup()
    assert tar.exists()
    assert file_lock.private_path_is_restricted(tar)

    # Wipe + restore.
    (root / "world.db").unlink()
    (root / "agent_trust.json").unlink()
    backup.restore_backup(tar)

    con = sqlite3.connect(str(root / "world.db"))
    assert con.execute("SELECT v FROM t").fetchone()[0] == "secret-data"
    con.close()
    assert (root / "agent_trust.json").read_text() == '[{"id":"vega"}]'
    assert file_lock.private_path_is_restricted(root / "world.db")
    assert file_lock.private_path_is_restricted(root / "agent_trust.json")


@pytest.mark.parametrize("name", ["world.db", "consent-preferences.sqlite3", "tasks.sqlite", "header-only.store"])
def test_sqlite_wal_commits_survive_snapshot_and_restore_for_real_store_names(tmp_path, name):
    root = tmp_path / "source"
    root.mkdir()
    connection = sqlite3.connect(root / name)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE evidence(value TEXT)")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("INSERT INTO evidence VALUES('committed in WAL')")
        connection.commit()
        assert Path(str(root / name) + "-wal").stat().st_size > 0
        with backup.recovery_scope(root, "acme", bytes(range(32))):
            archive = backup.create_backup(tmp_path / "snapshot.tgz")
            backup.verify_backup(archive)
    finally:
        connection.close()
    destination = tmp_path / "destination"
    with backup.recovery_scope(destination, "acme", bytes(range(32))):
        backup.restore_backup(archive, replace_existing=True)
    restored = sqlite3.connect(destination / name)
    try:
        assert restored.execute("SELECT value FROM evidence").fetchall() == [("committed in WAL",)]
    finally:
        restored.close()


@pytest.mark.parametrize("name", ["consent-preferences.sqlite3", "header-only.store"])
@pytest.mark.parametrize("fail_post_check", [False, True])
def test_restore_clears_stale_sqlite_sidecars_and_failed_restore_recovers_them(tmp_path, monkeypatch, name, fail_post_check):
    source = tmp_path / "source"
    source.mkdir()
    connection = sqlite3.connect(source / name)
    connection.execute("CREATE TABLE evidence(value TEXT)")
    connection.execute("INSERT INTO evidence VALUES('snapshot')")
    connection.commit()
    connection.close()
    with backup.recovery_scope(source, "acme", bytes(range(32))):
        archive = backup.create_backup(tmp_path / "snapshot.tgz")
    destination = tmp_path / "destination"
    destination.mkdir()
    live = destination / name
    connection = sqlite3.connect(live)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE evidence(value TEXT)")
    connection.commit()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.execute("INSERT INTO evidence VALUES('newer committed WAL')")
    connection.commit()
    pending = {suffix: Path(str(live) + suffix).read_bytes() for suffix in ("", "-wal", "-shm")}
    connection.close()
    # Model a closed owner whose committed WAL sidecars remain on disk.
    for suffix, content in pending.items():
        Path(str(live) + suffix).write_bytes(content)
    if fail_post_check:
        def fail(*_):
            raise backup.BackupError("injected post-check failure")
        monkeypatch.setattr(backup, "_verify_restored", fail)
    with backup.recovery_scope(destination, "acme", bytes(range(32))):
        if fail_post_check:
            with pytest.raises(backup.BackupError, match="injected"):
                backup.restore_backup(archive, replace_existing=True)
        else:
            backup.restore_backup(archive, replace_existing=True)
    connection = sqlite3.connect(live)
    try:
        expected = "newer committed WAL" if fail_post_check else "snapshot"
        assert connection.execute("SELECT value FROM evidence").fetchall() == [(expected,)]
    finally:
        connection.close()


@pytest.mark.parametrize("name", ["consent-preferences.sqlite3", "header-only.store"])
def test_hash_consistent_malformed_sqlite_still_fails_post_restore_integrity(tmp_path, name):
    path = tmp_path / name
    path.write_bytes(b"SQLite format 3\x00" + b"invalid database")
    with pytest.raises(backup.BackupError, match="database integrity"):
        backup._verify_restored(tmp_path, {name: (backup._sha256(path), path.stat().st_size)})


def test_long_windows_source_and_restore_paths_keep_hashed_drafts_and_sqlite(tmp_path):
    import shutil
    def filesystem(path):
        return Path(file_lock._windows_extended_path(path)) if os.name == "nt" else path
    source = tmp_path / ("long-profile-" + "x" * 90)
    destination = tmp_path / ("long-restored-" + "y" * 90)
    relative = Path("draft-recovery") / ("a" * 64) / ("b" * 64 + ".draft")
    native_source = filesystem(source)
    native_destination = filesystem(destination)
    try:
        (native_source / relative).parent.mkdir(parents=True)
        (native_source / relative).write_bytes(b"synthetic long-path draft")
        database = sqlite3.connect(native_source / "store.sqlite3")
        database.execute("CREATE TABLE evidence(value TEXT)")
        database.execute("INSERT INTO evidence VALUES('long path')")
        database.commit()
        database.close()
        with backup.recovery_scope(source, "acme", bytes(range(32))):
            archive = backup.create_backup(tmp_path / "snapshot.tgz")
        with backup.recovery_scope(destination, "acme", bytes(range(32))):
            backup.restore_backup(archive, replace_existing=True)
        assert (native_destination / relative).read_bytes() == b"synthetic long-path draft"
    finally:
        for path in (native_source, native_destination):
            if path.exists():
                shutil.rmtree(path)


def test_manifest_records_client():
    from maverick.paths import data_dir
    _seed(data_dir())
    tar = backup.create_backup()
    m = backup.read_manifest(tar)
    assert m["client_id"] == "acme" and m["schema"] == backup.SCHEMA
    assert "world.db" in m["files"]


def test_restore_refuses_cross_client(monkeypatch):
    from maverick.paths import data_dir
    _seed(data_dir())
    tar = backup.create_backup()  # client_id = acme
    # Now this deployment is a DIFFERENT client.
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "beta")
    client.reset_client_cache()
    with pytest.raises(backup.BackupError):
        backup.restore_backup(tar)
    # force overrides.
    backup.restore_backup(tar, force=True)


def test_restore_rejects_file_not_in_manifest(tmp_path):
    # The manifest is an exhaustive allow-list. A payload file with no manifest
    # entry (and thus no recorded SHA-256) is a corrupt/tampered archive trying
    # to write an unverified file into the live root; restore must reject it,
    # not silently pass it through (the old `want is not None` guard skipped it).
    from maverick.paths import data_dir
    _seed(data_dir())
    tar = backup.create_backup()

    tampered = tmp_path / "tampered.tgz"
    extra = tmp_path / "sneaky"
    extra.write_text("unverified payload")
    with tarfile.open(tar, "r:gz") as src, tarfile.open(tampered, "w:gz") as dst:
        for m in src.getmembers():
            dst.addfile(m, src.extractfile(m) if m.isfile() else None)
        dst.add(extra, arcname="data/sneaky.txt")

    with pytest.raises(backup.BackupError, match="not in the manifest"):
        backup.restore_backup(tampered)


def test_restore_rejects_path_traversal(tmp_path):
    # Hand-craft a malicious tarball with a ../ member.
    bad = tmp_path / "evil.tgz"
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "x").write_text("data")
    import json
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema": 1, "client_id": "acme", "files": {}}))
    with tarfile.open(bad, "w:gz") as tar:
        tar.add(manifest, arcname="manifest.json")
        tar.add(payload / "x", arcname="data/../../escape")
    with pytest.raises(backup.BackupError):
        backup.restore_backup(bad, allow_unsigned=True)


def test_backup_excludes_prior_backups(monkeypatch):
    """The backups/ subtree lives under the client root; it must NOT be swept
    into a new backup, or each backup would contain every earlier one and grow
    quadratically."""
    from maverick.paths import data_dir
    _seed(data_dir())
    first = backup.create_backup()
    assert first.exists()
    # A second backup must not contain the first .tgz under data/backups/.
    second = backup.create_backup()
    with tarfile.open(second, "r:gz") as tar:
        members = tar.getnames()
    assert not any(name.startswith("data/backups/") for name in members), members
    assert "data/world.db" in members


def _seed_key_material(root):
    """Write stand-ins for the at-rest key, its rotation keyring, and the
    audit signing key at their real on-disk locations (crypto_at_rest.py,
    audit/signing.py)."""
    keys_dir = root / "keys"
    keyring_dir = keys_dir / "at_rest.d"
    keyring_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / "at_rest.key").write_bytes(b"\x00" * 32)
    (keyring_dir / "k1.key").write_bytes(b"\x01" * 32)
    audit_keys_dir = root / "audit" / "keys"
    audit_keys_dir.mkdir(parents=True, exist_ok=True)
    (audit_keys_dir / "signing.key").write_bytes(b"\x02" * 32)
    # Not secrets: a DEK wrapped under the primary key, and a public key.
    (keys_dir / "dek.wrapped").write_bytes(b"\x03" * 64)
    (audit_keys_dir / "signing.pub").write_bytes(b"\x04" * 32)


def test_backup_excludes_key_material_by_default():
    """The at-rest encryption key and audit signing key decrypt/authenticate
    everything else the archive carries; bundling them inside the same copy
    nullifies at-rest encryption for anyone who obtains it (offsite backup,
    S3 bucket, standby host, a DSAR export handed to the data subject).
    docs/encryption.md's escrow guidance is "not next to the data they
    unlock" -- the default archive must not carry any *.key member."""
    from maverick.paths import data_dir
    root = data_dir()
    _seed(root)
    _seed_key_material(root)

    tar = backup.create_backup()
    with tarfile.open(tar, "r:gz") as archive:
        members = archive.getnames()
    assert not any(name.endswith(".key") for name in members), members
    assert "data/keys/at_rest.key" not in members
    assert "data/keys/at_rest.d/k1.key" not in members
    assert "data/audit/keys/signing.key" not in members
    assert "data/world.db" in members  # everything else still ships
    # Wrapped/public material is what a recovery of the ciphertext needs.
    assert "data/keys/dek.wrapped" in members
    assert "data/audit/keys/signing.pub" in members


def test_backup_include_keys_opts_back_in():
    from maverick.paths import data_dir
    root = data_dir()
    _seed(root)
    _seed_key_material(root)

    tar = backup.create_backup(include_keys=True)
    with tarfile.open(tar, "r:gz") as archive:
        members = archive.getnames()
    assert "data/keys/at_rest.key" in members
    assert "data/keys/at_rest.d/k1.key" in members
    assert "data/audit/keys/signing.key" in members


_WORKSPACE_KEY_FILES = (
    "tenants/acme/audit/keys/signing.key",
    "tenants/clientco/keys/at_rest.d/old.key",
    "tenants/clientco/keys/at_rest.key",
)


def _seed_workspace_key_material(home):
    """Per-workspace key files at their real locations: the audit signing key
    (audit/signing.py) and a client deployment's at-rest key + keyring
    (crypto_at_rest.py), all under ``tenants/<id>/``."""
    for name in _WORKSPACE_KEY_FILES:
        path = home / Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x05" * 32)
    # Not secrets: a wrapped DEK and a public key.
    (home / "tenants" / "clientco" / "keys" / "dek.wrapped").write_bytes(b"\x06" * 64)
    (home / "tenants" / "acme" / "audit" / "keys" / "signing.pub").write_bytes(b"\x07" * 32)


def _whole_home(home):
    return backup.recovery_scope(home, "installation:test", bytes(range(32)), whole_home=True)


def test_backup_excludes_workspace_key_material_by_default(tmp_path):
    """A whole-home backup must withhold every workspace's audit signing key and
    a client deployment's at-rest keys too, not only the ones at the archive
    root: anyone holding the archive could otherwise decrypt that workspace's
    data and forge its tamper-evident audit trail."""
    home = tmp_path / "wholehome"
    _seed(home)
    _seed_key_material(home)
    _seed_workspace_key_material(home)

    with _whole_home(home):
        tar = backup.create_backup(tmp_path / "default.tgz")
    with tarfile.open(tar, "r:gz") as archive:
        members = archive.getnames()
    assert not any(name.endswith(".key") for name in members), members
    # Ciphertext and public keys still ship: recovery of the payload needs them.
    assert "data/tenants/clientco/keys/dek.wrapped" in members
    assert "data/tenants/acme/audit/keys/signing.pub" in members
    assert "data/world.db" in members


def test_backup_include_keys_keeps_workspace_key_material(tmp_path):
    home = tmp_path / "wholehome"
    _seed(home)
    _seed_workspace_key_material(home)

    with _whole_home(home):
        tar = backup.create_backup(tmp_path / "with-keys.tgz", include_keys=True)
    with tarfile.open(tar, "r:gz") as archive:
        members = archive.getnames()
    for name in _WORKSPACE_KEY_FILES:
        assert f"data/{name}" in members, members


def test_withheld_key_files_lists_what_the_operator_must_escrow(tmp_path):
    home = tmp_path / "wholehome"
    _seed(home)
    _seed_key_material(home)
    _seed_workspace_key_material(home)

    with _whole_home(home):
        listed = backup.withheld_key_files()
    assert listed == sorted([
        "audit/keys/signing.key",
        "keys/at_rest.d/k1.key",
        "keys/at_rest.key",
        *_WORKSPACE_KEY_FILES,
    ])


def _is_closed(connection):
    try:
        connection.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        return True
    return False


def test_restore_closes_cached_federation_state_connections_before_replacing_the_file(monkeypatch):
    from maverick import federation
    from maverick.paths import data_dir

    root = data_dir()
    _seed(root)
    state = federation._FederationState(root / "federation" / "inbound_state.sqlite3")
    assert state.claim_replay("scope", "sig", expires_at=time.time() + 60, now=time.time()) is False
    with federation._STATE_FILE_GATE.shared():
        cached = state._connect()
    archive = backup.create_backup()
    closed_when_replaced = []
    real_publish = backup._publish_staged_file

    def checked_publish(source, destination):
        if destination.name == "inbound_state.sqlite3":
            closed_when_replaced.append(_is_closed(cached))
        return real_publish(source, destination)

    monkeypatch.setattr(backup, "_publish_staged_file", checked_publish)
    backup.restore_backup(archive, replace_existing=True)
    # The federation file is in the archive, so the replacement reached it, and the cached
    # connection was already closed at that point.
    assert closed_when_replaced == [True]
    assert state.claim_replay("scope", "sig2", expires_at=time.time() + 60, now=time.time()) is False


def test_a_state_call_during_a_restore_waits_for_the_replacement(monkeypatch):
    import threading

    from maverick import federation
    from maverick.paths import data_dir

    root = data_dir()
    _seed(root)
    state = federation._FederationState(root / "federation" / "inbound_state.sqlite3")
    assert state.claim_replay("scope", "sig", expires_at=time.time() + 60, now=time.time()) is False
    archive = backup.create_backup()
    real_publish = backup._publish_staged_file
    results: dict[str, object] = {}
    callers: list[threading.Thread] = []

    def publish_while_a_call_arrives(source, destination):
        if destination.name == "inbound_state.sqlite3" and not callers:
            caller = threading.Thread(
                target=lambda: results.update(
                    claimed=state.claim_replay("scope", "sig2", expires_at=time.time() + 60, now=time.time())
                )
            )
            callers.append(caller)
            caller.start()
            caller.join(timeout=0.3)
            # The call waits until the replacement has finished; it does not open the file during it.
            assert caller.is_alive(), "a state call must wait while the state file is replaced"
        return real_publish(source, destination)

    monkeypatch.setattr(backup, "_publish_staged_file", publish_while_a_call_arrives)
    backup.restore_backup(archive, replace_existing=True)
    assert callers, "the federation state file was not replaced"
    callers[0].join(timeout=10)
    assert not callers[0].is_alive()
    assert results["claimed"] is False


def test_replace_existing_restore_preserves_live_workspace_keys(tmp_path):
    """A keys-excluded archive must not turn a live workspace key into a
    replacement target: deleting it would leave that workspace's restored data
    unreadable."""
    source = tmp_path / "source"
    _seed(source)
    _seed_workspace_key_material(source)
    with _whole_home(source):
        archive = backup.create_backup(tmp_path / "no-keys.tgz")

    destination = tmp_path / "destination"
    _seed_workspace_key_material(destination)
    live = destination / "tenants" / "clientco" / "keys" / "at_rest.key"
    live.write_bytes(b"\x09" * 32)
    with _whole_home(destination):
        backup.restore_backup(archive, replace_existing=True)
    assert live.read_bytes() == b"\x09" * 32
    assert (destination / "tenants" / "acme" / "audit" / "keys" / "signing.key").exists()


def test_archive_carrying_only_workspace_keys_does_not_make_live_root_keys_disposable(tmp_path):
    """Archives made before workspace keys were withheld carry them without any
    root-level key. Restoring one with replace_existing must not read that as
    'this archive includes keys' and delete the live root keys it lacks."""
    source = tmp_path / "source"
    _seed(source)
    _seed_workspace_key_material(source)
    with _whole_home(source):
        legacy_shaped = backup.create_backup(tmp_path / "legacy.tgz", include_keys=True)

    destination = tmp_path / "destination"
    _seed(destination)
    _seed_key_material(destination)
    with _whole_home(destination):
        backup.restore_backup(legacy_shaped, replace_existing=True)
    assert (destination / "keys" / "at_rest.key").read_bytes() == b"\x00" * 32
    assert (destination / "audit" / "keys" / "signing.key").read_bytes() == b"\x02" * 32


def test_live_listing_for_an_older_archive_matches_what_the_archive_carries(tmp_path):
    """The installation upgrade check lists the live home the way the snapshot it
    took before the upgrade was listed (``include_keys`` taken from the archive)
    and demands the same files. An archive from before workspace keys were
    withheld holds them but no root key, so the live listing must keep the
    workspace keys and still leave out the root keys the archive never had."""
    source = tmp_path / "source"
    _seed(source)
    _seed_workspace_key_material(source)
    with _whole_home(source):
        older = backup.create_backup(tmp_path / "older.tgz", include_keys=True)
        for name in ("keys/at_rest.key", "audit/keys/signing.key"):  # appeared later
            (source / Path(name)).parent.mkdir(parents=True, exist_ok=True)
            (source / Path(name)).write_bytes(b"\x08" * 32)
        expected = backup.read_manifest(older)["files"]
        stage = tmp_path / "stage"
        stage.mkdir()
        observed = backup._stage(
            source, stage, include_keys=backup._archive_includes_keys(expected))
    assert set(observed) == set(expected)


def test_replace_existing_restore_preserves_live_keys_when_archive_excludes_them(tmp_path):
    """replace_existing unlinks live files absent from the archive. A default
    (keys-excluded) archive must not turn the live at-rest/audit keys into
    such targets -- deleting them would leave the restored ciphertext
    unreadable. Keys travel only when the archive itself carries them."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("payload")
    with backup.recovery_scope(source, "acme", bytes(range(32))):
        without_keys = backup.create_backup(tmp_path / "no-keys.tgz")
        _seed_key_material(source)
        with_keys = backup.create_backup(tmp_path / "with-keys.tgz", include_keys=True)

    destination = tmp_path / "destination"
    destination.mkdir()
    _seed_key_material(destination)
    (destination / "keys" / "at_rest.key").write_bytes(b"\x07" * 32)
    with backup.recovery_scope(destination, "acme", bytes(range(32))):
        backup.restore_backup(without_keys, replace_existing=True)
    assert (destination / "keys" / "at_rest.key").read_bytes() == b"\x07" * 32
    assert (destination / "keys" / "at_rest.d" / "k1.key").exists()
    assert (destination / "audit" / "keys" / "signing.key").exists()

    with backup.recovery_scope(destination, "acme", bytes(range(32))):
        backup.restore_backup(with_keys, replace_existing=True)
    assert (destination / "keys" / "at_rest.key").read_bytes() == b"\x00" * 32


def _repack(src_tar, dst_tar, *, mutate_manifest=None, mutate_data=None, resign=False):
    """Rebuild a backup tarball, optionally mutating the manifest dict or a
    named data file's bytes — to forge corrupt / schema-incompatible backups."""
    import io
    import json
    with tarfile.open(src_tar, "r:gz") as t:
        members = t.getmembers()
        blobs = {m.name: (t.extractfile(m).read() if m.isfile() else None) for m in members}
    manifest = json.loads(blobs["manifest.json"].decode())
    if mutate_manifest:
        mutate_manifest(manifest)
    if resign:
        manifest.pop("authentication", None)
        key = backup._operator_key(required=True)
        manifest = backup._authenticate_for_write(manifest, key)
    blobs["manifest.json"] = json.dumps(manifest).encode()
    if mutate_data:
        name, data = mutate_data
        blobs[name] = data
    with tarfile.open(dst_tar, "w:gz") as t:
        for m in members:
            if not m.isfile():
                continue
            info = tarfile.TarInfo(m.name)
            info.size = len(blobs[m.name])
            t.addfile(info, io.BytesIO(blobs[m.name]))


def test_restore_refuses_when_world_appears_live():
    """restore_backup's own transaction lock only serializes concurrent
    restores; WorldModel takes its cross_process_lock only briefly during
    __init__, so a long-running process holds no lock a restore could see
    -- but it does keep touching world.db's WAL/SHM sidecars. Publishing
    over world.db with a process still holding it open silently orphans
    every later write on the old, unlinked inode (a split-brain, not a
    crash)."""
    from maverick.paths import data_dir
    root = data_dir()
    _seed(root)
    tar = backup.create_backup()

    (root / "world.db-wal").write_bytes(b"live-wal-content")
    now = time.time()
    os.utime(root / "world.db-wal", (now, now))

    with pytest.raises(backup.BackupError, match="still appears to have the world database open"):
        backup.restore_backup(tar)
    # force overrides the guard.
    backup.restore_backup(tar, force=True)


def test_restore_proceeds_when_wal_sidecar_is_stale():
    from maverick.paths import data_dir
    root = data_dir()
    _seed(root)
    tar = backup.create_backup()

    stale_wal = root / "world.db-wal"
    stale_wal.write_bytes(b"old-checkpointed-wal")
    stale_time = time.time() - 3600
    os.utime(stale_wal, (stale_time, stale_time))

    backup.restore_backup(tar)  # does not raise


def test_restore_live_guard_only_fires_when_backup_carries_world_db():
    """A backup that never included world.db shouldn't be blocked by
    activity on a world.db it will never publish over."""
    from maverick.paths import data_dir
    root = data_dir()
    _seed(root)
    (root / "world.db").unlink()  # this backup will not carry world.db
    tar = backup.create_backup()
    m = backup.read_manifest(tar)
    assert "world.db" not in m["files"]

    live_wal = root / "world.db-wal"
    live_wal.write_bytes(b"live-wal-content")
    now = time.time()
    os.utime(live_wal, (now, now))

    backup.restore_backup(tar)  # does not raise: nothing to publish over


def test_restore_refuses_forward_schema(tmp_path, monkeypatch):
    from maverick.paths import data_dir
    from maverick.world_model import SCHEMA_VERSION
    _seed(data_dir())
    tar = backup.create_backup()
    forward = tmp_path / "forward.tgz"
    _repack(tar, forward,
            mutate_manifest=lambda m: m.update(world_schema_version=SCHEMA_VERSION + 5),
            resign=True)
    (data_dir() / "world.db").unlink()
    with pytest.raises(backup.BackupError, match="newer than this binary"):
        backup.restore_backup(forward)
    # Administrative force never makes an unsupported database readable.
    with pytest.raises(backup.BackupError, match="newer than this binary"):
        backup.restore_backup(forward, force=True)
    assert not (data_dir() / "world.db").exists()


def test_restore_detects_corruption(tmp_path):
    from maverick.paths import data_dir
    _seed(data_dir())
    tar = backup.create_backup()
    corrupt = tmp_path / "corrupt.tgz"
    # Flip the agent_trust.json bytes but keep the manifest's recorded SHA-256.
    _repack(tar, corrupt, mutate_data=("data/agent_trust.json", b"TAMPERED"))
    original = (data_dir() / "agent_trust.json").read_text()
    with pytest.raises(backup.BackupError, match="integrity check failed"):
        backup.restore_backup(corrupt)
    # Verify-then-write: the live root was NOT partially overwritten.
    assert (data_dir() / "agent_trust.json").read_text() == original


def test_restore_clears_stale_wal_sidecar():
    """DR scenario: a stale, uncheckpointed world.db-wal in the live root must
    NOT survive a restore and replay post-backup mutations back over the
    restored DB. Backups exclude the -wal/-shm sidecars on purpose (the
    consistent .db copy already folds them in), so restore is responsible for
    removing any pre-existing ones in the live root."""
    from maverick.paths import data_dir
    root = data_dir()

    # Baseline world.db (WAL mode, fully checkpointed) holding only the content
    # the backup will capture.
    root.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(root / "world.db"))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE t (v TEXT)")
    con.execute("INSERT INTO t VALUES ('secret-data')")
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()
    (root / "agent_trust.json").write_text('[{"id":"vega"}]')

    tar = backup.create_backup()  # snapshots the clean baseline only

    # A post-backup mutation that lives ONLY in the WAL (never checkpointed):
    # keep the connection open so SQLite cannot checkpoint, capture the live
    # sidecar bytes, then close. Writing those bytes back recreates exactly the
    # post-crash stale-WAL-on-disk state (close-time checkpoint truncates it,
    # so we must reconstruct it to model the hard-crash case).
    con = sqlite3.connect(str(root / "world.db"))
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("INSERT INTO t VALUES ('post-backup-mutation')")
    con.commit()
    wal_bytes = (root / "world.db-wal").read_bytes()
    shm_path = root / "world.db-shm"
    shm_bytes = shm_path.read_bytes() if shm_path.exists() else None
    assert wal_bytes, "test needs a non-empty stale WAL"
    con.close()
    (root / "world.db-wal").write_bytes(wal_bytes)
    if shm_bytes is not None:
        shm_path.write_bytes(shm_bytes)
    assert (root / "world.db-wal").stat().st_size > 0

    backup.restore_backup(tar, force=True)

    # The stale WAL must be gone, and reopening must show ONLY the backed-up
    # content — the post-backup mutation must not have been replayed back in.
    assert not (root / "world.db-wal").exists()
    con = sqlite3.connect(str(root / "world.db"))
    rows = {r[0] for r in con.execute("SELECT v FROM t").fetchall()}
    con.close()
    assert rows == {"secret-data"}, rows


def test_restore_is_atomic_and_leaves_no_part_temp(monkeypatch):
    """Crash-consistent restore: each file lands via a fsync'd temp + os.replace
    (not a torn direct write), no .part temp survives, and a DB's stale sidecar
    is cleared BEFORE the restored .db lands -- so no crash instant pairs the new
    .db with the old WAL."""
    import os as _os

    from maverick.paths import data_dir
    root = data_dir()
    _seed(root)
    tar = backup.create_backup()

    # A stale, pre-existing sidecar in the live root (the post-crash DR case).
    (root / "world.db").unlink()
    (root / "world.db-wal").write_bytes(b"stale-wal-bytes")

    real_replace = _os.replace
    seen = {"replaced": [], "wal_present_at_db_replace": None}

    def _spy_replace(a, b, **kw):
        b_path = Path(b)
        seen["replaced"].append(b_path.name)
        if b_path.suffix == ".db":
            seen["wal_present_at_db_replace"] = (root / "world.db-wal").exists()
        return real_replace(a, b, **kw)

    monkeypatch.setattr(backup.os, "replace", _spy_replace)
    backup.restore_backup(tar, force=True)

    # Correct contents restored.
    con = sqlite3.connect(str(root / "world.db"))
    assert con.execute("SELECT v FROM t").fetchone()[0] == "secret-data"
    con.close()
    assert (root / "agent_trust.json").read_text() == '[{"id":"vega"}]'

    # No leftover temp anywhere under the root.
    assert list(root.rglob("*.part")) == []

    # Every restored file went through os.replace (atomic write), and by the time
    # the .db was swapped in its stale sidecar was already gone.
    assert "world.db" in seen["replaced"]
    assert seen["wal_present_at_db_replace"] is False
    assert not (root / "world.db-wal").exists()


def test_create_errors_when_no_data(monkeypatch, tmp_path):
    # Point at an empty home with a fresh client -> no data root.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "empty"))
    client.reset_client_cache()
    with pytest.raises(backup.BackupError):
        backup.create_backup()


def test_cli_backup_create_info_restore():
    from click.testing import CliRunner
    from maverick.cli import main
    from maverick.paths import data_dir
    _seed(data_dir())
    runner = CliRunner()

    r = runner.invoke(main, ["backup", "create"])
    assert r.exit_code == 0 and "backup written" in r.output
    tarball = r.output.split("backup written:")[1].strip()

    r = runner.invoke(main, ["backup", "info", tarball])
    assert r.exit_code == 0 and "acme" in r.output

    (data_dir() / "world.db").unlink()
    r = runner.invoke(main, ["backup", "restore", tarball])
    assert r.exit_code == 0 and "restored into" in r.output
    assert (data_dir() / "world.db").exists()


def test_cli_backup_create_names_the_key_files_left_out():
    from click.testing import CliRunner
    from maverick.cli import main
    from maverick.paths import data_dir
    root = data_dir()
    _seed(root)
    _seed_key_material(root)

    r = CliRunner().invoke(main, ["backup", "create"])

    assert r.exit_code == 0, r.output
    before_written = r.output.split("backup written:")[0]
    for name in ("keys/at_rest.key", "keys/at_rest.d/k1.key", "audit/keys/signing.key"):
        assert name in before_written, r.output
    assert "dek.wrapped" not in r.output and "signing.pub" not in r.output
    # The last line stays the parseable result line.
    assert r.output.strip().splitlines()[-1].startswith("backup written:")


def test_cli_whole_home_backup_receipt_names_workspace_keys(tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main

    home = tmp_path / "wholehome"
    _seed(home)
    _seed_workspace_key_material(home)

    with _whole_home(home):
        result = CliRunner().invoke(
            main, ["backup", "create", "--out", str(tmp_path / "wholehome.tgz")]
        )

    assert result.exit_code == 0, result.output
    receipt = result.output.split("backup written:")[0]
    for name in _WORKSPACE_KEY_FILES:
        assert f"  {name}" in receipt, result.output
    with tarfile.open(tmp_path / "wholehome.tgz", "r:gz") as archive:
        members = archive.getnames()
    for name in _WORKSPACE_KEY_FILES:
        assert f"data/{name}" not in members


def test_cli_backup_create_with_keys_does_not_claim_any_were_left_out():
    from click.testing import CliRunner
    from maverick.cli import main
    from maverick.paths import data_dir
    root = data_dir()
    _seed(root)
    _seed_key_material(root)

    r = CliRunner().invoke(main, ["backup", "create", "--include-keys"])

    assert r.exit_code == 0, r.output
    assert "left out" not in r.output.lower()


def test_create_requires_operator_key_by_default(monkeypatch):
    from maverick.paths import data_dir

    _seed(data_dir())
    monkeypatch.delenv("MAVERICK_BACKUP_SIGNING_KEY")

    with pytest.raises(backup.BackupError, match="requires MAVERICK_BACKUP_SIGNING_KEY"):
        backup.create_backup()


def test_unsigned_compatibility_requires_explicit_opt_in(monkeypatch):
    from maverick.paths import data_dir

    root = data_dir()
    _seed(root)
    monkeypatch.delenv("MAVERICK_BACKUP_SIGNING_KEY")
    archive = backup.create_backup(allow_unsigned=True)

    with pytest.raises(backup.BackupError, match="unsigned"):
        backup.read_manifest(archive)
    manifest = backup.read_manifest(archive, allow_unsigned=True)
    assert manifest["authentication"] == {"algorithm": "none"}

    (root / "agent_trust.json").unlink()
    with pytest.raises(backup.BackupError, match="unsigned"):
        backup.restore_backup(archive)
    backup.restore_backup(archive, allow_unsigned=True)
    assert (root / "agent_trust.json").read_text() == '[{"id":"vega"}]'


def test_legacy_schema_one_restore_is_explicitly_unsigned(tmp_path):
    from maverick.paths import data_dir

    root = data_dir()
    _seed(root)
    archive = backup.create_backup()
    legacy = tmp_path / "legacy-schema-one.tgz"

    def _to_legacy(manifest):
        manifest["schema"] = 1
        manifest["files"] = {
            name: record["sha256"] for name, record in manifest["files"].items()
        }
        manifest.pop("authentication", None)

    _repack(archive, legacy, mutate_manifest=_to_legacy)
    (root / "agent_trust.json").unlink()

    with pytest.raises(backup.BackupError, match="unsigned"):
        backup.restore_backup(legacy)
    backup.restore_backup(legacy, allow_unsigned=True)
    assert (root / "agent_trust.json").exists()


def test_manifest_tamper_is_rejected_even_with_force(tmp_path):
    from maverick.paths import data_dir

    _seed(data_dir())
    archive = backup.create_backup()
    tampered = tmp_path / "tampered-manifest.tgz"
    _repack(
        archive,
        tampered,
        mutate_manifest=lambda manifest: manifest.update(client_id="attacker"),
    )

    with pytest.raises(backup.BackupError, match="signature verification failed"):
        backup.restore_backup(tampered, force=True)


def test_non_ascii_manifest_signature_is_rejected_not_a_crash(tmp_path):
    # The archive is supplied input: a 64-character non-ASCII signature used to
    # raise TypeError from hmac.compare_digest instead of BackupError.
    from maverick.paths import data_dir

    _seed(data_dir())
    archive = backup.create_backup()
    tampered = tmp_path / "non-ascii-signature.tgz"
    _repack(
        archive,
        tampered,
        mutate_manifest=lambda manifest: manifest["authentication"].update(
            signature="é" * 64
        ),
    )

    with pytest.raises(backup.BackupError, match="signature verification failed"):
        backup.verify_backup(tampered)


def test_wrong_operator_key_cannot_verify_archive(monkeypatch):
    from maverick.paths import data_dir

    _seed(data_dir())
    archive = backup.create_backup()
    monkeypatch.setenv(
        "MAVERICK_BACKUP_SIGNING_KEY",
        bytes(reversed(range(32))).hex(),
    )

    with pytest.raises(backup.BackupError, match="configured operator key"):
        backup.read_manifest(archive)


def test_restore_rejects_symlink_archive_member(tmp_path):
    from maverick.paths import data_dir

    _seed(data_dir())
    archive = backup.create_backup()
    malicious = tmp_path / "symlink-member.tgz"
    with tarfile.open(archive, "r:gz") as source, tarfile.open(malicious, "w:gz") as out:
        for member in source.getmembers():
            out.addfile(member, source.extractfile(member) if member.isfile() else None)
        link = tarfile.TarInfo("data/linked-secret")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        out.addfile(link)

    with pytest.raises(backup.BackupError, match="unsupported archive member type"):
        backup.restore_backup(malicious)


def test_restore_rejects_duplicate_archive_member(tmp_path):
    from maverick.paths import data_dir

    _seed(data_dir())
    archive = backup.create_backup()
    malicious = tmp_path / "duplicate-member.tgz"
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        blobs = {
            member.name: source.extractfile(member).read()
            for member in members
            if member.isfile()
        }
    with tarfile.open(malicious, "w:gz") as out:
        for member in members:
            out.addfile(member, io.BytesIO(blobs[member.name]) if member.isfile() else None)
        duplicate = tarfile.TarInfo("data/agent_trust.json")
        duplicate.size = len(blobs["data/agent_trust.json"])
        out.addfile(duplicate, io.BytesIO(blobs["data/agent_trust.json"]))

    with pytest.raises(backup.BackupError, match="duplicate"):
        backup.restore_backup(malicious)


@pytest.mark.parametrize(
    "member_name",
    [
        "data/report:alternate-stream.txt",
        "data/CON.txt",
        "data/a//b.txt",
        "data/.restore-transactions/forged-journal",
        "data/" + "a" * 256,
    ],
)
def test_restore_rejects_nonportable_or_reserved_member_paths(
    tmp_path, member_name,
):
    from maverick.paths import data_dir

    _seed(data_dir())
    archive = backup.create_backup()
    malicious = tmp_path / f"bad-path-{abs(hash(member_name))}.tgz"
    with tarfile.open(archive, "r:gz") as source, tarfile.open(malicious, "w:gz") as out:
        for member in source.getmembers():
            out.addfile(member, source.extractfile(member) if member.isfile() else None)
        extra = tarfile.TarInfo(member_name)
        extra.size = 1
        out.addfile(extra, io.BytesIO(b"x"))

    with pytest.raises(backup.BackupError, match="unsafe|reserved|too long"):
        backup.restore_backup(malicious)


def test_restore_rejects_casefold_path_collision(tmp_path):
    from maverick.paths import data_dir

    _seed(data_dir())
    archive = backup.create_backup()
    malicious = tmp_path / "case-collision.tgz"
    with tarfile.open(archive, "r:gz") as source, tarfile.open(malicious, "w:gz") as out:
        for member in source.getmembers():
            out.addfile(member, source.extractfile(member) if member.isfile() else None)
        for name in ("data/Readme.txt", "data/README.TXT"):
            extra = tarfile.TarInfo(name)
            extra.size = 1
            out.addfile(extra, io.BytesIO(b"x"))

    with pytest.raises(backup.BackupError, match="case-insensitive"):
        backup.restore_backup(malicious)


def test_restore_enforces_member_and_expanded_size_bounds(monkeypatch):
    from maverick.paths import data_dir

    _seed(data_dir())
    archive = backup.create_backup()

    monkeypatch.setattr(backup, "MAX_ARCHIVE_MEMBERS", 2)
    with pytest.raises(backup.BackupError, match="member-count"):
        backup.read_manifest(archive)

    monkeypatch.setattr(backup, "MAX_ARCHIVE_MEMBERS", 100_000)
    monkeypatch.setattr(backup, "MAX_ARCHIVE_FILE_BYTES", 4)
    with pytest.raises(backup.BackupError, match="per-file"):
        backup.read_manifest(archive)

    monkeypatch.setattr(backup, "MAX_ARCHIVE_FILE_BYTES", 8 * 1024**3)
    monkeypatch.setattr(backup, "MAX_ARCHIVE_EXPANDED_BYTES", 10)
    with pytest.raises(backup.BackupError, match="expanded-size"):
        backup.read_manifest(archive)

    monkeypatch.setattr(backup, "MAX_ARCHIVE_EXPANDED_BYTES", 256 * 1024**3)
    monkeypatch.setattr(backup, "MAX_ARCHIVE_COMPRESSED_BYTES", 1)
    with pytest.raises(backup.BackupError, match="bounded"):
        backup.read_manifest(archive)


def test_restore_streams_without_getmembers_or_extractall(monkeypatch):
    from maverick.paths import data_dir

    root = data_dir()
    _seed(root)
    archive = backup.create_backup()
    (root / "agent_trust.json").unlink()

    def _forbidden(*_args, **_kwargs):  # pragma: no cover - assertion is the test
        raise AssertionError("restore must use bounded streaming tar iteration")

    monkeypatch.setattr(tarfile.TarFile, "getmembers", _forbidden)
    monkeypatch.setattr(tarfile.TarFile, "extractall", _forbidden)
    backup.restore_backup(archive)
    assert (root / "agent_trust.json").exists()


def test_unique_backup_staging_ignores_planted_legacy_part(tmp_path):
    from maverick.paths import data_dir

    _seed(data_dir())
    output_dir = file_lock.ensure_private_directory(tmp_path / "output")
    destination = output_dir / "snapshot.tgz"
    legacy_part = destination.with_suffix(destination.suffix + ".part")
    file_lock.atomic_create_bytes(legacy_part, b"planted")

    created = backup.create_backup(destination)

    assert created == destination
    assert legacy_part.read_bytes() == b"planted"
    assert file_lock.private_path_is_restricted(created)


def test_create_refuses_planted_regular_destination(tmp_path):
    from maverick.paths import data_dir

    _seed(data_dir())
    output_dir = file_lock.ensure_private_directory(tmp_path / "output")
    destination = output_dir / "snapshot.tgz"
    file_lock.atomic_create_bytes(destination, b"planted")

    with pytest.raises(backup.BackupError, match="existing backup destination"):
        backup.create_backup(destination)
    assert destination.read_bytes() == b"planted"


def test_create_refuses_planted_final_symlink(tmp_path):
    from maverick.paths import data_dir

    _seed(data_dir())
    output_dir = file_lock.ensure_private_directory(tmp_path / "output")
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"do not overwrite")
    destination = output_dir / "snapshot.tgz"
    try:
        os.symlink(victim, destination)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")

    with pytest.raises(backup.BackupError, match="existing backup destination"):
        backup.create_backup(destination)
    assert victim.read_bytes() == b"do not overwrite"


def test_restore_refuses_planted_live_symlink(tmp_path):
    from maverick.paths import data_dir

    root = data_dir()
    _seed(root)
    archive = backup.create_backup()
    target = root / "agent_trust.json"
    target.unlink()
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"do not overwrite")
    try:
        os.symlink(victim, target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")

    with pytest.raises(backup.BackupError, match="planted or aliased"):
        backup.restore_backup(archive)
    assert victim.read_bytes() == b"do not overwrite"


def test_partial_restore_failure_rolls_back_entire_file_set(monkeypatch):
    from maverick.paths import data_dir

    root = data_dir()
    _seed(root)
    archive = backup.create_backup()

    (root / "agent_trust.json").write_text('[{"id":"live-new"}]')
    (root / "audit" / "2026-06-18.ndjson").write_text('{"kind":"live-new"}\n')
    connection = sqlite3.connect(str(root / "world.db"))
    connection.execute("UPDATE t SET v = 'live-new'")
    connection.commit()
    connection.close()
    wal = root / "world.db-wal"
    wal.write_bytes(b"pre-restore-sidecar")
    # Backdate it: this fixture is a pre-existing sidecar to verify rollback
    # restores unchanged, not a signal that a process currently has the
    # database open -- a fresh mtime here would trip the live-world guard
    # this test isn't exercising.
    stale = time.time() - 3600
    os.utime(wal, (stale, stale))
    before = {
        "trust": (root / "agent_trust.json").read_bytes(),
        "audit": (root / "audit" / "2026-06-18.ndjson").read_bytes(),
        "db": (root / "world.db").read_bytes(),
        "wal": wal.read_bytes(),
    }

    real_publish = backup._publish_staged_file
    failed = False

    def _fail_once(source, destination):
        nonlocal failed
        if destination.suffix == ".db" and not failed:
            failed = True
            raise OSError("injected apply failure")
        return real_publish(source, destination)

    monkeypatch.setattr(backup, "_publish_staged_file", _fail_once)
    with pytest.raises(OSError, match="injected apply failure"):
        backup.restore_backup(archive)

    assert (root / "agent_trust.json").read_bytes() == before["trust"]
    assert (root / "audit" / "2026-06-18.ndjson").read_bytes() == before["audit"]
    assert (root / "world.db").read_bytes() == before["db"]
    assert wal.read_bytes() == before["wal"]
    assert not (root / backup._RESTORE_TX_ROOT).exists()


def test_commit_journal_failure_rolls_back(monkeypatch):
    from maverick.paths import data_dir

    root = data_dir()
    _seed(root)
    archive = backup.create_backup()
    (root / "agent_trust.json").write_text('[{"id":"live-new"}]')
    before = (root / "agent_trust.json").read_bytes()
    real_write = backup._write_journal
    failed = False

    def _fail_commit(tx, body, key):
        nonlocal failed
        if body.get("state") == "committed" and not failed:
            failed = True
            raise OSError("journal commit unavailable")
        return real_write(tx, body, key)

    monkeypatch.setattr(backup, "_write_journal", _fail_commit)
    with pytest.raises(OSError, match="journal commit unavailable"):
        backup.restore_backup(archive)

    assert (root / "agent_trust.json").read_bytes() == before
    assert not (root / backup._RESTORE_TX_ROOT).exists()


def test_next_restore_recovers_retained_applying_journal(monkeypatch):
    from maverick.paths import data_dir

    root = data_dir()
    _seed(root)
    archive = backup.create_backup()
    (root / "agent_trust.json").write_text('[{"id":"live-new"}]')

    real_publish = backup._publish_staged_file
    real_rollback = backup._rollback
    failed = False

    def _fail_db_once(source, destination):
        nonlocal failed
        if destination.suffix == ".db" and not failed:
            failed = True
            raise OSError("injected apply failure")
        return real_publish(source, destination)

    def _rollback_unavailable(*_args, **_kwargs):
        raise OSError("injected rollback outage")

    monkeypatch.setattr(backup, "_publish_staged_file", _fail_db_once)
    monkeypatch.setattr(backup, "_rollback", _rollback_unavailable)
    with pytest.raises(backup.BackupError, match="rollback is incomplete"):
        backup.restore_backup(archive)
    assert (root / backup._RESTORE_TX_ROOT).exists()

    recoveries = 0

    def _observe_recovery(*args, **kwargs):
        nonlocal recoveries
        recoveries += 1
        return real_rollback(*args, **kwargs)

    monkeypatch.setattr(backup, "_publish_staged_file", real_publish)
    monkeypatch.setattr(backup, "_rollback", _observe_recovery)
    backup.restore_backup(archive)

    assert recoveries == 1
    assert (root / "agent_trust.json").read_text() == '[{"id":"vega"}]'
    assert not (root / backup._RESTORE_TX_ROOT).exists()
