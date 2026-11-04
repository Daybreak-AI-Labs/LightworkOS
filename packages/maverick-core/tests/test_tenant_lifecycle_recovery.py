"""Signed restore and rollback cannot erase an installation's tenant history."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from maverick import backup, file_lock, paths
from maverick import workspace_recovery as recovery
from maverick.recovery_authorities import authority_policy
from maverick.tenant import registry

KEY = bytes(range(32))


@pytest.fixture
def home(tmp_path, monkeypatch):
    root = file_lock.ensure_private_directory(tmp_path / "home")
    monkeypatch.setenv("MAVERICK_HOME", str(root))
    monkeypatch.setenv("MAVERICK_CONFIG", str(root / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    return root


def barriers(home: Path, tenant="acme"):
    claim = paths._tenant_claim_path(home, paths._tenant_namespace_key(tenant))
    deletion = registry._retirement_path(tenant)
    return {"claim": claim, "deletion": deletion}


def fail_roster(_records):
    raise OSError("synthetic interrupted roster publication")


@pytest.mark.parametrize("force", [False, True])
def test_public_restore_cannot_reactivate_interrupted_deletion(home, tmp_path, monkeypatch, force):
    registry.create_tenant("acme")
    file_lock.atomic_write_text(home / "dashboard-tenant-roles.json", '{"acme":{"user:old":"admin"}}')
    roster = (home / "tenant_registry.json").read_bytes()
    with backup.recovery_scope(home, None, KEY, whole_home=True):
        archive = backup.create_backup(tmp_path / "before-delete.tgz")
        monkeypatch.setattr(registry, "_save", fail_roster)
        with pytest.raises(OSError, match="interrupted"):
            registry.delete_tenant("acme", purge=True)
        assert (home / "tenant_registry.json").read_bytes() == roster
        assert not registry.is_active("acme")
        originals = {path: path.read_bytes() for path in barriers(home).values()}
        rows = backup.compare_backup(archive)["items"]
        deletion = registry._retirement_path("acme").relative_to(home).as_posix()
        assert next(row for row in rows if row["path"] == deletion)["protected"] is True
        with pytest.raises(backup.BackupError, match="reconciliation"):
            backup.assert_accounting_unchanged(archive)
        with pytest.raises(backup.BackupError, match="tenant lifecycle history"):
            backup.restore_backup(archive, replace_existing=True, force=force)
        # Additive restore retains the newer denial, even when the old active
        # roster is copied. Its presence is never evidence of current admission.
        backup.restore_backup(archive, force=force)
    assert not registry.is_active("acme")
    assert registry.get_tenant("acme") is None
    assert all(path.read_bytes() == content for path, content in originals.items())


@pytest.mark.parametrize("tenant", ["Acme", "caf\u00e9", "team/name"])
def test_old_snapshot_cannot_release_a_name_after_uncertain_creation(home, tmp_path, monkeypatch, tenant):
    file_lock.atomic_write_text(home / "document.txt", "legacy data before tenant creation")
    with backup.recovery_scope(home, None, KEY, whole_home=True):
        archive = backup.create_backup(tmp_path / "before-create.tgz")
        original_save = registry._save
        monkeypatch.setattr(registry, "_save", fail_roster)
        with pytest.raises(OSError, match="interrupted"):
            registry.create_tenant(tenant)
        monkeypatch.setattr(registry, "_save", original_save)
        claim = barriers(home, tenant)["claim"]
        original = claim.read_bytes()
        assert authority_policy(claim.relative_to(home).as_posix(), is_sqlite=False) == "tenant_namespace_reservation"
        with pytest.raises(backup.BackupError, match="tenant lifecycle history"):
            backup.restore_backup(archive, replace_existing=True)
    paths._tenant_namespace_cache.clear()
    assert claim.read_bytes() == original
    with pytest.raises(ValueError, match="used before"):
        registry.create_tenant(tenant)


@pytest.mark.parametrize("purge", [False, True])
def test_unchanged_retirement_survives_backup_and_full_restore(home, tmp_path, purge):
    registry.create_tenant("acme")
    registry.delete_tenant("acme", purge=purge)
    originals = {path: path.read_bytes() for path in barriers(home).values()}
    file_lock.atomic_write_text(home / "document.txt", "snapshot document")
    with backup.recovery_scope(home, None, KEY, whole_home=True):
        archive = backup.create_backup(tmp_path / "retired.tgz")
        manifest = backup.verify_backup(archive)
        assert all(path.relative_to(home).as_posix() in manifest["files"] for path in originals)
        file_lock.atomic_write_text(home / "document.txt", "later document")
        backup.restore_backup(archive, replace_existing=True)
    assert (home / "document.txt").read_text(encoding="utf-8") == "snapshot document"
    assert all(path.read_bytes() == content for path, content in originals.items())
    paths._tenant_namespace_cache.clear()
    assert not registry.is_active("acme")
    with pytest.raises(ValueError):
        registry.create_tenant("acme")


def test_bootstrap_keeps_real_claim_and_tombstone_bytes_under_startup_hold(home, tmp_path):
    registry.create_tenant("acme")
    registry.delete_tenant("acme", purge=True)
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    originals = {}
    for path in barriers(home).values():
        relative = path.relative_to(home)
        target = stage / relative
        file_lock.ensure_private_directory(target.parent)
        file_lock.atomic_create_bytes(target, path.read_bytes())
        originals[relative.as_posix()] = path.read_bytes()
    removed, report = recovery._reconcile_bootstrap_stage(stage)
    assert not removed
    rows = {row["source"]: row for row in report["items"]}
    assert set(rows) == set(originals)
    for name, content in originals.items():
        assert (stage / name).read_bytes() == content
        assert rows[name]["safe_state"] == "global_start_blocked"
        assert rows[name]["state"] != "resolved"
        assert rows[name]["requires_external_readback"] is True
        assert authority_policy(name.swapcase(), is_sqlite=False) == authority_policy(name, is_sqlite=False)


def test_failed_publication_keeps_new_barriers_even_when_other_payloads_roll_back(home, tmp_path, monkeypatch):
    registry.create_tenant("acme")
    registry.delete_tenant("acme")
    originals = {path.relative_to(home): path.read_bytes() for path in barriers(home).values()}
    file_lock.atomic_write_text(home / "document.txt", "snapshot document")
    with backup.recovery_scope(home, None, KEY, whole_home=True):
        archive = backup.create_backup(tmp_path / "retired.tgz")
    destination = file_lock.ensure_private_directory(tmp_path / "destination")
    monkeypatch.setenv("MAVERICK_HOME", str(destination))

    def fail_verification(*_args):
        raise backup.BackupError("synthetic post-publication failure")

    monkeypatch.setattr(backup, "_verify_restored", fail_verification)
    with backup.recovery_scope(destination, None, KEY, whole_home=True):
        with pytest.raises(backup.BackupError, match="post-publication"):
            backup.restore_backup(archive, replace_existing=True)
    assert not (destination / "document.txt").exists()
    assert not (destination / "tenant_registry.json").exists()
    assert all((destination / name).read_bytes() == content for name, content in originals.items())
    paths._tenant_namespace_cache.clear()
    assert not registry.is_active("acme")
    with pytest.raises(ValueError):
        registry.create_tenant("acme")


@pytest.mark.parametrize("kind", ["claim", "deletion"])
def test_concurrent_barrier_wins_atomic_publication_and_survives_rollback(home, tmp_path, monkeypatch, kind):
    registry.create_tenant("acme")
    registry.delete_tenant("acme")
    relative = barriers(home)[kind].relative_to(home)
    winner = json.loads((home / relative).read_text(encoding="utf-8"))
    if kind == "claim":
        winner.update(canonical_id="Acme", segment="Acme")
    else:
        winner["deleted_at"] += 1
    winner_bytes = json.dumps(winner, sort_keys=True).encode()
    with backup.recovery_scope(home, None, KEY, whole_home=True):
        archive = backup.create_backup(tmp_path / "retired.tgz")
    destination = file_lock.ensure_private_directory(tmp_path / "destination")
    monkeypatch.setenv("MAVERICK_HOME", str(destination))
    original_create = file_lock.atomic_create_bytes_chunks
    injected = False

    def raced_create(path, chunks, **kwargs):
        nonlocal injected
        if not injected and backup._filesystem_path(path) == backup._filesystem_path(destination / relative):
            injected = True
            original_create(path, [winner_bytes], **kwargs)
        return original_create(path, chunks, **kwargs)

    # Stage extraction uses a temporary empty file plus a writer; only the
    # lifecycle publisher consumes an atomic stream for this destination.
    monkeypatch.setattr(file_lock, "atomic_create_bytes_chunks", raced_create)
    with backup.recovery_scope(destination, None, KEY, whole_home=True):
        with pytest.raises(backup.BackupError, match="tenant lifecycle history"):
            backup.restore_backup(archive, replace_existing=True)
    assert injected
    assert (destination / relative).read_bytes() == winner_bytes


@pytest.mark.parametrize("existed", [False, True])
def test_public_restore_recovers_old_journal_without_removing_or_rewinding_barriers(home, tmp_path, existed):
    registry.create_tenant("acme")
    registry.delete_tenant("acme")
    originals = {path.relative_to(home): path.read_bytes() for path in barriers(home).values()}
    with backup.recovery_scope(home, None, KEY, whole_home=True):
        archive = backup.create_backup(tmp_path / "current.tgz")
        tx = file_lock.ensure_private_directory(backup._transaction_root(home) / "older-journal")
        entries = []
        for relative in originals:
            entries.append({"rel": relative.as_posix(), "existed": existed, "sidecars": []})
            if existed:
                original = tx / "originals" / relative
                file_lock.ensure_private_directory(original.parent)
                file_lock.atomic_create_bytes(original, b"older original must not replace current barrier")
        backup._write_journal(tx, {"journal_schema": 1, "state": "applying", "entries": entries}, KEY)
        backup.restore_backup(archive, replace_existing=True)
    assert all((home / name).read_bytes() == content for name, content in originals.items())
    assert not registry.is_active("acme")
