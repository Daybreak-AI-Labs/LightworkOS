"""Recovery must not rewind irreversible spend/holds or opaque DB accounting."""
from __future__ import annotations

import sqlite3
import tarfile
from pathlib import Path

import pytest
from maverick import backup, file_lock


@pytest.fixture
def recovery(tmp_path):
    root = file_lock.ensure_private_directory(tmp_path / "live")
    file_lock.atomic_write_text(root / "document.txt", "unchanged non-accounting fixture")
    archive = tmp_path / "selected.tgz"
    with backup.recovery_scope(root, "guard-workspace", bytes(range(32))):
        yield root, archive


@pytest.mark.parametrize("name", [
    "usage/ledger.json", "usage/reservations.json", "usage/future-settlements.json",
    "tenants/second/usage/ledger.json", "provider_spend.json",
    "llm_gateway_team_budget/team_budget.json", "mcp_sidecar/call_budget.json",
    "budget_receipts.jsonl", "budget_receipts.jsonl.head", "budget_receipts.required",
    "tenant_registry.json", "provider_spend.json.required", "dashboard-owner.json",
    "draft-recovery/account/retention.index", "tenants/second/draft-recovery/account/retention.index",
    "provider_accounting_reviews/review.record", "tenants/second/provider_accounting_reviews/review.record",
    "connections/connections.sealed", "connections/oauth-setup.sealed",
    "tenants/second/connections/connections.sealed", "tenants/second/connections/oauth-setup.sealed",
    "pilot_learning_exclusions/record", "tenants/second/pilot_learning_exclusions/record",
    "task-file-recovery/task/record", "tenants/second/task-file-recovery/task/record",
])
@pytest.mark.parametrize("mutation", ["changed", "added", "deleted"])
def test_guard_refuses_every_irreversible_accounting_path_without_changing_live_state(recovery, name, mutation):
    root, archive = recovery
    path = root / name
    file_lock.ensure_private_directory(path.parent)
    if mutation != "added":
        file_lock.atomic_write_text(path, "opaque old-format state")
    backup.create_backup(archive)
    if mutation == "deleted":
        path.unlink()
    else:
        file_lock.atomic_write_text(path, "opaque new-format state")
    before = path.read_bytes() if path.exists() else None
    with pytest.raises(backup.BackupError, match="reconciliation"):
        backup.assert_accounting_unchanged(archive)
    assert (path.read_bytes() if path.exists() else None) == before
    assert backup.verify_backup(archive)["client_id"] == "guard-workspace"


def _database(path: Path, value: str) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS opaque_state (value TEXT)")
        connection.execute("INSERT INTO opaque_state VALUES (?)", (value,))


@pytest.mark.parametrize("name", ["world.db", "custom.sqlite", "consent.sqlite3", "opaque.store", "custom.lock"])
@pytest.mark.parametrize("mutation", ["changed", "added", "deleted"])
def test_all_sqlite_formats_are_protected_without_guessing_accounting_schema(recovery, name, mutation):
    root, archive = recovery
    path = root / name
    if mutation != "added":
        _database(path, "before")
    backup.create_backup(archive)
    if mutation == "deleted":
        path.unlink()
    else:
        _database(path, "after")
    with pytest.raises(backup.BackupError, match="reconciliation"):
        backup.assert_accounting_unchanged(archive)


def test_unchanged_accounting_allows_non_database_documents_and_lock_file_changes(recovery):
    root, archive = recovery
    usage = file_lock.ensure_private_directory(root / "usage")
    file_lock.atomic_write_text(usage / "ledger.json", '{"opaque": "accounting"}')
    file_lock.atomic_write_text(root / "document.txt", "before")
    backup.create_backup(archive)
    file_lock.atomic_write_text(root / "document.txt", "after")
    file_lock.atomic_write_text(usage / "ledger.json.lock", "different lock bytes")
    file_lock.atomic_write_text(root / "budget_receipts.jsonl.lock", "different lock bytes")
    backup.assert_accounting_unchanged(archive)
    assert (root / "document.txt").read_text() == "after"


def test_comparison_reports_complete_metadata_without_changing_or_exposing_payloads(recovery):
    root, archive = recovery
    file_lock.ensure_private_directory(root / "usage")
    file_lock.atomic_write_text(root / "usage" / "ledger.json", "prior accounting payload")
    file_lock.atomic_write_text(root / "deleted.txt", "prior document payload")
    _database(root / "custom.lock", "prior database payload")
    backup.create_backup(archive)
    file_lock.atomic_write_text(root / "usage" / "ledger.json", "current accounting payload")
    (root / "deleted.txt").unlink()
    file_lock.atomic_write_text(root / "added.txt", "current document payload")
    _database(root / "custom.lock", "current database payload")
    result = backup.compare_backup(archive)
    rows = {row["path"]: row for row in result["items"]}
    assert result["total_changes"] == 4 and result["protected_changes"] == 2
    assert rows["usage/ledger.json"]["change"] == "changed"
    assert rows["usage/ledger.json"]["protected"] is True
    assert rows["custom.lock"]["protected"] is True
    assert rows["deleted.txt"]["current"] is None
    assert rows["added.txt"]["snapshot"] is None
    assert all(set(row["current"] or row["snapshot"]) == {"sha256", "size"} for row in rows.values())
    assert "payload" not in str(result)
    assert (root / "usage" / "ledger.json").read_text() == "current accounting payload"
    with pytest.raises(backup.BackupError, match="reconciliation"):
        backup.assert_accounting_unchanged(archive)


def test_comparison_fingerprint_includes_a_file_named_authentication(recovery):
    root, archive = recovery
    file_lock.atomic_write_text(root / "authentication", "one")
    backup.create_backup(archive)
    before = backup.compare_backup(archive)
    file_lock.atomic_write_text(root / "authentication", "two")
    after = backup.compare_backup(archive)
    assert before["snapshot_state_sha256"] == after["snapshot_state_sha256"]
    assert before["live_state_sha256"] != after["live_state_sha256"]


def test_sqlite_wal_checkpoint_without_logical_changes_does_not_block(recovery):
    root, archive = recovery
    connection = sqlite3.connect(root / "custom.store")
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE usage_settlement_scopes (scope TEXT)")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("INSERT INTO usage_settlement_scopes VALUES ('settled')")
        connection.commit()
        backup.create_backup(archive)
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        backup.assert_accounting_unchanged(archive)
    finally:
        connection.close()


def test_guard_authenticates_snapshot_before_trusting_accounting(recovery):
    root, archive = recovery
    file_lock.atomic_write_text(root / "provider_spend.json", "current spend")
    backup.create_backup(archive)
    data = bytearray(archive.read_bytes())
    data[len(data) // 2] ^= 1
    archive.write_bytes(data)
    with pytest.raises(backup.BackupError):
        backup.assert_accounting_unchanged(archive)
    assert (root / "provider_spend.json").read_text() == "current spend"


def test_compiled_template_cache_never_blocks_recovery_but_goal_templates_do(recovery):
    # A page first rendered after the snapshot writes a new compiled-template
    # cache file; that must not block rollback, and restore must leave it alone.
    root, archive = recovery
    cache = file_lock.ensure_private_directory(root / "cache" / "templates")
    file_lock.atomic_write_text(cache / "__jinja2_before.cache", "compiled before")
    backup.create_backup(archive)
    with tarfile.open(archive, "r:gz") as tar:
        assert not any("cache/templates" in name for name in tar.getnames())
    file_lock.atomic_write_text(cache / "__jinja2_after.cache", "compiled after")
    file_lock.atomic_write_text(cache / "__jinja2_before.cache", "recompiled")
    backup.assert_accounting_unchanged(archive)
    goal_templates = file_lock.ensure_private_directory(root / "templates")
    file_lock.atomic_write_text(goal_templates / "goal.json", "new goal template")
    with pytest.raises(backup.BackupError, match="reconciliation"):
        backup.assert_accounting_unchanged(archive)


def test_session_registry_is_never_rewound_or_compared(recovery):
    # Signed-in page views update last_seen; a restore must neither block on
    # that nor bring back an older copy that would revive revoked sessions.
    root, archive = recovery
    sessions = root / "dashboard-sessions.sqlite3"
    _database(sessions, "issued")
    backup.create_backup(archive)
    with tarfile.open(archive, "r:gz") as tar:
        assert not any("dashboard-sessions" in name for name in tar.getnames())
    _database(sessions, "revoked after the snapshot")
    _database(root / "dashboard-sessions.sqlite3-journal", "transient")
    backup.assert_accounting_unchanged(archive)
    assert not any("dashboard-sessions" in name for name in backup._replacement_targets(root, {}))
    # Only the top-level registry is exempt; another SQLite store still blocks.
    tenant = file_lock.ensure_private_directory(root / "tenants" / "a")
    _database(tenant / "dashboard-sessions.sqlite3", "x")
    with pytest.raises(backup.BackupError, match="reconciliation"):
        backup.assert_accounting_unchanged(archive)
