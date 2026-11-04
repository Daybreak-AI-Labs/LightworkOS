from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from maverick import installation_recovery as maintenance


def reviewed_authorize(**kwargs):
    from maverick.installation_handoff import save_review
    if not kwargs.get("rollback_id"):
        release = {"version": "1.0.1", "runtime_sha256": hashlib.sha256(b"new-runtime").hexdigest(),
                   "installer_sha256": hashlib.sha256(b"new").hexdigest(), "signature": "fixture-reviewed-signature"}
        kwargs["review_id"] = save_review(release)["id"]
    return maintenance.authorize(**kwargs)



def digest(value):
    return hashlib.sha256(value).hexdigest()


@pytest.fixture
def installation(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    runtime = tmp_path / "maverick.exe"
    runtime.write_bytes(b"old-runtime")
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setattr(maintenance, "_runtime", lambda: runtime)
    monkeypatch.setattr(maintenance, "_native_channel", lambda _, **kwargs: {"native_sha256": digest(b"native-fixture"), "public_key": "fixture-only"})
    monkeypatch.setattr(maintenance, "blockers", list)
    monkeypatch.setattr(maintenance.workspace_recovery, "version", lambda: "1.0.0")
    return home, runtime, None


def grant():
    return reviewed_authorize(actor="global-admin", isolated=True, confirm_all_workspaces=True)


def row(identifier):
    return next(item for item in maintenance.status()["recovery_points"] if item["id"] == identifier)


def retire(identifier, **kwargs):
    return maintenance.retire(identifier, expected_sha256=row(identifier)["record_sha256"],
                              actor="global-admin", confirm=True, **kwargs)


def test_twenty_expired_grants_need_reviewed_retirement_before_another_update(installation, monkeypatch):
    grants = [grant() for _ in range(20)]
    monkeypatch.setattr(maintenance.time, "time", lambda: grants[-1]["expires_at"] + 1)
    with pytest.raises(maintenance.MaintenanceError, match="full"):
        grant()
    selected = grants[0]["id"]
    directory = maintenance._directory(selected)
    (directory / "old.msi").write_bytes(b"synthetic abandoned download")
    assert row(selected)["can_retire"] is True
    assert retire(selected)["retired"] is True
    assert not (directory / "old.msi").exists()
    assert grant()["id"] not in {item["id"] for item in grants}
    status = maintenance.status()
    assert len(status["recovery_points"]) == 20
    assert status["retirement_history"][0]["id"] == selected
    receipt = maintenance._read(maintenance._retired_directory(selected) / "record.json")
    assert receipt["retired_by"] == "global-admin"
    assert "grant_hash" not in receipt


@pytest.mark.parametrize("phase", ["prepared", "applying", "incomplete", "upgraded", "rolled_back"])
def test_active_or_unfinished_points_cannot_be_retired(installation, phase):
    selected = grant()["id"]
    directory = maintenance._directory(selected)
    record = maintenance._read(directory / "record.json")
    record["status"] = phase
    maintenance._write(directory / "record.json", record)
    if phase in {"upgraded", "rolled_back"}:
        maintenance._write(maintenance._store() / "active.json", {"schema": 1, "target": maintenance._target(), "id": selected})
    assert row(selected)["can_retire"] is False
    with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
        retire(selected)
    assert maintenance._read(directory / "record.json")["status"] == phase


def test_installed_upgrade_rollback_is_retained_but_obsolete_point_can_be_retired(installation):
    _, runtime, _ = installation
    selected = grant()["id"]
    path = maintenance._directory(selected) / "record.json"
    record = maintenance._read(path)
    record.update(status="upgraded", new_runtime_sha256=digest(b"old-runtime"), new={"version": "1.0.1"})
    maintenance._write(path, record)
    assert row(selected)["can_retire"] is False
    with pytest.raises(maintenance.MaintenanceError, match="installed application"):
        retire(selected)
    runtime.write_bytes(b"subsequent-installed-runtime")
    assert retire(selected)["retired"] is True


def test_retirement_requires_exact_review_and_confirmation_and_revokes_unused_grant(installation):
    approved = grant()
    selected = approved["id"]
    expected = row(selected)["record_sha256"]
    for actor, confirm in [("", True), ("admin", False)]:
        with pytest.raises(maintenance.MaintenanceError, match="[Rr]eview"):
            maintenance.retire(selected, expected_sha256=expected, actor=actor, confirm=confirm)
    path = maintenance._directory(selected) / "record.json"
    record = maintenance._read(path)
    record["expires_at"] += 1
    maintenance._write(path, record)
    with pytest.raises(maintenance.MaintenanceError, match="changed"):
        maintenance.retire(selected, expected_sha256=expected, actor="admin", confirm=True)
    expected = row(selected)["record_sha256"]
    result = maintenance.retire(selected, expected_sha256=expected, actor="admin", confirm=True)
    assert result["retired"]
    assert maintenance.retire(selected, expected_sha256=expected, actor="admin", confirm=True) == result
    with pytest.raises(maintenance.MaintenanceError, match="expired"):
        maintenance.inspect_grant(approved["authorization"])


def test_retirement_receipts_do_not_hide_active_points_and_history_is_bounded(installation, monkeypatch):
    monkeypatch.setattr(maintenance, "MAX_RETIREMENT_HISTORY", 2)
    for _ in range(4):
        retire(grant()["id"])
    selected = grant()["id"]
    maintenance._write(maintenance._store() / "active.json", {"schema": 1, "target": maintenance._target(), "id": selected})
    status = maintenance.status()
    assert [item["id"] for item in status["recovery_points"]] == [selected]
    assert status["recovery_points"][0]["pending_finalization"]
    assert len(status["retirement_history"]) == 2
    assert len(list(maintenance._store().glob("*/record.json"))) == 3


def test_retirement_refuses_unexpected_directory_without_deleting_contents(installation):
    selected = grant()["id"]
    unexpected = maintenance._directory(selected) / "unexpected"
    unexpected.mkdir()
    protected = unexpected / "keep.txt"
    protected.write_text("untouched")
    with pytest.raises(maintenance.MaintenanceError, match="unexpected"):
        retire(selected)
    assert protected.read_text() == "untouched"
    assert maintenance._read(maintenance._directory(selected) / "record.json")["status"] == "authorized"


def test_retirement_refuses_linked_payload_and_preserves_outside_file(installation, tmp_path):
    selected = grant()["id"]
    outside = tmp_path / "outside.msi"
    outside.write_bytes(b"untouched")
    os.link(outside, maintenance._directory(selected) / "old.msi")
    with pytest.raises(maintenance.MaintenanceError, match="alias"):
        retire(selected)
    assert outside.read_bytes() == b"untouched"


def test_retirement_cleanup_crash_revokes_grant_but_keeps_slot_until_exact_retry(installation, monkeypatch):
    approved = grant()
    selected = approved["id"]
    directory = maintenance._directory(selected)
    payload = directory / "old.msi"
    payload.write_bytes(b"synthetic")
    expected = row(selected)["record_sha256"]
    original = Path.unlink
    def interrupted(path, *args, **kwargs):
        if path.name == payload.name and path.parent == maintenance._retired_directory(selected):
            raise OSError("synthetic cleanup interruption")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", interrupted)
    with pytest.raises(OSError, match="interruption"):
        retire(selected)
    assert row(selected)["cleanup_pending"]
    assert maintenance._usable_point_count() == 1
    with pytest.raises(maintenance.MaintenanceError, match="expired"):
        maintenance.inspect_grant(approved["authorization"])
    monkeypatch.setattr(Path, "unlink", original)
    assert maintenance.retire(selected, expected_sha256=expected, actor="admin", confirm=True)["retired"]
    assert maintenance._usable_point_count() == 0
    assert not payload.exists()


def test_delayed_native_download_cannot_recreate_payload_after_retirement(installation):
    selected = grant()["id"]
    staging_directory = maintenance._directory(selected)
    retire(selected)
    with pytest.raises(FileNotFoundError):
        (staging_directory / "new.msi").write_bytes(b"late synthetic download")
    assert not staging_directory.exists()
    assert list(maintenance._retired_directory(selected).iterdir()) == [maintenance._retired_directory(selected) / "record.json"]


def test_operation_becoming_active_after_review_blocks_retirement(installation):
    selected = grant()["id"]
    expected = row(selected)["record_sha256"]
    maintenance._write(maintenance._store() / "active.json", {"schema": 1, "target": maintenance._target(), "id": selected})
    with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
        maintenance.retire(selected, expected_sha256=expected, actor="admin", confirm=True)
    assert maintenance._read(maintenance._directory(selected) / "record.json")["status"] == "authorized"
