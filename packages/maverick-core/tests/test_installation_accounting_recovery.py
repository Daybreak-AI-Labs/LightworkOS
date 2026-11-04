"""Application rollback must not erase irreversibly accounted provider usage."""
from __future__ import annotations

import hashlib
import json

import pytest
from maverick import backup, config, control_plane_lease, paths, quotas
from maverick import installation_recovery as maintenance


def reviewed_authorize(**kwargs):
    from maverick.installation_handoff import save_review
    if not kwargs.get("rollback_id"):
        release = {"version": "1.0.1", "runtime_sha256": hashlib.sha256(b"new-runtime").hexdigest(),
                   "installer_sha256": hashlib.sha256(b"new").hexdigest(), "signature": "fixture-reviewed-signature"}
        kwargs["review_id"] = save_review(release)["id"]
    return maintenance.authorize(**kwargs)



def _digest(value):
    return hashlib.sha256(value).hexdigest()


@pytest.fixture
def accounting_installation(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text("# synthetic local installation\n")
    installed = tmp_path / "installed"
    installed.mkdir()
    runtime = installed / "maverick.exe"
    runtime.write_bytes(b"old-runtime")
    (installed / "maverick-desktop.exe").write_bytes(b"native-fixture")
    selected_runtime = [runtime]
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.delenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", raising=False)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(maintenance, "blockers", list)
    monkeypatch.setattr(maintenance.workspace_recovery, "version", lambda: "1.0.0")
    monkeypatch.setattr(maintenance, "_runtime", lambda: selected_runtime[0])
    monkeypatch.setattr(maintenance, "_native_channel", lambda _, **kwargs: {"native_sha256": _digest(b"native-fixture"), "public_key": "fixture-only"})
    monkeypatch.setattr(quotas, "_quota_config", lambda: {"enforce": True, "max_dollars_per_day": 20.0, "max_tokens_per_day": 0})
    monkeypatch.setattr(quotas, "_today", lambda: "2026-09-06")
    control_plane_lease.release()
    with paths.tenant_scope(tenant="alpha"):
        yield home, runtime, selected_runtime
    control_plane_lease.release()


def _upgrade(installation, monkeypatch):
    _, runtime, selected_runtime = installation
    grant = reviewed_authorize(actor="global-admin", isolated=True, confirm_all_workspaces=True)
    directory = maintenance._directory(grant["id"])
    metadata = {"public_key": "fixture-only", "old": {"version": "1.0.0", "runtime_sha256": _digest(b"old-runtime")},
                "new": {"version": "1.0.1", "runtime_sha256": _digest(b"new-runtime"), "signature": "fixture-reviewed-signature"}}
    (directory / "downloads.json").write_text(json.dumps(metadata))
    for name in ("old", "new"):
        (directory / (name + ".msi")).write_bytes(name.encode())
    # Substitute only the external Windows signature/installer boundaries.
    # Snapshots, restoration admission, ledger writes and quota reads are real.
    monkeypatch.setattr(maintenance, "_installer", lambda directory, metadata, name: {
        **metadata[name], "sha256": backup._sha256(directory / (name + ".msi")),
        "product_code": name, "publisher_thumbprint": "c" * 40})
    events = []
    def install(directory, action, name):
        events.append((action, name))
        if action == "/i":
            runtime.write_bytes((name + "-runtime").encode())
        else:
            runtime.unlink(missing_ok=True)
    monkeypatch.setattr(maintenance, "_msiexec", install)
    maintenance.prepare(grant["authorization"])
    selected_runtime[0] = directory / "maverick.exe"
    assert maintenance.execute(grant["authorization"])["status"] == "upgraded"
    selected_runtime[0] = runtime
    events.clear()
    return grant, directory, events


def _new_spend(ledger, principal):
    ledger.record_cumulative(principal, "a" * 32, 30, 300, 300)
    ledger.record_cumulative(principal, "b" * 32, 5, 50, 50)
    assert ledger.usage(principal)["dollars"] == 35
    assert quotas.over_quota(principal) is not None


def _assert_spend_intact(ledger, principal):
    assert ledger.usage(principal)["dollars"] == 35
    assert ledger.settlement("a" * 32, principal)["total"]["dollars"] == 30
    assert ledger.settlement("b" * 32, principal)["total"]["dollars"] == 5
    assert "$35.00 >= $20.00" in quotas.over_quota(principal)


def test_completed_rollback_refuses_new_usage_before_preparing_or_running_msi(accounting_installation, monkeypatch):
    _, runtime, _ = accounting_installation
    principal = "user:synthetic-payer"
    ledger = quotas.UsageLedger()
    ledger.record_cumulative(principal, "a" * 32, 10, 100, 100)
    grant, directory, events = _upgrade(accounting_installation, monkeypatch)
    _new_spend(ledger, principal)
    original_snapshot = backup._sha256(directory / "before.tgz")
    rollback = reviewed_authorize(actor="global-admin", isolated=True, confirm_all_workspaces=True, rollback_id=grant["id"])
    with pytest.raises(backup.BackupError, match="accounting"):
        maintenance.prepare(rollback["authorization"])
    assert not events
    assert runtime.read_bytes() == b"new-runtime"
    assert backup._sha256(directory / "before.tgz") == original_snapshot
    assert not (maintenance._store() / "active.json").exists()
    maintenance.assert_normal_start_allowed()
    _assert_spend_intact(ledger, principal)


def test_prepared_rollback_rechecks_new_usage_before_msi_and_retains_startup_block(accounting_installation, monkeypatch):
    _, runtime, selected_runtime = accounting_installation
    principal = "user:synthetic-payer"
    ledger = quotas.UsageLedger()
    ledger.record_cumulative(principal, "a" * 32, 10, 100, 100)
    grant, directory, events = _upgrade(accounting_installation, monkeypatch)
    rollback = reviewed_authorize(actor="global-admin", isolated=True, confirm_all_workspaces=True, rollback_id=grant["id"])
    maintenance.prepare(rollback["authorization"])
    prepared = maintenance._read(directory / "record.json")
    snapshot_hashes = {name: backup._sha256(directory / name) for name in ("before.tgz", prepared["safety"]["name"])}
    _new_spend(ledger, principal)  # A late independent writer after preparation.
    selected_runtime[0] = directory / "maverick.exe"
    with pytest.raises(backup.BackupError, match="accounting"):
        maintenance.execute(rollback["authorization"])
    assert not events
    assert runtime.read_bytes() == b"new-runtime"
    assert {name: backup._sha256(directory / name) for name in snapshot_hashes} == snapshot_hashes
    with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
        maintenance.assert_normal_start_allowed()
    assert maintenance._read(maintenance._store() / "active.json")["id"] == grant["id"]
    _assert_spend_intact(ledger, principal)
