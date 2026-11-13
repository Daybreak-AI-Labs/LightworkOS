from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick import backup, config, control_plane_lease
from maverick import installation_recovery as maintenance


def reviewed_authorize(**kwargs):
    from maverick.installation_handoff import save_review
    if not kwargs.get("rollback_id"):
        release = {"version": "1.0.1", "runtime_sha256": hashlib.sha256(b"new-runtime").hexdigest(),
                   "installer_sha256": hashlib.sha256(b"new").hexdigest(), "signature": "fixture-reviewed-signature"}
        kwargs["review_id"] = save_review(release)["id"]
    return maintenance.authorize(**kwargs)


PRODUCT_CODE = "{11111111-2222-3333-4444-555555555555}"
PACKAGE_CODE = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
PUBLISHER = "C" * 40


def digest(value):
    return hashlib.sha256(value).hexdigest()


@pytest.fixture
def installation(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.delenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", raising=False)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(maintenance, "blockers", list)
    monkeypatch.setattr(maintenance.workspace_recovery, "version", lambda: "1.0.0")
    installed = tmp_path / "installed"
    installed.mkdir()
    runtime = installed / "maverick.exe"
    runtime.write_bytes(b"old-runtime")
    (installed / "maverick-desktop.exe").write_bytes(b"native-ui-fixture")
    (installed / "maverick-recovery.exe").write_bytes(b"old-runtime")
    (installed / "maverick-recovery-desktop.exe").write_bytes(b"native-ui-fixture")
    active = [runtime]
    monkeypatch.setattr(maintenance, "_runtime", lambda: active[0])
    monkeypatch.setattr(maintenance, "_executing_runtime", lambda: active[0])
    monkeypatch.setattr(maintenance, "_native_channel", lambda runtime, **kwargs: {
        "native_sha256": backup._sha256(
            kwargs.get("native_path") or runtime.parent / "maverick-desktop.exe"
        ),
        "public_key": "fixture-only",
        "publisher_thumbprint": PUBLISHER,
    })
    (home / "config.toml").write_text("# local configuration\n")
    for tenant in ("alpha", "beta"):
        root = home / "tenants" / tenant
        root.mkdir(parents=True)
        (root / "ledger.json").write_text("old-state")
        (root / "backups").mkdir()
        (root / "backups" / "operator.key").write_text("separate-custody")
    control_plane_lease.release()
    yield home, runtime, active
    control_plane_lease.release()


def staged(installation, monkeypatch, *, prepare=True):
    home, runtime, active = installation
    grant = reviewed_authorize(actor="global-admin", isolated=True, confirm_all_workspaces=True)
    directory = maintenance._directory(grant["id"])
    metadata = {"public_key": "fixture-only", "old": {"version": "1.0.0", "runtime_sha256": digest(b"old-runtime")},
                "new": {"version": "1.0.1", "runtime_sha256": digest(b"new-runtime"), "signature": "fixture-reviewed-signature"}}
    (directory / "downloads.json").write_text(json.dumps(metadata))
    for name in ("old", "new"):
        (directory / (name + ".msi")).write_bytes(name.encode())
    # Signature primitives are exercised separately with real Ed25519. This
    # transaction test substitutes only the external Windows trust/MSI engine.
    monkeypatch.setattr(maintenance, "_installer", lambda directory, metadata, label: {
        **metadata[label], "sha256": backup._sha256(directory / (label + ".msi")), "product_code": label,
        "publisher_thumbprint": "c" * 40})
    if prepare:
        maintenance.prepare(grant["authorization"])
        active[0] = directory / "maverick.exe"
    return grant, directory


def staged_repair(installation, monkeypatch, *, prepare=True):
    _, runtime, active = installation
    (runtime.parent / "Lightwork-recovery.msi").write_bytes(
        b"same-version-repair-msi"
    )
    monkeypatch.setattr(
        maintenance,
        "_registered_product_identity",
        lambda *_: {
            "product_code": PRODUCT_CODE,
            "package_code": PACKAGE_CODE,
            "install_directory": str(runtime.parent.absolute()),
            "package_name": "Lightwork.msi",
        },
    )
    monkeypatch.setattr(
        maintenance,
        "inspect_signed_msi",
        lambda *_args, **_kwargs: {
            "ProductVersion": "1.0.0",
            "ProductCode": PRODUCT_CODE,
            "PackageCode": PACKAGE_CODE,
            "UpgradeCode": "{AB5BC260-7EC9-4B70-AF78-28F4067BC530}",
            "PublisherThumbprint": PUBLISHER,
        },
    )
    grant = maintenance.authorize_repair(
        actor="native-desktop-repair", confirm_all_workspaces=True,
    )
    directory = maintenance._directory(grant["id"])
    candidate = directory / "new.msi"
    candidate.write_bytes(b"same-version-repair-msi")
    metadata = {
        "public_key": "fixture-only",
        "identity_transition": None,
        "new": {
            "version": "1.0.0",
            "runtime_sha256": digest(b"old-runtime"),
            "installer_sha256": backup._sha256(candidate),
        },
    }
    (directory / "downloads.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(maintenance, "_installer", lambda directory, metadata, label: {
        **metadata[label],
        "sha256": backup._sha256(directory / (label + ".msi")),
        "product_code": PRODUCT_CODE,
        "package_code": PACKAGE_CODE,
        "publisher_thumbprint": PUBLISHER,
    })
    if prepare:
        maintenance.prepare(grant["authorization"])
        active[0] = directory / "maverick.exe"
    return grant, directory


def staged_reviewed_repair(
    installation, monkeypatch, *, retained_installer: bytes | None, prepare=True,
):
    _, runtime, active = installation
    candidate_bytes = b"same-version-repair-msi"
    retained = runtime.parent / "Lightwork-recovery.msi"
    if retained_installer is None:
        retained.unlink(missing_ok=True)
    else:
        retained.write_bytes(retained_installer)
    monkeypatch.setattr(
        maintenance,
        "_registered_product_identity",
        lambda *_: {
            "product_code": PRODUCT_CODE,
            "package_code": PACKAGE_CODE,
            "install_directory": str(runtime.parent.absolute()),
            "package_name": "Lightwork.msi",
        },
    )
    monkeypatch.setattr(
        maintenance,
        "inspect_signed_msi",
        lambda *_args, **_kwargs: {
            "ProductVersion": "1.0.0",
            "ProductCode": PRODUCT_CODE,
            "PackageCode": PACKAGE_CODE,
            "UpgradeCode": "{AB5BC260-7EC9-4B70-AF78-28F4067BC530}",
            "PublisherThumbprint": PUBLISHER,
        },
    )
    expected = {
        "expected_runtime_sha256": digest(b"old-runtime"),
        "expected_installer_sha256": digest(candidate_bytes),
        "expected_public_key": "fixture-only",
        "expected_version": "1.0.0",
    }
    capability = maintenance.repair_capability(**expected)
    grant = maintenance.authorize_repair(
        actor="native-desktop-repair",
        confirm_all_workspaces=True,
        **expected,
    )
    directory = maintenance._directory(grant["id"])
    (directory / "new.msi").write_bytes(candidate_bytes)
    metadata = {
        "public_key": "fixture-only",
        "identity_transition": None,
        "new": {
            "version": "1.0.0",
            "runtime_sha256": digest(b"old-runtime"),
            "installer_sha256": digest(candidate_bytes),
        },
    }
    (directory / "downloads.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(maintenance, "_installer", lambda directory, metadata, label: {
        **metadata[label],
        "sha256": backup._sha256(directory / (label + ".msi")),
        "product_code": PRODUCT_CODE,
        "package_code": PACKAGE_CODE,
        "publisher_thumbprint": PUBLISHER,
    })
    if prepare:
        maintenance.prepare(grant["authorization"])
        active[0] = directory / "maverick.exe"
    return grant, directory, capability


def fake_installer(runtime, events):
    def install(directory, action, label):
        events.append((action, label))
        if action == "/i":
            runtime.write_bytes((label + "-runtime").encode())
        else:
            runtime.unlink(missing_ok=True)
    return install


def fake_repair_installer(runtime, events):
    def install(_directory, action, label):
        events.append((action, label))
        if action == "/i":
            runtime.write_bytes(b"old-runtime")
            (runtime.parent / "maverick-recovery.exe").write_bytes(b"old-runtime")
            (runtime.parent / "maverick-desktop.exe").write_bytes(b"native-ui-fixture")
            (runtime.parent / "maverick-recovery-desktop.exe").write_bytes(
                b"native-ui-fixture"
            )
    return install


@pytest.mark.parametrize("registered_name", ["Lightwork.msi", "new.msi"])
@pytest.mark.parametrize("returncode", [0, 1603])
def test_repair_msi_reinstalls_the_verified_package_under_its_registered_name(
    installation, monkeypatch, registered_name, returncode,
):
    # Windows Installer resolves a maintenance-mode (REINSTALL) source as the
    # launched-from directory plus the product's registered PackageName. A
    # package launched under any other file name fails source resolution with
    # error 1316 during ProcessComponents (observed as 1603 on the hosted
    # acceptance VM), so the verified bytes must be offered under that name.
    grant, directory = staged_repair(installation, monkeypatch)
    record = maintenance._read(directory / "record.json")
    record["old"]["package_name"] = registered_name
    maintenance._write(directory / "record.json", record)
    launched = directory / registered_name
    calls = []

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        assert launched.is_file() and not launched.is_symlink()
        assert launched.read_bytes() == (directory / "new.msi").read_bytes()
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(maintenance.subprocess, "run", run)
    if returncode:
        with pytest.raises(maintenance.MaintenanceError, match="could not finish"):
            maintenance._msiexec(directory, "/i", "new")
    else:
        maintenance._msiexec(directory, "/i", "new")
    arguments, kwargs = calls[0]
    assert arguments[1:3] == ["/i", maintenance.installer_path(launched)]
    assert "REINSTALL=ALL" in arguments
    assert "REINSTALLMODE=vamus" in arguments
    install_directory = Path(record["installed_runtime"]).parent
    assert "INSTALLDIR=" + maintenance.installer_path(install_directory) in arguments
    assert arguments[6] == maintenance.installer_path(directory / "i-new.log")
    assert kwargs["check"] is False
    assert kwargs["timeout"] == 1800
    # The verified candidate stays for finalization and recovery; only the
    # transient registered-name copy is removed, whatever msiexec returned.
    assert (directory / "new.msi").is_file()
    assert launched.exists() == (registered_name == "new.msi")


def test_repair_msi_refuses_a_record_without_the_registered_package_name(
    installation, monkeypatch,
):
    grant, directory = staged_repair(installation, monkeypatch)
    record = maintenance._read(directory / "record.json")
    del record["old"]["package_name"]
    maintenance._write(directory / "record.json", record)
    monkeypatch.setattr(
        maintenance.subprocess, "run",
        lambda *_args, **_kwargs: pytest.fail("msiexec must not start without the registered name"),
    )
    with pytest.raises(maintenance.MaintenanceError, match="registered package name"):
        maintenance._msiexec(directory, "/i", "new")
    assert (directory / "new.msi").is_file()


def _simulate_windows(monkeypatch):
    """The registered-installer lookup is Windows-only by design; the tests
    below exercise its PowerShell contract with the OS probe and the
    Windows-only subprocess flag stubbed, while subprocess.run is faked."""
    monkeypatch.setattr(
        maintenance, "os", SimpleNamespace(name="nt", environ=os.environ),
    )
    monkeypatch.setattr(maintenance.subprocess, "CREATE_NO_WINDOW", 0, raising=False)


def test_registered_installer_lookup_uses_the_fixed_product_family_and_os_powershell(
    installation, tmp_path, monkeypatch,
):
    _, runtime, _ = installation
    _simulate_windows(monkeypatch)
    calls = []

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "ProductCode": PRODUCT_CODE.lower(),
                "PackageCode": PACKAGE_CODE.lower(),
                "InstallLocation": str(runtime.parent),
                "PackageName": "Lightwork.msi",
            }),
        )

    monkeypatch.setenv("PSModulePath", str(tmp_path / "untrusted-modules"))
    monkeypatch.setattr(maintenance.subprocess, "run", run)
    scratch = tmp_path / "scratch"
    result = maintenance._registered_product_identity("1.0.0", scratch, runtime)
    assert result == {
        "product_code": PRODUCT_CODE,
        "package_code": PACKAGE_CODE,
        "install_directory": str(runtime.parent.absolute()),
        "package_name": "Lightwork.msi",
    }
    arguments, kwargs = calls[0]
    assert arguments[-2:] == ["-Version", "1.0.0"]
    script = (scratch / "inspect-registered-installer.ps1").read_text()
    assert "AB5BC260-7EC9-4B70-AF78-28F4067BC530" in script
    # Windows Installer resolves a maintenance-mode source as the launched-from
    # directory plus the registered PackageName; the lookup must report it.
    assert "'PackageName'" in script
    assert "LocalPackage" not in (scratch / "inspect-registered-installer.ps1").read_text()
    assert kwargs["env"]["PSModulePath"] != str(tmp_path / "untrusted-modules")
    assert kwargs["check"] is False


def test_registered_installer_lookup_rejects_non_object_output(
    installation, tmp_path, monkeypatch,
):
    _, runtime, _ = installation
    _simulate_windows(monkeypatch)
    monkeypatch.setattr(
        maintenance.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="[]"),
    )
    with pytest.raises(maintenance.MaintenanceError, match="identity or installation directory"):
        maintenance._registered_product_identity("1.0.0", tmp_path / "scratch", runtime)


@pytest.mark.parametrize("package_name", [
    None, "", "Lightwork", "..\\Lightwork.msi", "sub/Lightwork.msi", "C:\\Lightwork.msi",
    "..", "Light\"work.msi", "x" * 252 + ".msi",
])
def test_registered_installer_lookup_rejects_unsafe_package_names(
    installation, tmp_path, monkeypatch, package_name,
):
    _, runtime, _ = installation
    _simulate_windows(monkeypatch)
    response = {
        "ProductCode": PRODUCT_CODE,
        "PackageCode": PACKAGE_CODE,
        "InstallLocation": str(runtime.parent),
    }
    if package_name is not None:
        response["PackageName"] = package_name
    monkeypatch.setattr(
        maintenance.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=json.dumps(response)),
    )
    with pytest.raises(maintenance.MaintenanceError, match="identity or installation directory"):
        maintenance._registered_product_identity("1.0.0", tmp_path / "scratch", runtime)


def test_registered_product_is_rechecked_before_repair(
    installation, tmp_path, monkeypatch,
):
    _, runtime, _ = installation
    directory = maintenance.file_lock.ensure_private_directory(tmp_path / "retained")
    record = {
        "old_version": "1.0.0",
        "installed_runtime": str(runtime),
        "old": {
            "product_code": PRODUCT_CODE,
            "package_code": PACKAGE_CODE,
            "install_directory": str(runtime.parent.absolute()),
            "package_name": "Lightwork.msi",
        },
    }
    for drift in (
        {"package_code": "{FFFFFFFF-EEEE-DDDD-CCCC-BBBBBBBBBBBB}"},
        {"package_name": "Renamed.msi"},
    ):
        monkeypatch.setattr(
            maintenance,
            "_registered_product_identity",
            lambda *_, drift=drift: {**record["old"], **drift},
        )
        with pytest.raises(maintenance.MaintenanceError, match="package or location"):
            maintenance._verify_repair_registration(directory, record)


def test_unknown_or_mismatched_repair_operation_is_refused_before_msi(
    installation, monkeypatch,
):
    grant, directory = staged_repair(installation, monkeypatch, prepare=False)
    record = maintenance._read(directory / "record.json")
    record["operation"] = "future-operation"
    maintenance._write(directory / "record.json", record)
    with pytest.raises(maintenance.MaintenanceError, match="unsupported"):
        maintenance.prepare(grant["authorization"])
    assert not (maintenance._store() / "active.json").exists()

    grant, directory = staged_repair(installation, monkeypatch)
    record = maintenance._read(directory / "record.json")
    record["finalization"] = "upgraded"
    maintenance._write(directory / "record.json", record)
    calls = []
    monkeypatch.setattr(maintenance, "_msiexec", lambda *_: calls.append("msi"))
    with pytest.raises(maintenance.MaintenanceError, match="does not match"):
        maintenance.execute(grant["authorization"])
    assert calls == []


def test_completed_upgrade_rollback_reinstalls_exact_old_binary_before_old_state(installation, monkeypatch):
    home, runtime, active = installation
    grant, directory = staged(installation, monkeypatch)
    events = []
    monkeypatch.setattr(maintenance, "_msiexec", fake_installer(runtime, events))
    assert maintenance.execute(grant["authorization"])["status"] == "upgraded"
    active[0] = runtime
    (home / "tenants" / "alpha" / "ledger.json").write_text("new-v2-state")
    (home / "tenants" / "beta" / "after-upgrade.json").write_text("new file")
    rollback = reviewed_authorize(actor="global-admin", isolated=True, confirm_all_workspaces=True, rollback_id=grant["id"])
    maintenance.prepare(rollback["authorization"])
    with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
        maintenance.assert_normal_start_allowed()
    active[0] = directory / "maverick.exe"
    original_restore = backup.restore_backup
    def checked_restore(*args, **kwargs):
        assert runtime.read_bytes() == b"old-runtime"
        events.append("restore")
        return original_restore(*args, **kwargs)
    monkeypatch.setattr(backup, "restore_backup", checked_restore)
    assert maintenance.execute(rollback["authorization"])["status"] == "rolled_back"
    assert events == [("/i", "new"), ("/x", "new"), ("/i", "old"), "restore"]
    assert (home / "tenants" / "alpha" / "ledger.json").read_text() == "old-state"
    assert not (home / "tenants" / "beta" / "after-upgrade.json").exists()
    assert (home / "tenants" / "beta" / "backups" / "operator.key").read_text() == "separate-custody"
    record = maintenance._read(directory / "record.json")
    assert (directory / record["safety"]["name"]).is_file()
    maintenance.assert_normal_start_allowed()


def test_failed_old_install_does_not_restore_state_or_allow_normal_start_and_can_resume(installation, monkeypatch):
    home, runtime, active = installation
    grant, directory = staged(installation, monkeypatch)
    monkeypatch.setattr(maintenance, "_msiexec", fake_installer(runtime, []))
    maintenance.execute(grant["authorization"])
    active[0] = runtime
    (home / "tenants" / "alpha" / "ledger.json").write_text("new-v2-state")
    rollback = reviewed_authorize(actor="global-admin", isolated=True, confirm_all_workspaces=True, rollback_id=grant["id"])
    maintenance.prepare(rollback["authorization"])
    active[0] = directory / "maverick.exe"
    def fail(*_):
        raise maintenance.MaintenanceError("synthetic MSI failure")
    monkeypatch.setattr(maintenance, "_msiexec", fail)
    with pytest.raises(maintenance.MaintenanceError, match="synthetic"):
        maintenance.execute(rollback["authorization"])
    assert (home / "tenants" / "alpha" / "ledger.json").read_text() == "new-v2-state"
    with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
        maintenance.assert_normal_start_allowed()
    token = maintenance.resume(grant["id"])
    monkeypatch.setattr(maintenance, "_msiexec", fake_installer(runtime, []))
    assert maintenance.execute(token)["status"] == "rolled_back"


def test_only_one_concurrent_execution_consumes_review(installation, monkeypatch):
    _, runtime, _ = installation
    grant, _ = staged(installation, monkeypatch)
    calls = []
    monkeypatch.setattr(maintenance, "_msiexec", fake_installer(runtime, calls))
    def attempt():
        try:
            return maintenance.execute(grant["authorization"])["status"]
        except maintenance.MaintenanceError:
            return "refused"
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: attempt(), range(2))) == ["refused", "upgraded"]
    assert calls == [("/i", "new")]


def test_live_control_plane_and_missing_explicit_all_workspace_review_are_refused(installation):
    with pytest.raises(maintenance.MaintenanceError, match="global administrator"):
        reviewed_authorize(actor="admin", isolated=True, confirm_all_workspaces=False)
    grant = reviewed_authorize(actor="admin", isolated=True, confirm_all_workspaces=True)
    control_plane_lease.acquire(role="workspace-recovery")
    with pytest.raises(maintenance.MaintenanceError, match="Pause"):
        maintenance.prepare(grant["authorization"])


def test_changed_source_and_expired_grant_refuse_before_installers(installation, monkeypatch):
    _, runtime, _ = installation
    grant = reviewed_authorize(actor="admin", isolated=True, confirm_all_workspaces=True)
    runtime.write_bytes(b"changed")
    with pytest.raises(maintenance.MaintenanceError, match="source application changed"):
        maintenance.prepare(grant["authorization"])
    monkeypatch.setattr(maintenance.time, "time", lambda: grant["expires_at"] + 1)
    with pytest.raises(maintenance.MaintenanceError, match="expired"):
        maintenance.inspect_grant(grant["authorization"])


def test_same_version_repair_uses_signed_snapshot_and_startup_gate(
    installation, monkeypatch,
):
    home, runtime, _ = installation
    grant, directory = staged_repair(installation, monkeypatch)
    record = maintenance._read(directory / "record.json")
    assert record["operation"] == "repair"
    assert record["old"]["product_code"] == record["new"]["product_code"]
    assert record["old"]["publisher_thumbprint"] == record["new"]["publisher_thumbprint"]
    assert (directory / "before.tgz").is_file()
    with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
        maintenance.assert_normal_start_allowed()
    events = []
    monkeypatch.setattr(maintenance, "_msiexec", fake_repair_installer(runtime, events))
    assert maintenance.execute(grant["authorization"])["status"] == "repaired"
    assert events == [("/i", "new")]
    assert (home / "tenants" / "alpha" / "ledger.json").read_text() == "old-state"
    maintenance.assert_normal_start_allowed()


def test_recovery_copies_repair_missing_runtime_and_corrupt_native_shell(
    installation, monkeypatch,
):
    _, runtime, _ = installation
    runtime.unlink()
    (runtime.parent / "maverick-desktop.exe").write_bytes(b"damaged-native-shell")
    grant, directory = staged_repair(installation, monkeypatch)
    record = maintenance._read(directory / "record.json")
    assert record["damaged_core_files"] == ["maverick-desktop.exe", "maverick.exe"]
    events = []
    monkeypatch.setattr(maintenance, "_msiexec", fake_repair_installer(runtime, events))
    assert maintenance.execute(grant["authorization"])["status"] == "repaired"
    assert runtime.read_bytes() == b"old-runtime"
    assert (runtime.parent / "maverick-desktop.exe").read_bytes() == b"native-ui-fixture"
    assert events == [("/i", "new")]


def test_missing_recovery_copy_refuses_before_creating_repair_authorization(
    installation, monkeypatch,
):
    _, runtime, _ = installation
    monkeypatch.setattr(
        maintenance,
        "_registered_product_identity",
        lambda *_: {
            "product_code": PRODUCT_CODE,
            "package_code": PACKAGE_CODE,
            "install_directory": str(runtime.parent.absolute()),
            "package_name": "Lightwork.msi",
        },
    )
    (runtime.parent / "Lightwork-recovery.msi").write_bytes(b"same-version-repair-msi")
    monkeypatch.setattr(
        maintenance,
        "inspect_signed_msi",
        lambda *_args, **_kwargs: {
            "ProductVersion": "1.0.0",
            "ProductCode": PRODUCT_CODE,
            "PackageCode": PACKAGE_CODE,
            "UpgradeCode": "{AB5BC260-7EC9-4B70-AF78-28F4067BC530}",
            "PublisherThumbprint": PUBLISHER,
        },
    )
    (runtime.parent / "maverick-recovery.exe").unlink()
    with pytest.raises(maintenance.MaintenanceError, match="Neither installed application copy"):
        maintenance.authorize_repair(
            actor="native-desktop-repair", confirm_all_workspaces=True,
        )
    assert maintenance._records() == []


@pytest.mark.parametrize("restore_recovery_pair", [True, False])
def test_signed_current_manifest_uses_primary_pair_to_repair_broken_recovery_pair(
    installation, monkeypatch, restore_recovery_pair,
):
    _, runtime, active = installation
    retained_installer = runtime.parent / "Lightwork-recovery.msi"
    retained_installer.write_bytes(b"same-version-repair-msi")
    monkeypatch.setattr(
        maintenance,
        "_registered_product_identity",
        lambda *_: {
            "product_code": PRODUCT_CODE,
            "package_code": PACKAGE_CODE,
            "install_directory": str(runtime.parent.absolute()),
            "package_name": "Lightwork.msi",
        },
    )
    monkeypatch.setattr(
        maintenance,
        "inspect_signed_msi",
        lambda *_args, **_kwargs: {
            "ProductVersion": "1.0.0",
            "ProductCode": PRODUCT_CODE,
            "PackageCode": PACKAGE_CODE,
            "UpgradeCode": "{AB5BC260-7EC9-4B70-AF78-28F4067BC530}",
            "PublisherThumbprint": PUBLISHER,
        },
    )
    (runtime.parent / "maverick-recovery.exe").unlink()
    (runtime.parent / "maverick-recovery-desktop.exe").write_bytes(b"broken-recovery-shell")
    installer_sha256 = backup._sha256(retained_installer)
    grant = maintenance.authorize_repair(
        actor="native-desktop-repair",
        confirm_all_workspaces=True,
        expected_runtime_sha256=digest(b"old-runtime"),
        expected_installer_sha256=installer_sha256,
        expected_public_key="fixture-only",
        expected_version="1.0.0",
    )
    directory = maintenance._directory(grant["id"])
    candidate = directory / "new.msi"
    candidate.write_bytes(b"same-version-repair-msi")
    metadata = {
        "public_key": "fixture-only",
        "identity_transition": None,
        "new": {
            "version": "1.0.0",
            "runtime_sha256": digest(b"old-runtime"),
            "installer_sha256": installer_sha256,
        },
    }
    (directory / "downloads.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(maintenance, "_installer", lambda directory, metadata, label: {
        **metadata[label],
        "sha256": backup._sha256(directory / (label + ".msi")),
        "product_code": PRODUCT_CODE,
        "package_code": PACKAGE_CODE,
        "publisher_thumbprint": PUBLISHER,
    })

    maintenance.prepare(grant["authorization"])
    record = maintenance._read(directory / "record.json")
    assert record["damaged_core_files"] == [
        "maverick-recovery-desktop.exe", "maverick-recovery.exe",
    ]
    active[0] = directory / "maverick.exe"
    events = []

    def install_primary_only(_directory, action, label):
        events.append((action, label))
        runtime.write_bytes(b"old-runtime")
        (runtime.parent / "maverick-desktop.exe").write_bytes(b"native-ui-fixture")
        if restore_recovery_pair:
            (runtime.parent / "maverick-recovery.exe").write_bytes(b"old-runtime")
            (runtime.parent / "maverick-recovery-desktop.exe").write_bytes(
                b"native-ui-fixture"
            )

    monkeypatch.setattr(maintenance, "_msiexec", install_primary_only)
    if restore_recovery_pair:
        assert maintenance.execute(grant["authorization"])["status"] == "repaired"
    else:
        with pytest.raises(maintenance.MaintenanceError, match="recovery copy"):
            maintenance.execute(grant["authorization"])
        assert maintenance._read(directory / "record.json")["status"] == "incomplete"
        with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
            maintenance.assert_normal_start_allowed()
        authorization = maintenance.resume(grant["id"])
        assert maintenance.execute(authorization)["status"] == "repair_recovered"
    assert events == [("/i", "new")]
    assert (runtime.parent / "maverick-recovery.exe").read_bytes() == b"old-runtime"
    assert (runtime.parent / "maverick-recovery-desktop.exe").read_bytes() == b"native-ui-fixture"


def test_primary_repair_fallback_requires_exact_signed_manifest_identity(
    installation, monkeypatch,
):
    _, runtime, _ = installation
    retained_installer = runtime.parent / "Lightwork-recovery.msi"
    retained_installer.write_bytes(b"same-version-repair-msi")
    monkeypatch.setattr(
        maintenance,
        "_registered_product_identity",
        lambda *_: {
            "product_code": PRODUCT_CODE,
            "package_code": PACKAGE_CODE,
            "install_directory": str(runtime.parent.absolute()),
            "package_name": "Lightwork.msi",
        },
    )
    monkeypatch.setattr(
        maintenance,
        "inspect_signed_msi",
        lambda *_args, **_kwargs: {
            "ProductVersion": "1.0.0",
            "ProductCode": PRODUCT_CODE,
            "PackageCode": PACKAGE_CODE,
            "UpgradeCode": "{AB5BC260-7EC9-4B70-AF78-28F4067BC530}",
            "PublisherThumbprint": PUBLISHER,
        },
    )
    (runtime.parent / "maverick-recovery.exe").unlink()
    with pytest.raises(maintenance.MaintenanceError, match="Neither installed application copy"):
        maintenance.authorize_repair(
            actor="native-desktop-repair",
            confirm_all_workspaces=True,
            expected_runtime_sha256="f" * 64,
            expected_installer_sha256=backup._sha256(retained_installer),
            expected_public_key="fixture-only",
            expected_version="1.0.0",
        )
    assert maintenance._records() == []


@pytest.mark.parametrize("retained_installer", [None, b"corrupt-retained-msi"])
def test_signed_primary_repairs_a_missing_or_corrupt_retained_installer(
    installation, monkeypatch, retained_installer,
):
    _, runtime, active = installation
    grant, directory, capability = staged_reviewed_repair(
        installation,
        monkeypatch,
        retained_installer=retained_installer,
        prepare=False,
    )
    assert capability["runtime_role"] == "primary"
    assert capability["retained_installer_available"] is False
    record = maintenance._read(directory / "record.json")
    assert record["old"]["publisher_thumbprint"] is None
    assert record["retained_installer_available_at_authorization"] is False

    maintenance.prepare(grant["authorization"])
    active[0] = directory / "maverick.exe"
    assert (directory / "repair-source.msi").read_bytes() == b"same-version-repair-msi"
    prepared = maintenance._read(directory / "record.json")
    assert prepared["old"]["publisher_thumbprint"] == PUBLISHER

    def repair(_directory, action, label):
        assert (action, label) == ("/i", "new")
        runtime.write_bytes(b"old-runtime")
        (runtime.parent / "maverick-recovery.exe").write_bytes(b"old-runtime")
        (runtime.parent / "maverick-desktop.exe").write_bytes(b"native-ui-fixture")
        (runtime.parent / "maverick-recovery-desktop.exe").write_bytes(
            b"native-ui-fixture"
        )
        (runtime.parent / "Lightwork-recovery.msi").write_bytes(
            b"same-version-repair-msi"
        )

    monkeypatch.setattr(maintenance, "_msiexec", repair)
    assert maintenance.execute(grant["authorization"])["status"] == "repaired"
    assert (runtime.parent / "Lightwork-recovery.msi").read_bytes() == (
        b"same-version-repair-msi"
    )
    maintenance.assert_normal_start_allowed()


def test_failed_repair_recovers_missing_installer_from_verified_candidate_without_replay(
    installation, monkeypatch,
):
    home, runtime, _ = installation
    grant, directory, _ = staged_reviewed_repair(
        installation, monkeypatch, retained_installer=None,
    )
    calls = []

    def fail_candidate(_directory, action, label):
        calls.append((action, label))
        runtime.write_bytes(b"failed-candidate-runtime")
        (runtime.parent / "maverick-desktop.exe").write_bytes(b"failed-native")
        (runtime.parent / "maverick-recovery.exe").unlink(missing_ok=True)
        (runtime.parent / "maverick-recovery-desktop.exe").unlink(missing_ok=True)
        (runtime.parent / "Lightwork-recovery.msi").write_bytes(b"failed-msi")
        (home / "tenants" / "alpha" / "ledger.json").write_text("failed-state")
        raise maintenance.MaintenanceError("synthetic repair failure")

    monkeypatch.setattr(maintenance, "_msiexec", fail_candidate)
    with pytest.raises(maintenance.MaintenanceError, match="synthetic repair"):
        maintenance.execute(grant["authorization"])

    authorization = maintenance.resume(grant["id"])
    monkeypatch.setattr(
        maintenance,
        "_msiexec",
        lambda *_: pytest.fail("failed candidate must not be replayed during recovery"),
    )
    assert maintenance.execute(authorization)["status"] == "repair_recovered"
    assert calls == [("/i", "new")]
    assert runtime.read_bytes() == b"old-runtime"
    assert (runtime.parent / "maverick-recovery.exe").read_bytes() == b"old-runtime"
    assert (runtime.parent / "maverick-desktop.exe").read_bytes() == b"native-ui-fixture"
    assert (runtime.parent / "maverick-recovery-desktop.exe").read_bytes() == (
        b"native-ui-fixture"
    )
    assert (runtime.parent / "Lightwork-recovery.msi").read_bytes() == (
        b"same-version-repair-msi"
    )
    assert (home / "tenants" / "alpha" / "ledger.json").read_text() == "old-state"
    maintenance.assert_normal_start_allowed()


def test_interrupted_repair_resume_restores_registered_package_and_saved_state(
    installation, monkeypatch,
):
    home, runtime, _ = installation
    grant, directory = staged_repair(installation, monkeypatch)
    events = []

    def fail_candidate(_directory, action, label):
        events.append((action, label))
        runtime.write_bytes(b"corrupt-repair-runtime")
        (runtime.parent / "maverick-desktop.exe").write_bytes(b"corrupt-native-shell")
        (runtime.parent / "maverick-recovery.exe").unlink()
        (runtime.parent / "maverick-recovery-desktop.exe").write_bytes(
            b"corrupt-recovery-native-shell"
        )
        (runtime.parent / "Lightwork-recovery.msi").unlink()
        (home / "tenants" / "alpha" / "ledger.json").write_text("changed-by-failed-repair")
        raise maintenance.MaintenanceError("synthetic repair failure")

    monkeypatch.setattr(maintenance, "_msiexec", fail_candidate)
    with pytest.raises(maintenance.MaintenanceError, match="synthetic repair"):
        maintenance.execute(grant["authorization"])
    assert maintenance._read(directory / "record.json")["status"] == "incomplete"
    with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
        maintenance.assert_normal_start_allowed()

    authorization = maintenance.resume(grant["id"])
    assert maintenance.execute(authorization)["status"] == "repair_recovered"
    assert events == [("/i", "new")]
    assert runtime.read_bytes() == b"old-runtime"
    assert (runtime.parent / "maverick-desktop.exe").read_bytes() == b"native-ui-fixture"
    assert (runtime.parent / "maverick-recovery.exe").read_bytes() == b"old-runtime"
    assert (runtime.parent / "maverick-recovery-desktop.exe").read_bytes() == b"native-ui-fixture"
    assert (runtime.parent / "Lightwork-recovery.msi").read_bytes() == b"same-version-repair-msi"
    assert (home / "tenants" / "alpha" / "ledger.json").read_text() == "old-state"
    maintenance.assert_normal_start_allowed()


def test_failed_upgrade_identity_resumes_by_recovering_old_release_not_replaying_candidate(
    installation, monkeypatch,
):
    home, runtime, _ = installation
    grant, directory = staged(installation, monkeypatch)
    events = []

    def fail_candidate(_directory, action, label):
        events.append((action, label))
        runtime.write_bytes(b"candidate-with-wrong-identity")
        (home / "tenants" / "alpha" / "ledger.json").write_text(
            "changed-during-interrupted-upgrade"
        )

    monkeypatch.setattr(maintenance, "_msiexec", fail_candidate)
    with pytest.raises(maintenance.MaintenanceError, match="verified release"):
        maintenance.execute(grant["authorization"])
    assert maintenance._read(directory / "record.json")["status"] == "incomplete"

    authorization = maintenance.resume(grant["id"])
    monkeypatch.setattr(maintenance, "_msiexec", fake_installer(runtime, events))
    assert maintenance.execute(authorization)["status"] == "upgrade_recovered"
    assert events == [("/i", "new"), ("/x", "new"), ("/i", "old")]
    assert runtime.read_bytes() == b"old-runtime"
    assert (home / "tenants" / "alpha" / "ledger.json").read_text() == "old-state"
    maintenance.assert_normal_start_allowed()


def test_failed_repair_refuses_tampered_install_time_source_without_replaying_candidate(
    installation, monkeypatch,
):
    _, runtime, _ = installation
    grant, directory = staged_repair(installation, monkeypatch)
    events = []

    def fail_candidate(_directory, action, label):
        events.append((action, label))
        runtime.write_bytes(b"candidate-with-wrong-identity")
        raise maintenance.MaintenanceError("synthetic repair failure")

    monkeypatch.setattr(maintenance, "_msiexec", fail_candidate)
    with pytest.raises(maintenance.MaintenanceError, match="synthetic repair"):
        maintenance.execute(grant["authorization"])
    (directory / "repair-source.msi").write_bytes(b"tampered-retained-installer")

    authorization = maintenance.resume(grant["id"])
    with pytest.raises(maintenance.MaintenanceError, match="install-time repair package"):
        maintenance.execute(authorization)
    assert events == [("/i", "new")]
    assert runtime.read_bytes() == b"candidate-with-wrong-identity"
    with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
        maintenance.assert_normal_start_allowed()


def test_prepared_repair_without_active_marker_resumes_candidate_once(
    installation, monkeypatch,
):
    _, runtime, active = installation
    grant, directory = staged_repair(installation, monkeypatch, prepare=False)
    original = maintenance._write

    def fail_marker(path, record):
        if path == maintenance._store() / "active.json":
            raise OSError("synthetic marker write failure")
        original(path, record)

    monkeypatch.setattr(maintenance, "_write", fail_marker)
    with pytest.raises(OSError, match="marker"):
        maintenance.prepare(grant["authorization"])
    assert maintenance._read(directory / "record.json")["status"] == "prepared"
    assert not (maintenance._store() / "active.json").exists()

    monkeypatch.setattr(maintenance, "_write", original)
    authorization = maintenance.resume(grant["id"])
    active[0] = directory / "maverick.exe"
    events = []
    monkeypatch.setattr(maintenance, "_msiexec", fake_repair_installer(runtime, events))
    assert maintenance.execute(authorization)["status"] == "repaired"
    assert events == [("/i", "new")]


def test_terminal_repair_receipt_survives_active_marker_removal_failure(
    installation, monkeypatch,
):
    _, runtime, _ = installation
    grant, directory = staged_repair(installation, monkeypatch)
    events = []
    monkeypatch.setattr(maintenance, "_msiexec", fake_repair_installer(runtime, events))
    marker = maintenance._store() / "active.json"
    original_unlink = Path.unlink

    def fail_active(path, *args, **kwargs):
        if path == marker:
            raise OSError("synthetic marker removal failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_active)
    with pytest.raises(maintenance.MaintenanceError, match="startup block"):
        maintenance.execute(grant["authorization"])
    assert maintenance._read(directory / "record.json")["status"] == "repaired"
    assert marker.exists()

    monkeypatch.setattr(Path, "unlink", original_unlink)
    authorization = maintenance.resume(grant["id"])
    assert maintenance.execute(authorization)["status"] == "repaired"
    assert events == [("/i", "new")]
    maintenance.assert_normal_start_allowed()


@pytest.mark.parametrize(
    "changed,match",
    [
        ("key", "verification key"),
        ("transition", "signing identity"),
        ("version", "does not match"),
        ("runtime", "does not match"),
        ("installer", "does not match"),
        ("product", "does not match"),
        ("package", "does not match"),
        ("publisher", "does not match"),
    ],
)
def test_repair_refuses_release_or_installed_identity_drift_before_startup_block(
    installation, monkeypatch, changed, match,
):
    _, runtime, _ = installation
    grant, directory = staged_repair(installation, monkeypatch, prepare=False)
    protected = {
        path.name: backup._sha256(path)
        for path in (
            runtime,
            runtime.parent / "maverick-desktop.exe",
            runtime.parent / "maverick-recovery.exe",
            runtime.parent / "maverick-recovery-desktop.exe",
            runtime.parent / "Lightwork-recovery.msi",
        )
    }
    metadata_path = directory / "downloads.json"
    metadata = json.loads(metadata_path.read_text())
    if changed == "key":
        metadata["public_key"] = "different-key"
    elif changed == "transition":
        metadata["identity_transition"] = {"policy": {}}
    elif changed == "version":
        metadata["new"]["version"] = "1.0.1"
    elif changed == "runtime":
        metadata["new"]["runtime_sha256"] = "f" * 64
    elif changed == "installer":
        metadata["new"]["installer_sha256"] = "f" * 64
    else:
        original = maintenance._installer
        monkeypatch.setattr(
            maintenance,
            "_installer",
            lambda directory, metadata, label: original(directory, metadata, label) | {
                (
                    "product_code" if changed == "product"
                    else "package_code" if changed == "package"
                    else "publisher_thumbprint"
                ): (
                    "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"
                    if changed in {"product", "package"}
                    else "D" * 40
                ),
            },
        )
    metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(maintenance.MaintenanceError, match=match):
        maintenance.prepare(grant["authorization"])
    assert not (maintenance._store() / "active.json").exists()
    assert protected == {
        path.name: backup._sha256(path)
        for path in (
            runtime,
            runtime.parent / "maverick-desktop.exe",
            runtime.parent / "maverick-recovery.exe",
            runtime.parent / "maverick-recovery-desktop.exe",
            runtime.parent / "Lightwork-recovery.msi",
        )
    }


def test_repair_requires_registered_package_before_creating_a_grant(
    installation, monkeypatch,
):
    monkeypatch.setattr(
        maintenance,
        "_registered_product_identity",
        lambda *_: (_ for _ in ()).throw(
            maintenance.MaintenanceError("registered package unavailable")
        ),
    )
    with pytest.raises(maintenance.MaintenanceError, match="registered package"):
        maintenance.authorize_repair(
            actor="native-desktop-repair", confirm_all_workspaces=True,
        )
    assert maintenance._records() == []


def test_repair_completion_receipt_crash_finalizes_without_second_install(
    installation, monkeypatch,
):
    _, runtime, _ = installation
    grant, _ = staged_repair(installation, monkeypatch)
    events = []
    monkeypatch.setattr(maintenance, "_msiexec", fake_repair_installer(runtime, events))
    original = maintenance._write

    def crash(path, record):
        original(path, record)
        if record.get("status") == "repaired":
            raise SystemExit("synthetic repair receipt crash")

    monkeypatch.setattr(maintenance, "_write", crash)
    with pytest.raises(SystemExit, match="repair receipt"):
        maintenance.execute(grant["authorization"])
    monkeypatch.setattr(maintenance, "_write", original)
    authorization = maintenance.resume(grant["id"])
    assert maintenance.execute(authorization)["status"] == "repaired"
    assert events == [("/i", "new")]
    maintenance.assert_normal_start_allowed()


def test_upgrade_recovery_receipt_crash_finalizes_without_second_install(
    installation, monkeypatch,
):
    home, runtime, _ = installation
    grant, _ = staged(installation, monkeypatch)
    events = []

    def fail_candidate(_directory, action, label):
        events.append((action, label))
        runtime.write_bytes(b"candidate-with-wrong-identity")

    monkeypatch.setattr(maintenance, "_msiexec", fail_candidate)
    with pytest.raises(maintenance.MaintenanceError, match="verified release"):
        maintenance.execute(grant["authorization"])
    authorization = maintenance.resume(grant["id"])
    monkeypatch.setattr(maintenance, "_msiexec", fake_installer(runtime, events))
    original = maintenance._write

    def crash(path, record):
        original(path, record)
        if record.get("status") == "upgrade_recovered":
            raise SystemExit("synthetic recovery receipt crash")

    monkeypatch.setattr(maintenance, "_write", crash)
    with pytest.raises(SystemExit, match="recovery receipt"):
        maintenance.execute(authorization)
    monkeypatch.setattr(maintenance, "_write", original)
    recovered = list(events)
    # The receipt is terminal for an upgrade: resume must finalize it and
    # clear the startup block, not refuse it.
    authorization = maintenance.resume(grant["id"])
    assert maintenance.execute(authorization)["status"] == "upgrade_recovered"
    assert events == recovered
    maintenance.assert_normal_start_allowed()


def test_whole_home_archive_excludes_live_lease_and_nested_recovery_keys(installation):
    home, _, _ = installation
    with maintenance._locked(), maintenance._quiesced():
        directory = maintenance._store()
        maintenance._snapshot(directory, "scope-test", digest(b"old-runtime"))
        with maintenance._scope():
            manifest = backup.verify_backup(directory / "scope-test.tgz")
    names = set(manifest["files"])
    assert "config.toml" in names
    assert {"tenants/alpha/ledger.json", "tenants/beta/ledger.json"} <= names
    assert not any("backups/" in name or "control-plane" in name for name in names)
    assert (home / "control-plane-holder.json").is_file()


def test_two_grants_cannot_replace_an_active_operation_or_clear_its_startup_block(installation, monkeypatch):
    # Both approvals happen before either operation pauses the application.
    earlier = reviewed_authorize(actor="admin", isolated=True, confirm_all_workspaces=True)
    winner, _ = staged(installation, monkeypatch)
    with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
        maintenance.prepare(earlier["authorization"])
    with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
        reviewed_authorize(actor="admin", isolated=True, confirm_all_workspaces=True)
    assert maintenance._read(maintenance._store() / "active.json")["id"] == winner["id"]


def test_execution_cannot_clear_another_operation_marker(installation, monkeypatch):
    grant, _ = staged(installation, monkeypatch)
    marker = {"schema": 1, "target": maintenance._target(), "id": "b" * 32}
    maintenance._write(maintenance._store() / "active.json", marker)
    with pytest.raises(maintenance.MaintenanceError, match="Another reviewed operation"):
        maintenance.execute(grant["authorization"])
    assert maintenance._read(maintenance._store() / "active.json")["id"] == "b" * 32


@pytest.mark.parametrize("rollback", [False, True])
@pytest.mark.parametrize("changed", [False, True])
def test_crash_after_completion_receipt_requires_verified_finalization(installation, monkeypatch, rollback, changed):
    home, runtime, active = installation
    grant, directory = staged(installation, monkeypatch)
    events = []
    monkeypatch.setattr(maintenance, "_msiexec", fake_installer(runtime, events))
    if rollback:
        maintenance.execute(grant["authorization"])
        active[0] = runtime
        grant = reviewed_authorize(actor="admin", isolated=True, confirm_all_workspaces=True, rollback_id=grant["id"])
        maintenance.prepare(grant["authorization"])
        active[0] = directory / "maverick.exe"
    outcome = "rolled_back" if rollback else "upgraded"
    original = maintenance._write
    def crash(path, record):
        original(path, record)
        if record.get("status") == outcome:
            raise SystemExit("synthetic process exit after durable receipt")
    monkeypatch.setattr(maintenance, "_write", crash)
    with pytest.raises(SystemExit):
        maintenance.execute(grant["authorization"])
    monkeypatch.setattr(maintenance, "_write", original)
    count = len(events)
    if changed:
        (home / "tenants" / "beta" / "ledger.json").write_text("unexpected state")
    authorization = maintenance.resume(grant["id"])
    if changed:
        with pytest.raises(backup.BackupError, match="post-restore"):
            maintenance.execute(authorization)
        with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
            maintenance.assert_normal_start_allowed()
    else:
        assert maintenance.execute(authorization)["status"] == outcome
        maintenance.assert_normal_start_allowed()
    assert len(events) == count, "finalization must not execute the installers again"


@pytest.mark.parametrize("rollback", [False, True])
@pytest.mark.parametrize("drift", [False, True])
def test_terminal_finalization_with_real_committed_wal_database(installation, monkeypatch, rollback, drift):
    home, runtime, active = installation
    db = home / "tenants" / "alpha" / "reviews.sqlite3"
    script = "import os,sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('PRAGMA journal_mode=WAL'); c.execute('PRAGMA wal_autocheckpoint=0'); c.execute('CREATE TABLE reviews (value TEXT)'); c.execute(\"INSERT INTO reviews VALUES ('captured')\"); c.commit(); os._exit(0)"
    subprocess.run([sys.executable, "-c", script, str(db)], check=True)
    assert Path(str(db) + "-wal").stat().st_size > 0
    grant, directory = staged(installation, monkeypatch)
    events = []
    monkeypatch.setattr(maintenance, "_msiexec", fake_installer(runtime, events))
    if rollback:
        maintenance.execute(grant["authorization"])
        active[0] = runtime
        grant = reviewed_authorize(actor="admin", isolated=True, confirm_all_workspaces=True, rollback_id=grant["id"])
        maintenance.prepare(grant["authorization"])
        active[0] = directory / "maverick.exe"
    outcome = "rolled_back" if rollback else "upgraded"
    original = maintenance._write
    def crash(path, record):
        original(path, record)
        if record.get("status") == outcome:
            raise SystemExit("synthetic terminal receipt crash with committed WAL")
    monkeypatch.setattr(maintenance, "_write", crash)
    with pytest.raises(SystemExit):
        maintenance.execute(grant["authorization"])
    monkeypatch.setattr(maintenance, "_write", original)
    connection = sqlite3.connect(db)
    assert connection.execute("SELECT value FROM reviews").fetchall() == [("captured",)]
    if drift:
        connection.execute("INSERT INTO reviews VALUES ('changed after snapshot')")
        connection.commit()
    connection.close()
    count = len(events)
    authorization = maintenance.resume(grant["id"])
    if drift:
        with pytest.raises((maintenance.MaintenanceError, backup.BackupError)):
            maintenance.execute(authorization)
        assert (maintenance._store() / "active.json").exists()
    else:
        assert maintenance.execute(authorization)["status"] == outcome
        maintenance.assert_normal_start_allowed()
    assert len(events) == count


@pytest.mark.parametrize("changed", ["key", "native", "publisher"])
def test_staging_cannot_replace_the_installed_release_trust_identity(installation, monkeypatch, changed):
    _, runtime, _ = installation
    grant, directory = staged(installation, monkeypatch, prepare=False)
    metadata_path = directory / "downloads.json"
    metadata = json.loads(metadata_path.read_text())
    if changed == "key":
        metadata["public_key"] = "different-publisher-key"
        metadata_path.write_text(json.dumps(metadata))
    elif changed == "native":
        (runtime.parent / "maverick-desktop.exe").write_bytes(b"different-native-channel")
    else:
        original = maintenance._installer
        monkeypatch.setattr(maintenance, "_installer", lambda directory, metadata, label:
                            original(directory, metadata, label) | {"publisher_thumbprint": label})
    with pytest.raises(maintenance.MaintenanceError, match="key|native application changed|publisher changed"):
        maintenance.prepare(grant["authorization"])
    assert not (maintenance._store() / "active.json").exists()


def test_native_logs_are_bounded_and_never_accept_a_client_path(installation, monkeypatch):
    grant, directory = staged(installation, monkeypatch)
    (directory / "i-new.log").write_bytes(b"\xff\xfe" + ("fixture " * 5000 + "finished").encode("utf-16-le"))
    result = maintenance.logs(grant["id"])
    assert result["details"].endswith("finished")
    assert len(result["details"]) < 17000
    with pytest.raises(maintenance.MaintenanceError):
        maintenance.logs("../config.toml")


def test_upgrade_requires_exact_review_and_rejects_changed_reviewed_bytes(installation, monkeypatch):
    with pytest.raises(maintenance.MaintenanceError, match="exact release"):
        maintenance.authorize(actor="admin", isolated=True, confirm_all_workspaces=True)
    grant, directory = staged(installation, monkeypatch, prepare=False)
    (directory / "new.msi").write_bytes(b"changed")
    with pytest.raises(maintenance.MaintenanceError, match="exact native review"):
        maintenance.prepare(grant["authorization"])
    assert not (maintenance._store() / "active.json").exists()


# ---- a refused or unusable authorization leaves nothing behind ------------------

def point_directories(home):
    store = home / "backups" / "installation-recovery"
    return [path for path in store.iterdir() if path.is_dir() and len(path.name) == 32]


def test_an_expired_native_review_is_refused_before_any_point_directory_exists(installation):
    home, *_ = installation
    with pytest.raises(maintenance.MaintenanceError, match="expired or changed"):
        maintenance.authorize(actor="global-admin", isolated=True, confirm_all_workspaces=True, review_id="a" * 32)
    assert point_directories(home) == []


def test_an_unconfirmed_signing_transition_is_refused_without_leaving_a_point_directory(installation):
    from maverick.installation_handoff import save_review
    home, *_ = installation
    review = save_review({"version": "1.0.1", "runtime_sha256": digest(b"new-runtime"),
                          "installer_sha256": digest(b"new"), "signature": "fixture-reviewed-signature"})
    with pytest.raises(maintenance.MaintenanceError, match="Explicitly confirm"):
        maintenance.authorize(actor="global-admin", isolated=True, confirm_all_workspaces=True,
                              review_id=review["id"], identity_transition="{}", transition_sha256="0" * 64)
    assert point_directories(home) == []


def test_a_grant_that_cannot_be_handed_on_is_retired_and_frees_its_slot(installation):
    home, *_ = installation
    grant = reviewed_authorize(actor="global-admin", isolated=True, confirm_all_workspaces=True)
    assert len(point_directories(home)) == 1
    maintenance.discard_authorization(grant["authorization"], actor="global-admin")
    assert maintenance.status()["recovery_points"] == []
    assert [row["id"] for row in maintenance.status()["retirement_history"]] == [grant["id"]]
    with pytest.raises(maintenance.MaintenanceError, match="expired or was retired"):
        maintenance._grant(grant["authorization"])


def test_discarding_is_best_effort_and_never_masks_the_error_that_caused_it(installation):
    grant = reviewed_authorize(actor="global-admin", isolated=True, confirm_all_workspaces=True)
    maintenance.discard_authorization(grant["authorization"], actor="global-admin")
    maintenance.discard_authorization(grant["authorization"], actor="global-admin")   # already retired
    maintenance.discard_authorization("not-a-token", actor="global-admin")
    maintenance.discard_authorization(None, actor="global-admin")
