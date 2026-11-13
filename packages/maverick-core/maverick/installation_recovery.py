"""Reviewed Windows upgrade, repair, and rollback transactions over a whole local home.

The authenticated recovery server grants one bounded operation. A separate
retained runtime acquires the control-plane lock after that server exits;
only then does it snapshot or replace state. It never interprets budget ledgers.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from contextlib import contextmanager, suppress
from pathlib import Path
from urllib.parse import unquote

from . import (
    backup,
    config,
    control_plane_lease,
    file_lock,
    paths,
    release_identity_transition,
    workspace_recovery,
)
from .windows_installer_verification import (
    MAX_INSTALLER_BYTES,
    UPGRADE_CODE,
    InstallerVerificationError,
    inspect_signed_msi,
    installer_path,
    verify_minisign,
)

_ID = re.compile(r"^[0-9a-f]{32}$")
_TOKEN = re.compile(r"^([0-9a-f]{32}):([0-9a-f]{64})$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
MAX_EXPANDED_BYTES = 8 * 1024**3
MAX_TICKETS = 20
MAX_RETIREMENT_HISTORY = 100
MAINTENANCE_PROTOCOL = 2

_REGISTERED_INSTALLER = r"""param([Parameter(Mandatory=$true)][string]$Version)
$ErrorActionPreference = 'Stop'
$engine = New-Object -ComObject WindowsInstaller.Installer
$upgrade = '{""" + UPGRADE_CODE + r"""}'
$matches = @()
foreach ($product in @($engine.RelatedProducts($upgrade))) {
    try {
        if ($engine.ProductInfo($product, 'VersionString') -cne $Version) { continue }
        $matches += [pscustomobject]@{
            ProductCode = $product
            PackageCode = $engine.ProductInfo($product, 'PackageCode')
            InstallLocation = $engine.ProductInfo($product, 'InstallLocation')
            PackageName = $engine.ProductInfo($product, 'PackageName')
        }
    } catch { throw }
}
if ($matches.Count -ne 1) { throw 'The installed Lightwork product identity is ambiguous or unavailable.' }
$matches[0] | ConvertTo-Json -Compress
"""


class MaintenanceError(RuntimeError):
    """Maintenance has not established the authority or consistency it needs."""


_TERMINAL_BY_OPERATION = {
    "upgrade": frozenset({"upgraded", "upgrade_recovered"}),
    "repair": frozenset({"repaired", "repair_recovered"}),
    "rollback": frozenset({"rolled_back"}),
}


def _operation(record: dict) -> str:
    operation = record.get("operation")
    if not isinstance(operation, str) or operation not in _TERMINAL_BY_OPERATION:
        raise MaintenanceError("The reviewed installation operation is unsupported.")
    return operation


def _home() -> Path:
    return backup._filesystem_path(paths.maverick_home()).absolute()


def _store() -> Path:
    return file_lock.ensure_private_directory(_home() / "backups" / "installation-recovery")


def _target() -> str:
    return hashlib.sha256(str(_home()).encode()).hexdigest()


def _key() -> bytes:
    path = _store() / "operator.key"
    if not path.exists():
        file_lock.atomic_create_text(path, secrets.token_hex(32))
    return backup._decode_operator_key(file_lock.atomic_read_text(path))


def _scope():
    return backup.recovery_scope(_home(), "installation:" + _target(), _key(),
                                 max_expanded_bytes=MAX_EXPANDED_BYTES, whole_home=True)


def _directory(identifier: str) -> Path:
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise MaintenanceError("Select an installation recovery point from this computer.")
    return _store() / identifier


def _write(path: Path, record: dict) -> None:
    encoded = json.dumps(backup._authenticate_for_write(record, _key()))
    if len(encoded.encode("utf-8")) > 128 * 1024:
        raise MaintenanceError("The saved recovery details, including separate key files, exceed this installation's record limit. Existing recovery points have been kept.")
    file_lock.atomic_write_text(path, encoded)


def _read(path: Path) -> dict:
    if path.stat().st_size > 128 * 1024:
        raise MaintenanceError("Installation recovery metadata exceeds its size limit.")
    record = json.loads(file_lock.atomic_read_text(path))
    with _scope():
        backup._verify_authentication(record, allow_unsigned=False, label="installation recovery")
    if record.get("schema") != 1 or record.get("target") != _target():
        raise MaintenanceError("This installation recovery point belongs to a different data home.")
    return record


@contextmanager
def _locked():
    with file_lock.cross_process_lock(_store() / "operations", strict=True):
        yield


@contextmanager
def _quiesced():
    # Reusing a web server's lease would not establish quiescence.
    if control_plane_lease.current() is not None:
        raise MaintenanceError("Pause Lightwork from the desktop maintenance controls first.")
    lease = control_plane_lease.acquire(role="installation-maintenance")
    if lease is None:
        raise MaintenanceError("Installation recovery requires the single control plane lock.")
    try:
        yield
    finally:
        control_plane_lease.release()


def _shared_blockers(global_configuration: dict) -> list[str]:
    """Tenant overlays cannot remove the shared administration's authority."""
    reasons = []
    global_kms = global_configuration.get("kms") or {}
    if not isinstance(global_kms, dict) or global_kms.get("provider", "local") != "local":
        reasons.append("Shared administration uses a remote key service and requires coordinated recovery.")
    # Tenant settings can shadow deployment-global settings. The shared state
    # is still part of a whole-home restore, even if no tenant directory exists.
    for section, defaults in (("world_model", {"", "sqlite"}), ("governed_records", {"", "local"}),
                              ("memory", {"", "local", "sqlite", "auto"}), ("queue", {""})):
        value = global_configuration.get(section) or {}
        if not isinstance(value, dict) or str(value.get("backend") or "").lower() not in defaults:
            reasons.append("Shared " + section.replace("_", " ") + " uses an external authority and requires coordinated recovery.")
    knowledge = global_configuration.get("knowledge") or {}
    if not isinstance(knowledge, dict) or str(knowledge.get("store") or "sqlite") != "sqlite" or knowledge.get("path"):
        reasons.append("Shared knowledge storage is outside the default local data home and requires coordinated recovery.")
    dispatch = global_configuration.get("grpc_dispatch") or {}
    if not isinstance(dispatch, dict) or dispatch.get("target"):
        reasons.append("Shared remote workers require coordinated shutdown and recovery.")
    for section in ("redis", "qdrant", "pgvector"):
        if global_configuration.get(section):
            reasons.append("Shared " + section + " storage requires its own verified recovery process.")
    return reasons


def blockers() -> list[str]:
    """All tenants matter because one installed runtime serves the whole home."""
    reasons = []
    # Loading settings also admits wizard-persisted environment values. Check
    # injected key custody after that load, including in a fresh helper process.
    global_configuration = config.load_global_config()
    if config.config_path().absolute() != paths.maverick_home().absolute() / "config.toml" or os.environ.get(config.CONFIG_OVERLAY_ENV):
        reasons.append("Settings outside this local data home require a coordinated administrator recovery process.")
    if any(os.environ.get(prefix + suffix) for prefix in ("MAVERICK_", "LIGHTWORK_") for suffix in ("ENCRYPTION_KEY", "KMS_KEK")):
        reasons.append("Environment-managed encryption keys require separate coordinated recovery.")
    reasons.extend(_shared_blockers(global_configuration))
    tenants = _home() / "tenants"
    directories = list(tenants.iterdir()) if tenants.exists() else []
    if len(directories) > 200:
        reasons.append("This installation exceeds the local recovery limit of 200 workspaces.")
        return reasons
    token = paths.set_tenant(None)
    try:
        reasons.extend(workspace_recovery.restore_blockers())
        for directory in directories:
            file_lock.ensure_private_directory(directory)
            tenant = unquote(directory.name, errors="strict")
            if paths._tenant_segment(paths.canonical_tenant_id(tenant)) != directory.name:
                raise MaintenanceError("A workspace directory has no unambiguous portable identity.")
            with paths.tenant_scope(tenant=tenant):
                reasons.extend(workspace_recovery.restore_blockers())
                kms = config.load_config().get("kms") or {}
                if not isinstance(kms, dict) or kms.get("provider", "local") != "local":
                    reasons.append("A workspace uses a remote key service and requires coordinated recovery.")
    finally:
        paths.reset_tenant(token)
    return list(dict.fromkeys(reasons))


def _executing_runtime() -> Path:
    if os.name != "nt" or not getattr(sys, "frozen", False):
        raise MaintenanceError("Installation recovery requires the packaged Windows application.")
    return Path(sys.executable).absolute()


def _runtime() -> Path:
    executable = _executing_runtime()
    if executable.name.casefold() == "maverick-recovery.exe":
        return executable.with_name("maverick.exe")
    return executable


def _native_channel(
    runtime: Path,
    *,
    expected_version: str | None = None,
    native_path: Path | None = None,
) -> dict:
    native = native_path or runtime.parent / "maverick-desktop.exe"
    digest = backup._sha256(native)
    result = subprocess.run([str(native), "--maintenance-channel"], capture_output=True, text=True,
                            encoding="utf-8", timeout=30, check=False,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        channel = json.loads(result.stdout) if result.returncode == 0 and len(result.stdout) <= 16384 else {}
        public_key = channel.get("public_key")
        if (not isinstance(public_key, str) or not public_key or len(public_key) > 4096
                or channel.get("version") != (expected_version or workspace_recovery.version())
                or channel.get("packaged_runtime") is not True or backup._sha256(native) != digest):
            raise ValueError("unbound channel")
    except (TypeError, ValueError) as exc:
        raise MaintenanceError("The installed native application's release identity could not be established.") from exc
    return {"native_sha256": digest, "public_key": public_key}


def _valid_package_name(name: object) -> bool:
    """One ordinary MSI file name, as Windows Installer registers it for a product."""
    return (
        isinstance(name, str)
        and 4 < len(name) <= 255
        and name.lower().endswith(".msi")
        and not name.endswith((" ", "."))
        and not any(char in '\\/:*?"<>|' or ord(char) < 32 for char in name)
        and Path(name).name == name
    )


def _registered_product_identity(version: str, scratch: Path, installed_runtime: Path) -> dict:
    """Read the registered package identity without using Windows' private cache as source."""
    if os.name != "nt" or not _VERSION.fullmatch(str(version)):
        raise MaintenanceError("Repair requires one registered packaged Windows release.")
    file_lock.ensure_private_directory(scratch)
    script = scratch / "inspect-registered-installer.ps1"
    if script.exists():
        if file_lock.atomic_read_text(script) != _REGISTERED_INSTALLER:
            raise MaintenanceError("The registered-installer inspection helper changed.")
    else:
        file_lock.atomic_create_text(script, _REGISTERED_INSTALLER)
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    environment = {
        name: value for name, value in os.environ.items()
        if name.lower() != "psmodulepath"
    }
    environment["PSModulePath"] = str(powershell.parent / "Modules")
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", installer_path(script), "-Version", version],
        capture_output=True,
        text=True,
        timeout=120,
        creationflags=subprocess.CREATE_NO_WINDOW,
        check=False,
        env=environment,
    )
    try:
        value = json.loads(result.stdout) if result.returncode == 0 and len(result.stdout) <= 16384 else {}
        if not isinstance(value, dict):
            raise ValueError("invalid registered product response")
        product_code = value.get("ProductCode")
        package_code = value.get("PackageCode")
        package_name = value.get("PackageName")
        install_location = Path(value.get("InstallLocation", ""))
        guid = r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
        expected_location = installed_runtime.parent.absolute()
        if (not re.fullmatch(guid, product_code or "")
                or not re.fullmatch(guid, package_code or "")
                or not install_location.is_absolute() or install_location.is_symlink()
                or install_location.absolute() != expected_location
                or not _valid_package_name(package_name)):
            raise ValueError("invalid registered product")
    except (OSError, TypeError, ValueError) as exc:
        raise MaintenanceError(
            "The registered Lightwork package identity or installation directory is unavailable. Repair was refused before changing the installation."
        ) from exc
    return {
        "product_code": product_code.upper(),
        "package_code": package_code.upper(),
        "install_directory": str(install_location.absolute()),
        # Windows Installer resolves a maintenance-mode source as the
        # launched-from directory plus this registered file name.
        "package_name": package_name,
    }


def _verify_repair_registration(directory: Path, record: dict) -> None:
    registered = _registered_product_identity(
        record["old_version"], directory, Path(record["installed_runtime"]),
    )
    expected = record["old"]
    if any(registered[name] != expected.get(name) for name in (
        "product_code", "package_code", "install_directory", "package_name",
    )):
        raise MaintenanceError(
            "The installed Windows product, package or location differs from the reviewed repair. Recovery remains blocked."
        )


def _repair_anchor(
    runtime: Path,
    scratch: Path,
    registered: dict,
    *,
    expected_runtime_sha256: str | None = None,
    expected_installer_sha256: str | None = None,
    expected_public_key: str | None = None,
    expected_version: str | None = None,
    allow_verified_candidate_installer: bool = False,
    executing_pair_only: bool = False,
) -> dict:
    """Bind one surviving runtime pair to the signed installed-release identity."""
    directory = runtime.parent
    recovery_runtime = directory / "maverick-recovery.exe"
    recovery_native = directory / "maverick-recovery-desktop.exe"
    recovery_installer = directory / "Lightwork-recovery.msi"
    expected_binding = (
        expected_runtime_sha256,
        expected_installer_sha256,
        expected_public_key,
    )
    reviewed_release = expected_version is not None
    if any(value is not None for value in expected_binding) and (
        not all(isinstance(value, str) for value in expected_binding)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_runtime_sha256 or "")
        or not re.fullmatch(r"[0-9a-f]{64}", expected_installer_sha256 or "")
        or not expected_public_key
        or len(expected_public_key) > 4096
    ):
        raise MaintenanceError("The signed repair release identity is incomplete.")
    if reviewed_release and (
        not all(isinstance(value, str) for value in expected_binding)
        or not _VERSION.fullmatch(expected_version or "")
        or expected_version != workspace_recovery.version()
    ):
        raise MaintenanceError("The signed repair release identity is incomplete.")
    installer_sha256 = expected_installer_sha256
    properties = None
    try:
        if recovery_installer.is_symlink() or not recovery_installer.is_file():
            raise MaintenanceError("The retained install-time package is unavailable.")
        if recovery_installer.stat().st_size > MAX_INSTALLER_BYTES:
            raise MaintenanceError(
                "The retained install-time package exceeds its supported size limit."
            )
        observed_installer_sha256 = backup._sha256(recovery_installer)
        if expected_installer_sha256 is not None and not hmac.compare_digest(
            observed_installer_sha256, expected_installer_sha256,
        ):
            raise MaintenanceError("The retained install-time package identity changed.")
        properties = inspect_signed_msi(
            recovery_installer,
            version=workspace_recovery.version(),
            scratch=scratch,
        )
        if (
            backup._sha256(recovery_installer) != observed_installer_sha256
            or properties["ProductCode"].upper() != registered["product_code"]
            or properties["PackageCode"].upper() != registered["package_code"]
        ):
            raise MaintenanceError(
                "The installed recovery source does not match the registered Windows package."
            )
        installer_sha256 = observed_installer_sha256
    except (OSError, KeyError, TypeError, backup.BackupError,
            InstallerVerificationError, MaintenanceError) as exc:
        if not (reviewed_release and allow_verified_candidate_installer):
            raise MaintenanceError(
                "The retained install-time recovery source is unavailable. Use the signed Lightwork installer to restore Lightwork."
            ) from exc
        properties = None
    if executing_pair_only:
        if not reviewed_release:
            raise MaintenanceError("An exact signed repair release is required for this capability check.")
        executing = _executing_runtime()
        if executing == recovery_runtime:
            candidates = ((recovery_runtime, recovery_native),)
        elif executing == runtime:
            candidates = ((runtime, directory / "maverick-desktop.exe"),)
        else:
            raise MaintenanceError(
                "The maintenance request did not come from an installed application runtime."
            )
    elif reviewed_release:
        candidates = (
            (recovery_runtime, recovery_native),
            (runtime, directory / "maverick-desktop.exe"),
        )
    else:
        # Direct callers without a signature-verified release review retain the
        # original strict contract: only the separate recovery pair may anchor.
        candidates = ((recovery_runtime, recovery_native),)
    selected = None
    for candidate_runtime, candidate_native in candidates:
        try:
            if any(path.is_symlink() or not path.is_file()
                   or path.stat().st_size > MAX_INSTALLER_BYTES
                   for path in (candidate_runtime, candidate_native)):
                continue
            runtime_sha256 = backup._sha256(candidate_runtime)
            native = _native_channel(
                runtime,
                expected_version=workspace_recovery.version(),
                native_path=candidate_native,
            )
            if (expected_runtime_sha256 is not None
                    and not hmac.compare_digest(runtime_sha256, expected_runtime_sha256)):
                continue
            if (expected_public_key is not None
                    and not hmac.compare_digest(native["public_key"], expected_public_key)):
                continue
            selected = (candidate_runtime, candidate_native, runtime_sha256, native)
            break
        except (OSError, MaintenanceError):
            continue
    if selected is None:
        raise MaintenanceError(
            "Neither installed application copy matches the signed current release. Use the signed Lightwork installer to restore Lightwork."
        )
    selected_runtime, selected_native, runtime_sha256, native = selected
    return {
        "runtime": selected_runtime,
        "runtime_sha256": runtime_sha256,
        "native": selected_native,
        "native_sha256": native["native_sha256"],
        "public_key": native["public_key"],
        "installer": recovery_installer,
        "installer_sha256": installer_sha256,
        "publisher_thumbprint": (
            properties["PublisherThumbprint"].upper() if properties is not None else None
        ),
        "retained_installer_available": properties is not None,
    }


def repair_capability(
    *,
    expected_runtime_sha256: str | None,
    expected_installer_sha256: str | None,
    expected_public_key: str | None,
    expected_version: str | None,
) -> dict:
    """Read-only proof that this exact packaged runtime can prepare a repair."""
    runtime = _runtime()
    with backup._temporary_directory(prefix="lightwork-repair-capability-") as scratch:
        registered = _registered_product_identity(
            workspace_recovery.version(), scratch, runtime,
        )
        anchor = _repair_anchor(
            runtime,
            scratch,
            registered,
            expected_runtime_sha256=expected_runtime_sha256,
            expected_installer_sha256=expected_installer_sha256,
            expected_public_key=expected_public_key,
            expected_version=expected_version,
            allow_verified_candidate_installer=True,
            executing_pair_only=True,
        )
    return {
        "schema": "lightwork.installation-repair-capability.v1",
        "compatible": True,
        "version": expected_version,
        "runtime_sha256": anchor["runtime_sha256"],
        "installer_sha256": anchor["installer_sha256"],
        "public_key": anchor["public_key"],
        "runtime_role": (
            "recovery" if anchor["runtime"].name.casefold() == "maverick-recovery.exe"
            else "primary"
        ),
        "product_code": registered["product_code"],
        "package_code": registered["package_code"],
        "publisher_thumbprint": anchor["publisher_thumbprint"],
        "retained_installer_available": anchor["retained_installer_available"],
    }


def _admit_local() -> None:
    reasons = blockers()
    if reasons:
        raise MaintenanceError(" ".join(reasons))


def _transition_source(record):
    return {"version": record["old_version"], "runtime_sha256": record["old_runtime_sha256"],
            "native_sha256": record["native_sha256"], "public_key": record["public_key"]}


def _verified_transition(value, record, *, admit=True):
    if admit and not config.signing_identity_transition_enabled():
        raise MaintenanceError("Signing identity transitions are disabled. A global administrator must enable this trust capability in Settings before reviewing a bridge release.")
    try:
        return release_identity_transition.verify(value, installed=_transition_source(record), admit=admit)
    except release_identity_transition.IdentityTransitionError as exc:
        raise MaintenanceError(str(exc)) from exc


def review_identity_transition(value, *, isolated: bool) -> dict:
    if not isolated:
        raise MaintenanceError("Review signing identity transitions in the isolated Workspace recovery mode.")
    runtime = _runtime()
    source = {"old_version": workspace_recovery.version(), "old_runtime_sha256": backup._sha256(runtime),
              **_native_channel(runtime)}
    return release_identity_transition.summary(_verified_transition(value, source))


def _check_transition_installers(record, old, new, *, admit=False):
    envelope = record.get("identity_transition")
    if envelope is None:
        if old.get("publisher_thumbprint") != new.get("publisher_thumbprint"):
            raise MaintenanceError("The installer publisher changed. Review an authenticated exact-release identity transition in Workspace recovery first.")
        return
    if release_identity_transition.digest(envelope) != record.get("transition_sha256"):
        raise MaintenanceError("The reviewed signing identity transition changed.")
    if not admit and not record.get("transition_admitted_at"):
        raise MaintenanceError("This signing identity transition has no completed admission receipt.")
    verified = _verified_transition(envelope, record, admit=admit)
    try:
        release_identity_transition.verify_installers(verified, old=old, new=new)
    except release_identity_transition.IdentityTransitionError as exc:
        raise MaintenanceError(str(exc)) from exc


def authorize(*, actor: str, isolated: bool, confirm_all_workspaces: bool,
              rollback_id: str | None = None, identity_transition=None, transition_sha256: str | None = None,
              confirm_identity_transition: bool = False, review_id: str | None = None) -> dict:
    if not isolated or confirm_all_workspaces is not True or not actor:
        raise MaintenanceError("A global administrator must explicitly review all local workspaces in recovery mode.")
    runtime = _runtime()
    with _locked():
        assert_normal_start_allowed()
        _admit_local()
        if rollback_id:
            if identity_transition is not None or transition_sha256 is not None:
                raise MaintenanceError("Rollback uses only its originally admitted exact identity pair.")
            directory = _directory(rollback_id)
            record = _read(directory / "record.json")
            if record.get("status") != "upgraded" or backup._sha256(runtime) != record.get("new_runtime_sha256"):
                raise MaintenanceError("Rollback requires the matching completed upgrade on this computer.")
            _verify_runtime(record, "new")
        else:
            if review_id is None:
                raise MaintenanceError("Review the exact release in the native app before authorizing an upgrade.")
            if _usable_point_count() >= MAX_TICKETS:
                raise MaintenanceError("The installation recovery store is full. Review and retire unused authorizations or obsolete recovery points in Workspace recovery.")
            from .installation_handoff import reviewed_release
            reviewed = reviewed_release(review_id)
            identifier = secrets.token_hex(16)
            # The directory is created only once every check below has passed,
            # so a refused authorization leaves nothing behind.
            directory = _directory(identifier)
            record = {"schema": 1, "target": _target(), "id": identifier, "status": "authorized",
                      "old_version": workspace_recovery.version(), "old_runtime_sha256": backup._sha256(runtime),
                      "installed_runtime": str(runtime), "created_at": time.time(), **_native_channel(runtime),
                      "reviewed_new": reviewed}
            if identity_transition is not None:
                if confirm_identity_transition is not True:
                    raise MaintenanceError("Explicitly confirm the reviewed change to installation signing trust.")
                envelope = _verified_transition(identity_transition, record)
                if release_identity_transition.digest(envelope) != transition_sha256:
                    raise MaintenanceError("Review and confirm the exact signing identity transition before authorizing it.")
                record.update(identity_transition=envelope, transition_sha256=transition_sha256)
            elif transition_sha256 is not None:
                raise MaintenanceError("The reviewed signing identity transition is missing.")
        nonce = secrets.token_hex(32)
        record.update(actor=actor, operation="rollback" if rollback_id else "upgrade",
                      grant_hash=hashlib.sha256(nonce.encode()).hexdigest(), expires_at=time.time() + 900)
        created = not directory.exists()
        file_lock.ensure_private_directory(directory)
        try:
            _write(directory / "record.json", record)
        except BaseException:
            if created:
                with suppress(OSError):
                    directory.rmdir()
            raise
        return {"id": record["id"], "authorization": record["id"] + ":" + nonce,
                "old_version": record["old_version"], "expires_at": record["expires_at"],
                "scope": "all local workspaces and shared administration files"}


def authorize_repair(
    *,
    actor: str,
    confirm_all_workspaces: bool,
    expected_runtime_sha256: str | None = None,
    expected_installer_sha256: str | None = None,
    expected_public_key: str | None = None,
    expected_version: str | None = None,
) -> dict:
    """Authorize one local, same-release repair from the bundled native UI."""
    if confirm_all_workspaces is not True or not actor:
        raise MaintenanceError(
            "Review and explicitly confirm protecting all local workspaces before repair."
        )
    runtime = _runtime()
    with _locked():
        assert_normal_start_allowed()
        _admit_local()
        if _usable_point_count() >= MAX_TICKETS:
            raise MaintenanceError(
                "The installation recovery store is full. Review and retire obsolete recovery points before repair."
            )
        identifier = secrets.token_hex(16)
        directory = file_lock.ensure_private_directory(_directory(identifier))
        try:
            old_version = workspace_recovery.version()
            registered = _registered_product_identity(old_version, directory, runtime)
            anchor = _repair_anchor(
                runtime,
                directory,
                registered,
                expected_runtime_sha256=expected_runtime_sha256,
                expected_installer_sha256=expected_installer_sha256,
                expected_public_key=expected_public_key,
                expected_version=expected_version,
                allow_verified_candidate_installer=(expected_version is not None),
                executing_pair_only=(expected_version is not None),
            )
            old = {
                "version": old_version,
                "runtime_sha256": anchor["runtime_sha256"],
                "installer_sha256": anchor["installer_sha256"],
                "publisher_thumbprint": anchor["publisher_thumbprint"],
                **registered,
            }
            record = {
                "schema": 1,
                "target": _target(),
                "id": identifier,
                "status": "authorized",
                "operation": "repair",
                "actor": actor,
                "old_version": old_version,
                "old_runtime_sha256": anchor["runtime_sha256"],
                "installed_runtime": str(runtime),
                "recovery_runtime": str(anchor["runtime"]),
                "recovery_runtime_sha256": anchor["runtime_sha256"],
                "recovery_native": str(anchor["native"]),
                "recovery_native_sha256": anchor["native_sha256"],
                "recovery_installer": str(anchor["installer"]),
                "recovery_installer_sha256": anchor["installer_sha256"],
                "retained_installer_available_at_authorization": anchor[
                    "retained_installer_available"
                ],
                "reviewed_repair_release": expected_version is not None,
                "created_at": time.time(),
                "old": old,
                "native_sha256": anchor["native_sha256"],
                "public_key": anchor["public_key"],
            }
            nonce = secrets.token_hex(32)
            record.update(
                grant_hash=hashlib.sha256(nonce.encode()).hexdigest(),
                expires_at=time.time() + 900,
            )
            _write(directory / "record.json", record)
        except BaseException:
            for name in ("inspect-registered-installer.ps1", "inspect-installer.ps1"):
                path = directory / name
                if path.exists() and path.is_file() and not path.is_symlink():
                    path.unlink()
            try:
                directory.rmdir()
            except OSError:
                # Preserve unexpected files for diagnosis without masking the
                # original authorization failure.
                pass
            raise
        return {
            "id": identifier,
            "authorization": identifier + ":" + nonce,
            "directory": str(directory),
            "old_version": old_version,
            "expires_at": record["expires_at"],
            "operation": "repair",
            "scope": "application files, all local workspaces and shared administration files",
        }


def _grant(token: str) -> tuple[Path, dict]:
    match = _TOKEN.fullmatch(token) if isinstance(token, str) else None
    if match is None:
        raise MaintenanceError("Copy the current maintenance authorization from Workspace recovery.")
    directory = _directory(match[1])
    if not (directory / "record.json").exists():
        raise MaintenanceError("This maintenance authorization expired or was retired. Review it again in Workspace recovery.")
    record = _read(directory / "record.json")
    if record.get("expires_at", 0) < time.time() or not hmac.compare_digest(
            record.get("grant_hash", ""), hashlib.sha256(match[2].encode()).hexdigest()):
        raise MaintenanceError("This maintenance authorization expired or was already used. Review it again in Workspace recovery.")
    return directory, record


def inspect_grant(token: str) -> dict:
    with _locked():
        directory, record = _grant(token)
        return {"id": record["id"], "directory": str(directory), "old_version": record["old_version"],
                "operation": record["operation"], "helper": str(directory / "maverick.exe"),
                "identity_transition": record.get("identity_transition"),
                "reviewed_new": record.get("reviewed_new")}


def _installer(directory: Path, metadata: dict, label: str) -> dict:
    release = metadata.get(label) or {}
    if not isinstance(release, dict) or not _VERSION.fullmatch(str(release.get("version", ""))):
        raise MaintenanceError("The installer release identity is incomplete.")
    path = directory / (label + ".msi")
    digest = verify_minisign(path, metadata.get("public_key", ""), release.get("signature", ""))
    properties = inspect_signed_msi(path, version=release["version"], scratch=directory)
    return {
        **release,
        "sha256": digest,
        "product_code": properties["ProductCode"].upper(),
        "package_code": str(properties.get("PackageCode", "")).upper(),
        "publisher_thumbprint": properties["PublisherThumbprint"].upper(),
    }


def _snapshot(directory: Path, name: str, runtime_sha256: str) -> dict:
    destination = directory / (name + ".tgz")
    with _scope():
        backup.create_backup(destination, recovery_metadata={"schema": 1, "kind": "installation-" + name,
                              "target": _target(), "runtime_sha256": runtime_sha256,
                              "coverage": "all-local-workspaces-and-shared-administration"})
        manifest = backup.verify_backup(destination)
    return {"name": destination.name, "sha256": backup._sha256(destination), "files": len(manifest["files"]),
            "withheld_key_files": manifest.get("withheld_key_files")}


def _retained_identity(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, info.st_nlink


def _copy_retained_source(source: Path, destination: Path, expected_sha256: str) -> None:
    """Copy one immutable recovery source without reading a large MSI into RAM."""
    if destination.exists():
        raise MaintenanceError("The retained repair source already exists unexpectedly.")
    source = backup._filesystem_path(source)
    destination = backup._filesystem_path(destination)
    fd = -1
    try:
        before = source.lstat()
        if (backup._is_alias(source, before) or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1 or before.st_size > MAX_INSTALLER_BYTES):
            raise MaintenanceError("The installed recovery source is not one supported regular file.")
        fd = os.open(str(source), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        opened = os.fstat(fd)
        after_open = source.lstat()
        # Windows path stat infers executable bits from a .exe suffix while
        # fstat does not. Bind the actual file identity and type, not those
        # synthetic permission bits.
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or backup._is_alias(source, after_open)
                or _retained_identity(before) != _retained_identity(opened)
                or _retained_identity(opened) != _retained_identity(after_open)):
            raise MaintenanceError("The installed recovery source changed while it was opened.")
        with os.fdopen(fd, "rb") as reader:
            fd = -1
            digest, _ = backup._stream_to_new_private(
                reader, destination, expected_size=opened.st_size,
            )
        final = source.lstat()
        if (_retained_identity(after_open) != _retained_identity(final)
                or final.st_size != opened.st_size
                or getattr(final, "st_mtime_ns", None) != getattr(after_open, "st_mtime_ns", None)):
            raise MaintenanceError("The installed recovery source changed during retention.")
    except MaintenanceError:
        destination.unlink(missing_ok=True)
        raise
    except (OSError, backup.BackupError) as exc:
        destination.unlink(missing_ok=True)
        raise MaintenanceError("The installed recovery source could not be retained safely.") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not hmac.compare_digest(digest, expected_sha256):
        destination.unlink(missing_ok=True)
        raise MaintenanceError("The installed recovery source changed during retention.")


def _replace_from_retained(source: Path, target: Path, expected_sha256: str) -> None:
    """Atomically restore an exact retained application file into its fixed path."""
    if not re.fullmatch(r"[0-9a-f]{64}", str(expected_sha256)):
        raise MaintenanceError("The retained application identity is incomplete.")
    staging = target.with_name("." + target.name + "-" + secrets.token_hex(8) + ".repair")
    try:
        _copy_retained_source(source, staging, expected_sha256)
        file_lock._replace_with_retry(staging, target)
        if target.is_symlink() or not target.is_file() or not hmac.compare_digest(
                backup._sha256(target), expected_sha256):
            raise MaintenanceError("A recovered application file did not match its retained identity.")
    except (OSError, backup.BackupError) as exc:
        raise MaintenanceError("A retained application file could not be restored safely.") from exc
    finally:
        staging.unlink(missing_ok=True)


def _verify_repair_source(directory: Path, record: dict) -> Path:
    source = directory / "repair-source.msi"
    expected = record.get("recovery_installer_sha256")
    if (source.is_symlink() or not source.is_file()
            or not re.fullmatch(r"[0-9a-f]{64}", str(expected))
            or not hmac.compare_digest(backup._sha256(source), expected)):
        raise MaintenanceError("The retained install-time repair package changed or is unavailable.")
    properties = inspect_signed_msi(
        source, version=record["old_version"], scratch=directory,
    )
    old = record["old"]
    if (backup._sha256(source) != expected
            or properties["ProductCode"].upper() != old["product_code"]
            or properties["PackageCode"].upper() != old["package_code"]
            or properties["PublisherThumbprint"].upper() != old["publisher_thumbprint"]):
        raise MaintenanceError("The retained install-time repair package no longer matches the reviewed installation.")
    return source


def _restore_repair_files(directory: Path, record: dict) -> None:
    """Recover the complete single-file runtime/native shell set without MSI replay."""
    installed_runtime = Path(record["installed_runtime"])
    install_directory = installed_runtime.parent.absolute()
    if install_directory != Path(record["old"]["install_directory"]).absolute():
        raise MaintenanceError("The reviewed repair installation directory changed.")
    source_installer = _verify_repair_source(directory, record)
    sources = (
        (directory / "maverick.exe", installed_runtime, record["old_runtime_sha256"]),
        (directory / "maverick-desktop.exe", install_directory / "maverick-desktop.exe", record["native_sha256"]),
        (directory / "maverick.exe", install_directory / "maverick-recovery.exe", record["recovery_runtime_sha256"]),
        (directory / "maverick-desktop.exe", install_directory / "maverick-recovery-desktop.exe", record["recovery_native_sha256"]),
        (source_installer, install_directory / "Lightwork-recovery.msi", record["recovery_installer_sha256"]),
    )
    # Authenticate every source before the first installed byte changes.
    for source, _, expected in sources:
        if (source.is_symlink() or not source.is_file()
                or not hmac.compare_digest(backup._sha256(source), expected)):
            raise MaintenanceError("A retained application file changed before recovery.")
    for source, target, expected in sources:
        if target.parent.absolute() != install_directory:
            raise MaintenanceError("A recovered application target is outside the reviewed installation.")
        _replace_from_retained(source, target, expected)


def _prepare_repair(directory: Path, record: dict) -> None:
    if record["status"] != "authorized":
        raise MaintenanceError("The reviewed repair authorization is no longer available.")
    installed_runtime = Path(record["installed_runtime"])
    _verify_repair_registration(directory, record)
    anchor = _repair_anchor(
        installed_runtime,
        directory,
        record["old"],
        expected_runtime_sha256=record["old_runtime_sha256"],
        expected_installer_sha256=record["recovery_installer_sha256"],
        expected_public_key=record["public_key"],
        expected_version=(record["old_version"] if record.get("reviewed_repair_release") else None),
        allow_verified_candidate_installer=bool(record.get("reviewed_repair_release")),
        executing_pair_only=bool(record.get("reviewed_repair_release")),
    )
    if (str(anchor["runtime"]) != record.get("recovery_runtime")
            or str(anchor["native"]) != record.get("recovery_native")
            or str(anchor["installer"]) != record.get("recovery_installer")
            or anchor["runtime_sha256"] != record.get("recovery_runtime_sha256")
            or anchor["runtime_sha256"] != record.get("old_runtime_sha256")
            or anchor["native_sha256"] != record.get("recovery_native_sha256")
            or anchor["native_sha256"] != record.get("native_sha256")
            or anchor["installer_sha256"] != record.get("recovery_installer_sha256")
            or anchor["installer_sha256"] != record["old"].get("installer_sha256")
            or anchor["publisher_thumbprint"] is not None
            and record["old"].get("publisher_thumbprint") is not None
            and anchor["publisher_thumbprint"] != record["old"]["publisher_thumbprint"]
            or not hmac.compare_digest(anchor["public_key"], record.get("public_key", ""))
    ):
        raise MaintenanceError("The installed recovery copy changed after repair authorization.")
    metadata_path = directory / "downloads.json"
    if metadata_path.stat().st_size > 64 * 1024:
        raise MaintenanceError("The repair installer metadata exceeds its limit.")
    metadata = json.loads(file_lock.atomic_read_text(metadata_path))
    if not hmac.compare_digest(str(metadata.get("public_key", "")), record["public_key"]):
        raise MaintenanceError("The repair verification key differs from the installed native application.")
    if metadata.get("identity_transition") is not None:
        raise MaintenanceError("Repair cannot change the application's signing identity.")
    new = _installer(directory, metadata, "new")
    installer_sha256 = str(new.get("installer_sha256", ""))
    if (new["version"] != record["old_version"]
            or new.get("runtime_sha256") != record["old_runtime_sha256"]
            or not re.fullmatch(r"[0-9a-f]{64}", installer_sha256)
            or not hmac.compare_digest(new["sha256"], installer_sha256)
            or not hmac.compare_digest(new["sha256"], record["old"]["installer_sha256"])
            or new["product_code"] != record["old"]["product_code"]
            or new["package_code"] != record["old"]["package_code"]
            or record["old"].get("publisher_thumbprint") is not None
            and new["publisher_thumbprint"] != record["old"]["publisher_thumbprint"]):
        raise MaintenanceError(
            "The repair package does not match the installed application build, product, package and publisher."
        )
    file_lock.atomic_write_bytes(directory / "maverick.exe", anchor["runtime"].read_bytes())
    file_lock.atomic_write_bytes(directory / "maverick-desktop.exe", anchor["native"].read_bytes())
    repair_source = directory / "repair-source.msi"
    if repair_source.exists():
        if (repair_source.is_symlink() or not repair_source.is_file()
                or not hmac.compare_digest(
                    backup._sha256(repair_source), record["recovery_installer_sha256"],
                )):
            raise MaintenanceError("The retained repair source already exists with another identity.")
    else:
        # The updater and this runtime independently verified the exact current
        # MSI. Retain it before creating the startup block, so recovery does not
        # depend on the installed copy surviving a failed repair.
        _copy_retained_source(
            directory / "new.msi",
            repair_source,
            record["recovery_installer_sha256"],
        )
    if (backup._sha256(directory / "maverick.exe") != record["old_runtime_sha256"]
            or backup._sha256(directory / "maverick-desktop.exe") != record["native_sha256"]
            or backup._sha256(directory / "repair-source.msi") != record["recovery_installer_sha256"]):
        raise MaintenanceError("The retained repair helpers changed during copy.")
    damage = []
    for path, expected in (
        (installed_runtime, record["old_runtime_sha256"]),
        (installed_runtime.parent / "maverick-desktop.exe", record["native_sha256"]),
        (installed_runtime.parent / "maverick-recovery.exe", record["old_runtime_sha256"]),
        (installed_runtime.parent / "maverick-recovery-desktop.exe", record["native_sha256"]),
    ):
        try:
            if path.is_symlink() or not path.is_file() or backup._sha256(path) != expected:
                damage.append(path.name)
        except OSError:
            damage.append(path.name)
    record["old"]["publisher_thumbprint"] = new["publisher_thumbprint"]
    record.update(
        new=new,
        new_runtime_sha256=record["old_runtime_sha256"],
        damaged_core_files=sorted(set(damage)),
        retained_installer_available_at_prepare=anchor["retained_installer_available"],
        before=_snapshot(directory, "before", record["old_runtime_sha256"]),
    )


def prepare(token: str) -> dict:
    """Called by the native shell only after stopping its owned recovery server."""
    with _locked(), _quiesced():
        directory, record = _grant(token)
        assert_normal_start_allowed()
        _admit_local()
        operation = _operation(record)
        if operation == "upgrade":
            current = backup._sha256(_runtime())
            if record["status"] != "authorized" or current != record["old_runtime_sha256"]:
                raise MaintenanceError("The reviewed source application changed.")
            metadata_path = directory / "downloads.json"
            if metadata_path.stat().st_size > 64 * 1024:
                raise MaintenanceError("The installer metadata exceeds its limit.")
            metadata = json.loads(file_lock.atomic_read_text(metadata_path))
            if not hmac.compare_digest(str(metadata.get("public_key", "")), record["public_key"]):
                raise MaintenanceError("The staged verification key does not match the installed native application.")
            if metadata.get("identity_transition") != record.get("identity_transition"):
                raise MaintenanceError("The staged signing identity transition does not match the administrator's review.")
            if backup._sha256(Path(record["installed_runtime"]).parent / "maverick-desktop.exe") != record["native_sha256"]:
                raise MaintenanceError("The native application changed after authorization.")
            old = _installer(directory, metadata, "old")
            new = _installer(directory, metadata, "new")
            reviewed = record.get("reviewed_new")
            if reviewed and any(new.get(key) != reviewed.get(key) for key in ("version", "runtime_sha256", "signature")):
                raise MaintenanceError("The staged release differs from the administrator's exact native review.")
            if reviewed and not hmac.compare_digest(new["sha256"], reviewed["installer_sha256"]):
                raise MaintenanceError("The staged installer differs from the administrator's exact native review.")
            _check_transition_installers(record, old, new, admit=True)
            if old["version"] != record["old_version"] or tuple(map(int, new["version"].split("."))) <= tuple(map(int, old["version"].split("."))):
                raise MaintenanceError("The retained installers do not match the reviewed upgrade.")
            for release in (old, new):
                if not re.fullmatch(r"[0-9a-f]{64}", str(release.get("runtime_sha256", ""))):
                    raise MaintenanceError("The release lacks an exact runtime identity.")
            if old["runtime_sha256"] != current:
                raise MaintenanceError("The retained release does not match the installed application build.")
            for name in ("maverick.exe", "maverick-desktop.exe"):
                source = Path(record["installed_runtime"]).parent / name
                # Keep the helper and its native recovery UI outside MSI ownership.
                file_lock.atomic_write_bytes(directory / name, source.read_bytes())
            if backup._sha256(directory / "maverick.exe") != current:
                raise MaintenanceError("The retained application helper changed during copy.")
            record.update(old=old, new=new,
                          new_runtime_sha256=new["runtime_sha256"],
                          before=_snapshot(directory, "before", current))
            if record.get("identity_transition") is not None:
                record["transition_admitted_at"] = time.time()
        elif operation == "repair":
            _prepare_repair(directory, record)
        elif operation == "rollback":
            current = backup._sha256(_runtime())
            if record["status"] != "upgraded" or current != record["new_runtime_sha256"]:
                raise MaintenanceError("The installed application no longer matches this completed upgrade.")
            _verify_runtime(record, "new")
            _check_transition_installers(record, record["old"], record["new"])
            with _scope():
                archive = directory / "before.tgz"
                if backup._sha256(archive) != record["before"]["sha256"]:
                    raise MaintenanceError("The pre-upgrade snapshot changed.")
                # Refuse before creating a startup block or touching either
                # installer. Reverting real spend would reopen exhausted caps.
                backup.assert_accounting_unchanged(archive)
            record["safety"] = _snapshot(directory, "safety-" + secrets.token_hex(8), current)
        else:
            raise MaintenanceError("The reviewed installation operation is unsupported.")
        record.update(status="prepared", prepared_at=time.time())
        _write(directory / "record.json", record)
        _write(_store() / "active.json", {"schema": 1, "target": _target(), "id": record["id"]})
        return {"id": record["id"], "helper": str(directory / "maverick.exe"), "operation": record["operation"]}


def _registered_package_copy(directory: Path, record: dict, package: Path) -> Path | None:
    """Offer the verified repair package under the product's registered file name.

    Windows Installer resolves a maintenance-mode (REINSTALL) source as the
    launched-from directory plus the registered PackageName. A package launched
    under any other file name fails source resolution (error 1316) and the
    reinstall dies in ProcessComponents with 1603. The copy is transient and
    byte-verified against the reviewed candidate; the candidate itself stays
    for finalization and recovery.
    """
    registered = (record.get("old") or {}).get("package_name")
    if not _valid_package_name(registered):
        raise MaintenanceError(
            "The registered package name for this repair is unavailable. Review the repair again in Install & updates."
        )
    if registered.lower() == package.name.lower():
        return None
    transient = directory / registered
    if transient.is_symlink() or (transient.exists() and not transient.is_file()):
        raise MaintenanceError("The registered-name repair package path is not one ordinary file.")
    transient.unlink(missing_ok=True)
    _copy_retained_source(package, transient, record["new"]["sha256"])
    return transient


def _msiexec(directory: Path, action: str, name: str) -> None:
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "msiexec.exe"
    from .windows_installer_verification import installer_path
    record = _read(directory / "record.json")
    package = directory / (name + ".msi")
    transient = None
    if action == "/i" and record.get("operation") == "repair":
        transient = _registered_package_copy(directory, record, package)
    arguments = [str(executable), action, installer_path(transient or package), "/passive", "/norestart",
                 "/L*v", installer_path(directory / (action.strip("/") + "-" + name + ".log"))]
    if action == "/i":
        arguments.append("INSTALLDIR=" + installer_path(Path(record["installed_runtime"]).parent))
        if record.get("operation") == "repair":
            arguments.extend(("REINSTALL=ALL", "REINSTALLMODE=vamus"))
    try:
        result = subprocess.run(arguments,
                                check=False, timeout=1800, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    finally:
        if transient is not None:
            transient.unlink(missing_ok=True)
    if result.returncode not in ((0, 3010, 1605) if action == "/x" else (0, 3010)):
        raise MaintenanceError("Windows Installer could not finish. The recovery point and installation logs have been kept.")


def _verify_runtime(record: dict, label: str) -> None:
    path = Path(record["installed_runtime"])
    if not path.is_file() or backup._sha256(path) != record[label + "_runtime_sha256"]:
        raise MaintenanceError("The installed application does not match the verified release. Workspace restoration has not been marked complete.")
    if record.get("operation") == "repair":
        recovery_runtime = path.parent / "maverick-recovery.exe"
        main_native = path.parent / "maverick-desktop.exe"
        recovery_native = path.parent / "maverick-recovery-desktop.exe"
        expected = (
            (recovery_runtime, record["recovery_runtime_sha256"]),
            (main_native, record["native_sha256"]),
            (recovery_native, record["recovery_native_sha256"]),
        )
        if any(item.is_symlink() or not item.is_file() or backup._sha256(item) != digest
               for item, digest in expected):
            raise MaintenanceError(
                "The installed application or its recovery copy does not match the verified release. Recovery remains blocked."
            )
        native = _native_channel(
            path,
            expected_version=record[label]["version"],
            native_path=recovery_native,
        )
        if (native.get("public_key") != record["public_key"]
                or native.get("native_sha256") != record["recovery_native_sha256"]):
            raise MaintenanceError(
                "The installed recovery signing identity changed. Recovery remains blocked."
            )
        ticket = _directory(record["id"])
        _verify_repair_registration(ticket, record)
        anchor = _repair_anchor(
            path,
            ticket,
            record["old"],
            expected_runtime_sha256=record["old_runtime_sha256"],
            expected_installer_sha256=record["recovery_installer_sha256"],
            expected_public_key=record["public_key"],
            expected_version=record["old_version"],
        )
        if (
            anchor["runtime_sha256"] != record["recovery_runtime_sha256"]
            or anchor["native_sha256"] != record["recovery_native_sha256"]
            or anchor["installer_sha256"] != record["recovery_installer_sha256"]
            or anchor["public_key"] != record["public_key"]
            or anchor["publisher_thumbprint"] != record["old"]["publisher_thumbprint"]
        ):
            raise MaintenanceError(
                "The installed recovery source changed. Recovery remains blocked."
            )
        return
    if record.get("identity_transition") is not None:
        side = record["identity_transition"]["policy"]["from" if label == "old" else "to"]
        native = _native_channel(path, expected_version=side["version"])
        if any(native.get(name) != side[name] for name in ("native_sha256", "public_key")):
            raise MaintenanceError("The installed desktop signing identity does not match the reviewed release. Recovery remains blocked.")
    else:
        native = _native_channel(path, expected_version=record[label]["version"])
        if (native.get("public_key") != record["public_key"]
                or label == "old" and native.get("native_sha256") != record["native_sha256"]):
            raise MaintenanceError("The installed desktop signing identity changed without an admitted bridge. Recovery remains blocked; obtain the administrator's reviewed transition release.")


def _verify_completed_state(directory: Path, record: dict, outcome: str) -> None:
    labels = {
        "upgraded": "new",
        "upgrade_recovered": "old",
        "rolled_back": "old",
        "repaired": "new",
        "repair_recovered": "old",
    }
    try:
        label = labels[outcome]
    except (KeyError, TypeError) as exc:
        raise MaintenanceError("The installation completion outcome is unsupported.") from exc
    _verify_runtime(record, label)
    with _scope():
        archive = directory / "before.tgz"
        if backup._sha256(archive) != record["before"]["sha256"]:
            raise MaintenanceError("The completed operation's snapshot changed.")
        manifest = backup.verify_backup(archive)
        expected = {name: (row["sha256"], row["size"]) for name, row in manifest["files"].items()}
        if backup._replacement_targets(_home(), expected) != set(expected):
            raise MaintenanceError("Local files changed after the completion receipt. The startup block remains in place.")
        # A committed SQLite WAL may be checkpointed when a reader closes,
        # without changing logical data. Compare through the same online
        # snapshot representation used for the archive, then integrity-check
        # that representation. Non-database bytes remain exact hash checks.
        with backup._temporary_directory(prefix="lightwork-completion-check-") as temporary:
            stage = file_lock.ensure_private_directory(temporary / "data")
            observed = backup._stage(_home(), stage, include_keys=backup._archive_includes_keys(expected))
            if set(observed) != set(expected):
                raise MaintenanceError("Local files changed after the completion receipt.")
            backup._verify_restored(stage, expected)


def _verified_before_archive(directory: Path, record: dict, operation: str) -> Path:
    archive = directory / "before.tgz"
    if backup._sha256(archive) != record["before"]["sha256"]:
        raise MaintenanceError(f"The pre-{operation} snapshot changed.")
    manifest = backup.verify_backup(archive)
    binding = manifest.get("recovery", {})
    if (binding.get("target") != _target()
            or binding.get("runtime_sha256") != record["old_runtime_sha256"]):
        raise MaintenanceError(
            f"The pre-{operation} snapshot does not match this application and data home."
        )
    backup.assert_accounting_unchanged(archive)
    return archive


def _recover_failed_upgrade(directory: Path, record: dict) -> None:
    with _scope():
        archive = _verified_before_archive(directory, record, "upgrade")
        _msiexec(directory, "/x", "new")
        _msiexec(directory, "/i", "old")
        _verify_runtime(record, "old")
        backup.restore_backup(archive, replace_existing=True)


def _recover_failed_repair(directory: Path, record: dict) -> None:
    with _scope():
        archive = _verified_before_archive(directory, record, "repair")
        _restore_repair_files(directory, record)
        _verify_runtime(record, "old")
        backup.restore_backup(archive, replace_existing=True)


def execute(token: str) -> dict:
    """Run from the retained old binary after the native shell exits.

    Success means exact installed runtime AND matching local state. A failure
    retains the startup block, signed receipt, installers and safety snapshots.
    """
    with _locked(), _quiesced():
        directory, record = _grant(token)
        active = _read(_store() / "active.json")
        if active.get("id") != record["id"]:
            raise MaintenanceError("Another reviewed operation owns installation recovery. Its startup block has been preserved.")
        operation = _operation(record)
        if record["status"] != "prepared" or backup._sha256(_runtime()) != record["old_runtime_sha256"]:
            raise MaintenanceError("Only the reviewed retained application can complete this maintenance operation.")
        finalization = record.get("finalization")
        if finalization is not None and finalization not in _TERMINAL_BY_OPERATION[operation]:
            raise MaintenanceError("The installation completion receipt does not match its reviewed operation.")
        _admit_local()
        record.update(status="applying", grant_hash="", started_at=time.time())
        _write(directory / "record.json", record)
        try:
            if operation == "repair":
                _verify_repair_registration(directory, record)
                metadata = {"public_key": record["public_key"], "new": record["new"]}
                verified = _installer(directory, metadata, "new")
                if any(verified.get(name) != record["new"].get(name) for name in (
                    "sha256", "runtime_sha256", "installer_sha256", "product_code",
                    "package_code", "publisher_thumbprint",
                )):
                    raise MaintenanceError("The retained repair installer changed after review.")
            else:
                metadata = {"public_key": record["public_key"], "old": record["old"], "new": record["new"]}
                installers = {}
                for label in ("old", "new"):
                    verified = _installer(directory, metadata, label)
                    if verified["sha256"] != record[label]["sha256"]:
                        raise MaintenanceError("A retained installer changed after review.")
                    installers[label] = verified
                _check_transition_installers(record, installers["old"], installers["new"])
            if record.get("finalization") in {
                "upgraded", "upgrade_recovered", "rolled_back", "repaired", "repair_recovered",
            }:
                outcome = record["finalization"]
                _verify_completed_state(directory, record, outcome)
            elif operation == "upgrade":
                if record.get("upgrade_resume") == "restore_retained_release":
                    _recover_failed_upgrade(directory, record)
                    outcome = "upgrade_recovered"
                    _verify_completed_state(directory, record, outcome)
                else:
                    _msiexec(directory, "/i", "new")
                    _verify_runtime(record, "new")
                    outcome = "upgraded"
            elif operation == "repair":
                if record.get("repair_resume") == "restore_retained_sources":
                    _recover_failed_repair(directory, record)
                    outcome = "repair_recovered"
                else:
                    _msiexec(directory, "/i", "new")
                    _verify_runtime(record, "new")
                    outcome = "repaired"
                _verify_completed_state(directory, record, outcome)
            elif operation == "rollback":
                with _scope():
                    archive = directory / "before.tgz"
                    if backup._sha256(archive) != record["before"]["sha256"]:
                        raise MaintenanceError("The pre-upgrade snapshot changed.")
                    manifest = backup.verify_backup(archive)
                    binding = manifest.get("recovery", {})
                    if binding.get("target") != _target() or binding.get("runtime_sha256") != record["old_runtime_sha256"]:
                        raise MaintenanceError("The pre-upgrade snapshot does not match this application and data home.")
                    # Recheck under the fresh lease immediately before MSI;
                    # accounting may have changed after the prepared review.
                    backup.assert_accounting_unchanged(archive)
                    # Downgrade through explicit reviewed uninstall/install; never
                    # disable the general MSI downgrade guard or ledger guards.
                    _msiexec(directory, "/x", "new")
                    _msiexec(directory, "/i", "old")
                    _verify_runtime(record, "old")
                    backup.restore_backup(archive, replace_existing=True)
                outcome = "rolled_back"
            else:
                raise MaintenanceError("The reviewed installation operation is unsupported.")
            record.update(status=outcome, completed_at=time.time())
            _write(directory / "record.json", record)
        except Exception as exc:
            record.update(status="incomplete", failed_at=time.time())
            record["error"] = str(exc)[:2000]
            _write(directory / "record.json", record)
            raise
        try:
            (_store() / "active.json").unlink()
        except OSError as exc:
            raise MaintenanceError(
                "Installation completed, but its startup block could not be cleared. Resume this operation in Install & updates."
            ) from exc
        return {"id": record["id"], "status": outcome}


def logs(identifier: str) -> dict:
    """Bounded local-only diagnostics for a fixed reviewed operation."""
    with _locked():
        directory = _directory(identifier)
        record = _read(directory / "record.json")
        sections = ["Operation: " + str(record.get("operation")), "State: " + str(record.get("status"))]
        if record.get("error"):
            sections.append(str(record["error"])[:2000])
        for name in ("i-new.log", "x-new.log", "i-old.log"):
            path = directory / name
            if not path.exists():
                continue
            file_lock.ensure_private_file(path)
            with path.open("rb") as source:
                unicode_log = source.read(2) == b"\xff\xfe"
                start = max(0, path.stat().st_size - 16000)
                source.seek(start - start % 2 if unicode_log else start)
                payload = source.read(16000)
            text = payload.decode("utf-16-le" if unicode_log else "utf-8", errors="replace")
            text = "".join(char for char in text if char in "\n\r\t" or ord(char) >= 32)
            sections.append(name + " (most recent output)\n" + text)
        return {"id": identifier, "details": "\n\n".join(sections)}


def assert_normal_start_allowed() -> None:
    # Do not create state or keys during ordinary startup.
    marker = _home() / "backups" / "installation-recovery" / "active.json"
    if marker.exists():
        raise MaintenanceError("Installation recovery is unfinished. Open Install & updates in Lightwork Desktop to finish recovery before starting workspace work.")
    try:
        workspace_recovery.assert_bootstrap_start_allowed()
    except workspace_recovery.RecoveryError as exc:
        raise MaintenanceError(str(exc)) from exc


def resume(identifier: str) -> str:
    """Native, explicitly confirmed retry of an already authorized operation.

    No new operation, target, version or snapshot may be selected by this path.
    Normal HTTP routes never expose this local OS-user recovery primitive.
    """
    with _locked():
        directory = _directory(identifier)
        record = _read(directory / "record.json")
        operation = _operation(record)
        original_status = record.get("status")
        marker = _store() / "active.json"
        active = _read(marker) if marker.exists() else None
        if ((active is not None and active.get("id") != identifier)
                or active is None and original_status != "prepared"
                or original_status not in {
            "prepared", "applying", "incomplete", "upgraded", "upgrade_recovered",
            "rolled_back", "repaired", "repair_recovered",
        }):
            raise MaintenanceError("This installation has no unfinished reviewed operation to resume.")
        if original_status in {
            "upgraded", "upgrade_recovered", "rolled_back", "repaired", "repair_recovered",
        }:
            if original_status not in _TERMINAL_BY_OPERATION[operation]:
                raise MaintenanceError(
                    "The installation completion receipt does not match its reviewed operation."
                )
            # A crash between the signed completion receipt and marker removal
            # is recoverable only after rechecking exact binary and local state.
            record["finalization"] = original_status
        elif operation == "repair" and original_status in {"applying", "incomplete"}:
            # Do not replay a candidate that already failed its exact installed
            # identity check. Recover the application from the separately
            # retained install-time sources, then restore the exact data snapshot.
            record["repair_resume"] = "restore_retained_sources"
        elif operation == "upgrade" and original_status in {"applying", "incomplete"}:
            # A failed candidate may be deterministically bad. The exact old MSI
            # and pre-upgrade state were authenticated before the first attempt.
            record["upgrade_resume"] = "restore_retained_release"
        nonce = secrets.token_hex(32)
        record.update(status="prepared", grant_hash=hashlib.sha256(nonce.encode()).hexdigest(), expires_at=time.time() + 900)
        _write(directory / "record.json", record)
        if active is None:
            _write(marker, {"schema": 1, "target": _target(), "id": identifier})
        return identifier + ":" + nonce


def _retired_directory(identifier: str) -> Path:
    return _directory(identifier).with_name("retired-" + identifier)


def _records() -> list[tuple[Path, dict]]:
    records = []
    for path in _store().glob("*/record.json"):
        record = _read(path)
        expected = {_directory(record.get("id"))}
        if record.get("status") == "retired":
            expected.add(_retired_directory(record["id"]))
        if path.parent not in expected:
            raise MaintenanceError("An installation recovery point has a mismatched identity.")
        records.append((path, record))
    return records


def _usable_point_count() -> int:
    return sum(record.get("status") != "retired" or record.get("cleanup_pending", False)
               for _, record in _records())


def _record_sha256(record: dict) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _installed_identity() -> tuple[Path, str] | None:
    try:
        runtime = _runtime()
        return runtime.resolve(), backup._sha256(runtime)
    except (MaintenanceError, OSError):
        return None


def _retirement_blocker(record: dict, active_id: str | None, installed: tuple[Path, str] | None) -> str | None:
    if active_id is not None or record.get("status") in {"prepared", "applying", "incomplete"}:
        return "An installation operation is unfinished. Finish it before retiring recovery points."
    if record.get("status") in {
        "authorized", "upgrade_recovered", "rolled_back", "repaired", "repair_recovered", "retired",
    }:
        return None
    if record.get("status") == "upgraded":
        try:
            if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("new_runtime_sha256", ""))):
                return "The installed application identity could not be established. Keep this recovery point."
            if installed is None or installed[0] != Path(record["installed_runtime"]).resolve():
                return "The installed application identity could not be established. Keep this recovery point."
            if installed[1] == record.get("new_runtime_sha256"):
                return "This recovery point protects rollback of the installed application. Keep it until a later application update."
            return None
        except (MaintenanceError, OSError, KeyError):
            return "The installed application identity could not be established. Keep this recovery point."
    return "This recovery point is not eligible for retirement."


def _retirement_files(directory: Path) -> list[Path]:
    # Installation points contain flat, private files only. Never recursively
    # delete a user-selected directory or follow an alias into another tree.
    store = file_lock.require_private_directory(_store()).resolve()
    file_lock.require_private_directory(directory)
    if directory.resolve() != directory or directory.parent.resolve() != store:
        raise MaintenanceError("The recovery point is outside its private installation store.")
    files = list(directory.iterdir())
    if len(files) > 128:
        raise MaintenanceError("This recovery point contains an unexpected number of files.")
    for path in files:
        info = path.lstat()
        if file_lock._unsafe_lock_alias(path, info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise MaintenanceError("This recovery point contains an unexpected directory or file alias; no files were retired.")
    return files


def _prune_retirement_history() -> None:
    retired = [(path, record) for path, record in _records()
               if record.get("status") == "retired" and not record.get("cleanup_pending")]
    retired.sort(key=lambda item: (item[1]["retired_at"], item[1]["id"]), reverse=True)
    for path, _ in retired[MAX_RETIREMENT_HISTORY:]:
        files = _retirement_files(path.parent)
        if files != [path]:
            raise MaintenanceError("A retired recovery point has unexpected remaining files. Its receipt was kept.")
        path.unlink()
        path.parent.rmdir()


def retire(identifier: str, *, expected_sha256: str, actor: str, confirm: bool) -> dict:
    """Retire only an explicitly reviewed, inactive local installation point."""
    if not actor or confirm is not True:
        raise MaintenanceError("Review and explicitly confirm this installation recovery retirement.")
    with _locked():
        directory = _directory(identifier)
        if not directory.exists():
            directory = _retired_directory(identifier)
        record = _read(directory / "record.json")
        if record.get("id") != identifier:
            raise MaintenanceError("The installation recovery point changed. Refresh and review it again.")
        digest = record.get("retirement_sha256") if record.get("status") == "retired" else _record_sha256(record)
        if not isinstance(expected_sha256, str) or not hmac.compare_digest(digest, expected_sha256):
            raise MaintenanceError("The installation recovery point changed. Refresh and review it again.")
        marker = _store() / "active.json"
        active_id = _read(marker).get("id") if marker.exists() else None
        reason = _retirement_blocker(record, active_id, _installed_identity() if record.get("status") == "upgraded" else None)
        if reason:
            raise MaintenanceError(reason)
        _retirement_files(directory)
        if record.get("status") != "retired":
            record = ({key: record.get(key) for key in ("schema", "target", "id", "old_version", "created_at", "completed_at")}
                      | {"previous_status": record["status"], "new_version": record.get("new", {}).get("version")})
            record.update(status="retired", retirement_sha256=digest, retired_by=actor,
                          retired_at=time.time(), cleanup_pending=True)
            # Persist revocation before deleting any retained payload. A crash
            # can retry this exact retirement, but cannot revive an old grant.
            _write(directory / "record.json", record)
        destination = _retired_directory(identifier)
        if directory != destination:
            if destination.exists() or destination.resolve().parent != _store().resolve():
                raise MaintenanceError("The retired recovery directory is not available. Its signed receipt was kept.")
            # Native downloads never create the point directory. Moving the
            # revoked point prevents a delayed download from writing new bytes
            # at its old path after cleanup has reported completion.
            directory.rename(destination)
            directory = destination
        for path in _retirement_files(directory):
            if path.name != "record.json":
                path.unlink()
        record["cleanup_pending"] = False
        _write(directory / "record.json", record)
        _prune_retirement_history()
        return {"id": identifier, "retired": True}


def discard_authorization(authorization: str, *, actor: str) -> None:
    """Retire a grant that was issued but could not be handed on or staged.

    The caller already holds the error that explains the failure, so this never
    raises: a grant that cannot be retired here stays visible, with its expiry,
    for an administrator to retire from Workspace recovery.
    """
    match = _TOKEN.fullmatch(authorization) if isinstance(authorization, str) else None
    if match is None:
        return
    with suppress(OSError, ValueError, KeyError, MaintenanceError):
        record = _read(_directory(match[1]) / "record.json")
        retire(match[1], expected_sha256=_record_sha256(record), actor=actor, confirm=True)


def status() -> dict:
    store = _home() / "backups" / "installation-recovery"
    records, history = [], []
    if store.exists():
        with _locked():
            active_id = _read(store / "active.json").get("id") if (store / "active.json").exists() else None
            saved = _records()
            installed = _installed_identity() if any(
                record.get("status") == "upgraded" for _, record in saved
            ) else None
            for _, record in saved:
                row = {key: record.get(key) for key in ("id", "status", "old_version", "created_at", "completed_at")}
                if record.get("status") == "retired" and not record.get("cleanup_pending"):
                    history.append(row | {key: record.get(key) for key in ("retired_at", "retired_by", "previous_status", "new_version")})
                    continue
                reason = _retirement_blocker(record, active_id, installed)
                records.append(row | {"new_version": record.get("new", {}).get("version"),
                                      "snapshot_saved": bool(record.get("before")),
                                      "withheld_key_files": (record.get("before") or {}).get("withheld_key_files"),
                                      "pending_finalization": record.get("id") == active_id,
                                      "can_retire": reason is None, "retirement_blocker": reason,
                                      "record_sha256": record.get("retirement_sha256") or _record_sha256(record),
                                      "cleanup_pending": record.get("cleanup_pending", False)})
    records.sort(key=lambda row: (not row["pending_finalization"], -row["created_at"]))
    history.sort(key=lambda row: row["retired_at"], reverse=True)
    return {"maintenance_protocol": MAINTENANCE_PROTOCOL,
            "recovery_points": records, "retirement_history": history[:MAX_RETIREMENT_HISTORY],
            "retirement_history_limit": MAX_RETIREMENT_HISTORY, "point_limit": MAX_TICKETS,
            "incomplete": (store / "active.json").exists(),
            "coverage": "All local workspaces and shared administration. External stores and services are excluded."}
