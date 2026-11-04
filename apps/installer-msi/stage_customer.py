"""Stage a complete frozen runtime and a strict customer Tauri configuration.

Run on the build host. The customer never executes Python, Git, or pip.
Publisher public keys and channel URLs are build inputs, never webview input.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-pc-windows-msvc"
UPGRADE_CODE = "AB5BC260-7EC9-4B70-AF78-28F4067BC530"
RECOVERY_FRAGMENT = Path(__file__).with_name("customer-recovery.wxs")
RECOVERY_COMPONENTS = ["LightworkRecoveryCopies", "LightworkRepairShortcut"]


def validate_channel(endpoint: str, public_key: str) -> None:
    url = urlsplit(endpoint)
    try:
        port = url.port
    except ValueError as exc:
        raise ValueError("customer update endpoint must have a valid HTTPS port") from exc
    if (url.scheme != "https" or not url.hostname or url.username is not None
            or url.password is not None or url.fragment or len(endpoint) > 4096
            or port == 0 or "\\" in endpoint or any(ord(char) <= 32 for char in endpoint)):
        raise ValueError("customer update endpoint must be an HTTPS URL without credentials or fragment")
    try:
        # Tauri's public key is base64-wrapped minisign text. Validate both
        # layers so a missing/placeholder key cannot produce a customer build.
        decoded = base64.b64decode(public_key, validate=True).decode("ascii").splitlines()
        raw = base64.b64decode(decoded[1], validate=True)
        if len(decoded) != 2 or not decoded[0].startswith("untrusted comment:") or len(raw) != 42:
            raise ValueError
        if raw[:2] != b"Ed":
            raise ValueError
    except (ValueError, IndexError, UnicodeError) as exc:
        raise ValueError("customer update public key is not a valid Tauri minisign key") from exc


def runtime_metadata(binary: Path) -> dict:
    """Hash the executable in bounded memory, including its exact byte count."""
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("runtime must be an existing regular executable")
    with binary.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise ValueError("customer runtime must be a Windows executable")
        stream.seek(0)
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return {"sha256": digest.hexdigest(), "bytes": size}


def runtime_check_environment(directory: Path) -> dict[str, str]:
    """Use only OS launch settings and disposable config/profile/cache paths.

    This isolates trusted build checks from operator configuration; it is not a
    sandbox for untrusted executables or an installed-customer acceptance test.
    """
    allowed = {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE",
               "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "LANG", "LC_ALL", "TZ"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    paths = {name: directory / name for name in ("home", "profile", "temporary", "appdata", "localappdata",
                                                "xdg-config", "xdg-data", "xdg-cache")}
    for path in paths.values():
        path.mkdir()
    config = paths["home"] / "config.toml"
    config.write_text("# Isolated customer-runtime build check; no provider configuration.\n", encoding="utf-8")
    system_root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT")
    environment.update(
        PATH=str(Path(system_root) / "System32") if system_root else "",
        HOME=str(paths["profile"]), USERPROFILE=str(paths["profile"]),
        APPDATA=str(paths["appdata"]), LOCALAPPDATA=str(paths["localappdata"]),
        XDG_CONFIG_HOME=str(paths["xdg-config"]), XDG_DATA_HOME=str(paths["xdg-data"]),
        XDG_CACHE_HOME=str(paths["xdg-cache"]),
        TEMP=str(paths["temporary"]), TMP=str(paths["temporary"]), TMPDIR=str(paths["temporary"]),
        MAVERICK_HOME=str(paths["home"]), MAVERICK_CONFIG=str(config),
        PYTHONUTF8="1", PYINSTALLER_RESET_ENVIRONMENT="1", NO_COLOR="1",
    )
    return environment


def verify_runtime(binary: Path, cohort: dict, *, run=subprocess.run) -> dict:
    metadata = runtime_metadata(binary)
    binary = binary.resolve()
    with tempfile.TemporaryDirectory(prefix="lightwork-runtime-check-") as temporary:
        directory = Path(temporary)
        environment = runtime_check_environment(directory)
        for arguments in (["version"], ["release-runtime-check"], ["dashboard", "--help"], ["mcp", "--help"]):
            result = run([str(binary), *arguments], check=True, capture_output=True,
                         text=True, timeout=120, env=environment, cwd=directory)
            # An immediate recheck binds all probes to the reported input. This
            # is drift detection, not atomic admission against hostile writers.
            try:
                unchanged = runtime_metadata(binary) == metadata
            except (OSError, ValueError):
                unchanged = False
            if not unchanged:
                raise ValueError("customer runtime changed during verification; rebuild and stage again")
            if arguments == ["version"]:
                for package in cohort["packages"]:
                    expected = rf"^\s*{re.escape(package['distribution'])}\s+{re.escape(cohort['version'])}\s*$"
                    if re.search(expected, result.stdout, re.MULTILINE) is None:
                        raise ValueError(f"frozen runtime omits the expected {package['distribution']} cohort version")
    return metadata


def stage(runtime: Path, output: Path, endpoint: str, public_key: str,
          *, fixture_version: str | None = None, fault_fragment: Path | None = None) -> Path:
    validate_channel(endpoint, public_key)
    cohort = tomllib.loads((ROOT / "release-cohort.toml").read_text(encoding="utf-8"))
    version = cohort["version"] if fixture_version is None else fixture_version
    if (not isinstance(version, str) or len(version) > 13
            or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version)
            or any(int(value) > limit for value, limit in zip(version.split("."), (255, 255, 65535), strict=True))):
        raise ValueError("Windows desktop package version must be numeric major.minor.patch within 255.255.65535")
    if fixture_version is None and int(version.rsplit(".", 1)[1]) >= 65535:
        raise ValueError(
            "Windows desktop base package patch must be below 65535 so the acceptance upgrade can be built"
        )
    if fault_fragment is not None and fixture_version is None:
        raise ValueError("fault injection is allowed only in a labelled acceptance fixture")
    if output.exists():
        raise FileExistsError(f"customer staging directory already exists: {output.resolve()}")
    metadata = verify_runtime(runtime, cohort)
    output.mkdir(parents=True, exist_ok=False)
    sidecar = output / f"maverick-{TARGET}.exe"
    shutil.copyfile(runtime, sidecar)
    if runtime_metadata(sidecar) != metadata:
        raise ValueError("staged runtime changed during copy")
    wix = {
        "upgradeCode": UPGRADE_CODE,
        "enableElevatedUpdateTask": False,
        "fragmentPaths": [str(RECOVERY_FRAGMENT.resolve())],
        "componentRefs": RECOVERY_COMPONENTS,
    }
    if fault_fragment is not None:
        wix["fragmentPaths"].append(str(fault_fragment.resolve()))
        wix["featureRefs"] = ["LightworkAcceptanceHarness"]
    config = {
        "version": version,
        "bundle": {
            "targets": ["msi"], "category": "Productivity",
            "shortDescription": "Lightwork workspace and complete local runtime",
            "longDescription": "Lightwork with its complete runtime. No Python or Git is required on the target computer.",
            "externalBin": [str(output.resolve() / "maverick")],
            "icon": [str(ROOT / "apps/installer-desktop/src-tauri/icons/icon.ico")],
            "createUpdaterArtifacts": False,
            "windows": {"webviewInstallMode": {"type": "offlineInstaller"},
                        "allowDowngrades": False, "wix": wix},
        },
        "plugins": {"updater": {"pubkey": public_key, "endpoints": [endpoint],
                                  "windows": {"installMode": "passive"}}},
    }
    target = output / "tauri.customer.json"
    target.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (output / "runtime-inventory.json").write_text(json.dumps({
        "schema": "lightwork.windows-customer-build.v1", "version": version,
        "cohort_version": cohort["version"], "complete_release_cohort": True,
        "packages": cohort["packages"], "runtime": metadata,
        "acceptance_fixture": fixture_version is not None,
        "requires_customer_python": False, "requires_customer_git": False,
        "publisher_signature_verified": False,
        "installed_recovery": {
            "runtime": "maverick-recovery.exe",
            "native_shell": "maverick-recovery-desktop.exe",
            "signed_installer": "Lightwork-recovery.msi",
            "start_menu": "Repair Lightwork",
        },
    }, indent=2) + "\n", encoding="utf-8")
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--public-key-file", type=Path, required=True)
    parser.add_argument("--acceptance-fixture-version")
    parser.add_argument("--acceptance-fault-fragment", type=Path)
    args = parser.parse_args()
    print(stage(args.runtime, args.output, args.endpoint,
                args.public_key_file.read_text(encoding="utf-8").strip(),
                fixture_version=args.acceptance_fixture_version,
                fault_fragment=args.acceptance_fault_fragment))


if __name__ == "__main__":
    main()
