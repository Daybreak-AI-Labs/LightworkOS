#!/usr/bin/env python3
"""Verify reviewed local dependency sources and their application overrides."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import tarfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = {
    "vendor/rust/glib": "0.18.5",
    "vendor/rust/glib-macros": "0.18.5",
    "vendor/rust/gtk3-macros": "0.18.2",
    "vendor/js/deepmerge": "4.3.1",
    "vendor/js/picomatch-v2": "2.3.2",
    "vendor/js/picomatch-v3": "3.0.2",
    "vendor/js/picomatch-v4": "4.0.7",
}
REMOVED = {"proc-macro-error", "proc-macro-error-attr", "proc-macro-error2", "proc-macro-error-attr2", "unic-char-property",
           "unic-char-range", "unic-common", "unic-ucd-ident", "unic-ucd-version"}


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    inventory = json.loads((root / "vendor/provenance.json").read_text())
    entries = inventory["packages"]
    if {entry["path"]: entry["version"] for entry in entries} != PACKAGES:
        return ["vendor package inventory differs from the reviewed set"]
    if len(entries) != len(PACKAGES):
        return ["duplicate vendor package inventory entry"]
    for entry in entries:
        base = root / entry["path"]
        files = {}
        for path in base.rglob("*"):
            if path.is_symlink():
                errors.append(f"symlink in reviewed source: {path.relative_to(root)}")
            elif path.is_file():
                files[path.relative_to(base).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        if files != entry["files"]:
            errors.append(f"source inventory or content changed: {entry['path']}")
        if not any(name.upper().startswith("LICENSE") for name in files):
            errors.append(f"missing upstream license: {entry['path']}")
    for app in ("desktop", "installer-desktop"):
        directory = root / "apps" / app / "src-tauri"
        manifest = tomllib.loads((directory / "Cargo.toml").read_text())
        patches = manifest["patch"]["crates-io"]
        for name in ("glib", "glib-macros", "gtk3-macros"):
            if patches.get(name) != {"path": f"../../../vendor/rust/{name}"}:
                errors.append(f"{app}: {name} does not use the reviewed path")
        lock = tomllib.loads((directory / "Cargo.lock").read_text())
        for package in lock["package"]:
            name = package["name"]
            if name in REMOVED:
                errors.append(f"{app}: retired dependency returned: {name}")
            if name in ("glib", "glib-macros", "gtk3-macros"):
                if "source" in package or package["version"] != PACKAGES[f"vendor/rust/{name}"]:
                    errors.append(f"{app}: {name} is not the reviewed local source")
    harness = tomllib.loads((root / "vendor/tests/Cargo.toml").read_text())
    for name in ("glib", "glib-macros"):
        if harness["patch"]["crates-io"].get(name) != {"path": f"../rust/{name}"}:
            errors.append(f"regression harness: {name} does not use the reviewed path")
    frontend = root / "apps/installer-desktop"
    package = json.loads((frontend / "package.json").read_text())
    if package["pnpm"]["overrides"].get("deepmerge") != "file:../../vendor/js/deepmerge":
        errors.append("installer: deepmerge does not use the reviewed local source")
    lock_text = (frontend / "pnpm-lock.yaml").read_text()
    if "deepmerge: '@lightwork/deepmerge@file:../../vendor/js/deepmerge'" not in lock_text:
        errors.append("installer: deepmerge lock resolution differs")
    _validate_picomatch(root, package, lock_text, {entry["path"]: entry for entry in entries}, errors)
    return errors


def _validate_picomatch(
    root: Path, installer: dict, desktop_lock: str, inventory: dict, errors: list[str]
) -> None:
    desktop_path = "file:../../vendor/js/picomatch-v4"
    desktop_resolution = f"'@lightwork/picomatch-v4@{desktop_path}'"
    if installer["pnpm"]["overrides"].get("picomatch") != desktop_path:
        errors.append("installer: picomatch does not use the reviewed local source")
    if f"\n  picomatch: {desktop_path}\n" not in desktop_lock or (
        f"{desktop_resolution}:\n    resolution: {{directory: ../../vendor/js/picomatch-v4, type: directory}}"
        not in desktop_lock
    ):
        errors.append("installer: picomatch lock resolution differs")
    snapshot_assignments = re.findall(r"(?m)^      picomatch: (.+)$", desktop_lock.partition("\nsnapshots:\n")[2])
    if not snapshot_assignments or any(item != desktop_resolution for item in snapshot_assignments) or re.search(
        r"(?<![-\w/])picomatch@(?:[0-9]|npm:)|registry\.npmjs\.org/picomatch/", desktop_lock
    ):
        errors.append("installer: unreviewed picomatch registry resolution")

    mobile = root / "apps/mobile-companion"
    mobile_manifest = json.loads((mobile / "package.json").read_text())
    mobile_lock = json.loads((mobile / "package-lock.json").read_text())["packages"]
    expected = {
        "node_modules/picomatch": 3,
        "node_modules/anymatch/node_modules/picomatch": 2,
        "node_modules/jest-util/node_modules/picomatch": 2,
        "node_modules/micromatch/node_modules/picomatch": 2,
    }
    actual = {path: entry for path, entry in mobile_lock.items() if path.endswith("/node_modules/picomatch")
              or path == "node_modules/picomatch" or entry.get("name") == "picomatch"
              or "/picomatch/-/picomatch-" in entry.get("resolved", "")}
    if actual.keys() != expected.keys():
        errors.append("mobile: unreviewed picomatch registry resolution")
    overrides = mobile_manifest["overrides"]
    for major in (2, 3, 4):
        path = f"vendor/js/picomatch-v{major}"
        local = json.loads((root / path / "package.json").read_text())
        version = PACKAGES[path] + "+lightwork.1"
        name = f"@lightwork/picomatch-v{major}"
        if local["name"] != name or local["version"] != version:
            errors.append(f"{path}: reviewed package identity differs")
        if major == 4:
            continue
        archive_path = f"vendor/archives/lightwork-picomatch-v{major}-{version}.tgz"
        archive_bytes = (root / archive_path).read_bytes()
        recorded = inventory[path].get("mobile_archive")
        if recorded != {"path": archive_path, "sha256": hashlib.sha256(archive_bytes).hexdigest()}:
            errors.append(f"mobile: picomatch v{major} local archive differs from its provenance")
            continue
        packed_files: dict[str, str] = {}
        with tarfile.open(root / archive_path, "r:gz") as archive:
            for member in archive:
                reader = archive.extractfile(member) if member.isfile() else None
                relative = member.name.removeprefix("package/")
                if reader is None or relative == member.name or relative in packed_files:
                    errors.append(f"mobile: invalid picomatch v{major} archive member")
                    continue
                packed_files[relative] = hashlib.sha256(reader.read()).hexdigest()
        if packed_files != inventory[path]["files"]:
            errors.append(f"mobile: picomatch v{major} archive is not the exact reviewed source")
        local_spec = f"file:../../{archive_path}"
        same_integrity = "sha512-" + base64.b64encode(hashlib.sha512(archive_bytes).digest()).decode("ascii")
        for alias, alias_major in expected.items():
            if alias_major != major or alias not in actual:
                continue
            entry = actual[alias]
            if (entry.get("name"), entry.get("version"), entry.get("resolved"), entry.get("integrity")) != (
                name, version, local_spec, same_integrity
            ) or entry.get("link"):
                errors.append("mobile: unreviewed picomatch registry resolution")
        # npm resolves a transitive file override relative to its dependent,
        # not the root. An exact root v3 pin makes Expo's hoist deterministic.
        if major == 2 and any(overrides.get(owner, {}).get("picomatch") != "file:../../../../" + archive_path
                              for owner in ("anymatch", "jest-util", "micromatch")):
            errors.append("mobile: picomatch v2 does not use the reviewed local source")
        if major == 3 and (
            mobile_manifest["devDependencies"].get("picomatch") != local_spec
            or overrides.get("@expo/cli", {}).get("picomatch") != "$picomatch"
        ):
            errors.append("mobile: picomatch v3 does not use the reviewed local source")


def main() -> int:
    try:
        errors = validate()
    except (OSError, KeyError, ValueError, TypeError, tarfile.TarError) as exc:
        errors = [f"invalid vendor inventory or lockfile: {exc}"]
    if errors:
        for error in errors:
            print(f"vendor patches: FAILED: {error}")
        return 1
    print("vendor patches: verified source hashes, licenses and dependency resolution")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
