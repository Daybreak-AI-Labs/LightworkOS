#!/usr/bin/env python3
"""Verify reviewed local dependency sources and their application overrides."""
from __future__ import annotations

import hashlib
import json
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
    return errors


def main() -> int:
    try:
        errors = validate()
    except (OSError, KeyError, ValueError, TypeError) as exc:
        errors = [f"invalid vendor inventory or lockfile: {exc}"]
    if errors:
        for error in errors:
            print(f"vendor patches: FAILED: {error}")
        return 1
    print("vendor patches: verified source hashes, licenses and dependency resolution")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
