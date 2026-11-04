"""Fail OSV findings except the exact, source-verified GLib backport.

OSV identifies path dependencies by their upstream registry name/version. Keep
its full report; distinguish a repaired local source from an affected registry
release only after checking the source inventory and the resolved Cargo lock.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from scripts.check_vendor_patches import ROOT, validate

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

GLIB_FIXED_IDS = {"RUSTSEC-2024-0429", "GHSA-wrw7-89jp-8q8g"}
LOCAL_LOCKS = {
    "apps/desktop/src-tauri/Cargo.lock",
    "apps/installer-desktop/src-tauri/Cargo.lock",
    "vendor/tests/Cargo.lock",
}


def evaluate(report: dict, scanner_exit: int, root: Path = ROOT) -> tuple[list[str], list[dict]]:
    errors = validate(root)
    repaired: list[dict] = []
    if scanner_exit not in (0, 1):
        errors.append(f"OSV scanner did not complete successfully: exit {scanner_exit}")
    results = report.get("results")
    if not isinstance(results, list):
        return [*errors, "OSV report has no valid results array"], repaired
    findings = 0
    for result in results:
        source = result["source"]
        path = Path(source["path"])
        if not path.is_absolute():
            path = root / path
        local_lock = next((name for name in LOCAL_LOCKS if path.resolve() == (root / name).resolve()), None)
        for entry in result["packages"]:
            package = entry["package"]
            for advisory in entry.get("vulnerabilities", []):
                findings += 1
                identifier = advisory["id"]
                eligible = (
                    not errors and source["type"] == "lockfile" and local_lock is not None
                    and package == {"name": "glib", "version": "0.18.5", "ecosystem": "crates.io"}
                    and identifier in GLIB_FIXED_IDS
                )
                if eligible:
                    lock = tomllib.loads(path.read_text())
                    resolved = [p for p in lock["package"] if p["name"] == "glib"]
                    eligible = len(resolved) == 1 and resolved[0]["version"] == "0.18.5" and "source" not in resolved[0]
                if eligible:
                    repaired.append({"lockfile": local_lock, "advisory": identifier,
                                     "resolution": "verified local backport of gtk-rs/gtk-rs-core#1343"})
                else:
                    errors.append(f"unresolved: {source['path']}: {package['name']} {package['version']}: {identifier}")
    if scanner_exit == 1 and findings == 0:
        errors.append("OSV exited with failure but supplied no vulnerability findings")
    return errors, repaired


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--scanner-exit", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        errors, repaired = evaluate(json.loads(args.report.read_text()), args.scanner_exit)
        inventory_hash = hashlib.sha256((ROOT / "vendor/provenance.json").read_bytes()).hexdigest()
        args.output.write_text(json.dumps({"inventory_sha256": inventory_hash,
                                          "source_verified_backports": repaired,
                                          "unresolved": errors}, indent=2) + "\n")
    except (OSError, KeyError, ValueError, TypeError, AttributeError) as exc:
        print(f"dependency audit: invalid evidence: {exc}")
        return 1
    for error in errors:
        print(f"dependency audit: {error}")
    print(f"dependency audit: {len(repaired)} source-verified backport findings; {len(errors)} unresolved errors")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
