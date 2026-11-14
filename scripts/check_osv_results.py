"""Fail OSV findings except the source-verified GLib backport and dated risks.

OSV identifies path dependencies by their upstream registry name/version. Keep
its full report; distinguish a repaired local source from an affected registry
release only after checking the source inventory and the resolved Cargo lock.
An advisory with no compatible fixed release is recorded, not hidden, and only
for the reviewed lockfile, exact package version and advisory, until its date.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import date
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
EXPECTED_LOCKFILES = frozenset({
    "requirements/ci.txt", "requirements/docs.txt",
    "rust/Cargo.lock", "vendor/tests/Cargo.lock", "examples/clients/rust/Cargo.lock",
    "apps/desktop/src-tauri/Cargo.lock", "apps/installer-desktop/src-tauri/Cargo.lock",
    "apps/desktop-oauth-return/Cargo.lock", "apps/desktop-runtime/Cargo.lock",
    "apps/installer-msi/verify-update/Cargo.lock", "apps/zed-extension/Cargo.lock",
    "apps/jetbrains-plugin/gradle.lockfile", "examples/clients/typescript/package-lock.json",
    "apps/installer-desktop/pnpm-lock.yaml", "apps/mobile-companion/package-lock.json",
    "apps/mobile-companion/tests/package-lock.json",
    "packages/maverick-dashboard/tests/browser/package-lock.json",
    "packages/maverick-dashboard/tests/js/package-lock.json",
    "examples/clients/csharp/packages.lock.json", "examples/clients/go/go.mod",
    "go/model-proxy/go.mod", "examples/clients/java/pom.xml",
    "demo/dsar-concierge/requirements-standalone.txt", "demo/environment-threat-hunter/requirements.txt",
    "demo/grc-concierge/requirements.txt", "demo/model-risk-ai-assurance-officer/requirements.txt",
    "demo/platform-threat-hunter/requirements.txt",
})
_MOBILE_LOCK = "apps/mobile-companion/package-lock.json"
#: Reviewed advisories whose only fixed releases break the pinned toolchain.
#: Each covers one lockfile, one exact package version and the listed IDs until
#: review_by; a new advisory, another version or lockfile, or a lapsed date fails.
ACCEPTED_RISKS = (
    {
        "lockfile": _MOBILE_LOCK,
        "package": {"name": "tar", "version": "6.2.1", "ecosystem": "npm"},
        "advisories": frozenset({
            "GHSA-23hp-3jrh-7fpw", "GHSA-34x7-hfp2-rc4v", "GHSA-83g3-92jg-28cx", "GHSA-8qq5-rm4j-mr97",
            "GHSA-8x88-c5mf-7j5w", "GHSA-9ppj-qmqm-q256", "GHSA-gvwx-54wh-qm9j", "GHSA-qffp-2rhf-9h96",
            "GHSA-r292-9mhp-454m", "GHSA-r6q2-hw4h-h46w", "GHSA-vmf3-w455-68vh", "GHSA-w8wr-v893-vjvp",
        }),
        "accepted": "2026-11-05",
        "review_by": "2027-02-05",
        "reason": "Only tar 7 is fixed, and Expo CLI 0.22 (Expo SDK 52) reads tar's default export, "
                  "which tar 7 removed: with tar 7 `expo prebuild` cannot unpack its template. Expo CLI "
                  "extracts only Expo-published template and app archives fetched over TLS from npm or "
                  "Expo, and the documented build path (build-native.cjs) first checks the template "
                  "against the sha512 pinned in native-template.json. Running `expo prebuild` or "
                  "`expo run:*` directly fetches the default template without that pin. Remove this "
                  "entry when the companion moves to Expo SDK 53 or later (tar 7).",
    },
    {
        "lockfile": _MOBILE_LOCK,
        "package": {"name": "image-size", "version": "1.2.1", "ecosystem": "npm"},
        "advisories": frozenset({"GHSA-5p2g-fcmc-qvqq", "GHSA-w3rx-r6r6-pgpr"}),
        "accepted": "2026-11-05",
        "review_by": "2027-02-05",
        "reason": "Only image-size 2 is fixed, and Metro 0.81 (React Native 0.76) calls the package as a "
                  "function, which image-size 2 no longer exports, so image assets would stop bundling. "
                  "Metro measures the app's images and those shipped in its locked npm packages; the "
                  "infinite loop needs a crafted JXL, HEIF or ICNS file among them. Remove this entry with the "
                  "React Native and Expo SDK upgrade.",
    },
)


def _accepted_risk(path: Path, package: dict, identifier: str, root: Path, today: date) -> dict | None:
    for risk in ACCEPTED_RISKS:
        if (path.resolve() == (root / risk["lockfile"]).resolve() and package == risk["package"]
                and identifier in risk["advisories"] and today <= date.fromisoformat(risk["review_by"])):
            return risk
    return None


def _coverage_errors(
    results: list[dict], root: Path, python_lock: Path | None, docs_lock: Path | None,
) -> list[str]:
    expected = {name: (root / name).resolve() for name in EXPECTED_LOCKFILES}
    # CI copies these two reviewed files to names understood by OSV. Bind to
    # those exact scan inputs, never to a matching basename in the report.
    if python_lock is not None:
        expected["requirements/ci.txt"] = python_lock.resolve()
    if docs_lock is not None:
        expected["requirements/docs.txt"] = docs_lock.resolve()
    observed = {
        (root / result["source"]["path"]).resolve()
        for result in results if result["source"]["type"] == "lockfile"
    }
    return [f"OSV report missing lockfile coverage: {name}"
            for name, path in sorted(expected.items()) if path not in observed]


def evaluate(
    report: dict, scanner_exit: int, root: Path = ROOT, today: date | None = None,
    *, python_lock: Path | None = None, docs_lock: Path | None = None,
) -> tuple[list[str], list[dict], list[dict]]:
    errors = validate(root)
    sources_verified = not errors
    today = today or date.today()
    repaired: list[dict] = []
    accepted: list[dict] = []
    if scanner_exit not in (0, 1):
        errors.append(f"OSV scanner did not complete successfully: exit {scanner_exit}")
    results = report.get("results")
    if not isinstance(results, list):
        return [*errors, "OSV report has no valid results array"], repaired, accepted
    errors.extend(_coverage_errors(results, root, python_lock, docs_lock))
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
                    sources_verified and source["type"] == "lockfile" and local_lock is not None
                    and package == {"name": "glib", "version": "0.18.5", "ecosystem": "crates.io"}
                    and identifier in GLIB_FIXED_IDS
                )
                if eligible:
                    lock = tomllib.loads(path.read_text())
                    resolved = [p for p in lock["package"] if p["name"] == "glib"]
                    eligible = len(resolved) == 1 and resolved[0]["version"] == "0.18.5" and "source" not in resolved[0]
                risk = None if eligible else _accepted_risk(path, package, identifier, root, today)
                if eligible:
                    repaired.append({"lockfile": local_lock, "advisory": identifier,
                                     "resolution": "verified local backport of gtk-rs/gtk-rs-core#1343"})
                elif risk is not None:
                    accepted.append({"lockfile": risk["lockfile"], "package": f"{package['name']} {package['version']}",
                                     "advisory": identifier, "accepted": risk["accepted"],
                                     "review_by": risk["review_by"], "reason": risk["reason"]})
                else:
                    errors.append(f"unresolved: {source['path']}: {package['name']} {package['version']}: {identifier}")
    if scanner_exit == 1 and findings == 0:
        errors.append("OSV exited with failure but supplied no vulnerability findings")
    return errors, repaired, accepted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--scanner-exit", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python-lockfile", type=Path)
    parser.add_argument("--docs-lockfile", type=Path)
    args = parser.parse_args()
    try:
        errors, repaired, accepted = evaluate(
            json.loads(args.report.read_text()), args.scanner_exit,
            python_lock=args.python_lockfile, docs_lock=args.docs_lockfile,
        )
        inventory_hash = hashlib.sha256((ROOT / "vendor/provenance.json").read_bytes()).hexdigest()
        args.output.write_text(json.dumps({"inventory_sha256": inventory_hash,
                                          "source_verified_backports": repaired,
                                          "accepted_risks": accepted,
                                          "unresolved": errors}, indent=2) + "\n")
    except (OSError, KeyError, ValueError, TypeError, AttributeError) as exc:
        print(f"dependency audit: invalid evidence: {exc}")
        return 1
    for error in errors:
        print(f"dependency audit: {error}")
    print(f"dependency audit: {len(repaired)} source-verified backport findings; "
          f"{len(accepted)} accepted-risk findings; {len(errors)} unresolved errors")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
