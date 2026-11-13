"""Governed release updates — verify + plan upgrades, offline-capable.

A **release manifest** is an Ed25519-signed JSON document (signed and verified
by :mod:`maverick.release_manifest_signing`) describing one release: its
version, its artifacts (name + sha256 + size), the **minimum version it can
upgrade from**, and the ordered list of **governed migrations** it introduces.
Because it verifies **offline**, an air-gapped bank can receive an update
bundle out-of-band (physical media / one-way transfer), verify the signature
**and** every artifact hash, and apply it under change control — no network,
no "trust the vendor," and every step reproducible.

This module owns the *decision* layer — verify a manifest, verify a bundle's
contents against it, and compute a safe upgrade **plan**. Swapping the running
binary/container is deployment-specific (systemd, container tag, Tauri
auto-update) and is intentionally out of scope here; those callers ask this
module "is this update authentic, intact, and safe to apply from where I am?".
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .release_manifest_signing import (
    sign_manifest,
    trusted_publisher_keys,
    verify_manifest_signature,
)


def _within(base: Path, candidate: Path) -> bool:
    """True iff ``candidate`` resolves to a path inside ``base`` (zip-slip guard)."""
    try:
        candidate.resolve().relative_to(base)
        return True
    except ValueError:
        return False


def _ver(s: str | None) -> tuple[int, int, int]:
    """Parse ``v0.1.6`` / ``0.1.6`` / ``0.1.6-rc1`` → ``(0, 1, 6)``."""
    core = str(s or "0").lstrip("vV").split("-")[0].split("+")[0]
    parts = [int(x) for x in core.split(".") if x.isdigit()]
    parts += [0, 0, 0]
    return tuple(parts[:3])  # type: ignore[return-value]


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(version: str, artifacts: list[dict], *, min_from: str,
                   migrations: list[str] | None, private_key_hex: str,
                   notes: str = "") -> dict:
    """Sign a release manifest. ``artifacts`` are ``{name, sha256, size}`` dicts."""
    payload = {
        "kind": "lightwork.release",
        "version": str(version),
        "min_from": str(min_from),
        "artifacts": artifacts,
        "migrations": list(migrations or []),
        "notes": notes,
    }
    return sign_manifest(payload, private_key_hex)


def verify_manifest(doc: dict, trusted_pubkeys: list[str] | None = None) -> tuple[bool, str]:
    """Authenticate a manifest against the shipped publisher key set."""
    return verify_manifest_signature(doc, trusted_publisher_keys(trusted_pubkeys))


@dataclass
class BundleCheck:
    ok: bool
    reason: str
    version: str = ""
    issues: list[str] = field(default_factory=list)
    #: The parsed, signature-verified manifest on the success path — so callers
    #: (apply_bundle) don't re-read/re-parse manifest.json and can't act on a
    #: different file than the one just verified.
    manifest: dict = field(default_factory=dict)


def verify_bundle(bundle_dir: str | Path, *,
                  trusted_pubkeys: list[str] | None = None) -> BundleCheck:
    """Verify an offline update bundle: the manifest signature **and** every
    artifact's sha256. Both must hold — a tampered binary is caught even if the
    manifest is authentic (the hash won't match) and vice-versa."""
    d = Path(bundle_dir)
    mpath = d / "manifest.json"
    if not mpath.exists():
        return BundleCheck(False, "no manifest.json in bundle")
    try:
        doc = json.loads(mpath.read_text("utf-8"))
    except Exception as e:  # noqa: BLE001
        return BundleCheck(False, f"unreadable manifest: {e}")
    if not isinstance(doc, dict):
        return BundleCheck(False, "unreadable manifest: not a JSON object")
    ok, why = verify_manifest(doc, trusted_pubkeys)
    if not ok:
        return BundleCheck(False, f"manifest signature: {why}", doc.get("version", ""))
    base = d.resolve()
    issues: list[str] = []
    for art in doc.get("artifacts", []):
        name = art.get("name", "?")
        # Defense-in-depth (the manifest is signed, but a misused signing key or
        # a malicious insider shouldn't be able to point an artifact outside the
        # bundle): reject absolute names and ``..`` escapes before touching the
        # path, so we never hash/"bless" a file elsewhere on the host and never
        # hand an escaping path to the caller's install hook.
        fp = d / name
        if os.path.isabs(name) or not _within(base, fp):
            issues.append(f"artifact escapes bundle dir: {name}")
            continue
        if not fp.exists():
            issues.append(f"missing artifact: {name}")
            continue
        actual = sha256_file(fp)
        if actual != art.get("sha256"):
            issues.append(f"hash mismatch: {name} ({actual[:12]}… != "
                          f"{str(art.get('sha256'))[:12]}…)")
    if issues:
        return BundleCheck(False, "artifact verification failed",
                           doc.get("version", ""), issues)
    return BundleCheck(True, "ok", doc.get("version", ""), manifest=doc)


def _stage_verified_bundle(source: Path, manifest: dict) -> tempfile.TemporaryDirectory[str]:
    """Copy verified bundle bytes into a private temp dir and verify them again.

    ``apply_bundle`` performs deployment work after verification, so the original
    staging directory may be mutable during migrations. Installing from this
    private copy pins the artifact bytes that survived a post-copy hash check.
    """
    tmp = tempfile.TemporaryDirectory(prefix="maverick-bundle-")
    staged = Path(tmp.name)
    try:
        (staged / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        for art in manifest.get("artifacts", []):
            name = art.get("name", "")
            src = source / name
            dst = staged / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            actual = sha256_file(dst)
            if actual != art.get("sha256"):
                raise ValueError(
                    f"staged artifact hash mismatch: {name} "
                    f"({actual[:12]}… != {str(art.get('sha256'))[:12]}…)"
                )
        return tmp
    except Exception:
        tmp.cleanup()
        raise


@dataclass
class UpgradePlan:
    ok: bool
    reason: str
    from_version: str
    to_version: str
    migrations: list[str] = field(default_factory=list)
    downgrade: bool = False


def plan_upgrade(current_version: str, manifest: dict) -> UpgradePlan:
    """Decide whether it's safe to apply ``manifest`` from ``current_version``.

    Blocks a **downgrade**, a **no-op** (same version), and a **version gap**
    (current below the manifest's ``min_from`` — the site must step through an
    intermediate release so migrations apply in order). On success, returns the
    ordered governed migrations the caller must run."""
    cur, to = _ver(current_version), _ver(manifest.get("version"))
    mn = _ver(manifest.get("min_from"))
    migs = list(manifest.get("migrations", []))
    if to == cur:
        return UpgradePlan(False, "already on this version", current_version,
                           manifest.get("version", ""), [])
    if to < cur:
        return UpgradePlan(False, "manifest is older than the running version",
                           current_version, manifest.get("version", ""),
                           downgrade=True)
    if cur < mn:
        return UpgradePlan(
            False,
            f"version gap: running {current_version} is below min_from "
            f"{manifest.get('min_from')} — upgrade to an intermediate release first",
            current_version, manifest.get("version", ""), migs)
    return UpgradePlan(True, "ok", current_version, manifest.get("version", ""), migs)


@dataclass
class ApplyResult:
    ok: bool
    reason: str
    from_version: str
    to_version: str
    applied_migrations: list[str] = field(default_factory=list)
    dry_run: bool = False
    #: Opaque handle from the ``snapshot()`` hook, captured before the risky
    #: steps — the thing ``rollback`` restores.
    snapshot: str = ""
    #: True if a failed apply auto-triggered the injected ``rollback`` hook.
    rolled_back: bool = False


def apply_bundle(bundle_dir: str | Path, current_version: str, *,
                 trusted_pubkeys: list[str] | None = None,
                 migrate=None, install=None, snapshot=None, rollback=None,
                 dry_run: bool = False) -> ApplyResult:
    """Apply an offline update bundle: **verify → plan → [snapshot] → migrate →
    install**, with an optional **auto-rollback** on failure.

    Deployment-agnostic by injection — the caller passes ``migrate(id)`` (run one
    governed migration) and ``install(bundle_dir, manifest)`` (swap the binary /
    container tag); this owns the *order and the gates* so the risky steps only
    run after the signature, hashes, and version-gap checks pass. For non-dry
    applies, ``bundle_dir`` is a private staged copy whose artifact hashes were
    rechecked before migrations run. ``dry_run`` stops after planning.

    ``snapshot()`` (optional) captures a checkpoint **before** the risky steps
    and returns an opaque handle; ``rollback(bundle_dir, manifest, handle)``
    (optional) restores it. When both are supplied, a failing migration or
    install **auto-rolls-back** to the snapshot and sets ``rolled_back``. Both
    default to ``None`` → behaviour is byte-identical to a no-hook apply (no
    checkpoint, no undo), so existing callers are unaffected."""
    d = Path(bundle_dir)
    vc = verify_bundle(d, trusted_pubkeys=trusted_pubkeys)
    if not vc.ok:
        return ApplyResult(False, f"verify: {vc.reason}", current_version, vc.version)
    # Reuse the manifest verify_bundle already parsed — no second read/parse, and
    # no chance to act on a different manifest file than the one just verified.
    manifest = vc.manifest
    plan = plan_upgrade(current_version, manifest)
    if not plan.ok:
        return ApplyResult(False, f"plan: {plan.reason}", current_version, plan.to_version)
    if dry_run:
        return ApplyResult(True, "dry-run ok", plan.from_version, plan.to_version,
                           list(plan.migrations), dry_run=True)
    try:
        staged_tmp = _stage_verified_bundle(d, manifest)
    except Exception as e:  # noqa: BLE001 - no deployment changes have run yet
        return ApplyResult(False, f"stage failed: {e}", plan.from_version, plan.to_version)
    staged = Path(staged_tmp.name)
    try:
        handle = ""
        if snapshot is not None:
            try:
                handle = str(snapshot() or "")
            except Exception as e:  # noqa: BLE001 - snapshot fails BEFORE any change; safe to abort
                return ApplyResult(False, f"snapshot failed: {e}",
                                   plan.from_version, plan.to_version)

        def _undo(reason: str, applied: list[str]) -> ApplyResult:
            """Fail an apply, auto-rolling-back to the snapshot when a hook + handle
            exist. If the rollback itself fails, say so loudly (that's the
            break-glass case an operator must see)."""
            if rollback is not None and handle:
                try:
                    rollback(staged, manifest, handle)
                except Exception as e:  # noqa: BLE001
                    return ApplyResult(False, f"{reason}; rollback ALSO failed: {e}",
                                       plan.from_version, plan.to_version, applied,
                                       snapshot=handle, rolled_back=False)
                return ApplyResult(False, reason, plan.from_version, plan.to_version,
                                   applied, snapshot=handle, rolled_back=True)
            return ApplyResult(False, reason, plan.from_version, plan.to_version,
                               applied, snapshot=handle)

        applied: list[str] = []
        for mig in plan.migrations:
            try:
                if migrate is not None:
                    migrate(mig)
                applied.append(mig)
            except Exception as e:  # noqa: BLE001 - stop at the first failing migration
                return _undo(f"migration {mig} failed: {e}", applied)
        if install is not None:
            try:
                install(staged, manifest)
            except Exception as e:  # noqa: BLE001
                return _undo(f"install failed after migrations: {e}", applied)
        return ApplyResult(True, "applied", plan.from_version, plan.to_version,
                           applied, snapshot=handle)
    finally:
        staged_tmp.cleanup()


def rollback_bundle(bundle_dir: str | Path, handle: str, *, rollback,
                    trusted_pubkeys: list[str] | None = None) -> ApplyResult:
    """Manually roll a deployment back to snapshot ``handle`` via the injected
    ``rollback(bundle_dir, manifest, handle)`` hook — the operator-driven
    counterpart to :func:`apply_bundle`'s auto-rollback (for when a bad release
    is only caught after it applied cleanly). The bundle is verified for manifest
    *context* (version), but a verify failure does **not** block the restore — you
    must be able to roll back even away from a since-suspect bundle."""
    d = Path(bundle_dir)
    vc = verify_bundle(d, trusted_pubkeys=trusted_pubkeys)
    manifest = vc.manifest if vc.ok else {}
    to = manifest.get("version", "")
    try:
        rollback(d, manifest, handle)
    except Exception as e:  # noqa: BLE001 - report; the caller decides break-glass next steps
        return ApplyResult(False, f"rollback failed: {e}", "", to, snapshot=str(handle))
    return ApplyResult(True, "rolled back", "", to, snapshot=str(handle),
                       rolled_back=True)


# ---- CLI: python -m maverick.release_update {verify-bundle,plan,apply,rollback} --

def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse

    p = argparse.ArgumentParser(prog="maverick.release_update",
                                description="Verify + plan Lightwork updates offline.")
    sub = p.add_subparsers(dest="cmd", required=True)

    vb = sub.add_parser("verify-bundle", help="verify an offline update bundle dir")
    vb.add_argument("dir")
    vb.add_argument("--pubkey", default=None, help="comma-separated trusted pubkey hex")

    pl = sub.add_parser("plan", help="plan an upgrade from the running version")
    pl.add_argument("--current", required=True, help="running version, e.g. v0.1.6")
    pl.add_argument("--manifest", required=True, help="path to a manifest.json")

    ap = sub.add_parser("apply", help="verify + plan + apply an offline bundle")
    ap.add_argument("dir")
    ap.add_argument("--current", required=True, help="running version, e.g. v0.1.6")
    ap.add_argument("--pubkey", default=None, help="comma-separated trusted pubkey hex")
    ap.add_argument("--dry-run", action="store_true",
                    help="verify + plan only; do not run migrations or install")

    rb = sub.add_parser("rollback",
                        help="restore a workspace snapshot taken before an apply")
    rb.add_argument("dir", help="the bundle dir (for manifest/version context)")
    rb.add_argument("--snapshot", required=True, help="snapshot id to restore")
    rb.add_argument("--store", required=True, help="snapshot store dir")
    rb.add_argument("--dest", required=True, help="workspace dir to restore into")
    rb.add_argument("--pubkey", default=None, help="comma-separated trusted pubkey hex")

    args = p.parse_args(argv)

    if args.cmd == "verify-bundle":
        trust = [k.strip() for k in args.pubkey.split(",")] if args.pubkey else None
        res = verify_bundle(args.dir, trusted_pubkeys=trust)
        print(f"{'OK' if res.ok else 'FAIL'}: {res.reason}  (version {res.version or '?'})")
        for issue in res.issues:
            print("  -", issue)
        return 0 if res.ok else 1

    if args.cmd == "apply":
        trust = [k.strip() for k in args.pubkey.split(",")] if args.pubkey else None
        # The CLI carries no deployment-specific migrate/install hooks — those
        # live in the caller (systemd unit, container orchestrator, Tauri
        # updater). It prints each step so an operator sees the governed order;
        # a real swap wires the callbacks in code. Without --dry-run it still
        # gates on signature + hashes + version before printing "would apply".
        def _migrate(mig: str) -> None:
            print(f"  migration: {mig}")

        def _install(bundle_dir, manifest) -> None:
            print(f"  install: {manifest.get('version')} "
                  f"({len(manifest.get('artifacts', []))} artifact(s)) — "
                  "wire a deployment install hook to perform the swap")

        res = apply_bundle(args.dir, args.current, trusted_pubkeys=trust,
                           migrate=_migrate, install=_install, dry_run=args.dry_run)
        head = "DRY-RUN" if res.dry_run else ("APPLIED" if res.ok else "FAILED")
        print(f"{head}: {res.reason}")
        if res.ok:
            print(f"  {res.from_version} → {res.to_version}")
            print(f"  migrations: {', '.join(res.applied_migrations) or 'none'}")
        return 0 if res.ok else 1

    if args.cmd == "rollback":
        trust = [k.strip() for k in args.pubkey.split(",")] if args.pubkey else None
        from .workspace_snapshot import restore_snapshot

        def _rollback(bundle_dir, manifest, snap_id) -> None:
            restore_snapshot(Path(args.store), snap_id, Path(args.dest))

        res = rollback_bundle(args.dir, args.snapshot, rollback=_rollback,
                              trusted_pubkeys=trust)
        print(f"{'ROLLED BACK' if res.ok else 'FAILED'}: {res.reason}")
        return 0 if res.ok else 1

    manifest = json.loads(Path(args.manifest).read_text("utf-8"))
    plan = plan_upgrade(args.current, manifest)
    print(f"{'OK' if plan.ok else 'BLOCKED'}: {plan.reason}")
    if plan.ok:
        print(f"  {plan.from_version} → {plan.to_version}")
        print(f"  migrations: {', '.join(plan.migrations) or 'none'}")
    return 0 if plan.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
