"""Governed release updates: offline manifest + bundle verification and safe
upgrade planning. See maverick/release_update.py."""
from __future__ import annotations

import json

import pytest
from maverick import release_manifest_signing as S
from maverick import release_update as R

pytest.importorskip("cryptography")


@pytest.fixture
def keys():
    priv, pub = S.new_publisher_keypair()
    return priv, [pub]


def _artifact(tmp_path, name, data=b"binary-bytes"):
    (tmp_path / name).write_bytes(data)
    return {"name": name, "sha256": R.sha256_file(tmp_path / name), "size": len(data)}


def test_manifest_sign_verify_and_tamper(keys):
    priv, trust = keys
    doc = R.build_manifest("v0.1.7", [], min_from="v0.1.5", migrations=["m1"],
                           private_key_hex=priv)
    ok, why = R.verify_manifest(doc, trust)
    assert ok and why == "ok"
    doc["version"] = "v9.9.9"  # tamper
    ok, why = R.verify_manifest(doc, trust)
    assert not ok and why == "bad_signature"


def test_verify_manifest_defaults_to_the_configured_release_keys(keys, monkeypatch):
    priv, trust = keys
    doc = R.build_manifest("v0.1.7", [], min_from="v0.1.5", migrations=[],
                           private_key_hex=priv)
    monkeypatch.setattr(S, "_release_cfg", dict)
    monkeypatch.delenv("MAVERICK_RELEASE_PUBKEYS", raising=False)
    assert R.verify_manifest(doc) == (False, "no_trust_anchor")
    monkeypatch.setenv("MAVERICK_RELEASE_PUBKEYS", trust[0])
    assert R.verify_manifest(doc) == (True, "ok")


def test_bundle_verifies_signature_and_hashes(tmp_path, keys):
    priv, trust = keys
    art = _artifact(tmp_path, "maverick-macos-arm64")
    doc = R.build_manifest("v0.1.7", [art], min_from="v0.1.5", migrations=[],
                           private_key_hex=priv)
    (tmp_path / "manifest.json").write_text(json.dumps(doc))
    res = R.verify_bundle(tmp_path, trusted_pubkeys=trust)
    assert res.ok and res.version == "v0.1.7"
    assert res.manifest.get("version") == "v0.1.7"   # parsed manifest returned for reuse


def test_bundle_catches_tampered_artifact(tmp_path, keys):
    priv, trust = keys
    art = _artifact(tmp_path, "maverick-macos-arm64")
    doc = R.build_manifest("v0.1.7", [art], min_from="v0.1.5", migrations=[],
                           private_key_hex=priv)
    (tmp_path / "manifest.json").write_text(json.dumps(doc))
    (tmp_path / "maverick-macos-arm64").write_bytes(b"swapped-malicious")  # tamper file
    res = R.verify_bundle(tmp_path, trusted_pubkeys=trust)
    assert not res.ok and any("hash mismatch" in i for i in res.issues)


def test_bundle_rejects_path_traversal_artifact(tmp_path, keys):
    priv, trust = keys
    # A signed manifest whose artifact name escapes the bundle dir must be
    # rejected before we hash/"bless" a file elsewhere on the host (zip-slip).
    art = {"name": "../evil", "sha256": "0" * 64, "size": 1}
    doc = R.build_manifest("v0.1.7", [art], min_from="v0.1.5", migrations=[],
                           private_key_hex=priv)
    (tmp_path / "manifest.json").write_text(json.dumps(doc))
    res = R.verify_bundle(tmp_path, trusted_pubkeys=trust)
    assert not res.ok and any("escapes bundle dir" in i for i in res.issues)


def test_bundle_catches_missing_artifact(tmp_path, keys):
    priv, trust = keys
    art = {"name": "ghost", "sha256": "0" * 64, "size": 1}
    doc = R.build_manifest("v0.1.7", [art], min_from="v0.1.5", migrations=[],
                           private_key_hex=priv)
    (tmp_path / "manifest.json").write_text(json.dumps(doc))
    res = R.verify_bundle(tmp_path, trusted_pubkeys=trust)
    assert not res.ok and any("missing artifact" in i for i in res.issues)


def test_plan_upgrade_paths():
    m = {"version": "v0.1.7", "min_from": "v0.1.5", "migrations": ["m6", "m7"]}
    ok = R.plan_upgrade("v0.1.6", m)
    assert ok.ok and ok.migrations == ["m6", "m7"] and ok.to_version == "v0.1.7"

    assert not R.plan_upgrade("v0.1.7", m).ok            # no-op
    down = R.plan_upgrade("v0.2.0", m)
    assert not down.ok and down.downgrade                # downgrade blocked
    gap = R.plan_upgrade("v0.1.3", m)
    assert not gap.ok and "version gap" in gap.reason    # below min_from


def _bundle(tmp_path, priv, *, version="v0.1.7", min_from="v0.1.5", migrations=None):
    art = _artifact(tmp_path, "maverick-macos-arm64")
    doc = R.build_manifest(version, [art], min_from=min_from,
                           migrations=migrations or [], private_key_hex=priv)
    (tmp_path / "manifest.json").write_text(json.dumps(doc))
    return tmp_path


def test_apply_runs_migrations_then_install_in_order(tmp_path, keys):
    priv, trust = keys
    d = _bundle(tmp_path, priv, migrations=["m6", "m7"])
    ran: list[str] = []
    res = R.apply_bundle(d, "v0.1.6", trusted_pubkeys=trust,
                         migrate=ran.append,
                         install=lambda _d, _m: ran.append("install"))
    assert res.ok and res.applied_migrations == ["m6", "m7"]
    assert ran == ["m6", "m7", "install"]                # migrations before install


def test_apply_installs_from_private_staged_copy_after_migration_swap(tmp_path, keys):
    priv, trust = keys
    d = _bundle(tmp_path, priv, migrations=["m6"])
    original_hash = R.sha256_file(tmp_path / "maverick-macos-arm64")
    installed: dict[str, str] = {}

    def _migrate(_mig):
        (tmp_path / "maverick-macos-arm64").write_bytes(b"swapped-malicious")

    def _install(bundle_dir, manifest):
        artifact = bundle_dir / manifest["artifacts"][0]["name"]
        installed["bundle_dir"] = str(bundle_dir)
        installed["sha256"] = R.sha256_file(artifact)

    res = R.apply_bundle(d, "v0.1.6", trusted_pubkeys=trust,
                         migrate=_migrate, install=_install)

    assert res.ok
    assert installed["sha256"] == original_hash
    assert installed["bundle_dir"] != str(d)
    assert R.sha256_file(tmp_path / "maverick-macos-arm64") != original_hash


def test_apply_dry_run_skips_migrations_and_install(tmp_path, keys):
    priv, trust = keys
    d = _bundle(tmp_path, priv, migrations=["m6"])
    touched: list[str] = []
    res = R.apply_bundle(d, "v0.1.6", trusted_pubkeys=trust,
                         migrate=touched.append,
                         install=lambda _d, _m: touched.append("install"),
                         dry_run=True)
    assert res.ok and res.dry_run and res.applied_migrations == ["m6"]
    assert touched == []                                 # nothing actually run


def test_apply_stops_at_first_failing_migration(tmp_path, keys):
    priv, trust = keys
    d = _bundle(tmp_path, priv, migrations=["m6", "boom", "m8"])
    installed: list[str] = []

    def _migrate(mig):
        if mig == "boom":
            raise RuntimeError("migration exploded")

    res = R.apply_bundle(d, "v0.1.6", trusted_pubkeys=trust, migrate=_migrate,
                         install=lambda _d, _m: installed.append("install"))
    assert not res.ok and "boom" in res.reason
    assert res.applied_migrations == ["m6"]              # stopped before m8
    assert installed == []                               # never installed on failure


def test_apply_refuses_a_tampered_bundle(tmp_path, keys):
    priv, trust = keys
    d = _bundle(tmp_path, priv, migrations=["m6"])
    (tmp_path / "maverick-macos-arm64").write_bytes(b"swapped")   # tamper post-manifest
    res = R.apply_bundle(d, "v0.1.6", trusted_pubkeys=trust,
                         migrate=lambda _m: None, install=lambda _d, _m: None)
    assert not res.ok and res.reason.startswith("verify:")


def test_apply_refuses_a_blocked_plan(tmp_path, keys):
    priv, trust = keys
    d = _bundle(tmp_path, priv, migrations=["m6"])
    res = R.apply_bundle(d, "v0.2.0", trusted_pubkeys=trust,   # downgrade
                         migrate=lambda _m: None, install=lambda _d, _m: None)
    assert not res.ok and res.reason.startswith("plan:")


def test_apply_auto_rolls_back_on_failed_install(tmp_path, keys):
    priv, trust = keys
    d = _bundle(tmp_path, priv, migrations=["m6"])
    events: list[str] = []

    def _install(_d, _m):
        raise RuntimeError("install boom")

    res = R.apply_bundle(d, "v0.1.6", trusted_pubkeys=trust,
                         migrate=events.append, install=_install,
                         snapshot=lambda: "snap-1",
                         rollback=lambda _d, _m, h: events.append(f"rollback:{h}"))
    assert not res.ok and "install boom" in res.reason
    assert res.rolled_back is True and res.snapshot == "snap-1"
    assert events == ["m6", "rollback:snap-1"]           # migration ran, then rolled back


def test_apply_reports_when_rollback_itself_fails(tmp_path, keys):
    priv, trust = keys
    d = _bundle(tmp_path, priv, migrations=[])

    def _install(_d, _m):
        raise RuntimeError("install boom")

    def _rollback(_d, _m, _h):
        raise RuntimeError("restore boom")

    res = R.apply_bundle(d, "v0.1.6", trusted_pubkeys=trust, install=_install,
                         snapshot=lambda: "snap-1", rollback=_rollback)
    assert not res.ok and "rollback ALSO failed" in res.reason
    assert res.rolled_back is False                       # break-glass: undo did not complete


def test_apply_snapshot_failure_aborts_before_any_change(tmp_path, keys):
    priv, trust = keys
    d = _bundle(tmp_path, priv, migrations=["m6"])
    touched: list[str] = []

    def _snapshot():
        raise RuntimeError("snap boom")

    res = R.apply_bundle(d, "v0.1.6", trusted_pubkeys=trust,
                         migrate=touched.append,
                         install=lambda _d, _m: touched.append("install"),
                         snapshot=_snapshot, rollback=lambda *_a: None)
    assert not res.ok and "snapshot failed" in res.reason
    assert touched == []                                  # nothing ran


def test_apply_without_hooks_is_byte_identical(tmp_path, keys):
    priv, trust = keys
    d = _bundle(tmp_path, priv, migrations=["m6"])
    res = R.apply_bundle(d, "v0.1.6", trusted_pubkeys=trust,
                         migrate=lambda _m: None, install=lambda _d, _m: None)
    assert res.ok and res.snapshot == "" and res.rolled_back is False


def test_rollback_bundle_manual(tmp_path, keys):
    priv, trust = keys
    d = _bundle(tmp_path, priv, migrations=[])
    called: dict = {}

    def _rollback(_bundle_dir, manifest, h):
        called["v"], called["h"] = manifest.get("version"), h

    res = R.rollback_bundle(d, "snap-9", rollback=_rollback, trusted_pubkeys=trust)
    assert res.ok and res.rolled_back and res.snapshot == "snap-9"
    assert called == {"v": "v0.1.7", "h": "snap-9"}       # manifest context passed through
