"""Plugin version-pinning lockfile: write/read/verify, the discovery gate
under off/warn/enforce, and the CLI verbs."""
from __future__ import annotations

import types

from click.testing import CliRunner
from maverick import plugin_lock as pl
from maverick import plugins as plugins_mod


class _EP:
    def __init__(self, name, dist_name, version):
        self.name = name
        self.value = f"{name}_mod:factory"
        self.dist = types.SimpleNamespace(name=dist_name, version=version)


def _fake_eps(monkeypatch, dists):
    """dists: [(ep_name, dist_name, version)] exposed as maverick.tools eps."""
    eps = [_EP(n, d, v) for n, d, v in dists]
    monkeypatch.setattr(plugins_mod, "_entry_points",
                        lambda group: eps if group == "maverick.tools" else [])


def test_write_read_verify_roundtrip(tmp_path, monkeypatch):
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0")])
    lock = tmp_path / "plugins.lock.json"
    pins = pl.write_lock(lock)
    assert pins == {"acme-tools": "1.0.0"}
    assert pl.read_lock(lock) == pins
    report = pl.verify_lock(lock)
    assert report["ok"] and not report["drifted"]


def test_verify_detects_drift_missing_unpinned(tmp_path, monkeypatch):
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0"),
                            ("t2", "other-dist", "2.0")])
    lock = tmp_path / "plugins.lock.json"
    pl.write_lock(lock)
    # Versions move on; one dist vanishes; a new one appears.
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.1.0"),
                            ("t3", "new-dist", "0.1")])
    report = pl.verify_lock(lock)
    assert report["drifted"] == [("acme-tools", "1.0.0", "1.1.0")]
    assert report["missing"] == ["other-dist"]
    assert report["unpinned"] == ["new-dist"]
    assert not report["ok"]


def test_verify_fails_for_unpinned_only(tmp_path, monkeypatch):
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0")])
    lock = tmp_path / "plugins.lock.json"
    pl.write_lock(lock)
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0"),
                            ("t2", "new-dist", "0.1")])
    report = pl.verify_lock(lock)
    assert report["drifted"] == []
    assert report["missing"] == []
    assert report["unpinned"] == ["new-dist"]
    assert not report["ok"]


def test_no_lockfile_is_ok(tmp_path):
    report = pl.verify_lock(tmp_path / "nope.json")
    assert report["ok"] and report["unlocked"]


def _set_lock_env(monkeypatch, tmp_path, policy):
    lock = tmp_path / "plugins.lock.json"
    monkeypatch.setattr(pl, "lock_path", lambda: lock)
    monkeypatch.setenv("MAVERICK_PLUGIN_LOCK_POLICY", policy)
    return lock


def test_gate_enforce_refuses_drift(tmp_path, monkeypatch):
    pl.reset_warned()
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0")])
    lock = _set_lock_env(monkeypatch, tmp_path, "enforce")
    pl.write_lock(lock)
    _fake_eps(monkeypatch, [("t1", "acme-tools", "9.9.9")])  # drifted
    assert pl.dist_allowed_by_lock("acme-tools") is False
    # warn policy loads anyway
    monkeypatch.setenv("MAVERICK_PLUGIN_LOCK_POLICY", "warn")
    pl.reset_warned()
    assert pl.dist_allowed_by_lock("acme-tools") is True
    # off policy never reads the lock
    monkeypatch.setenv("MAVERICK_PLUGIN_LOCK_POLICY", "off")
    assert pl.dist_allowed_by_lock("acme-tools") is True


def test_gate_enforce_refuses_unpinned(tmp_path, monkeypatch):
    pl.reset_warned()
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0")])
    lock = _set_lock_env(monkeypatch, tmp_path, "enforce")
    pl.write_lock(lock)
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0"),
                            ("t2", "stranger", "0.1")])
    assert pl.dist_allowed_by_lock("acme-tools") is True
    assert pl.dist_allowed_by_lock("stranger") is False
    assert pl.dist_allowed_by_lock(None) is True  # unknown dist: can't pin


def test_discovery_skips_drifted_under_enforce(tmp_path, monkeypatch):
    """End-to-end: _gate consults the lock and drops the drifted plugin."""
    pl.reset_warned()
    lock = _set_lock_env(monkeypatch, tmp_path, "enforce")
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0")])
    pl.write_lock(lock)
    _fake_eps(monkeypatch, [("t1", "acme-tools", "2.0.0")])
    monkeypatch.setattr(plugins_mod, "_allowed_plugin_names", lambda: None)
    monkeypatch.setattr(plugins_mod, "_permission_policy", lambda: (set(), False))
    monkeypatch.setattr(plugins_mod, "_load", lambda ep, what: lambda: "tool")
    assert plugins_mod.discover_tools() == []


def test_cli_lock_and_verify(tmp_path, monkeypatch):
    from maverick import cli as cli_mod
    pl.reset_warned()
    lock = tmp_path / "plugins.lock.json"
    monkeypatch.setattr(pl, "lock_path", lambda: lock)
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0")])
    r = CliRunner().invoke(cli_mod.main, ["plugin", "lock"])
    assert r.exit_code == 0, r.output
    assert "acme-tools == 1.0.0" in r.output
    r2 = CliRunner().invoke(cli_mod.main, ["plugin", "verify"])
    assert r2.exit_code == 0 and "plugins.lock OK" in r2.output
    _fake_eps(monkeypatch, [("t1", "acme-tools", "3.0.0")])
    r3 = CliRunner().invoke(cli_mod.main, ["plugin", "verify"])
    assert r3.exit_code == 1 and "DRIFT acme-tools" in r3.output


# ---- content-integrity hashing ----

def test_write_lock_records_content_hashes(tmp_path, monkeypatch):
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0")])
    monkeypatch.setattr(pl, "_dist_content_hash", lambda d: "deadbeef")
    lock = tmp_path / "plugins.lock.json"
    pl.write_lock(lock)
    assert pl.read_hashes(lock) == {"acme-tools": "deadbeef"}


def test_enforce_refuses_on_content_drift_same_version(tmp_path, monkeypatch):
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0")])
    lock = tmp_path / "plugins.lock.json"
    monkeypatch.setattr(pl, "_dist_content_hash", lambda d: "AAAA")
    pl.write_lock(lock)
    monkeypatch.setattr(pl, "lock_path", lambda: lock)
    monkeypatch.setenv("MAVERICK_PLUGIN_LOCK_POLICY", "enforce")

    # Same version (1.0.0), but the recomputed content hash now differs.
    pl.reset_warned()
    monkeypatch.setattr(pl, "_dist_content_hash", lambda d: "BBBB")
    assert pl.dist_allowed_by_lock("acme-tools") is False  # tampered build refused

    # Matching hash -> allowed.
    pl.reset_warned()
    monkeypatch.setattr(pl, "_dist_content_hash", lambda d: "AAAA")
    assert pl.dist_allowed_by_lock("acme-tools") is True


def test_warn_policy_allows_content_drift(tmp_path, monkeypatch):
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0")])
    lock = tmp_path / "plugins.lock.json"
    monkeypatch.setattr(pl, "_dist_content_hash", lambda d: "AAAA")
    pl.write_lock(lock)
    monkeypatch.setattr(pl, "lock_path", lambda: lock)
    monkeypatch.setenv("MAVERICK_PLUGIN_LOCK_POLICY", "warn")
    pl.reset_warned()
    monkeypatch.setattr(pl, "_dist_content_hash", lambda d: "BBBB")
    assert pl.dist_allowed_by_lock("acme-tools") is True  # warns, loads anyway


def test_legacy_lock_without_hashes_is_version_only(tmp_path, monkeypatch):
    # A lockfile from before hashing has no "hashes" block -> no content check.
    _fake_eps(monkeypatch, [("t1", "acme-tools", "1.0.0")])
    lock = tmp_path / "plugins.lock.json"
    import json
    lock.write_text(json.dumps({"pins": {"acme-tools": "1.0.0"}}), encoding="utf-8")
    assert pl.read_hashes(lock) == {}
    monkeypatch.setattr(pl, "lock_path", lambda: lock)
    monkeypatch.setenv("MAVERICK_PLUGIN_LOCK_POLICY", "enforce")
    pl.reset_warned()
    # Even if current content "differs", there's no pinned hash to compare -> allowed.
    monkeypatch.setattr(pl, "_dist_content_hash", lambda d: "whatever")
    assert pl.dist_allowed_by_lock("acme-tools") is True


def test_content_hash_covers_metadata_native_and_unrecorded_files(tmp_path, monkeypatch):
    """The plugin hash must cover all load-affecting installed bytes, not just .py."""
    import importlib.metadata as metadata

    site = tmp_path / "site"
    pkg = site / "acme_plugin"
    info = site / "acme_plugin-1.0.dist-info"
    pkg.mkdir(parents=True)
    info.mkdir()
    source = pkg / "__init__.py"
    native = pkg / "native.so"
    entry_points = info / "entry_points.txt"
    source.write_text("def factory(): return 'safe'\n", encoding="utf-8")
    native.write_bytes(b"native-v1")
    entry_points.write_text("[maverick.tools]\nsafe = acme_plugin:factory\n", encoding="utf-8")

    class _Path:
        def __init__(self, rel):
            self.rel = rel

        def __str__(self):
            return self.rel

        def locate(self):
            return site / self.rel

    # Simulate RECORD omitting a generated module; recursive package hashing
    # should still detect it if it appears after the lock is written.
    monkeypatch.setattr(metadata, "files", lambda dist: [
        _Path("acme_plugin/__init__.py"),
        _Path("acme_plugin/native.so"),
        _Path("acme_plugin-1.0.dist-info/entry_points.txt"),
    ])

    original = pl._dist_content_hash("acme-plugin")
    entry_points.write_text("[maverick.tools]\nowned = evilmod:factory\n", encoding="utf-8")
    assert pl._dist_content_hash("acme-plugin") != original

    entry_points.write_text("[maverick.tools]\nsafe = acme_plugin:factory\n", encoding="utf-8")
    assert pl._dist_content_hash("acme-plugin") == original

    native.write_bytes(b"native-v2")
    assert pl._dist_content_hash("acme-plugin") != original

    native.write_bytes(b"native-v1")
    assert pl._dist_content_hash("acme-plugin") == original

    (pkg / "generated.py").write_text("def factory(): return 'owned'\n", encoding="utf-8")
    assert pl._dist_content_hash("acme-plugin") != original


def test_write_lock_leaves_no_temp_residue(tmp_path):
    lock = tmp_path / "plugins.lock.json"
    pl.write_lock(lock)
    assert lock.exists()
    assert list(tmp_path.glob("*.tmp")) == []  # unique temp + replace, no leftover
