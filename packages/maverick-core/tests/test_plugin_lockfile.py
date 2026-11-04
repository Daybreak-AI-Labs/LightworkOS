"""plugin_lockfile: deterministic plugin pinning lockfile. No network."""
from __future__ import annotations

from maverick.tools.plugin_lockfile import plugin_lockfile


def _run(**kw):
    return plugin_lockfile().fn(kw)


def test_generate_sorted_and_deterministic():
    plugins = [
        {"name": "zeta", "version": "2.0.0", "sha256": "bbb"},
        {"name": "alpha", "version": "1.0.0", "sha256": "aaa"},
    ]
    a = _run(op="generate", plugins=plugins)
    b = _run(op="generate", plugins=list(reversed(plugins)))
    assert a == b  # sorted -> order-independent + deterministic
    lines = a.splitlines()
    assert lines[1] == "alpha==1.0.0==aaa"
    assert lines[2] == "zeta==2.0.0==bbb"


def test_generate_empty_hash_line():
    out = _run(op="generate", plugins=[{"name": "p", "version": "1.2.3"}])
    assert out.splitlines()[-1] == "p==1.2.3=="


def test_verify_ok():
    lock = _run(op="generate", plugins=[{"name": "p", "version": "1.0.0", "sha256": "h"}])
    out = _run(op="verify", lockfile=lock, installed=[{"name": "p", "version": "1.0.0", "sha256": "h"}])
    assert out.startswith("OK") and "1 plugin" in out


def test_verify_drift_version_and_hash():
    lock = _run(op="generate", plugins=[{"name": "p", "version": "1.0.0", "sha256": "h"}])
    ver = _run(op="verify", lockfile=lock, installed=[{"name": "p", "version": "2.0.0", "sha256": "h"}])
    assert ver.startswith("DRIFT") and "version 2.0.0 != pinned 1.0.0" in ver
    sha = _run(op="verify", lockfile=lock, installed=[{"name": "p", "version": "1.0.0", "sha256": "x"}])
    assert sha.startswith("DRIFT") and "sha256 mismatch" in sha


def test_verify_missing_and_unpinned():
    lock = _run(op="generate", plugins=[{"name": "p", "version": "1.0.0"}])
    miss = _run(op="verify", lockfile=lock, installed=[])
    assert miss.startswith("DRIFT") and "p: missing" in miss
    extra = _run(
        op="verify",
        lockfile=lock,
        installed=[{"name": "p", "version": "1.0.0"}, {"name": "q", "version": "9.9"}],
    )
    assert extra.startswith("DRIFT") and "q: installed but not pinned" in extra


def test_errors():
    t = plugin_lockfile()
    assert t.fn({"op": "generate"}).startswith("ERROR")  # no plugins
    assert t.fn({"op": "generate", "plugins": [{"name": "p"}]}).startswith("ERROR")  # no version
    assert t.fn({"op": "verify", "installed": []}).startswith("ERROR")  # no lockfile
    assert t.fn({"op": "nope"}).startswith("ERROR")
