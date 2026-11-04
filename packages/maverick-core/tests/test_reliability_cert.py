"""Reliability certification: harness logic + the real composed checks."""
from __future__ import annotations

import json

from maverick import reliability_cert as rc
from maverick.file_lock import private_path_is_restricted


def test_certify_with_injected_checks_pass():
    cert = rc.certify({
        "a": lambda: (True, "fine"),
        "b": lambda: (True, "also fine"),
    }, now=1000.0)
    assert cert["passed"] is True
    assert cert["checks"]["a"]["passed"] and cert["checks"]["b"]["passed"]
    assert cert["issued_at"] == 1000.0
    assert cert["environment"]["python"]


def test_certify_failing_check_fails_cert():
    cert = rc.certify({
        "good": lambda: (True, "ok"),
        "bad": lambda: (False, "nope"),
    })
    assert cert["passed"] is False
    assert cert["checks"]["bad"]["detail"] == "nope"


def test_crashing_check_is_a_failing_check():
    def boom():
        raise RuntimeError("drill exploded")

    cert = rc.certify({"boom": boom})
    assert cert["passed"] is False
    assert "RuntimeError" in cert["checks"]["boom"]["detail"]


def test_write_cert_0600(tmp_path):
    cert = rc.certify({"a": lambda: (True, "ok")})
    path = rc.write_cert(cert, tmp_path / "cert.json")
    assert path.exists()
    assert private_path_is_restricted(path, 0o600)
    loaded = json.loads(path.read_text())
    assert loaded["kind"] == "maverick-reliability-cert"


def test_sign_cert_signed_or_honestly_unsigned(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    cert = rc.sign_cert(rc.certify({"a": lambda: (True, "ok")}))
    sig = cert["signature"]
    if sig is None:
        return  # cryptography absent: honestly unsigned
    assert sig["alg"] == "ed25519" and len(sig["pubkey"]) == 64
    # the signature verifies over the canonical payload
    from maverick.audit.signing import verify_ed25519
    payload = json.dumps({k: v for k, v in cert.items() if k != "signature"},
                         sort_keys=True, separators=(",", ":")).encode()
    assert verify_ed25519(sig["pubkey"], sig["sig"], payload)


def test_real_wal_contention_check_passes(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    ok, detail = rc._check_wal_contention(writers=8, rows_each=10)
    assert ok, detail
    assert "8 writers" in detail


def test_real_plugin_reliability_check_passes():
    ok, detail = rc._check_plugin_reliability()
    assert ok, detail


def test_default_checks_registered():
    assert set(rc.DEFAULT_CHECKS) == {
        "chaos_gameday", "plugin_reliability", "wal_contention"}


def test_write_cert_concurrent_no_temp_residue(tmp_path):
    """A fixed ".tmp" collides between two concurrent write_cert calls; the
    unique temp keeps the cert file valid with no leftover temp."""
    import json
    import threading

    p = tmp_path / "cert.json"
    n = 12

    def worker(i: int):
        rc.write_cert({"verdict": "pass", "i": i}, path=p)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert isinstance(json.loads(p.read_text()), dict)  # valid, not torn
    assert list(tmp_path.glob("*.tmp")) == []
