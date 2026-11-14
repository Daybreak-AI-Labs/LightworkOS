"""Tests for audit-log signing and verification (maverick.audit.signing)."""
from __future__ import annotations

import json
import os
import stat

import pytest

# --- tamper-evident audit log must actually be wired in ---

def _crypto_works() -> bool:
    # `cryptography` can import yet panic on use when its native backend is
    # half-installed (missing _cffi_backend), so probe an actual op.
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        ed25519.Ed25519PrivateKey.generate()
        return True
    except BaseException:
        return False


def test_audit_log_signing_roundtrip_and_tamper(tmp_path, monkeypatch):
    import json

    if not _crypto_works():
        pytest.skip("cryptography backend unavailable")
    import maverick.audit.signing as signing
    from maverick.audit import verify_chain
    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    # Keep generated keys out of the real ~/.maverick.
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    adir = tmp_path / "audit"
    alog = AuditLog(adir, sign=True)
    for i in range(3):
        assert alog.record(AuditEvent(ts=float(i), kind="tool_call", agent="a", payload={"i": i})) is True

    files = list(adir.glob("*.ndjson"))
    assert len(files) == 1
    path = files[0]
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    assert {"hash", "sig", "key_id"} <= set(first)  # rows are signed + chained
    assert verify_chain(path) == []                 # intact chain verifies

    rows = [json.loads(x) for x in lines]
    rows[1]["payload"] = {"i": 999}                 # tamper a historical row
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    assert verify_chain(path)                        # break detected


# --- signer refuses to silently restart on a torn line ---

def test_audit_signer_refuses_torn_resume(tmp_path, monkeypatch):
    if not _crypto_works():
        pytest.skip("cryptography backend unavailable")
    import maverick.audit.signing as signing

    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    p = tmp_path / "a.ndjson"
    signing.AuditSigner(p).write({"v": 1, "kind": "x"})
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"partial": ')  # torn final line, no newline / not valid JSON
    with pytest.raises(ValueError):
        signing.AuditSigner(p)  # resume must refuse, not restart from genesis


# ---------- audit signing: tampered rows flagged, not crashed ----------

def _crypto_available() -> bool:
    try:
        import cryptography.hazmat.primitives.asymmetric.ed25519  # noqa: F401
        return True
    except BaseException:
        return False


def test_audit_verify_flags_nonhex_sig_instead_of_crashing(tmp_path, monkeypatch):
    if not _crypto_available():
        return
    import json as _json

    from maverick.audit import signing
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    path = tmp_path / "audit.ndjson"
    s = signing.AuditSigner(path)
    s.write({"event": "a"})
    s.write({"event": "b"})
    # Corrupt line 1's sig to a non-hex string.
    lines = path.read_text().splitlines()
    row = _json.loads(lines[0])
    row["sig"] = "zzzz-not-hex"
    lines[0] = _json.dumps(row)
    path.write_text("\n".join(lines) + "\n")
    # Must return a ChainBreak (not raise), and still check later rows.
    breaks = signing.verify_chain(path)
    assert breaks  # did not crash
    assert any(b.reason == "bad_signature" for b in breaks)


@pytest.mark.usefixtures("local_audit_key_custody")
def test_audit_verify_rejects_lone_pubkey(tmp_path, monkeypatch):
    """A .pub with no sibling .key (attacker-dropped) is not trusted."""
    if not _crypto_available():
        return
    import json as _json

    from maverick.audit import signing
    keydir = tmp_path / "keys"
    monkeypatch.setattr(signing, "KEY_DIR", keydir)
    path = tmp_path / "audit.ndjson"
    s = signing.AuditSigner(path)
    s.write({"event": "a"})
    # Remove the private key, leaving only the .pub (simulating a
    # verifier host that only has a dropped pubkey).
    for keyfile in keydir.glob("*.key"):
        keyfile.unlink()
    breaks = signing.verify_chain(path)
    assert any(b.reason == "no_pubkey" for b in breaks)
    _ = _json  # silence


def test_audit_verify_rejects_path_traversal_key_id(tmp_path, monkeypatch):
    if not _crypto_available():
        return
    import json as _json

    from maverick.audit import signing
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    path = tmp_path / "audit.ndjson"
    s = signing.AuditSigner(path)
    s.write({"event": "a"})

    lines = path.read_text().splitlines()
    row = _json.loads(lines[0])
    row["key_id"] = "../../tmp/evil"
    lines[0] = _json.dumps(row)
    path.write_text("\n".join(lines) + "\n")

    breaks = signing.verify_chain(path)
    assert any(b.reason == "no_pubkey" for b in breaks)


def test_audit_signer_writes_chained_signed_rows(tmp_path, monkeypatch):
    if not _crypto_available():
        return  # extra not installed
    from maverick.audit import signing
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    path = tmp_path / "audit.ndjson"
    s = signing.AuditSigner(path)
    assert s.write({"event": "goal_start", "goal_id": 1})
    assert s.write({"event": "tool_call", "tool": "shell"})
    assert s.write({"event": "goal_end", "status": "done"})

    breaks = signing.verify_chain(path)
    assert breaks == []


def test_audit_signer_detects_tamper(tmp_path, monkeypatch):
    if not _crypto_available():
        return
    from maverick.audit import signing
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    path = tmp_path / "audit.ndjson"
    s = signing.AuditSigner(path)
    s.write({"event": "goal_start", "goal_id": 1})
    s.write({"event": "goal_end", "status": "done"})

    # Tamper: rewrite line 1's content but keep its hash/sig.
    lines = path.read_text().splitlines()
    row = json.loads(lines[0])
    row["event"] = "tampered"
    lines[0] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n")

    breaks = signing.verify_chain(path)
    assert breaks
    assert any(b.reason == "bad_hash" for b in breaks)


def test_audit_signer_resumes_chain(tmp_path, monkeypatch):
    if not _crypto_available():
        return
    from maverick.audit import signing
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    path = tmp_path / "audit.ndjson"
    s1 = signing.AuditSigner(path)
    s1.write({"event": "a"})
    s1.write({"event": "b"})

    # New signer instance should pick up where the last left off.
    s2 = signing.AuditSigner(path)
    s2.write({"event": "c"})

    breaks = signing.verify_chain(path)
    assert breaks == []


class TestAuditKeyPerms:
    @pytest.mark.skipif(os.name != "posix", reason="POSIX perms")
    def test_private_key_created_0600(self, monkeypatch, tmp_path):
        from maverick.audit import signing
        monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
        # Real Ed25519 material is exactly 32 bytes and the key id is a 16-char
        # lowercase-hex fingerprint; _save_keypair validates both.
        priv_path = signing._save_keypair(b"P" * 32, b"K" * 32, "0123456789abcdef")
        mode = stat.S_IMODE(priv_path.stat().st_mode)
        assert mode == 0o600, oct(mode)

    def test_private_key_bytes_are_never_newline_translated(self, monkeypatch, tmp_path):
        """Raw Ed25519 material must remain exactly 32 bytes on Windows."""
        from maverick.audit import signing

        monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
        private = (b"A" * 10) + b"\n" + (b"B" * 21)

        priv_path = signing._save_keypair(
            private, b"P" * 32, "0123456789abcdef"
        )

        assert len(private) == 32
        assert priv_path.read_bytes() == private


def test_signed_row_keeps_colliding_payload_fields_and_verifies(tmp_path, monkeypatch):
    # A payload key_id (an API key's id) was overwritten by the signer's key
    # id; a payload hash/sig or an integer dict key made the row unverifiable.
    import json

    if not _crypto_works():
        pytest.skip("cryptography backend unavailable")
    import maverick.audit.signing as signing
    from maverick.audit import verify_chain

    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    path = tmp_path / "2026-01-01.ndjson"
    signer = signing.AuditSigner(path)
    assert signer.write({"kind": "api_key", "key_id": "my-api-key-id-123",
                         "hash": "x", "sig": "y", "m": {2: "a", 10: "b"}})
    row = json.loads(path.read_text().splitlines()[0])
    assert row["payload_key_id"] == "my-api-key-id-123"
    assert row["payload_hash"] == "x" and row["payload_sig"] == "y"
    assert row["key_id"] != "my-api-key-id-123"
    assert verify_chain(path) == []
