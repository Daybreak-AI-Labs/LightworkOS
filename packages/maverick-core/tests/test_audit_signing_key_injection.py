"""Env-injected audit signing key (enterprise key custody).

When ``MAVERICK_AUDIT_SIGNING_KEY`` holds a raw Ed25519 private key, that key is
the active audit signer and is held in memory only -- never written to the local
key dir -- so the chain's trust anchor can live in a KMS / secrets manager and be
injected at deploy time. Only the public half (+ an ``.injected`` marker) is
persisted, so local ``verify_chain`` still trusts the chain.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest
from maverick.audit import signing


@pytest.fixture(autouse=True)
def _temp_keys(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    monkeypatch.setattr(
        signing, "_INJECTED_KEYPAIR_CACHE", signing._INJECTED_KEYPAIR_UNREAD
    )
    monkeypatch.delenv(signing._SIGNING_KEY_ENV, raising=False)
    yield


def _fresh_key_hex() -> tuple[str, bytes]:
    """A raw 32-byte Ed25519 private key as hex, plus its raw bytes."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return raw.hex(), raw


def test_offline_signature_verification_does_not_resolve_active_config(
    tmp_path,
) -> None:
    invalid_config = tmp_path / "invalid.toml"
    invalid_config.write_text("[broken", encoding="utf-8")
    env = os.environ.copy()
    env["MAVERICK_CONFIG"] = str(invalid_config)
    script = """
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from maverick.audit.signing import verify_ed25519

private = ed25519.Ed25519PrivateKey.generate()
public = private.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
message = b"offline-proof"
signature = private.sign(message)
assert verify_ed25519(public.hex(), signature.hex(), message)
print("verified")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "verified"


def test_injected_key_signs_without_writing_private_to_disk(monkeypatch):
    key_hex, _ = _fresh_key_hex()
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, key_hex)

    priv, pub, key_id = signing._load_or_create_keypair()
    key_dir = signing._key_dir()

    # The private key is NEVER persisted; only the public half + marker are.
    assert not (key_dir / f"{key_id}.key").exists()
    assert (key_dir / f"{key_id}.pub").exists()
    assert (key_dir / f"{key_id}.injected").exists()
    # key_id is the deterministic fingerprint of the public key.
    import hashlib
    assert key_id == hashlib.sha256(pub).hexdigest()[:16]


def test_injected_key_is_removed_from_process_environment(monkeypatch):
    key_hex, _ = _fresh_key_hex()
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, key_hex)

    first = signing._load_or_create_keypair()
    second = signing._load_or_create_keypair()

    assert signing._SIGNING_KEY_ENV not in os.environ
    assert second == first


def test_injected_key_initialization_is_atomic(monkeypatch):
    import concurrent.futures
    import threading

    key_hex, _ = _fresh_key_hex()
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, key_hex)
    entered, release, second_started = threading.Event(), threading.Event(), threading.Event()
    original = signing._decode_injected_key

    def paused(raw):
        entered.set()
        assert release.wait(5)
        return original(raw)

    monkeypatch.setattr(signing, "_decode_injected_key", paused)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(signing._injected_keypair)
        assert entered.wait(5)
        def second_call():
            second_started.set()
            return signing._injected_keypair()
        second = pool.submit(second_call)
        try:
            assert second_started.wait(5)
            assert not second.done()
        finally:
            release.set()
        assert first.result(timeout=5) == second.result(timeout=5)


def test_unexpected_key_initialization_failure_stays_closed(monkeypatch):
    key_hex, _ = _fresh_key_hex()
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, key_hex)
    monkeypatch.setattr(signing, "_decode_injected_key", lambda raw: (_ for _ in ()).throw(RuntimeError("failed")))
    with pytest.raises(RuntimeError):
        signing._injected_keypair()
    with pytest.raises(ValueError, match="invalid or unavailable"):
        signing._load_or_create_keypair()


def test_local_rotation_refused_for_external_signer(monkeypatch):
    key_hex, _ = _fresh_key_hex()
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, key_hex)
    with pytest.raises(signing.OffHostSigningRequiredError, match="secret manager"):
        signing.rotate_audit_keypair()
    assert not list(signing._key_dir().glob("*.key"))


def test_injected_key_chain_verifies_via_active_key(tmp_path, monkeypatch):
    key_hex, _ = _fresh_key_hex()
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, key_hex)

    audit = tmp_path / "2026-06-20.ndjson"
    s = signing.AuditSigner(audit)
    s.write({"event": "first"})
    s.write({"event": "second"})

    # Trust comes from the active injected key, not the writable marker.
    assert signing.verify_chain(audit) == []


@pytest.mark.parametrize("plant_private_key", [False, True])
def test_offhost_verifier_rejects_planted_local_keys(tmp_path, monkeypatch, plant_private_key):
    from maverick.audit import worm

    monkeypatch.setattr(signing, "require_offhost_signing", lambda: False)
    malicious = tmp_path / "2026-06-21.ndjson"
    rogue = signing.AuditSigner(malicious)
    rogue.write({"event": "rewritten"})
    key_dir = signing._key_dir()
    rogue_id = (key_dir / "active").read_text().strip()
    rogue_public = (key_dir / f"{rogue_id}.pub").read_bytes()
    if not plant_private_key:
        (key_dir / f"{rogue_id}.key").unlink()
        (key_dir / f"{rogue_id}.injected").write_bytes(b"")
    trusted_hex, _ = _fresh_key_hex()
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, trusted_hex)
    signing._reset_injected_keypair_cache()
    assert rogue_id not in signing.trusted_audit_public_keys()
    assert "no_pubkey" in {b.reason for b in signing.verify_chain(malicious)}
    with pytest.raises(worm.WormUnavailable):
        worm._trusted_public_key(rogue_id, {})
    monkeypatch.setattr("maverick._STARTUP_AUDIT_TRUSTED_PUBLIC_KEYS", rogue_public.hex())
    assert signing.verify_chain(malicious) == []


def test_injected_key_accepts_base64(monkeypatch):
    import base64

    _, raw = _fresh_key_hex()
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, base64.b64encode(raw).decode())
    _, _, key_id = signing._load_or_create_keypair()
    assert signing._is_valid_key_id(key_id)


def test_injected_key_precedence_over_on_disk(monkeypatch):
    # An on-disk key exists first...
    _, _, disk_id = signing._load_or_create_keypair()
    # ...then an injected key is provided: it must win.
    key_hex, _ = _fresh_key_hex()
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, key_hex)
    # The injected key is read-and-consumed once per process; the on-disk read
    # above already populated the cache with "no env key". Reset it so this call
    # models the realistic case (env injected, process restarted, env re-read).
    monkeypatch.setattr(
        signing, "_INJECTED_KEYPAIR_CACHE", signing._INJECTED_KEYPAIR_UNREAD
    )
    _, _, active_id = signing._load_or_create_keypair()
    assert active_id != disk_id
    assert (signing._key_dir() / f"{active_id}.injected").exists()


def test_malformed_injected_key_never_falls_back_to_disk(monkeypatch):
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, "not-a-valid-key")
    with pytest.raises(ValueError, match="invalid"):
        signing._load_or_create_keypair()
    with pytest.raises(ValueError, match="invalid"):
        signing.trusted_audit_public_keys()


def test_configured_kms_failure_does_not_fall_back_to_disk(monkeypatch):
    monkeypatch.setenv(signing._KMS_WRAPPED_KEY_ENV, "invalid")
    monkeypatch.setattr(signing, "_kms_wrapped_keypair", lambda: None)
    with pytest.raises(signing.OffHostSigningRequiredError):
        signing._load_or_create_keypair()


def test_verifier_pins_do_not_trust_other_local_keypairs(monkeypatch):
    monkeypatch.setattr(signing, "require_offhost_signing", lambda: False)
    _private, _public, rogue_id = signing._load_or_create_keypair()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    pinned = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr("maverick._STARTUP_AUDIT_TRUSTED_PUBLIC_KEYS", pinned.hex())
    assert rogue_id not in signing.trusted_audit_public_keys()


def test_empty_explicit_public_key_does_not_use_local_registry(tmp_path):
    audit = tmp_path / "2026-06-22.ndjson"
    signing.AuditSigner(audit).write({"event": "example"})
    assert signing.verify_chain(audit) == []
    assert signing.verify_chain(audit, pubkey_hex="")[0].reason == "no_pubkey"


def test_decode_injected_key_rejects_wrong_length(monkeypatch):
    # 16 bytes of hex -> not a 32-byte Ed25519 key.
    assert signing._decode_injected_key("00" * 16) is None
    assert signing._decode_injected_key("") is None
    # A valid 32-byte hex round-trips.
    _, raw = _fresh_key_hex()
    assert signing._decode_injected_key(raw.hex()) == raw


def test_decode_injected_key_rejects_base64_with_stray_characters():
    # Non-validating base64 drops stray characters and yields some other key.
    import base64

    _, raw = _fresh_key_hex()
    std = base64.b64encode(raw).decode()
    url = base64.urlsafe_b64encode(raw).decode()
    assert signing._decode_injected_key(std) == raw
    assert signing._decode_injected_key(url) == raw
    assert signing._decode_injected_key(std[:10] + "!*" + std[10:]) is None


# ----- off-host signing enforcement + KMS-wrapped key source -----

def test_offhost_not_required_by_default(monkeypatch):
    # No enterprise mode, no flag, no off-host key -> on-disk key is allowed.
    monkeypatch.delenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", raising=False)
    monkeypatch.delenv(signing._SIGNING_KEY_ENV, raising=False)
    monkeypatch.delenv(signing._KMS_WRAPPED_KEY_ENV, raising=False)
    monkeypatch.setattr(signing, "require_offhost_signing", lambda: False)
    priv, pub, _ = signing._load_or_create_keypair()
    assert len(priv) == 32 and len(pub) == 32


def test_offhost_required_refuses_on_disk_key(monkeypatch):
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "1")
    monkeypatch.delenv(signing._SIGNING_KEY_ENV, raising=False)
    monkeypatch.delenv(signing._KMS_WRAPPED_KEY_ENV, raising=False)
    with pytest.raises(RuntimeError, match="off-host audit signing is required"):
        signing._load_or_create_keypair()


def test_offhost_required_satisfied_by_injected_key(monkeypatch):
    # An env-injected (KMS-sourced) key satisfies the requirement -- no raise.
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "1")
    key_hex, raw = _fresh_key_hex()
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, key_hex)
    priv, pub, _ = signing._load_or_create_keypair()
    assert priv == raw


def test_kms_wrapped_key_source(monkeypatch):
    # A KMS-wrapped blob unwraps (via the configured cloud KMS) into memory.
    import base64
    from unittest import mock
    key32 = bytes(range(32))
    monkeypatch.setenv(signing._KMS_WRAPPED_KEY_ENV, base64.b64encode(b"wrapped").decode())

    class _FakeKEK:
        def unwrap(self, wrapped, *, context=None):
            assert context == b"maverick-audit-signing"
            return key32

    monkeypatch.setattr("maverick.config.load_config", lambda: {"kms": {"provider": "vault"}})
    with mock.patch("maverick.kms_backends.build_cloud_kms", return_value=_FakeKEK()):
        res = signing._kms_wrapped_keypair()
    assert res is not None and res[0] == key32


def test_require_offhost_env_overrides(monkeypatch):
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "on")
    assert signing.require_offhost_signing() is True
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "off")
    assert signing.require_offhost_signing() is False
