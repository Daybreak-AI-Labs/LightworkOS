"""Regression: the audit Ed25519 key must not be a general-purpose
signing oracle.

If ``sign_detached_digest`` (dashboard evidence exports) and ``sign_envelope``
(federation exchange) signed the bare SHA-256 digest of their canonical JSON --
byte-for-byte what ``AuditSigner.write`` signs for a chain row whose ``hash``
field equals that digest -- anyone who could obtain a detached-digest
signature or a federation envelope signature for an attacker-chosen payload
could mint a row that ``verify_chain``
accepted as genuinely signed by the audit key, without ever touching the
private key. Domain-separating each non-row use closes that reuse.
"""
from __future__ import annotations

import hashlib
import json

import pytest
from maverick import federation_envelope
from maverick.audit import signing

pytestmark = pytest.mark.usefixtures("local_audit_key_custody")


@pytest.fixture(autouse=True)
def _temp_keys(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    yield


def _forged_row(prev_hash: str, key_id: str) -> tuple[dict, str]:
    """Build the exact row an attacker wants accepted, and its digest."""
    forged = {
        "kind": "tool_call",
        "tool": "wire_transfer",
        "decision": "APPROVED",
        "amount": 60000,
        "prev_hash": prev_hash,
        "key_id": key_id,
    }
    canon = json.dumps(forged, sort_keys=True, default=str).encode("utf-8")
    return forged, hashlib.sha256(canon).hexdigest()


def test_detached_digest_signature_no_longer_forges_a_chain_row(tmp_path):
    path = tmp_path / "2026-01-01.ndjson"
    s = signing.AuditSigner(path)
    s.write({"kind": "tool_call", "tool": "wire_transfer", "decision": "DENIED", "amount": 60000})
    assert signing.verify_chain(path) == []
    tip = json.loads(path.read_text().splitlines()[-1])["hash"]

    forged, digest = _forged_row(tip, s._key_id)
    sig = signing.sign_detached_digest(digest)
    row = dict(forged)
    row["hash"] = digest
    row["sig"] = sig["signature"]
    with open(path, "a") as f:
        f.write(json.dumps(row) + "\n")

    breaks = signing.verify_chain(path)
    assert any(b.reason == "bad_signature" for b in breaks), (
        "a detached-digest signature verified as a valid audit-chain row "
        f"signature; breaks={breaks}"
    )


def test_envelope_signature_no_longer_forges_a_chain_row(tmp_path):
    path = tmp_path / "2026-01-01.ndjson"
    s = signing.AuditSigner(path)
    s.write({"kind": "tool_call", "tool": "wire_transfer", "decision": "DENIED", "amount": 60000})
    tip = json.loads(path.read_text().splitlines()[-1])["hash"]

    env = federation_envelope.sign_envelope({"kind": "human_approval", "by": "cfo", "prev_hash": tip})
    body = {k: v for k, v in env.items() if k != "sig"}
    row = dict(env)
    row["hash"] = federation_envelope._digest(body)
    with open(path, "a") as f:
        f.write(json.dumps(row) + "\n")

    breaks = signing.verify_chain(path)
    assert any(b.reason == "bad_signature" for b in breaks), (
        "a federation-envelope signature verified as a valid audit-chain row "
        f"signature; breaks={breaks}"
    )


def test_detached_digest_and_envelope_signatures_do_not_cross_verify():
    digest = hashlib.sha256(b"cross-protocol probe").hexdigest()
    detached = signing.sign_detached_digest(digest)
    pubkey = signing._load_or_create_keypair()[1].hex()

    # A signature minted for the detached-digest protocol must not verify as
    # a valid signature over the SAME digest under the envelope protocol's
    # domain-separated message, and vice versa -- each prefix is exclusive.
    assert not signing.verify_ed25519(
        pubkey, detached["signature"], federation_envelope._envelope_message(digest)
    )
    env = federation_envelope.sign_envelope({"kind": "probe", "digest": digest})
    body = {k: v for k, v in env.items() if k != "sig"}
    env_digest = federation_envelope._digest(body)
    assert not signing.verify_detached_digest(pubkey, env_digest, env["sig"])


def test_verify_detached_digest_round_trips(tmp_path):
    digest = hashlib.sha256(b"evidence export payload").hexdigest()
    signed = signing.sign_detached_digest(digest)
    pubkey = signing._load_or_create_keypair()[1].hex()

    assert signing.verify_detached_digest(pubkey, digest, signed["signature"])
    # Tampered digest must not verify under the original signature.
    other_digest = hashlib.sha256(b"a different payload").hexdigest()
    assert not signing.verify_detached_digest(pubkey, other_digest, signed["signature"])


def test_sign_envelope_round_trips_after_domain_separation():
    env = federation_envelope.sign_envelope({"schema": "maverick-test-fed/1", "origin": "peer-a"})
    peers = {"peer-a": {"origin": "peer-a", "pubkey": env["pubkey"]}}
    ok, reason = federation_envelope.verify_envelope(
        env, expected_schema="maverick-test-fed/1", peers=peers
    )
    assert ok, reason
