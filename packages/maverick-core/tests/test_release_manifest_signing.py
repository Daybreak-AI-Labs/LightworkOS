"""Release-manifest signatures: Ed25519 signing, offline verification and the
trusted publisher key set. See maverick/release_manifest_signing.py."""
from __future__ import annotations

import json

import pytest
from maverick import release_manifest_signing as S

pytest.importorskip("cryptography")


def _payload(**kw):
    base = dict(kind="lightwork.release", version="v0.1.7", min_from="v0.1.5",
                artifacts=[], migrations=["m1"], notes="")
    base.update(kw)
    return base


@pytest.fixture
def keys():
    priv, pub = S.new_publisher_keypair()
    return priv, pub, [pub]


@pytest.fixture
def no_configured_keys(monkeypatch):
    monkeypatch.delenv("MAVERICK_RELEASE_PUBKEYS", raising=False)
    monkeypatch.setattr(S, "_release_cfg", dict)


def test_signed_manifest_verifies_against_its_key(keys):
    priv, pub, trust = keys
    doc = S.sign_manifest(_payload(), priv)
    assert doc["key_id"] == pub
    assert S.verify_manifest_signature(doc, trust) == (True, "ok")


def test_signature_covers_canonical_json_of_every_other_field(keys):
    # Byte format: ``sig`` is the Ed25519 signature over the sorted-key,
    # whitespace-free JSON of every field except ``sig`` and ``key_id``.
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv, pub, _trust = keys
    doc = S.sign_manifest(_payload(), priv)
    body = {k: v for k, v in doc.items() if k not in ("sig", "key_id")}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
        bytes.fromhex(doc["sig"]), canonical)


def test_resigning_a_signed_document_replaces_its_signature(keys):
    priv, _pub, trust = keys
    other_priv, other_pub = S.new_publisher_keypair()
    doc = S.sign_manifest(S.sign_manifest(_payload(), other_priv), priv)
    assert doc["key_id"] != other_pub
    assert S.verify_manifest_signature(doc, trust) == (True, "ok")


def test_tamper_is_caught(keys):
    priv, _pub, trust = keys
    doc = S.sign_manifest(_payload(), priv)
    doc["version"] = "v9.9.9"  # flip a field after signing
    assert S.verify_manifest_signature(doc, trust) == (False, "bad_signature")


def test_untrusted_key_is_refused(keys):
    _priv, _pub, trust = keys
    rogue_priv, _rogue_pub = S.new_publisher_keypair()
    doc = S.sign_manifest(_payload(), rogue_priv)
    assert S.verify_manifest_signature(doc, trust) == (False, "untrusted_key")


def test_empty_trust_set_refuses_everything(keys):
    priv, _pub, _trust = keys
    doc = S.sign_manifest(_payload(), priv)
    assert S.verify_manifest_signature(doc, []) == (False, "no_trust_anchor")


def test_unsigned_document_is_refused(keys):
    _priv, _pub, trust = keys
    assert S.verify_manifest_signature(_payload(), trust) == (False, "unsigned")


def test_trusted_key_match_ignores_case(keys):
    priv, pub, _trust = keys
    doc = S.sign_manifest(_payload(), priv)
    assert S.verify_manifest_signature(doc, [pub.upper()]) == (True, "ok")


def test_non_dict_document_is_malformed_without_raising():
    # A corrupt file that parses to valid but non-object JSON must not crash
    # the caller.
    assert S.verify_manifest_signature(["not", "a", "dict"], ["aa" * 32]) == (False, "malformed")


def test_explicit_trust_set_wins_over_configured_keys(monkeypatch):
    monkeypatch.setenv("MAVERICK_RELEASE_PUBKEYS", "aa" * 32)
    assert S.trusted_publisher_keys([" " + "BB" * 32, " "]) == ["bb" * 32]


def test_trusted_keys_come_from_env_then_config(monkeypatch, no_configured_keys):
    assert S.trusted_publisher_keys() == []
    monkeypatch.setenv("MAVERICK_RELEASE_PUBKEYS", "AA" * 32 + ", ," + "cc" * 32)
    monkeypatch.setattr(S, "_release_cfg", lambda: {"publisher_pubkeys": ["BB" * 32]})
    assert S.trusted_publisher_keys() == ["aa" * 32, "cc" * 32, "bb" * 32]


def test_config_keys_may_be_a_comma_separated_string(monkeypatch, no_configured_keys):
    monkeypatch.setattr(S, "_release_cfg",
                        lambda: {"publisher_pubkeys": "aa" * 32 + "," + "bb" * 32})
    assert S.trusted_publisher_keys() == ["aa" * 32, "bb" * 32]


def test_release_config_section_supplies_the_trust_set(monkeypatch):
    monkeypatch.delenv("MAVERICK_RELEASE_PUBKEYS", raising=False)
    monkeypatch.setattr("maverick.config.load_config",
                        lambda *a, **k: {"release": {"publisher_pubkeys": ["dd" * 32]}})
    assert S.trusted_publisher_keys() == ["dd" * 32]
