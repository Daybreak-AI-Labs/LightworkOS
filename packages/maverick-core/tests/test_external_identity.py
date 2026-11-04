"""Platform-native external-agent identity (maverick.external_identity).

Three per-surface verifiers over the trust registry — JWT (issuer/audience/
jwks_file), webhook-format HMAC (hmac_secret_ref via the secret provider),
and the domain-separated Ed25519 request envelope (pinned pubkey + nonce) —
plus the strict parsing of the four new TrustedAgent identity fields and the
mint-token read-modify-write round-trip that must preserve them.

All key material is generated locally; no network is ever touched. If this
sandbox's ``cryptography``/PyJWT is broken the crypto-dependent tests are
SKIPPED (not xfailed) — CI has working crypto and is the real gate.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import time

import pytest
from maverick import external_identity
from maverick.agent_trust import TrustedAgent, load_registry
from maverick.external_identity import (
    envelope_message,
    verify_agent_envelope,
    verify_agent_hmac,
    verify_agent_jwt,
)

# ---- crypto availability gate (same probe as test_oidc) ----------------------
_CRYPTO_OK = True
_CRYPTO_SKIP_REASON = ""
try:  # noqa: SIM105
    import jwt  # noqa: F401
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    _probe = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _probe.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
except Exception as _e:  # pragma: no cover - env-dependent
    _CRYPTO_OK = False
    _CRYPTO_SKIP_REASON = f"working cryptography/PyJWT unavailable: {type(_e).__name__}: {_e}"

requires_crypto = pytest.mark.skipif(not _CRYPTO_OK, reason=_CRYPTO_SKIP_REASON)

ISSUER = "https://partner-idp.example.com"
AUDIENCE = "lightwork-gateway"
AGENT = "partner-bot"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    """Sandbox the managed-overlay/config/audit paths and the nonce ledger."""
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import config
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _registry(**overrides) -> dict[str, TrustedAgent]:
    entry = {"id": AGENT, "direction": "inbound",
             "jwt_issuer": ISSUER, "jwt_audience": AUDIENCE}
    entry.update(overrides)
    return load_registry({"agent_trust": {"agents": [entry]}})


# ---- registry parsing of the four identity fields ----------------------------


def test_identity_fields_parse_and_default_empty():
    reg = load_registry({"agent_trust": {"agents": [
        {"id": "a", "jwt_issuer": ISSUER, "jwt_audience": AUDIENCE,
         "jwks_file": "/keys/partner.pem",  # pragma: allowlist secret
         "hmac_secret_ref": "PARTNER_SECRET"},  # pragma: allowlist secret
        {"id": "b"},
    ]}})
    a = reg["a"]
    assert a.jwt_issuer == ISSUER
    assert a.jwt_audience == AUDIENCE
    assert a.jwks_file == "/keys/partner.pem"
    assert a.hmac_secret_ref == "PARTNER_SECRET"  # pragma: allowlist secret
    b = reg["b"]
    assert (b.jwt_issuer, b.jwt_audience, b.jwks_file, b.hmac_secret_ref) == ("", "", "", "")


@pytest.mark.parametrize(("field", "bad"), [
    ("jwt_issuer", "iss\x00uer"),      # control char
    ("jwt_issuer", 123),               # non-string
    ("jwt_audience", " padded"),       # unstripped edge whitespace
    ("jwks_file", ["not", "a", "path"]),
    ("hmac_secret_ref", "x" * 4097),   # over the length bound
])
def test_malformed_identity_field_drops_entry(field, bad):
    reg = load_registry({"agent_trust": {"agents": [{"id": "a", field: bad}]}})
    assert "a" not in reg


# ---- JWT ---------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem, pub


def _mint(priv_pem, **claim_overrides) -> str:
    now = int(time.time())
    claims = {"sub": AGENT, "iss": ISSUER, "aud": AUDIENCE,
              "iat": now, "exp": now + 600}
    claims.update(claim_overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, priv_pem, algorithm="RS256",
                      headers={"kid": "k1"})


@requires_crypto
def test_jwt_happy_path_with_pem_jwks_file(tmp_path, rsa_keys):
    priv_pem, pub_pem, _ = rsa_keys
    key_file = tmp_path / "partner.pem"
    key_file.write_bytes(pub_pem)
    reg = _registry(jwks_file=str(key_file))
    agent, rule = verify_agent_jwt(_mint(priv_pem), registry=reg)
    assert agent is not None and agent.id == AGENT
    assert rule == "ok"


@requires_crypto
def test_jwt_happy_path_with_json_jwks_file(tmp_path, rsa_keys):
    priv_pem, _, pub = rsa_keys
    from jwt.algorithms import RSAAlgorithm
    jwk = json.loads(RSAAlgorithm.to_jwk(pub))
    jwk["kid"] = "k1"
    key_file = tmp_path / "jwks.json"
    key_file.write_text(json.dumps({"keys": [jwk]}), encoding="utf-8")
    reg = _registry(jwks_file=str(key_file))
    agent, rule = verify_agent_jwt(_mint(priv_pem), registry=reg)
    assert agent is not None and agent.id == AGENT
    assert rule == "ok"


@requires_crypto
def test_jwt_for_another_subject_never_authenticates_this_agent(tmp_path, rsa_keys):
    """A validly-signed token whose sub names agent B must not resolve as A."""
    priv_pem, pub_pem, _ = rsa_keys
    key_file = tmp_path / "partner.pem"
    key_file.write_bytes(pub_pem)
    reg = _registry(jwks_file=str(key_file))
    agent, rule = verify_agent_jwt(_mint(priv_pem, sub="other-bot"), registry=reg)
    assert agent is None
    assert rule == "subject_mismatch"


@requires_crypto
def test_jwt_wrong_audience_rejected(tmp_path, rsa_keys):
    priv_pem, pub_pem, _ = rsa_keys
    key_file = tmp_path / "partner.pem"
    key_file.write_bytes(pub_pem)
    reg = _registry(jwks_file=str(key_file))
    agent, rule = verify_agent_jwt(
        _mint(priv_pem, aud="some-other-client"), registry=reg)
    assert agent is None
    assert rule == "no_matching_entry"


@requires_crypto
def test_jwt_expired_rejected(tmp_path, rsa_keys):
    priv_pem, pub_pem, _ = rsa_keys
    key_file = tmp_path / "partner.pem"
    key_file.write_bytes(pub_pem)
    reg = _registry(jwks_file=str(key_file))
    now = int(time.time())
    agent, rule = verify_agent_jwt(
        _mint(priv_pem, iat=now - 7200, exp=now - 3600), registry=reg)
    assert agent is None
    assert rule == "jwt_invalid"


@requires_crypto
def test_jwt_alg_none_rejected(tmp_path, rsa_keys):
    _, pub_pem, _ = rsa_keys
    key_file = tmp_path / "partner.pem"
    key_file.write_bytes(pub_pem)
    reg = _registry(jwks_file=str(key_file))
    now = int(time.time())
    unsigned = jwt.encode(
        {"sub": AGENT, "iss": ISSUER, "aud": AUDIENCE,
         "iat": now, "exp": now + 600},
        key=None, algorithm="none")
    agent, rule = verify_agent_jwt(unsigned, registry=reg)
    assert agent is None
    assert rule == "jwt_invalid"


@requires_crypto
def test_jwt_never_matches_entry_without_jwt_issuer(rsa_keys):
    """Entries not enrolled for JWT (bearer/pubkey-only) are invisible to it."""
    priv_pem, _, _ = rsa_keys
    reg = load_registry({"agent_trust": {"agents": [
        {"id": AGENT, "direction": "inbound", "pubkey": "ab" * 32},
    ]}})
    agent, rule = verify_agent_jwt(_mint(priv_pem), registry=reg)
    assert agent is None
    assert rule == "no_matching_entry"


@requires_crypto
def test_jwt_revoked_entry_rejected_after_valid_signature(tmp_path, rsa_keys):
    priv_pem, pub_pem, _ = rsa_keys
    key_file = tmp_path / "partner.pem"
    key_file.write_bytes(pub_pem)
    reg = _registry(jwks_file=str(key_file), revoked=True)
    agent, rule = verify_agent_jwt(_mint(priv_pem), registry=reg)
    assert agent is None
    assert rule == "revoked"


# ---- HMAC --------------------------------------------------------------------

_SECRET_NAME = "XA_TEST_HMAC_SECRET"  # pragma: allowlist secret
_SECRET = "s3cret-value"  # pragma: allowlist secret


def _hmac_sig(secret: str, ts: str, body: bytes) -> str:
    mac = hmac_mod.new(secret.encode(), f"{ts}.".encode() + body,
                       hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _hmac_registry(**overrides):
    entry = {"id": "hooky", "direction": "inbound",
             "hmac_secret_ref": _SECRET_NAME}
    entry.update(overrides)
    return load_registry({"agent_trust": {"agents": [entry]}})


def test_hmac_happy_path(monkeypatch):
    monkeypatch.setenv(_SECRET_NAME, _SECRET)
    body = b'{"title": "quote run"}'
    ts = str(int(time.time()))
    agent, rule = verify_agent_hmac(
        "hooky", body, ts, _hmac_sig(_SECRET, ts, body),
        registry=_hmac_registry())
    assert agent is not None and agent.id == "hooky"
    assert rule == "ok"


def test_hmac_stale_timestamp_rejected(monkeypatch):
    monkeypatch.setenv(_SECRET_NAME, _SECRET)
    body = b"{}"
    ts = str(int(time.time()) - 4000)  # well past the 300s window
    agent, rule = verify_agent_hmac(
        "hooky", body, ts, _hmac_sig(_SECRET, ts, body),
        registry=_hmac_registry())
    assert agent is None
    assert rule == "bad_signature"


def test_hmac_bad_signature_rejected(monkeypatch):
    monkeypatch.setenv(_SECRET_NAME, _SECRET)
    body = b"{}"
    ts = str(int(time.time()))
    agent, rule = verify_agent_hmac(
        "hooky", body, ts, _hmac_sig("wrong-secret", ts, body),
        registry=_hmac_registry())
    assert agent is None
    assert rule == "bad_signature"


def test_hmac_missing_or_unresolvable_secret_ref_rejected(monkeypatch):
    body = b"{}"
    ts = str(int(time.time()))
    sig = _hmac_sig(_SECRET, ts, body)
    # No hmac_secret_ref on the entry: the scheme is not configured.
    reg = load_registry({"agent_trust": {"agents": [
        {"id": "hooky", "direction": "inbound"}]}})
    assert verify_agent_hmac("hooky", body, ts, sig, registry=reg) == (
        None, "hmac_not_configured")
    # Ref present but the named secret does not resolve: fail closed.
    monkeypatch.delenv(_SECRET_NAME, raising=False)
    assert verify_agent_hmac("hooky", body, ts, sig,
                             registry=_hmac_registry()) == (
        None, "secret_unresolved")


# ---- Ed25519 request envelope ------------------------------------------------


def _ed25519_pair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return priv, pub_hex


def _envelope_registry(pub_hex: str, **overrides):
    entry = {"id": "sig-bot", "direction": "inbound", "pubkey": pub_hex}
    entry.update(overrides)
    return load_registry({"agent_trust": {"agents": [entry]}})


@requires_crypto
def test_envelope_happy_path():
    priv, pub_hex = _ed25519_pair()
    now = time.time()
    ts = str(int(now))
    body = b'{"tool": "read_file"}'
    sig = priv.sign(envelope_message("sig-bot", ts, "nonce-1", body)).hex()
    agent, rule = verify_agent_envelope(
        "sig-bot", body, ts, "nonce-1", sig,
        registry=_envelope_registry(pub_hex), now=now)
    assert agent is not None and agent.id == "sig-bot"
    assert rule == "ok"


@requires_crypto
def test_envelope_replayed_nonce_rejected():
    priv, pub_hex = _ed25519_pair()
    reg = _envelope_registry(pub_hex)
    now = time.time()
    ts = str(int(now))
    body = b"{}"
    sig = priv.sign(envelope_message("sig-bot", ts, "nonce-2", body)).hex()
    first = verify_agent_envelope("sig-bot", body, ts, "nonce-2", sig,
                                  registry=reg, now=now)
    assert first[1] == "ok"
    agent, rule = verify_agent_envelope("sig-bot", body, ts, "nonce-2", sig,
                                        registry=reg, now=now)
    assert agent is None
    assert rule == "replay"


@requires_crypto
def test_envelope_future_timestamp_rejected():
    priv, pub_hex = _ed25519_pair()
    now = time.time()
    ts = str(int(now) + 120)  # beyond the 60s skew; signature itself is valid
    body = b"{}"
    sig = priv.sign(envelope_message("sig-bot", ts, "nonce-3", body)).hex()
    agent, rule = verify_agent_envelope(
        "sig-bot", body, ts, "nonce-3", sig,
        registry=_envelope_registry(pub_hex), now=now)
    assert agent is None
    assert rule == "future_ts"


@requires_crypto
def test_envelope_tampered_body_rejected():
    priv, pub_hex = _ed25519_pair()
    now = time.time()
    ts = str(int(now))
    sig = priv.sign(envelope_message("sig-bot", ts, "nonce-4", b"{}")).hex()
    agent, rule = verify_agent_envelope(
        "sig-bot", b'{"evil": true}', ts, "nonce-4", sig,
        registry=_envelope_registry(pub_hex), now=now)
    assert agent is None
    assert rule == "bad_signature"


@requires_crypto
def test_envelope_wrong_key_rejected():
    _, pub_hex = _ed25519_pair()
    other_priv, _ = _ed25519_pair()
    now = time.time()
    ts = str(int(now))
    body = b"{}"
    sig = other_priv.sign(envelope_message("sig-bot", ts, "nonce-5", body)).hex()
    agent, rule = verify_agent_envelope(
        "sig-bot", body, ts, "nonce-5", sig,
        registry=_envelope_registry(pub_hex), now=now)
    assert agent is None
    assert rule == "bad_signature"


@requires_crypto
def test_envelope_outbound_only_entry_rejected():
    priv, pub_hex = _ed25519_pair()
    now = time.time()
    ts = str(int(now))
    body = b"{}"
    sig = priv.sign(envelope_message("sig-bot", ts, "nonce-6", body)).hex()
    agent, rule = verify_agent_envelope(
        "sig-bot", body, ts, "nonce-6", sig,
        registry=_envelope_registry(pub_hex, direction="outbound"), now=now)
    assert agent is None
    assert rule == "direction"


# ---- mint round-trip preserves the identity fields ---------------------------


def test_mint_token_preserves_identity_fields():
    """mint_token's read-modify-write goes through _entry_from_agent; if that
    enumeration misses a field, minting a bearer silently erases it."""
    from maverick import external_agents as xa
    from maverick.agent_trust import lookup, put_agent
    put_agent({"id": AGENT, "direction": "inbound",
               "jwt_issuer": ISSUER, "jwt_audience": AUDIENCE,
               "jwks_file": "/keys/partner.pem",
               "hmac_secret_ref": _SECRET_NAME})
    xa.mint_token(AGENT, "rest")
    agent = lookup(AGENT)
    assert agent is not None
    assert agent.jwt_issuer == ISSUER
    assert agent.jwt_audience == AUDIENCE
    assert agent.jwks_file == "/keys/partner.pem"
    assert agent.hmac_secret_ref == _SECRET_NAME
    assert agent.rest_token.startswith("sha256:")


# ---- single-use ledger: durable, per-agent bounded ---------------------------


def test_claim_once_refuses_the_same_key_twice():
    from maverick.external_identity import claim_once
    now = time.time()
    assert claim_once("a", "nonce:x", expires_at=now + 300, now=now) is None
    assert claim_once("a", "nonce:x", expires_at=now + 300, now=now) == "replay"
    # A different agent's identical nonce is untouched (keys are partitioned).
    assert claim_once("b", "nonce:x", expires_at=now + 300, now=now) is None


def test_claim_once_survives_a_fresh_process_view():
    """The ledger is on disk, so a claim made by one dashboard worker binds
    every other worker — an in-process cache could not do this."""
    import importlib

    from maverick import external_identity
    now = time.time()
    assert external_identity.claim_once(
        "a", "nonce:worker", expires_at=now + 300, now=now) is None
    reloaded = importlib.reload(external_identity)
    assert reloaded.claim_once(
        "a", "nonce:worker", expires_at=now + 300, now=now) == "replay"


def test_claim_once_budget_is_per_agent(monkeypatch):
    """A saturated agent is refused alone; it can never lock out other agents
    (a single global cache would let two chatty agents deny everyone else)."""
    from maverick import external_identity
    monkeypatch.setattr(external_identity, "_MAX_KEYS_PER_AGENT", 3)
    now = time.time()
    for i in range(3):
        assert external_identity.claim_once(
            "noisy", f"nonce:{i}", expires_at=now + 300, now=now) is None
    assert external_identity.claim_once(
        "noisy", "nonce:overflow", expires_at=now + 300,
        now=now) == "replay_budget_full"
    assert external_identity.claim_once(
        "quiet", "nonce:0", expires_at=now + 300, now=now) is None
    # Expired keys prune, so the budget recovers on its own.
    later = now + 600
    assert external_identity.claim_once(
        "noisy", "nonce:after-expiry", expires_at=later + 300,
        now=later) is None


def test_claim_once_fails_closed_on_a_corrupt_ledger():
    from maverick.external_identity import ReplayStoreError, _replay_path, claim_once
    now = time.time()
    assert claim_once("a", "nonce:1", expires_at=now + 300, now=now) is None
    _replay_path().write_text("{not json", encoding="utf-8")
    with pytest.raises(ReplayStoreError):
        claim_once("a", "nonce:2", expires_at=now + 300, now=now)


@requires_crypto
def test_envelope_replay_is_refused():
    priv, pub_hex = _ed25519_pair()
    now = time.time()
    ts = str(int(now))
    body = b'{"op": "post"}'
    sig = priv.sign(envelope_message("sig-bot", ts, "nonce-once", body)).hex()
    reg = _envelope_registry(pub_hex)
    agent, rule = verify_agent_envelope(
        "sig-bot", body, ts, "nonce-once", sig, registry=reg, now=now)
    assert agent is not None and rule == "ok"
    agent, rule = verify_agent_envelope(
        "sig-bot", body, ts, "nonce-once", sig, registry=reg, now=now)
    assert agent is None
    assert rule == "replay"


def test_hmac_replay_of_identical_bytes_is_refused(monkeypatch):
    """The signature is deterministic over (secret, timestamp, body), so a
    captured request replayed inside the freshness window presents the same
    signature and must not authenticate twice."""
    monkeypatch.setenv(_SECRET_NAME, _SECRET)
    body = b'{"title": "quote run"}'
    ts = str(int(time.time()))
    sig = _hmac_sig(_SECRET, ts, body)
    agent, rule = verify_agent_hmac(
        "hooky", body, ts, sig, registry=_hmac_registry())
    assert agent is not None and rule == "ok"
    agent, rule = verify_agent_hmac(
        "hooky", body, ts, sig, registry=_hmac_registry())
    assert agent is None
    assert rule == "replay"


# ---- Identity federation (https JWKS endpoints) ------------------------------


@requires_crypto
def test_jwt_federates_against_an_https_jwks_endpoint(monkeypatch, rsa_keys):
    priv_pem, _, pub = rsa_keys
    from jwt.algorithms import RSAAlgorithm

    jwk = json.loads(RSAAlgorithm.to_jwk(pub))
    jwk["kid"] = "k1"
    fetched: list[str] = []

    def fake_remote(jwt_mod, url):
        fetched.append(url)
        return external_identity._StaticJWKS(jwt_mod, [jwk])

    monkeypatch.setattr(external_identity, "_remote_jwks_client", fake_remote)
    reg = _registry(jwks_file="https://login.example.com/common/discovery/keys")
    agent, rule = verify_agent_jwt(_mint(priv_pem), registry=reg)
    assert agent is not None and agent.id == AGENT
    assert rule == "ok"
    assert fetched == ["https://login.example.com/common/discovery/keys"]


@requires_crypto
def test_jwt_plaintext_jwks_endpoint_is_refused(rsa_keys):
    priv_pem, _, _ = rsa_keys
    reg = _registry(jwks_file="http://login.example.com/keys")
    agent, rule = verify_agent_jwt(_mint(priv_pem), registry=reg)
    assert agent is None
    assert rule == "jwks_unavailable"


@requires_crypto
def test_jwt_federated_endpoint_failure_fails_closed(monkeypatch, rsa_keys):
    priv_pem, _, _ = rsa_keys
    monkeypatch.setattr(
        external_identity, "_remote_jwks_client", lambda jwt_mod, url: None,
    )
    reg = _registry(jwks_file="https://login.example.com/keys")
    agent, rule = verify_agent_jwt(_mint(priv_pem), registry=reg)
    assert agent is None
    assert rule == "jwks_unavailable"
