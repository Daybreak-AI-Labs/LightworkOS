"""Per-call scoped capability tokens -- "token exchange for every tool call".

The agent exchanges its run-long grant for a freshly minted, single-tool,
short-lived, signed token at the tool chokepoint. These tests cover the
exchange unit in isolation: scoping (the token authorizes ONE tool), expiry,
single-use replay defense, signature tamper-evidence, default rejection of
unsigned tokens, and the off-by-default enable gate.
"""
import time

import pytest
from maverick.capability import Capability
from maverick.tool_token import (
    ToolToken,
    _ReplayCache,
    mint_tool_token,
    tool_tokens_enabled,
    verify_tool_token,
)


def _crypto_keypair():
    """A real Ed25519 keypair, or skip when cryptography is unavailable/broken."""
    try:
        from maverick.audit.signing import _generate_keypair, _have_crypto
        if not _have_crypto():
            pytest.skip("cryptography not installed")
        priv, pub, _ = _generate_keypair()
    except BaseException:  # noqa: BLE001 -- pyo3 PanicException isn't an Exception
        pytest.skip("cryptography unavailable/broken in this environment")
    return priv.hex(), pub.hex()


# --- scoping: the minted token authorizes exactly one tool -----------------

def test_minted_token_is_scoped_to_one_tool():
    cap = Capability(principal="agent:coder-1")  # empty allow == all tools
    token = mint_tool_token(cap, "read_file", private_key_hex=None)
    assert token.tool == "read_file"
    # The scoped capability permits the one tool and nothing else, even though
    # the parent grant was all-permissive.
    assert token.capability.permits("read_file") is True
    assert token.capability.permits("shell") is False


def test_exchange_never_broadens_a_restricted_grant():
    # Parent only allows read_file; minting for it stays scoped, and a token
    # can never be minted that broadens to a denied/unlisted tool.
    cap = Capability(principal="p", allow_tools=frozenset({"read_file"}))
    token = mint_tool_token(cap, "read_file", private_key_hex=None)
    assert token.capability.permits("read_file") is True
    # Even if someone mints for an unlisted tool, the attenuation intersects to
    # nothing -> the token permits nothing.
    sneaky = mint_tool_token(cap, "shell", private_key_hex=None)
    assert sneaky.capability.permits("shell") is False


# --- signature roundtrip + tamper evidence ---------------------------------

def test_signed_token_verifies_and_tamper_is_caught():
    priv, pub = _crypto_keypair()
    cap = Capability(principal="agent:coder-1", max_risk="medium")
    token = mint_tool_token(cap, "read_file", private_key_hex=priv)
    assert token.signature is not None
    assert verify_tool_token(
        token, "read_file", public_key_hex=pub, replay_cache=_ReplayCache(),
    ) is True


def test_tampered_tool_fails_signature():
    priv, pub = _crypto_keypair()
    cap = Capability(principal="p")
    token = mint_tool_token(cap, "read_file", private_key_hex=priv)
    # Forge a broader-tool token reusing the original signature: the signed
    # bytes no longer match, so verification must fail.
    forged = ToolToken(
        capability=cap.attenuate(allow={"shell"}),
        tool="shell",
        jti=token.jti,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        signature=token.signature,
        key_id=token.key_id,
    )
    assert verify_tool_token(
        forged, "shell", public_key_hex=pub, replay_cache=_ReplayCache(),
    ) is False


def test_tool_mismatch_rejected():
    cap = Capability(principal="p")
    token = mint_tool_token(cap, "read_file", private_key_hex=None)
    assert verify_tool_token(
        token, "shell", replay_cache=_ReplayCache(),
    ) is False


# --- expiry ----------------------------------------------------------------

def test_expired_token_rejected():
    cap = Capability(principal="p")
    now = time.time()
    token = mint_tool_token(cap, "read_file", ttl=10, now=now, private_key_hex=None)
    # 11s later the 10s token is expired.
    assert verify_tool_token(
        token, "read_file", now=now + 11, replay_cache=_ReplayCache(),
    ) is False
    # still inside the window it verifies.
    assert verify_tool_token(
        token, "read_file", now=now + 5, replay_cache=_ReplayCache(), require_signature=False,
    ) is True


# --- single-use / replay defense -------------------------------------------

def test_token_is_single_use():
    cap = Capability(principal="p")
    cache = _ReplayCache()
    token = mint_tool_token(cap, "read_file", private_key_hex=None)
    assert verify_tool_token(token, "read_file", replay_cache=cache, require_signature=False) is True
    # A second verify of the same nonce is a replay.
    assert verify_tool_token(token, "read_file", replay_cache=cache) is False


def test_distinct_calls_get_distinct_nonces():
    cap = Capability(principal="p")
    a = mint_tool_token(cap, "read_file", private_key_hex=None)
    b = mint_tool_token(cap, "read_file", private_key_hex=None)
    assert a.jti != b.jti


def test_replay_cache_evicts_expired():
    cache = _ReplayCache(maxsize=8)
    now = time.time()
    assert cache.check_and_add("old", expires_at=now + 1, now=now) is True
    # Far in the future the expired nonce is purged, so the same id is fresh
    # again rather than wrongly remembered forever.
    assert cache.check_and_add("old", expires_at=now + 100, now=now + 50) is True


def test_overflow_evicts_soonest_to_expire_not_oldest_inserted():
    # A still-live nonce must survive capacity pressure while later-expiring
    # entries exist, so a captured token cannot be replayed within its TTL by
    # flooding the cache (regression: oldest-inserted eviction dropped it).
    cache = _ReplayCache(maxsize=2)
    now = time.time()
    # "captured" expires last -> should never be evicted while shorter-lived
    # entries remain, even though it was inserted first.
    assert cache.check_and_add("captured", expires_at=now + 100, now=now) is True
    assert cache.check_and_add("filler1", expires_at=now + 10, now=now) is True
    assert cache.check_and_add("filler2", expires_at=now + 20, now=now) is True
    # Cache is over capacity; the soonest-to-expire filler was evicted, not the
    # live captured nonce. Replaying it is still rejected.
    assert cache.check_and_add("captured", expires_at=now + 100, now=now) is False


# --- unsigned fallback -----------------------------------------------------

def test_unsigned_token_requires_explicit_unsigned_mode(monkeypatch):
    # Force the no-key path (as if cryptography were absent) so the token is
    # genuinely unsigned -- otherwise mint falls back to the deployment key.
    monkeypatch.setattr("maverick.tool_token._deployment_keypair", lambda: None)
    cap = Capability(principal="p")
    token = mint_tool_token(cap, "read_file", private_key_hex=None)
    assert token.signature is None
    # Unsigned tokens are refused by default so exported verifier consumers do
    # not accidentally trust attacker-controlled ToolToken objects.
    assert verify_tool_token(
        token, "read_file", replay_cache=_ReplayCache(),
    ) is False
    # Same-process fallback checks must opt in explicitly.
    assert verify_tool_token(
        token, "read_file", require_signature=False, replay_cache=_ReplayCache(),
    ) is True


def test_forged_unsigned_token_rejected_by_default():
    now = time.time()
    forged = ToolToken(
        capability=Capability(principal="attacker", allow_tools=frozenset({"shell"})),
        tool="shell",
        jti="attacker-fresh-nonce",
        issued_at=now,
        expires_at=now + 30,
        signature=None,
    )
    assert verify_tool_token(forged, "shell", replay_cache=_ReplayCache()) is False


# --- enable gate -----------------------------------------------------------

def test_disabled_by_default(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.delenv("MAVERICK_TOOL_TOKENS", raising=False)
    assert tool_tokens_enabled() is False


def test_enabled_via_env(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setenv("MAVERICK_TOOL_TOKENS", "1")
    assert tool_tokens_enabled() is True


def test_enabled_via_config(monkeypatch):
    monkeypatch.delenv("MAVERICK_TOOL_TOKENS", raising=False)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {"capabilities": {"per_call_tokens": True}},
    )
    assert tool_tokens_enabled() is True
