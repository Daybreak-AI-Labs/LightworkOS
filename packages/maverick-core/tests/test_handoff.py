"""Verified agent-to-agent handoffs (maverick.handoff): mint + the verifier's
trust checks. The verifier is the trust frame over agent_bus (transport) +
capability (the grant): it must accept an authentic, scoped, fresh handoff and
reject every tampering, escalation, impersonation, and replay path."""
from __future__ import annotations

import pytest
from maverick.capability import Capability
from maverick.handoff import (
    Envelope,
    NonceCache,
    mint_handoff,
    verify_handoff,
)

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

crypto = pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")


def _keypair() -> tuple[str, str]:
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return priv_hex, pub_hex


def _grant(principal="agent:finance_payroll-1", **kw) -> Capability:
    # A typical attenuated handoff grant: read-only, scoped, time-boxed.
    kw.setdefault("allow_tools", frozenset({"read_file", "knowledge_search"}))
    kw.setdefault("max_risk", "low")
    return Capability(principal=principal, **kw)


@crypto
def test_authentic_handoff_verifies_and_returns_the_grant():
    priv, pub = _keypair()
    grant = _grant()
    env = mint_handoff(
        sender="agent:gtm_commissions-2", recipient=grant.principal,
        task="reconcile Q2 commission accruals", grant=grant,
        issuer_private_hex=priv, issuer_pub_hex=pub,
        required_tools=("read_file",),
    )
    v = verify_handoff(env, trusted_issuers={pub}, now=env.ts)
    assert v.ok and v.rule == "ok"
    # The receiver runs under the delegated grant, nothing more (least privilege).
    assert v.grant is grant
    assert v.grant.permits("read_file") and not v.grant.permits("shell")


@crypto
def test_untrusted_issuer_is_rejected():
    priv, pub = _keypair()
    _, other_pub = _keypair()
    env = mint_handoff(
        sender="a", recipient="agent:finance_payroll-1", task="t", grant=_grant(),
        issuer_private_hex=priv, issuer_pub_hex=pub,
    )
    # Signed by `pub`, but only `other_pub` is anchored as trusted.
    v = verify_handoff(env, trusted_issuers={other_pub}, now=env.ts)
    assert not v.ok and v.rule == "untrusted_issuer"


@crypto
def test_tampering_any_field_breaks_the_signature():
    priv, pub = _keypair()
    env = mint_handoff(
        sender="a", recipient="agent:finance_payroll-1", task="reconcile", grant=_grant(),
        issuer_private_hex=priv, issuer_pub_hex=pub,
    )
    import dataclasses
    tampered = dataclasses.replace(env, task="reconcile AND wire the payout")
    v = verify_handoff(tampered, trusted_issuers={pub}, now=env.ts)
    assert not v.ok and v.rule == "tampered"


@crypto
def test_forged_grant_signature_is_rejected():
    priv, pub = _keypair()
    env = mint_handoff(
        sender="a", recipient="agent:finance_payroll-1", task="t", grant=_grant(),
        issuer_private_hex=priv, issuer_pub_hex=pub,
    )
    import dataclasses
    forged = dataclasses.replace(env, grant_sig="00" * 64)
    v = verify_handoff(forged, trusted_issuers={pub}, now=env.ts)
    # The forged grant sig fails to verify (it also breaks the envelope sig; the
    # grant check fires first either way -- both are rejections).
    assert not v.ok and v.rule in ("bad_grant_sig", "tampered")


@crypto
def test_no_privilege_escalation_in_a_handoff():
    # A handoff grant is an attenuation of the delegator's; the verifier returns
    # exactly it, so a receiver can never gain a tool the grant omits.
    priv, pub = _keypair()
    grant = _grant(allow_tools=frozenset({"read_file"}), max_risk="low")
    env = mint_handoff(
        sender="a", recipient=grant.principal, task="t", grant=grant,
        issuer_private_hex=priv, issuer_pub_hex=pub,
        required_tools=("read_file",),
    )
    v = verify_handoff(env, trusted_issuers={pub}, now=env.ts)
    assert v.ok
    for forbidden in ("shell", "write_file", "code_exec"):
        assert not v.grant.permits(forbidden)


@crypto
def test_required_tool_outside_the_grant_is_out_of_scope():
    priv, pub = _keypair()
    grant = _grant(allow_tools=frozenset({"read_file"}))
    env = mint_handoff(
        sender="a", recipient=grant.principal, task="t", grant=grant,
        issuer_private_hex=priv, issuer_pub_hex=pub,
        required_tools=("read_file", "shell"),   # shell is not in the grant
    )
    v = verify_handoff(env, trusted_issuers={pub}, now=env.ts)
    assert not v.ok and v.rule == "out_of_scope"


@crypto
def test_expired_grant_is_rejected():
    priv, pub = _keypair()
    grant = _grant(expires_at=1000.0)
    env = mint_handoff(
        sender="a", recipient=grant.principal, task="t", grant=grant,
        issuer_private_hex=priv, issuer_pub_hex=pub, ts=900.0,
    )
    v = verify_handoff(env, trusted_issuers={pub}, now=1500.0, max_age_s=10_000)
    assert not v.ok and v.rule == "grant_expired"


@crypto
def test_replay_is_rejected_by_the_nonce_cache():
    priv, pub = _keypair()
    env = mint_handoff(
        sender="a", recipient="agent:finance_payroll-1", task="t", grant=_grant(),
        issuer_private_hex=priv, issuer_pub_hex=pub,
    )
    cache = NonceCache()
    first = verify_handoff(env, trusted_issuers={pub}, nonce_cache=cache, now=env.ts)
    second = verify_handoff(env, trusted_issuers={pub}, nonce_cache=cache, now=env.ts)
    assert first.ok
    assert not second.ok and second.rule == "replay"


@crypto
def test_stale_and_future_timestamps_are_rejected():
    priv, pub = _keypair()
    env = mint_handoff(
        sender="a", recipient="agent:finance_payroll-1", task="t", grant=_grant(),
        issuer_private_hex=priv, issuer_pub_hex=pub, ts=1000.0,
    )
    stale = verify_handoff(env, trusted_issuers={pub}, now=1000.0 + 10_000, max_age_s=300)
    assert not stale.ok and stale.rule == "stale"
    future = verify_handoff(env, trusted_issuers={pub}, now=1000.0 - 1000, clock_skew_s=60)
    assert not future.ok and future.rule == "future_ts"


@crypto
def test_grant_swap_to_a_different_recipient_is_caught():
    # A validly-signed envelope whose grant is for someone OTHER than the named
    # recipient must be refused (defense in depth behind the signature).
    priv, pub = _keypair()
    from maverick.capability import sign_capability
    from maverick.handoff import _sign_ed25519
    victim_grant = _grant(principal="agent:victim-9")
    env = Envelope(
        sender="agent:attacker-1", recipient="agent:attacker-1",
        task="do it", grant=victim_grant, nonce="n1", ts=1000.0,
        grant_sig=sign_capability(victim_grant, priv), issuer_pub=pub,
    )
    import dataclasses
    env = dataclasses.replace(env, sig=_sign_ed25519(priv, env.signing_bytes()))
    v = verify_handoff(env, trusted_issuers={pub}, now=1000.0)
    assert not v.ok and v.rule == "grant_recipient_mismatch"


@crypto
def test_mint_refuses_a_grant_not_minted_for_the_recipient():
    priv, pub = _keypair()
    with pytest.raises(ValueError):
        mint_handoff(
            sender="a", recipient="agent:b-1", task="t",
            grant=_grant(principal="agent:someone-else-1"),
            issuer_private_hex=priv, issuer_pub_hex=pub,
        )


def test_fails_closed_without_cryptography(monkeypatch):
    # No crypto => the verifier cannot establish authenticity, so it must DENY
    # rather than fall open.
    monkeypatch.setattr("maverick.audit.signing._have_crypto", lambda: False)
    env = Envelope(
        sender="a", recipient="agent:b-1", task="t", grant=_grant(),
        nonce="n", ts=1000.0, grant_sig="x", issuer_pub="y", sig="z",
    )
    v = verify_handoff(env, trusted_issuers={"y"}, now=1000.0)
    assert not v.ok and v.rule == "no_crypto"


def test_unsigned_envelope_is_rejected():
    # An envelope that was never signed (no sig frame) is rejected even before
    # the trust-anchor check.
    if not _HAVE_CRYPTO:
        pytest.skip("cryptography not installed")
    env = Envelope(
        sender="a", recipient="agent:b-1", task="t", grant=_grant(),
        nonce="n", ts=1000.0,
    )
    v = verify_handoff(env, trusted_issuers={"y"}, now=1000.0)
    assert not v.ok and v.rule == "unsigned"


@crypto
def test_handoff_rejects_oversized_or_nonfinite_security_fields():
    priv, pub = _keypair()
    with pytest.raises(ValueError, match="too large|exceeds"):
        mint_handoff(
            sender="a", recipient="agent:finance_payroll-1",
            task="x" * (32 * 1024 + 1), grant=_grant(),
            issuer_private_hex=priv, issuer_pub_hex=pub,
        )
    with pytest.raises(ValueError, match="required_tools exceeds"):
        mint_handoff(
            sender="a", recipient="agent:finance_payroll-1", task="t",
            grant=_grant(), issuer_private_hex=priv, issuer_pub_hex=pub,
            required_tools=(f"tool-{i}" for i in range(129)),
        )
    with pytest.raises(ValueError, match="grant expiry is invalid"):
        mint_handoff(
            sender="a", recipient="agent:finance_payroll-1", task="t",
            grant=_grant(expires_at=float("inf")),
            issuer_private_hex=priv, issuer_pub_hex=pub,
        )


@crypto
def test_handoff_verifier_never_raises_on_nonfinite_timestamp():
    env = Envelope(
        sender="a", recipient="agent:finance_payroll-1", task="t",
        grant=_grant(), nonce="n", ts=float("nan"),
        grant_sig="x", issuer_pub="y", sig="z",
    )
    verdict = verify_handoff(env, trusted_issuers={"y"}, now=1000.0)
    assert not verdict.ok and verdict.rule == "malformed"


@crypto
def test_nonce_cache_saturation_fails_closed_then_prunes_expired_entries():
    priv, pub = _keypair()
    first = mint_handoff(
        sender="a", recipient="agent:finance_payroll-1", task="one", grant=_grant(),
        issuer_private_hex=priv, issuer_pub_hex=pub, ts=1000.0, nonce="n1",
    )
    second = mint_handoff(
        sender="a", recipient="agent:finance_payroll-1", task="two", grant=_grant(),
        issuer_private_hex=priv, issuer_pub_hex=pub, ts=1001.0, nonce="n2",
    )
    cache = NonceCache(max_entries=1)
    assert verify_handoff(
        first, trusted_issuers={pub}, nonce_cache=cache, now=1000.0
    ).ok
    full = verify_handoff(
        second, trusted_issuers={pub}, nonce_cache=cache, now=1001.0
    )
    assert not full.ok and full.rule == "nonce_cache_full"

    replacement = mint_handoff(
        sender="a", recipient="agent:finance_payroll-1", task="three", grant=_grant(),
        issuer_private_hex=priv, issuer_pub_hex=pub, ts=1301.0, nonce="n3",
    )
    assert verify_handoff(
        replacement, trusted_issuers={pub}, nonce_cache=cache, now=1301.0
    ).ok
