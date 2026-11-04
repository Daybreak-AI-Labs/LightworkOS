"""A PEM private key must be redacted IN FULL, not just its header line.

Previously, the private_key_pem pattern matched
only `-----BEGIN ... PRIVATE KEY-----`, so redact() replaced just that marker
and left the base64 key body + END line in cleartext. A private key pasted
into a goal / tool output / the blackboard would persist its actual secret
material in the world model and displayed output with only the header redacted.
"""
from __future__ import annotations

from maverick.safety.secret_detector import redact

# Synthetic non-secret fixture body (the PEM regex matches the BEGIN..END
# structure, not the body content) -- detect-secrets entropy plugin flags it.
_KEY_BODY = (
    "MIIEpAIBAAKCAQEA7Xy2hZ9qF8s1J3kLmN0pQrStUvWxYz0123456789abcdef\n"  # pragma: allowlist secret
    "GHIJKLMNOPqrstuvwxyzABCDEFabcdef0123456789+/aaaaaaaaaaaaaaaaaa\n"  # pragma: allowlist secret
    "bbbbbbbbbbbbbbbbbbccccccccccccccccccddddddddddddddddddeeeeeeee=="  # pragma: allowlist secret
)


def _pem(kind: str = "RSA ") -> str:
    return (f"-----BEGIN {kind}PRIVATE KEY-----\n{_KEY_BODY}\n"  # pragma: allowlist secret
            f"-----END {kind}PRIVATE KEY-----")


def test_full_pem_block_is_fully_redacted():
    text = f"my key is:\n{_pem()}\nthanks"
    red, matches = redact(text)
    assert matches
    # None of the key material may survive.
    assert "MIIEpAIBAAKCAQEA" not in red
    assert "eeeeeeee==" not in red
    assert "-----END RSA PRIVATE KEY-----" not in red  # pragma: allowlist secret
    assert "-----BEGIN RSA PRIVATE KEY-----" not in red  # pragma: allowlist secret
    # Surrounding text is preserved.
    assert "my key is:" in red and "thanks" in red


def test_large_pem_beyond_8192_chars_is_fully_redacted():
    # Regression: the 8192-char bound meant a PEM whose body+whitespace between
    # BEGIN and END exceeded 8192 chars left its TRAILING key material and the
    # END line in cleartext -- the leak got worse on the largest keys. Build a
    # body well over 8192 chars ending in a unique marker that must not survive.
    big_body = ("A" * 9000) + "\nTRAILINGSECRET=="  # > 8192 chars before END
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"  # pragma: allowlist secret
        f"{big_body}\n"
        "-----END RSA PRIVATE KEY-----"  # pragma: allowlist secret
    )
    red, matches = redact(text)
    assert matches
    assert "TRAILINGSECRET==" not in red
    assert "-----END RSA PRIVATE KEY-----" not in red  # pragma: allowlist secret


def test_openssh_and_ec_keys_fully_redacted():
    for kind in ("OPENSSH ", "EC ", ""):
        red, _ = redact(_pem(kind))
        assert "MIIEpAIBAAKCAQEA" not in red, kind
        assert "eeeeeeee==" not in red, kind


def test_bare_begin_marker_without_end_still_flagged():
    # A truncated/malformed marker (no END) must still be caught, not ignored.
    red, matches = redact("-----BEGIN RSA PRIVATE KEY-----")  # pragma: allowlist secret
    assert matches
    assert "[REDACTED:" in red


def test_pem_body_without_end_marker_is_fully_redacted():
    # The leak: a header WITH a base64 body but NO END marker (a key truncated
    # by a buffer/summary boundary). The prior pattern made the END group
    # optional, so this matched only the header and left the body in cleartext.
    red, matches = redact(f"here is a key:\n-----BEGIN PRIVATE KEY-----\n{_KEY_BODY}")  # pragma: allowlist secret
    assert matches
    assert "MIIEpAIBAAKCAQEA" not in red  # no key material survives
    assert "eeeeeeee==" not in red
    assert "[REDACTED:private_key_pem]" in red
    assert "here is a key:" in red  # surrounding text preserved


def test_redact_proven_does_not_falsely_certify_truncated_pem():
    # provable_redaction composes this detector; the leak made it issue a
    # PROVEN-clean certificate over text that still held key material.
    from maverick.provable_redaction import redact_proven
    proof = redact_proven(f"-----BEGIN PRIVATE KEY-----\n{_KEY_BODY}")  # pragma: allowlist secret
    assert "MIIEpAIBAAKCAQEA" not in proof.redacted
    assert proof.proven  # genuinely clean, not a false certificate
    assert proof.residual == []


def test_audit_event_redacts_truncated_pem_in_tool_payload():
    # The audit writer truncates summaries, which can strip a key's END marker;
    # _redact_event composes the same detector, so the body must not reach disk.
    from maverick.audit.writer import _redact_event
    out = _redact_event({
        "kind": "tool_result",
        "output_summary": f"-----BEGIN PRIVATE KEY-----\n{_KEY_BODY}",  # pragma: allowlist secret
    })
    assert "MIIEpAIBAAKCAQEA" not in out["output_summary"]
    assert "[REDACTED:private_key_pem]" in out["output_summary"]
