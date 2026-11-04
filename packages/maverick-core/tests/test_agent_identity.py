"""Tests for the agent_identity tool (maverick.tools.agent_identity)."""
from __future__ import annotations

from maverick.tools.agent_identity import agent_identity

# ---- agent_identity ----

def test_identity_stable_id():
    t = agent_identity()
    a = t.fn({"op": "id", "name": "verifier"})
    b = t.fn({"op": "id", "name": "verifier"})
    assert a == b and a.startswith("agent:")
    assert t.fn({"op": "id", "name": "coder"}) != a


def test_identity_sign_verify_roundtrip():
    t = agent_identity()
    signed = t.fn({"op": "sign", "name": "coder", "key": "s3cret", "payload": {"diff": "abc", "n": 1}})
    sig = [ln for ln in signed.splitlines() if ln.startswith("signature: ")][0].split(": ", 1)[1]
    ok = t.fn({"op": "verify", "name": "coder", "key": "s3cret", "payload": {"n": 1, "diff": "abc"}, "signature": sig})
    assert ok == "VALID"
    bad = t.fn({"op": "verify", "name": "coder", "key": "wrong", "payload": {"diff": "abc", "n": 1}, "signature": sig})
    assert bad == "INVALID"


def test_identity_validation():
    t = agent_identity()
    assert t.fn({"op": "sign", "name": "x"}).startswith("ERROR")
    assert t.fn({"op": "bogus"}).startswith("ERROR")
