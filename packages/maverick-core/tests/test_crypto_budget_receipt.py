"""crypto_budget_receipt: HMAC-signed budget receipts."""
from __future__ import annotations

from maverick.tools.crypto_budget_receipt import crypto_budget_receipt


def _run(**kw):
    return crypto_budget_receipt().fn(kw)


def test_issue_format_and_deterministic():
    a = _run(op="issue", goal_id="g1", dollars=12.5, key="secret")
    b = _run(op="issue", goal_id="g1", dollars=12.5, key="secret")
    assert a == b  # deterministic given key
    assert a.startswith("OK: g1|12.50|")
    body = a[len("OK: "):]
    assert len(body.split("|")) == 3


def test_issue_verify_roundtrip():
    issued = _run(op="issue", goal_id="g1", dollars=12.5, key="secret")
    out = _run(op="verify", receipt=issued, key="secret")
    assert out.startswith("VALID") and "goal=g1" in out and "dollars=12.50" in out


def test_verify_wrong_key():
    issued = _run(op="issue", goal_id="g1", dollars=12.5, key="secret")
    out = _run(op="verify", receipt=issued, key="other")
    assert out.startswith("INVALID") and "signature mismatch" in out


def test_verify_tampered_amount():
    out = _run(op="verify", receipt="g1|999.00|" + "0" * 64, key="secret")
    assert out.startswith("INVALID")


def test_verify_malformed():
    out = _run(op="verify", receipt="not-a-receipt", key="secret")
    assert out.startswith("INVALID") and "malformed" in out


def test_errors():
    t = crypto_budget_receipt()
    assert t.fn({"op": "issue", "key": "k"}).startswith("ERROR")  # no goal
    assert t.fn({"op": "issue", "goal_id": "g", "dollars": -1, "key": "k"}).startswith("ERROR")
    assert t.fn({"op": "issue", "goal_id": "g", "dollars": 1}).startswith("ERROR")  # no key
    assert t.fn({"op": "nope", "key": "k"}).startswith("ERROR")
