"""capability_negotiation: capability negotiation protocol."""
from __future__ import annotations

from maverick.tools.capability_negotiation import capability_negotiation


def _run(**kw):
    return capability_negotiation().fn({"op": "negotiate", **kw})


def test_full_grant_success():
    out = _run(requested=["read", "write"], allowed=["read", "write", "admin"])
    assert out.startswith("SUCCESS")
    assert "granted: [read, write]" in out
    assert "denied: []" in out


def test_partial_grant_no_required_is_success():
    out = _run(requested=["read", "delete"], allowed=["read"])
    # No required set -> partial grant still succeeds.
    assert out.startswith("SUCCESS")
    assert "granted: [read]" in out
    assert "delete: not offered" in out


def test_required_unmet_fails():
    out = _run(requested=["read", "delete"], allowed=["read"], required=["delete"])
    assert out.startswith("FAILURE")
    assert "unmet required: [delete]" in out


def test_explicit_deny_reason():
    out = _run(requested=["read", "admin"], allowed=["read", "admin"], deny=["admin"])
    assert "admin: explicitly denied" in out
    assert "granted: [read]" in out


def test_deny_overrides_allowed_and_fails_required():
    out = _run(requested=["admin"], allowed=["admin"], deny=["admin"], required=["admin"])
    assert out.startswith("FAILURE")
    assert "admin: explicitly denied" in out


def test_errors_and_unknown_op():
    t = capability_negotiation()
    assert t.fn({"op": "negotiate", "allowed": ["x"]}).startswith("ERROR")
    assert t.fn({"op": "negotiate", "requested": ["x"]}).startswith("ERROR")
    assert t.fn({"op": "nope", "requested": [], "allowed": []}).startswith("ERROR")


def test_factory_identity():
    t = capability_negotiation()
    assert t.name == "capability_negotiation"
    assert t.parallel_safe is True
