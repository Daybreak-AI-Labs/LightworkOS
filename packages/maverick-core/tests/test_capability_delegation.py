"""capability_delegation: privilege-escalation validation of delegation graphs."""
from __future__ import annotations

from maverick.tools.capability_delegation import capability_delegation


def _v(roots, grants):
    return capability_delegation().fn({"op": "validate", "roots": roots, "grants": grants})


def test_valid_chain():
    out = _v({"admin": ["deploy"]}, [
        {"from": "admin", "to": "alice", "cap": "deploy"},
        {"from": "alice", "to": "bob", "cap": "deploy"},
    ])
    assert out.startswith("VALID")
    assert "bob: deploy" in out and "alice: deploy" in out


def test_order_independent_fixpoint():
    # bob<-alice listed before alice<-admin; fixpoint still resolves both
    out = _v({"admin": ["deploy"]}, [
        {"from": "alice", "to": "bob", "cap": "deploy"},
        {"from": "admin", "to": "alice", "cap": "deploy"},
    ])
    assert out.startswith("VALID")


def test_escalation_flagged():
    out = _v({"admin": ["deploy"]}, [
        {"from": "mallory", "to": "bob", "cap": "deploy"},  # mallory doesn't hold it
    ])
    assert out.startswith("INVALID")
    assert "mallory -> bob" in out and "does not hold 'deploy'" in out


def test_circular_without_root_is_invalid():
    out = _v({}, [
        {"from": "a", "to": "b", "cap": "x"},
        {"from": "b", "to": "a", "cap": "x"},
    ])
    assert out.startswith("INVALID")
    assert "2 unauthorized" in out


def test_wrong_capability_not_granted():
    out = _v({"admin": ["read"]}, [{"from": "admin", "to": "alice", "cap": "write"}])
    assert out.startswith("INVALID") and "write" in out


def test_errors():
    t = capability_delegation()
    assert t.fn({"op": "validate", "grants": "x"}).startswith("ERROR")
    assert t.fn({"op": "validate", "roots": [], "grants": []}).startswith("ERROR")
    assert t.fn({"op": "validate", "grants": [{"from": "a"}]}).startswith("ERROR")
    assert t.fn({"op": "nope", "grants": []}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "capability_delegation" in names
