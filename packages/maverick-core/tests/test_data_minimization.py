"""data_minimization: purpose-limitation / field-allowlist checks."""
from __future__ import annotations

from maverick.tools.data_minimization import data_minimization


def _c(collected, allowed, required=None, purpose=None):
    args = {"op": "check", "collected": collected, "allowed": allowed}
    if required is not None:
        args["required"] = required
    if purpose is not None:
        args["purpose"] = purpose
    return data_minimization().fn(args)


def test_minimal():
    out = _c(["name", "email"], ["name", "email", "phone"], purpose="billing")
    assert out.startswith("MINIMAL")
    assert "purpose 'billing'" in out


def test_over_collection_flagged():
    out = _c(["name", "ssn", "dob"], ["name"], purpose="newsletter")
    assert out.startswith("VIOLATION")
    assert "over-collected (not permitted): dob, ssn" in out


def test_under_collection_flagged():
    out = _c(["name"], ["name", "email"], required=["name", "email"])
    assert out.startswith("VIOLATION")
    assert "under-collected (required, absent): email" in out


def test_both_over_and_under():
    out = _c(["name", "ssn"], ["name", "email"], required=["name", "email"])
    assert "over-collected (not permitted): ssn" in out
    assert "under-collected (required, absent): email" in out


def test_collected_object_keys_used():
    out = _c({"name": "Jo", "ssn": "x"}, ["name"])
    assert out.startswith("VIOLATION") and "ssn" in out


def test_errors():
    t = data_minimization()
    assert t.fn({"op": "check", "collected": "x", "allowed": ["a"]}).startswith("ERROR")
    assert t.fn({"op": "check", "collected": ["a"], "allowed": "x"}).startswith("ERROR")
    assert t.fn({"op": "check", "collected": ["a"], "allowed": ["a"], "required": "x"}).startswith("ERROR")
    assert t.fn({"op": "nope", "collected": ["a"], "allowed": ["a"]}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "data_minimization" in names
