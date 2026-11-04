"""privacy_budget: stateless cumulative epsilon calculator."""
from __future__ import annotations

from maverick.tools.privacy_budget import privacy_budget


def _check(**kw):
    return privacy_budget().fn({"op": "check", **kw})


def test_remaining_from_spent_list():
    out = _check(budget=1.0, spent=[0.3, 0.2])
    assert "remaining: 0.5" in out


def test_spent_as_number():
    out = _check(budget=2.0, spent=0.5)
    assert "remaining: 1.5" in out


def test_request_allowed_and_denied():
    assert "FITS" in _check(budget=1.0, spent=[0.4], request=0.5)
    denied = _check(budget=1.0, spent=[0.8], request=0.5)
    assert "DENIED" in denied and "exceeds remaining" in denied


def test_request_exactly_fits():
    assert "FITS" in _check(budget=1.0, spent=0.5, request=0.5)


def test_exhausted_note():
    out = _check(budget=1.0, spent=[0.6, 0.4])
    assert "budget exhausted" in out


def test_errors():
    t = privacy_budget()
    assert t.fn({"op": "check"}).startswith("ERROR")  # no budget
    assert _check(budget=1.0).startswith("ERROR")
    assert _check(budget=0, spent=0).startswith("ERROR")
    assert _check(budget=1.0, spent=[-0.1]).startswith("ERROR")
    assert _check(budget=1.0, spent="x").startswith("ERROR")
    assert _check(budget=1.0, spent=0, request=-1).startswith("ERROR")
    assert t.fn({"op": "nope", "budget": 1}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "privacy_budget" in names


def test_repeated_omitted_spend_is_not_allowed():
    t = privacy_budget()
    out = t.fn({"op": "check", "budget": 1.0, "request": 0.6})
    assert out == "ERROR: spent is required from a trusted cumulative ledger"


def test_output_warns_stateless_estimate():
    out = _check(budget=1.0, spent=0, request=0.1)
    assert "stateless estimate only" in out
    assert "does not persist or consume" in out
