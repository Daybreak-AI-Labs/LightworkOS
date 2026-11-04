"""consent_check: consent-record validity evaluation."""
from __future__ import annotations

from maverick.tools.consent_check import consent_check


def _c(consents, now=None, purpose=None):
    args = {"op": "check", "consents": consents}
    if now is not None:
        args["now"] = now
    if purpose is not None:
        args["purpose"] = purpose
    return consent_check().fn(args)


def test_valid():
    out = _c([{"purpose": "marketing", "granted": True, "granted_at": "2026-01-01"}], now="2026-06-10")
    assert out.startswith("VALID")
    assert "[VALID] marketing" in out


def test_not_granted():
    out = _c([{"purpose": "m", "granted": False}], now="2026-06-10")
    assert out.startswith("INVALID")
    assert "[NOT_GRANTED] m" in out


def test_withdrawn():
    out = _c([{"purpose": "m", "granted": True, "granted_at": "2026-01-01", "withdrawn_at": "2026-03-01"}], now="2026-06-10")
    assert "[WITHDRAWN] m: withdrawn 2026-03-01" in out


def test_expired():
    out = _c([{"purpose": "m", "granted": True, "granted_at": "2026-01-01", "expires": "2026-05-01"}], now="2026-06-10")
    assert "[EXPIRED] m: expired 2026-05-01" in out


def test_regrant_supersedes_withdrawal():
    out = _c([
        {"purpose": "m", "granted": True, "granted_at": "2026-01-01", "withdrawn_at": "2026-02-01"},
        {"purpose": "m", "granted": True, "granted_at": "2026-03-01"},  # newer grant
    ], now="2026-06-10")
    assert out.startswith("VALID")
    assert "[VALID] m" in out


def test_purpose_filter_and_no_record():
    consents = [{"purpose": "marketing", "granted": True, "granted_at": "2026-01-01"}]
    assert "[VALID] marketing" in _c(consents, now="2026-06-10", purpose="marketing")
    assert _c(consents, now="2026-06-10", purpose="analytics").startswith("NO_RECORD")


def test_errors():
    t = consent_check()
    assert t.fn({"op": "check", "consents": []}).startswith("ERROR")
    assert t.fn({"op": "check", "consents": [{"granted": True}]}).startswith("ERROR")  # no purpose
    assert t.fn({"op": "check", "consents": [{"purpose": "m", "granted": True, "expires": "nope"}], "now": "2026-06-10"}).startswith("ERROR")
    assert t.fn({"op": "check", "consents": [{"purpose": "m"}], "now": "bad"}).startswith("ERROR")
    assert t.fn({"op": "nope", "consents": [{"purpose": "m"}]}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "consent_check" in names
