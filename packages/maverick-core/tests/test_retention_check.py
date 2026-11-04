"""retention_check: data-retention / storage-limitation auditing."""
from __future__ import annotations

from maverick.tools.retention_check import retention_check


def _c(records, policy, today=None):
    args = {"op": "check", "records": records, "policy": policy}
    if today is not None:
        args["today"] = today
    return retention_check().fn(args)


def test_compliant_by_age_days():
    out = _c(
        [{"id": "a", "category": "logs", "age_days": 10}],
        {"logs": 30},
    )
    assert out.startswith("COMPLIANT")
    assert "1 records within retention" in out


def test_over_retained_by_age_days():
    out = _c(
        [{"id": "a", "category": "logs", "age_days": 400}],
        {"logs": 365},
    )
    assert out.startswith("VIOLATION")
    assert "[OVER_RETAINED] a (logs): age 400d > 365d limit, overdue 35d" in out


def test_age_from_created_and_today():
    out = _c(
        [{"id": "a", "category": "pii", "created": "2025-01-01"}],
        {"pii": 90},
        today="2026-06-10",
    )
    assert out.startswith("VIOLATION") and "[OVER_RETAINED] a (pii)" in out


def test_default_policy():
    out = _c(
        [{"id": "a", "category": "misc", "age_days": 100}],
        {"logs": 30, "default": 365},
    )
    assert out.startswith("COMPLIANT")  # misc -> default 365


def test_no_policy_flagged():
    out = _c(
        [{"id": "a", "category": "weird", "age_days": 5}],
        {"logs": 30},
    )
    assert out.startswith("VIOLATION")
    assert "[NO_POLICY] a (weird): age 5d, no retention policy" in out


def test_over_retained_sorted_by_overdue():
    out = _c([
        {"id": "small", "category": "c", "age_days": 35},   # overdue 5
        {"id": "big", "category": "c", "age_days": 130},    # overdue 100
    ], {"c": 30})
    lines = out.splitlines()
    assert "big" in lines[1] and "small" in lines[2]


def test_errors():
    t = retention_check()
    assert t.fn({"op": "check", "records": [], "policy": {"a": 1}}).startswith("ERROR")
    assert t.fn({"op": "check", "records": [{"id": "a", "category": "c"}], "policy": {}}).startswith("ERROR")
    assert t.fn({"op": "check", "records": [{"id": "a"}], "policy": {"c": 1}}).startswith("ERROR")  # missing category
    assert t.fn({"op": "check", "records": [{"id": "a", "category": "c"}], "policy": {"c": 1}}).startswith("ERROR")  # no age/created
    assert t.fn({"op": "check", "records": [{"id": "a", "category": "c", "created": "nope"}], "policy": {"c": 1}}).startswith("ERROR")
    assert t.fn({"op": "check", "records": [{"id": "a", "category": "c", "age_days": 1}], "policy": {"c": "x"}}).startswith("ERROR")
    assert t.fn({"op": "nope", "records": [{"id": "a", "category": "c", "age_days": 1}], "policy": {"c": 1}}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "retention_check" in names
