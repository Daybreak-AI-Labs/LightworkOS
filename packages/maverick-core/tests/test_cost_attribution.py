"""cost_attribution: spend breakdown across dimensions."""
from __future__ import annotations

from maverick.tools.cost_attribution import cost_attribution


def _report(items, **kw):
    return cost_attribution().fn({"op": "report", "items": items, **kw})


def test_total_and_principal_breakdown():
    items = [
        {"cost": 3.0, "principal": "alice"},
        {"cost": 1.0, "principal": "bob"},
    ]
    out = _report(items)
    assert "total=$4.0000" in out
    assert "alice: $3.0000 (75.0%)" in out


def test_multi_dimension():
    items = [
        {"cost": 2.0, "principal": "a", "tool": "shell"},
        {"cost": 2.0, "principal": "b", "tool": "shell"},
    ]
    out = _report(items, by=["principal", "tool"])
    assert "by principal:" in out and "by tool:" in out
    assert "shell: $4.0000 (100.0%)" in out


def test_unattributed_bucket():
    out = _report([{"cost": 1.0}], by=["tag"])
    assert "(unattributed): $1.0000" in out


def test_unknown_dimension_errors():
    assert _report([{"cost": 1}], by=["nope"]).startswith("ERROR")


def test_non_numeric_cost_errors():
    assert _report([{"cost": "free"}]).startswith("ERROR")


def test_non_dict_item_does_not_crash():
    # Model-supplied items may contain non-objects; must not raise.
    out = _report([1, 2, 3])
    assert out.startswith("ERROR")
    assert _report([None]).startswith("ERROR")


def test_top_infinity_does_not_crash():
    out = _report([{"cost": 1, "principal": "a"}], top=float("inf"))
    assert out.startswith("ERROR")
