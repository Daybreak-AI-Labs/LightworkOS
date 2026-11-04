"""migration_cost: provider migration cost calculator."""
from __future__ import annotations

from maverick.tools.migration_cost import migration_cost


def _compare(**kw):
    return migration_cost().fn({"op": "compare", **kw})


_USAGE = {"input_tokens": 10_000_000, "output_tokens": 2_000_000, "requests": 1000}
# from: $3/Mtok in, $15/Mtok out -> 30 + 30 = $60
# to:   $1/Mtok in, $5/Mtok out  -> 10 + 10 = $20
_FROM = {"name": "incumbent", "input_per_mtok": 3.0, "output_per_mtok": 15.0}
_TO = {"name": "challenger", "input_per_mtok": 1.0, "output_per_mtok": 5.0}


def test_switch_when_cheaper():
    out = _compare(usage=_USAGE, **{"from": _FROM, "to": _TO})
    assert out.startswith("SWITCH to challenger")
    assert "incumbent: $60.00/mo" in out
    assert "challenger: $20.00/mo" in out
    assert "delta=$40.00/mo" in out
    assert "66.7%" in out  # 40/60


def test_stay_when_pricier():
    out = _compare(usage=_USAGE, **{"from": _TO, "to": _FROM})
    assert out.startswith("STAY on challenger")
    assert "costs $40.00/mo more" in out


def test_even_when_identical():
    out = _compare(usage=_USAGE, **{"from": _FROM, "to": dict(_FROM, name="twin")})
    assert out.startswith("EVEN")


def test_per_request_fee_counts():
    usage = {"input_tokens": 0, "output_tokens": 0, "requests": 100}
    a = {"name": "a", "input_per_mtok": 0, "output_per_mtok": 0, "per_request": 0.01}
    b = {"name": "b", "input_per_mtok": 0, "output_per_mtok": 0}
    out = _compare(usage=usage, **{"from": a, "to": b})
    # a costs 100 * 0.01 = $1.00; b is free -> switch saves $1.00
    assert "a: $1.00/mo" in out and "b: $0.00/mo" in out
    assert out.startswith("SWITCH to b")


def test_default_op_is_compare():
    out = migration_cost().fn({"usage": _USAGE, "from": _FROM, "to": _TO})
    assert out.startswith("SWITCH to challenger")


def test_errors():
    t = migration_cost()
    assert t.fn({"op": "compare", "from": _FROM, "to": _TO}).startswith("ERROR")  # no usage
    assert t.fn({"usage": _USAGE, "from": _FROM}).startswith("ERROR")  # no 'to'
    assert t.fn({"op": "nope", "usage": _USAGE, "from": _FROM, "to": _TO}).startswith("ERROR")
    bad = t.fn({"usage": {"input_tokens": "lots"}, "from": _FROM, "to": _TO})
    assert bad.startswith("ERROR")
