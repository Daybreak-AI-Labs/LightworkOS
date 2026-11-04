"""cost_guardrail: long-context cost guardrail."""
from __future__ import annotations

from maverick.tools.cost_guardrail import cost_guardrail


def _check(**kw):
    return cost_guardrail().fn({"op": "check", **kw})


def test_allow_under_budget():
    out = _check(projected_dollars=10)  # default limit 50, 20%
    assert out.startswith("ALLOW")
    assert "headroom=$40.00" in out


def test_warn_near_limit():
    out = _check(projected_dollars=40)  # 80% of 50
    assert out.startswith("WARN")
    assert "80% of limit" in out


def test_block_over_hard_limit():
    out = _check(projected_dollars=60)  # hard defaults True
    assert out.startswith("BLOCK")
    assert "headroom=$-10.00" in out


def test_soft_limit_warns_not_blocks():
    out = _check(projected_dollars=60, hard=False)
    assert out.startswith("WARN")
    assert "advisory" in out


def test_custom_limit_and_tokens():
    out = _check(projected_dollars=100, limit=200, tokens=1_000_000)
    assert out.startswith("ALLOW")  # 50% of 200
    assert "tokens=1e+06" in out


def test_errors():
    t = cost_guardrail()
    assert t.fn({"op": "check"}).startswith("ERROR")  # no projected
    assert t.fn({"op": "check", "projected_dollars": 1, "limit": 0}).startswith("ERROR")
    assert t.fn({"op": "check", "projected_dollars": -1}).startswith("ERROR")
    assert t.fn({"op": "check", "projected_dollars": 1, "hard": "yes"}).startswith("ERROR")
    assert t.fn({"op": "nope", "projected_dollars": 1}).startswith("ERROR")
