"""risk_tier: operational LOW/MEDIUM/HIGH goal-risk scoring."""
from __future__ import annotations

from maverick.tools.risk_tier import risk_tier


def _s(signals, spend_usd=None):
    args = {"op": "score", "signals": signals}
    if spend_usd is not None:
        args["spend_usd"] = spend_usd
    return risk_tier().fn(args)


def test_low_when_no_signals():
    out = _s({})
    assert out.startswith("LOW (score 0)")
    assert "no elevated risk signals" in out


def test_single_light_signal_is_low():
    out = _s({"network": True})
    assert out.startswith("LOW (score 1)") and "network" in out


def test_medium_from_one_heavy_signal():
    out = _s({"shell": True})
    assert out.startswith("MEDIUM (score 2)") and "shell" in out


def test_high_from_multiple_heavy_signals():
    out = _s({"shell": True, "secrets": True, "production": True})
    assert out.startswith("HIGH (score 6)")
    # factors listed in weight-declared order: shell, secrets, production
    assert "shell, secrets, production" in out


def test_spend_weight_tiers():
    assert _s({}, spend_usd=10).startswith("LOW (score 1)")
    assert _s({}, spend_usd=100).startswith("MEDIUM (score 2)")
    assert "spend=$100" in _s({}, spend_usd=100)


def test_false_signals_ignored():
    out = _s({"shell": False, "network": True, "pii": False})
    assert out.startswith("LOW (score 1)")
    assert "shell" not in out and "pii" not in out


def test_factor_order_is_stable():
    # declared order is shell, secrets, pii, irreversible, production, ...
    out = _s({"pii": True, "shell": True})
    assert "shell, pii" in out  # shell precedes pii regardless of input order


def test_errors():
    t = risk_tier()
    assert t.fn({"op": "score", "signals": "x"}).startswith("ERROR")
    assert t.fn({"op": "score", "signals": {"bogus": True}}).startswith("ERROR")
    assert t.fn({"op": "score", "signals": {}, "spend_usd": -5}).startswith("ERROR")
    assert t.fn({"op": "score", "signals": {}, "spend_usd": "x"}).startswith("ERROR")
    assert t.fn({"op": "nope", "signals": {}}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "risk_tier" in names
