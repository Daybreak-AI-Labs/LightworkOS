"""risk_tier_classifier: general goal-risk LOW/MEDIUM/HIGH scorer."""
from __future__ import annotations

from maverick.tools.risk_tier_classifier import risk_tier_classifier


def _score(signals):
    return risk_tier_classifier().fn({"op": "score", "signals": signals})


def test_no_signals_is_low():
    out = _score({})
    assert out.startswith("tier: LOW")
    assert "score: 0" in out
    assert "none" in out


def test_single_egress_signal_is_low():
    # network_egress alone = 2 points, below MEDIUM threshold of 3.
    out = _score({"network_egress?": True})
    assert out.startswith("tier: LOW")
    assert "score: 2" in out
    assert "network egress (+2)" in out


def test_pii_alone_is_medium():
    out = _score({"touches_pii?": True})
    assert out.startswith("tier: MEDIUM")
    assert "score: 3" in out


def test_irreversible_money_is_high():
    out = _score({"irreversible?": True, "moves_money?": True})
    assert out.startswith("tier: HIGH")
    assert "score: 8" in out
    assert "irreversible action (+4)" in out
    assert "moves money (+4)" in out


def test_custom_weight_can_escalate():
    low = _score({"network_egress?": True})  # 2 -> LOW
    assert low.startswith("tier: LOW")
    bumped = _score({"network_egress?": True, "custom_weight": 5})  # 7 -> HIGH
    assert bumped.startswith("tier: HIGH")
    assert "custom adjustment (+5)" in bumped


def test_falsey_signals_not_counted():
    # Only literal True counts; False / "true" string must not add points.
    out = _score({"irreversible?": False, "moves_money?": "true"})
    assert out.startswith("tier: LOW")
    assert "score: 0" in out


def test_errors():
    t = risk_tier_classifier()
    assert t.fn({"op": "score"}).startswith("ERROR")  # no signals
    assert t.fn({"op": "nope", "signals": {}}).startswith("ERROR")
    assert t.fn({"op": "score", "signals": {"custom_weight": "x"}}).startswith("ERROR")


def test_non_finite_custom_weight_does_not_crash():
    # Regression: int(signals["custom_weight"]) raised OverflowError on inf.
    t = risk_tier_classifier()
    for bad in (float("inf"), float("-inf")):
        out = t.fn({"op": "score", "signals": {"custom_weight": bad}})
        assert out.startswith("ERROR")
