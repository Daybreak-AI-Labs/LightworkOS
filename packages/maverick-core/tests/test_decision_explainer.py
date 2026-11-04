"""decision_explainer: per-factor contribution breakdown for additive decisions."""
from __future__ import annotations

from maverick.tools.decision_explainer import decision_explainer


def _e(factors, intercept=None, threshold=None):
    args = {"op": "explain", "factors": factors}
    if intercept is not None:
        args["intercept"] = intercept
    if threshold is not None:
        args["threshold"] = threshold
    return decision_explainer().fn(args)


def test_score_and_contributions():
    out = _e({
        "income": {"weight": 0.8, "value": 0.5},   # +0.4
        "debt": {"weight": -1.0, "value": 0.1},     # -0.1
    })
    assert "score: 0.3" in out
    lines = out.splitlines()
    # ranked by magnitude: income (0.4) before debt (-0.1)
    assert "+0.4 income" in lines[2] and "-0.1 debt" in lines[3]


def test_threshold_approved():
    out = _e({"a": {"weight": 1, "value": 1}}, threshold=0.5)
    assert out.startswith("APPROVED")
    assert "margin +0.5" in out


def test_threshold_denied():
    out = _e({"a": {"weight": 1, "value": 0.2}}, threshold=0.5)
    assert out.startswith("DENIED")
    assert "< threshold 0.5" in out and "margin -0.3" in out


def test_intercept_applied():
    out = _e({"a": {"weight": 1, "value": 1}}, intercept=2)
    assert "score: 3" in out and "intercept 2" in out


def test_ranking_by_magnitude_then_name():
    out = _e({
        "z": {"weight": 1, "value": 0.5},
        "a": {"weight": 1, "value": 0.5},  # tie with z -> name order a before z
        "big": {"weight": 1, "value": 2},
    })
    lines = out.splitlines()
    assert "big" in lines[2] and "a" in lines[3] and "z" in lines[4]


def test_errors():
    t = decision_explainer()
    assert t.fn({"op": "explain", "factors": {}}).startswith("ERROR")
    assert t.fn({"op": "explain", "factors": {"a": {"weight": 1}}}).startswith("ERROR")
    assert t.fn({"op": "explain", "factors": {"a": {"weight": "x", "value": 1}}}).startswith("ERROR")
    assert t.fn({"op": "explain", "factors": {"a": {"weight": 1, "value": 1}}, "threshold": "x"}).startswith("ERROR")
    assert t.fn({"op": "nope", "factors": {"a": {"weight": 1, "value": 1}}}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "decision_explainer" in names
