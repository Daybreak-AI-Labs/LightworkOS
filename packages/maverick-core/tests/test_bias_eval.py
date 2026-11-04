"""bias_eval: group-fairness metrics (four-fifths, parity, equal opportunity)."""
from __future__ import annotations

from maverick.tools.bias_eval import bias_eval


def _e(groups, threshold=None):
    args = {"op": "evaluate", "groups": groups}
    if threshold is not None:
        args["threshold"] = threshold
    return bias_eval().fn(args)


def test_pass_when_rates_close():
    out = _e({
        "a": {"selected": 50, "total": 100},
        "b": {"selected": 45, "total": 100},
    })
    assert out.startswith("PASS")
    # ratio 0.45/0.50 = 0.9 >= 0.8
    assert "impact ratio 0.900" in out
    assert "demographic-parity difference: 0.050" in out


def test_fail_four_fifths():
    out = _e({
        "a": {"selected": 80, "total": 100},
        "b": {"selected": 50, "total": 100},  # ratio 0.625 < 0.8
    })
    assert out.startswith("FAIL")
    assert "adverse impact" in out


def test_custom_threshold():
    # ratio 0.9; threshold 0.95 -> fails
    out = _e({
        "a": {"selected": 50, "total": 100},
        "b": {"selected": 45, "total": 100},
    }, threshold=0.95)
    assert out.startswith("FAIL")


def test_equal_opportunity_difference():
    out = _e({
        "a": {"selected": 50, "total": 100, "tp": 40, "positives": 50},
        "b": {"selected": 50, "total": 100, "tp": 30, "positives": 50},
    })
    # TPR 0.8 vs 0.6 -> EO diff 0.2
    assert "equal-opportunity difference: 0.200" in out
    assert "a: TPR 0.800" in out and "b: TPR 0.600" in out


def test_no_eo_when_tp_absent():
    out = _e({
        "a": {"selected": 50, "total": 100},
        "b": {"selected": 45, "total": 100},
    })
    assert "equal-opportunity" not in out


def test_errors():
    t = bias_eval()
    assert t.fn({"op": "evaluate", "groups": {"a": {"selected": 1, "total": 2}}}).startswith("ERROR")  # <2
    assert t.fn({"op": "evaluate", "groups": {"a": {"selected": 1}, "b": {"selected": 1, "total": 2}}}).startswith("ERROR")
    assert t.fn({"op": "evaluate", "groups": {"a": {"selected": 3, "total": 2}, "b": {"selected": 1, "total": 2}}}).startswith("ERROR")
    assert t.fn({"op": "evaluate", "groups": {"a": {"selected": 0, "total": 0}, "b": {"selected": 0, "total": 1}}}).startswith("ERROR")
    assert t.fn({"op": "evaluate", "groups": {"a": {"selected": 1, "total": 2, "tp": 1}, "b": {"selected": 1, "total": 2}}}).startswith("ERROR")  # tp without positives
    assert t.fn({"op": "evaluate", "groups": {"a": {"selected": 1, "total": 2}, "b": {"selected": 1, "total": 2}}, "threshold": 0}).startswith("ERROR")
    assert t.fn({"op": "nope", "groups": {}}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "bias_eval" in names
