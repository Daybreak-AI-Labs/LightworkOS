"""anomaly_scan: MAD-based cross-run outlier detection."""
from __future__ import annotations

from maverick.tools.anomaly_scan import anomaly_scan


def _s(series, labels=None, threshold=None):
    args = {"op": "scan", "series": series}
    if labels is not None:
        args["labels"] = labels
    if threshold is not None:
        args["threshold"] = threshold
    return anomaly_scan().fn(args)


def test_clean_series():
    out = _s([10, 11, 9, 10, 11, 9])
    assert out.startswith("CLEAN")


def test_detects_spike():
    out = _s([10, 11, 9, 10, 11, 100])
    assert out.startswith("ANOMALY")
    assert "[5] 100" in out  # index 5 is the spike


def test_labels_used_in_output():
    out = _s([10, 11, 9, 10, 11, 100], labels=["a", "b", "c", "d", "e", "bad"])
    assert "[bad] 100" in out


def test_all_equal_is_clean():
    out = _s([5, 5, 5, 5])
    assert out.startswith("CLEAN") and "all equal" in out


def test_mad_zero_meanad_fallback():
    # median and MAD are 0 (majority zeros) but a nonzero value exists
    out = _s([0, 0, 0, 0, 9])
    assert out.startswith("ANOMALY")
    assert "meanAD" in out


def test_threshold_controls_sensitivity():
    series = [10, 11, 9, 10, 11, 20]
    # lenient threshold -> clean; strict -> flags the 20 (score ~12.8)
    assert _s(series, threshold=15).startswith("CLEAN")
    assert _s(series, threshold=2).startswith("ANOMALY")


def test_errors():
    t = anomaly_scan()
    assert t.fn({"op": "scan", "series": [1, 2]}).startswith("ERROR")  # <3
    assert t.fn({"op": "scan", "series": [1, 2, "x"]}).startswith("ERROR")
    assert t.fn({"op": "scan", "series": [1, 2, 3], "labels": ["a"]}).startswith("ERROR")
    assert t.fn({"op": "scan", "series": [1, 2, 3], "threshold": 0}).startswith("ERROR")
    assert t.fn({"op": "nope", "series": [1, 2, 3]}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "anomaly_scan" in names
