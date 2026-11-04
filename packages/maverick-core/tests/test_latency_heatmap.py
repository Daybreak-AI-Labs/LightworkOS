"""latency_heatmap: text heatmap of latency percentiles per bucket."""
from __future__ import annotations

from maverick.tools.latency_heatmap import latency_heatmap


def _run(**kw):
    return latency_heatmap().fn({"op": "render", **kw})


def _samples():
    return (
        [{"bucket": "fast", "ms": m} for m in (1, 2, 3, 4)]
        + [{"bucket": "slow", "ms": m} for m in (100, 200, 300, 400)]
    )


def test_buckets_and_header_rendered():
    out = _run(samples=_samples())
    assert "bucket" in out and "p50" in out and "p90" in out and "p99" in out
    assert "fast" in out and "slow" in out


def test_shading_blocks_present():
    out = _run(samples=_samples())
    # The hottest cell (slow p99 = max) must be a full block; the coldest a light one.
    assert "█" in out
    assert any(b in out for b in "░▒▓")
    assert "legend:" in out


def test_custom_percentiles():
    out = _run(samples=_samples(), percentiles=[50])
    assert "p50" in out
    assert "p90" not in out and "p99" not in out


def test_single_bucket_single_value():
    out = _run(samples=[{"bucket": "only", "ms": 42}])
    assert "only" in out and "42" in out
    # All cells equal -> full block (hi==lo path).
    assert "█" in out


def test_deterministic_output():
    s = _samples()
    assert _run(samples=s) == _run(samples=list(reversed(s)))


def test_errors():
    t = latency_heatmap()
    assert t.fn({"op": "render", "samples": []}).startswith("ERROR")
    assert t.fn({"op": "render", "samples": _samples(), "percentiles": [150]}).startswith("ERROR")
    assert t.fn({"op": "render", "samples": _samples(), "percentiles": "nope"}).startswith("ERROR")
    assert t.fn({"op": "bogus", "samples": _samples()}).startswith("ERROR")
