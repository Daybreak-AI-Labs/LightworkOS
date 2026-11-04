"""dp_stats: Laplace-mechanism differentially-private aggregates."""
from __future__ import annotations

import re

from maverick.tools.dp_stats import dp_stats


def _val(out):
    m = re.search(r"noisy=(-?[0-9.]+)", out)
    assert m, out
    return float(m.group(1))


def test_count_is_seeded_reproducible():
    a = dp_stats().fn({"op": "count", "value": 100, "epsilon": 1.0, "seed": 7})
    b = dp_stats().fn({"op": "count", "value": 100, "epsilon": 1.0, "seed": 7})
    assert a == b and a.startswith("OK")


def test_private_release_omits_exact_aggregate():
    count = dp_stats().fn({"op": "count", "value": 12345, "epsilon": 1.0, "seed": 5})
    total = dp_stats().fn({
        "op": "sum",
        "values": [1000, 5, 3.5],
        "clamp": 10,
        "epsilon": 1.0,
        "seed": 5,
    })

    assert "true=" not in count
    assert "true=" not in total


def test_smaller_epsilon_larger_scale():
    tight = dp_stats().fn({"op": "count", "value": 0, "epsilon": 0.1, "seed": 1})
    loose = dp_stats().fn({"op": "count", "value": 0, "epsilon": 10.0, "seed": 1})
    s_tight = float(re.search(r"laplace_scale=([0-9.]+)", tight).group(1))
    s_loose = float(re.search(r"laplace_scale=([0-9.]+)", loose).group(1))
    assert s_tight > s_loose


def test_sum_clamps_records():
    # Each record clamped to [0, 10]; 1000 is capped, so true sum = 10+5 = 15.
    out = dp_stats().fn({"op": "sum", "values": [1000, 5], "clamp": 10,
                         "epsilon": 50.0, "seed": 3})
    assert abs(_val(out) - 15) < 2.0  # tiny noise at high epsilon


def test_zero_epsilon_errors():
    assert dp_stats().fn({"op": "count", "value": 1, "epsilon": 0}).startswith("ERROR")


def test_sum_requires_clamp():
    assert dp_stats().fn({"op": "sum", "values": [1, 2]}).startswith("ERROR")
