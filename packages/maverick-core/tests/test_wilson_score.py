"""Wilson score interval: the shared confidence-bound helper used by
self_harness's promotion/retirement math and skill.stats's eviction gate.
"""
from __future__ import annotations

import pytest
from maverick.wilson_score import wilson_lower_bound, wilson_upper_bound


def test_lower_bound_zero_n_is_zero():
    assert wilson_lower_bound(0, 0) == 0.0


def test_upper_bound_zero_n_is_one():
    assert wilson_upper_bound(0, 0) == 1.0


def test_more_evidence_narrows_the_interval_around_a_stable_rate():
    # 4-of-5 vs. 40-of-50: same 0.8 win rate, 10x the evidence. The interval
    # must be tighter (higher lower bound, lower upper bound) with more
    # observations at the same rate.
    assert wilson_lower_bound(4, 5) < wilson_lower_bound(40, 50)
    assert wilson_upper_bound(4, 5) > wilson_upper_bound(40, 50)


def test_bounds_stay_within_unit_interval():
    for successes, n in [(0, 5), (1, 5), (5, 5), (3, 10), (0, 1), (1, 1)]:
        lo = wilson_lower_bound(successes, n)
        hi = wilson_upper_bound(successes, n)
        assert 0.0 <= lo <= hi <= 1.0


def test_small_sample_upper_bound_is_well_above_the_point_estimate():
    # The exact case that motivates gating on the bound instead of the raw
    # rate: 1 win in 5 uses is a 0.2 point estimate, but the data doesn't
    # rule out a much higher true rate.
    assert wilson_upper_bound(1, 5) == pytest.approx(0.6245, abs=1e-3)


def test_large_sample_upper_bound_approaches_the_point_estimate():
    # At n=1000, 200 successes (0.2 point estimate), the interval is tight.
    assert wilson_upper_bound(200, 1000) == pytest.approx(0.2259, abs=1e-3)
