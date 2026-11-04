"""Provider rate-limit predictor (re-triage build)."""
from __future__ import annotations

import pytest
from maverick import rate_limit_predictor as rlp


@pytest.fixture(autouse=True)
def _clean():
    rlp.reset()
    yield
    rlp.reset()


def test_under_limit_no_wait():
    for t in (100.0, 101.0, 102.0):
        rlp.record("anthropic", now=t)
    # 3 calls, limit 10 in 60s window -> no wait
    assert rlp.predict_wait_ms("anthropic", limit=10, window_s=60, now=103.0) == 0.0


def test_at_limit_predicts_wait():
    # 3 calls at t=100,101,102; limit 3, window 60s
    for t in (100.0, 101.0, 102.0):
        rlp.record("p", now=t)
    # at t=110, window covers all 3 -> at limit; oldest (100) ages out at 160
    wait = rlp.predict_wait_ms("p", limit=3, window_s=60, now=110.0)
    assert wait == pytest.approx((160.0 - 110.0) * 1000.0)


def test_old_calls_outside_window_ignored():
    rlp.record("p", now=0.0)     # far in the past
    rlp.record("p", now=100.0)
    # only the t=100 call is in the trailing 60s at now=120 -> under limit 2
    assert rlp.predict_wait_ms("p", limit=2, window_s=60, now=120.0) == 0.0


def test_unknown_provider_no_wait():
    assert rlp.predict_wait_ms("never-seen", limit=5, window_s=60, now=1.0) == 0.0


def test_zero_limit_safe():
    rlp.record("p", now=1.0)
    assert rlp.predict_wait_ms("p", limit=0, window_s=60, now=2.0) == 0.0


def test_report():
    rlp.record("a", now=1.0)
    rlp.record("a", now=2.0)
    rlp.record("b", now=1.0)
    rep = {r["provider"]: r["recorded"] for r in rlp.report()}
    assert rep == {"a": 2, "b": 1}
