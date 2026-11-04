"""Provider cost-curve fitter."""
from __future__ import annotations

from maverick.cost.curve_fitter import fit_all, fit_curve, gather


def test_recovers_linear_rates():
    # cost = 0.001*in + 0.002*out exactly
    rows = [(i, o, 0.001 * i + 0.002 * o)
            for (i, o) in [(100, 50), (200, 10), (50, 200), (300, 300), (10, 5)]]
    c = fit_curve(rows)
    assert c.basis == "least_squares"
    assert abs(c.a - 0.001) < 1e-6
    assert abs(c.b - 0.002) < 1e-6
    assert c.r2 > 0.999
    assert abs(c.predict(1000, 1000) - 3.0) < 1e-3


def test_empty_samples():
    c = fit_curve([])
    assert c.basis == "none" and c.n == 0
    assert c.predict(100, 100) == 0.0


def test_singular_falls_back_to_average():
    # all rows share the same in:out ratio -> singular system
    rows = [(10, 10, 0.2), (20, 20, 0.4), (30, 30, 0.6)]
    c = fit_curve(rows)
    assert c.basis == "average"
    # average rate 0.2/(20) = 0.01 per token, split evenly
    assert abs(c.a - 0.01) < 1e-6 and abs(c.b - 0.01) < 1e-6


def test_negative_cost_rows_ignored():
    rows = [(1, 1, -5.0), (100, 50, 0.2), (200, 100, 0.4)]
    c = fit_curve(rows)
    assert c.n == 2  # the negative-cost row dropped


class _Ep:
    def __init__(self, cost, provider=None, in_t=0, out_t=0):
        self.cost_dollars = cost
        self.in_tokens = in_t
        self.out_tokens = out_t
        if provider is not None:
            self.provider = provider


class _World:
    def __init__(self, eps):
        self._eps = eps

    def list_episodes(self, limit=500):
        return self._eps


def test_gather_groups_by_provider():
    eps = [
        _Ep(0.1, "anthropic", 100, 50),
        _Ep(0.2, "anthropic", 200, 100),
        _Ep(0.05, "openai", 100, 100),
        _Ep(0.0, "openai", 1, 1),  # zero cost dropped
    ]
    grouped = gather(_World(eps))
    assert set(grouped) == {"anthropic", "openai"}
    assert len(grouped["anthropic"]) == 2
    curves = fit_all(_World(eps))
    assert "anthropic" in curves and curves["anthropic"].n == 2
