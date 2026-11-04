"""provider_failover_policy: provider failover policy engine."""
from __future__ import annotations

from maverick.tools.provider_failover_policy import provider_failover_policy

_POLICY = {"max_error_rate": 0.1, "max_latency_ms": 500}


def _order(providers, policy=_POLICY):
    return provider_failover_policy().fn(
        {"op": "order", "providers": providers, "policy": policy}
    )


def test_ranks_eligible_best_first():
    out = _order([
        {"name": "slow", "healthy": True, "latency_ms": 400, "error_rate": 0.01},
        {"name": "fast", "healthy": True, "latency_ms": 100, "error_rate": 0.01},
    ])
    # Same error_rate -> lower latency wins the primary slot.
    assert out.startswith("PRIMARY fast")
    assert out.index("fast") < out.index("slow")


def test_excludes_unhealthy():
    out = _order([
        {"name": "down", "healthy": False, "latency_ms": 10, "error_rate": 0.0},
        {"name": "up", "healthy": True, "latency_ms": 200, "error_rate": 0.02},
    ])
    assert out.startswith("PRIMARY up") and "down" not in out


def test_excludes_over_threshold():
    out = _order([
        {"name": "laggy", "healthy": True, "latency_ms": 900, "error_rate": 0.01},
        {"name": "erry", "healthy": True, "latency_ms": 100, "error_rate": 0.5},
        {"name": "good", "healthy": True, "latency_ms": 300, "error_rate": 0.05},
    ])
    assert out.startswith("PRIMARY good")
    assert "laggy" not in out and "erry" not in out


def test_error_rate_beats_latency_in_ranking():
    out = _order([
        {"name": "lowlat", "healthy": True, "latency_ms": 50, "error_rate": 0.09},
        {"name": "lowerr", "healthy": True, "latency_ms": 400, "error_rate": 0.0},
    ])
    # Lowest error_rate ranks first even if its latency is higher.
    assert out.startswith("PRIMARY lowerr")


def test_none_when_all_ineligible():
    out = _order([
        {"name": "a", "healthy": False, "latency_ms": 10, "error_rate": 0.0},
        {"name": "b", "healthy": True, "latency_ms": 10, "error_rate": 0.9},
    ])
    assert out.startswith("NONE")


def test_errors():
    t = provider_failover_policy()
    assert t.fn({"op": "order"}).startswith("ERROR")  # no providers
    assert t.fn({"op": "nope", "providers": [], "policy": _POLICY}).startswith("ERROR")
    assert t.fn(
        {"op": "order",
         "providers": [{"name": "a", "healthy": True, "latency_ms": "x", "error_rate": 0.0}],
         "policy": _POLICY}
    ).startswith("ERROR")
