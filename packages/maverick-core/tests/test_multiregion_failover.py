"""multiregion_failover: multi-region failover selection."""
from __future__ import annotations

from maverick.tools.multiregion_failover import multiregion_failover


def _select(regions, client_region):
    return multiregion_failover().fn(
        {"op": "select", "regions": regions, "client_region": client_region}
    )


def test_prefers_client_region_when_eligible():
    out = _select([
        {"name": "us-east-1", "healthy": True, "rtt_ms": 5, "capacity_left": 10},
        {"name": "eu-west-1", "healthy": True, "rtt_ms": 1, "capacity_left": 10},
    ], "us-east-1")
    # Client's own region wins even though eu-west-1 has lower rtt.
    assert out.startswith("SELECT us-east-1")


def test_nearest_when_client_region_unavailable():
    out = _select([
        {"name": "us-east-1", "healthy": False, "rtt_ms": 5, "capacity_left": 10},
        {"name": "us-west-2", "healthy": True, "rtt_ms": 40, "capacity_left": 10},
        {"name": "eu-west-1", "healthy": True, "rtt_ms": 90, "capacity_left": 10},
    ], "us-east-1")
    assert out.startswith("SELECT us-west-2")
    assert "fallbacks: [eu-west-1]" in out


def test_skips_regions_without_capacity():
    out = _select([
        {"name": "zero-cap", "healthy": True, "rtt_ms": 5, "capacity_left": 0},
        {"name": "b", "healthy": True, "rtt_ms": 20, "capacity_left": 3},
    ], "client")
    # zero-cap is excluded entirely (not selected, not a fallback).
    assert out.startswith("SELECT b") and "zero-cap" not in out
    assert "fallbacks: [(none)]" in out


def test_ordered_fallback_list_by_rtt():
    out = _select([
        {"name": "far", "healthy": True, "rtt_ms": 100, "capacity_left": 5},
        {"name": "near", "healthy": True, "rtt_ms": 10, "capacity_left": 5},
        {"name": "mid", "healthy": True, "rtt_ms": 50, "capacity_left": 5},
    ], "elsewhere")
    assert out.startswith("SELECT near")
    assert "fallbacks: [mid, far]" in out


def test_none_when_nothing_eligible():
    out = _select([
        {"name": "a", "healthy": False, "rtt_ms": 5, "capacity_left": 10},
        {"name": "b", "healthy": True, "rtt_ms": 5, "capacity_left": 0},
    ], "client")
    assert out.startswith("NONE")


def test_errors():
    t = multiregion_failover()
    assert t.fn({"op": "select", "client_region": "x"}).startswith("ERROR")  # no regions
    assert t.fn({"op": "select", "regions": [{"name": "a", "healthy": True, "rtt_ms": 1, "capacity_left": 1}]}).startswith("ERROR")  # no client
    assert t.fn(
        {"op": "nope",
         "regions": [{"name": "a", "healthy": True, "rtt_ms": 1, "capacity_left": 1}],
         "client_region": "a"}
    ).startswith("ERROR")
