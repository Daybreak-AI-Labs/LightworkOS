"""cost_aware_router: cost-aware router v2 with per-role policies."""
from __future__ import annotations

from maverick.tools.cost_aware_router import cost_aware_router

_MODELS = [
    {"model": "cheap", "in_cost": 1.0, "out_cost": 2.0, "quality": 0.6},
    {"model": "mid", "in_cost": 3.0, "out_cost": 3.0, "quality": 0.8},
    {"model": "premium", "in_cost": 10.0, "out_cost": 20.0, "quality": 0.95},
]


def _route(role, models=_MODELS, policy=None):
    return cost_aware_router().fn(
        {"op": "route", "role": role, "models": models, "policy": policy or {}}
    )


def test_picks_cheapest_meeting_quality_floor():
    out = _route("planner", policy={"planner": {"min_quality": 0.75}})
    # cheap (0.6) fails the floor; mid is the cheapest that clears 0.75.
    assert out.startswith("ROUTE mid")


def test_picks_cheapest_overall_when_no_floor():
    out = _route("worker", policy={"worker": {}})
    assert out.startswith("ROUTE cheap")


def test_cost_ceiling_excludes_expensive():
    out = _route("planner", policy={"planner": {"min_quality": 0.9, "max_cost": 5.0}})
    # premium clears quality 0.9 but blended cost 30 > 5 -> nothing eligible.
    assert out.startswith("NONE")


def test_unknown_role_has_no_constraints():
    # No policy entry for the role -> any model eligible, cheapest wins.
    out = _route("misc", policy={"planner": {"min_quality": 0.9}})
    assert out.startswith("ROUTE cheap")


def test_cost_tie_breaks_to_higher_quality():
    models = [
        {"model": "a", "in_cost": 1.0, "out_cost": 1.0, "quality": 0.5},
        {"model": "b", "in_cost": 1.0, "out_cost": 1.0, "quality": 0.9},
    ]
    out = _route("r", models=models, policy={"r": {}})
    assert out.startswith("ROUTE b")


def test_errors():
    t = cost_aware_router()
    assert t.fn({"op": "route", "models": _MODELS, "policy": {}}).startswith("ERROR")  # no role
    assert t.fn({"op": "route", "role": "r", "policy": {}}).startswith("ERROR")  # no models
    assert t.fn(
        {"op": "route", "role": "r",
         "models": [{"model": "a", "in_cost": "x", "out_cost": 1.0, "quality": 0.5}],
         "policy": {}}
    ).startswith("ERROR")
