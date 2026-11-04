"""fairness_scheduler: weighted largest-remainder slot allocation."""
from __future__ import annotations

from maverick.tools.fairness_scheduler import fairness_scheduler


def _run(**kw):
    return fairness_scheduler().fn({"op": "schedule", **kw})


def test_equal_weights_split_evenly():
    out = _run(
        agents=[{"id": "a", "pending": 10}, {"id": "b", "pending": 10}],
        slots=4,
    )
    assert out.startswith("OK: allocated 4/4")
    assert "a: 2 " in out and "b: 2 " in out


def test_weighted_share():
    out = _run(
        agents=[
            {"id": "a", "weight": 3, "pending": 10},
            {"id": "b", "weight": 1, "pending": 10},
        ],
        slots=4,
    )
    assert "a: 3 " in out and "b: 1 " in out


def test_pending_cap_redistributes():
    # a wants 3 by weight but pending=1; the freed 2 slots flow to b.
    out = _run(
        agents=[
            {"id": "a", "weight": 3, "pending": 1},
            {"id": "b", "weight": 1, "pending": 10},
        ],
        slots=4,
    )
    assert out.startswith("OK: allocated 4/4")
    assert "a: 1 " in out and "b: 3 " in out


def test_largest_remainder_tie_break_by_id():
    # Three equal agents, 5 slots: floors 1 each, the 2 leftover go to the
    # lexicographically-first ids (a, b) deterministically.
    out = _run(
        agents=[
            {"id": "a", "pending": 10},
            {"id": "b", "pending": 10},
            {"id": "c", "pending": 10},
        ],
        slots=5,
    )
    assert "a: 2 " in out and "b: 2 " in out and "c: 1 " in out


def test_demand_below_slots_leaves_unallocated():
    out = _run(
        agents=[{"id": "a", "pending": 1}, {"id": "b", "pending": 1}],
        slots=5,
    )
    assert out.startswith("OK: allocated 2/5")
    assert "3 slot(s) unallocated" in out


def test_errors():
    t = fairness_scheduler()
    assert t.fn({"op": "schedule", "slots": 4}).startswith("ERROR")  # no agents
    assert t.fn({"op": "schedule", "agents": [{"id": "a", "pending": 1}]}).startswith("ERROR")  # no slots
    assert _run(agents=[{"pending": 1}], slots=2).startswith("ERROR")  # no id
    assert _run(
        agents=[{"id": "a", "pending": 1}, {"id": "a", "pending": 1}], slots=2
    ).startswith("ERROR")  # duplicate id
    assert t.fn({"op": "nope", "agents": [{"id": "a", "pending": 1}], "slots": 1}).startswith("ERROR")


def test_non_finite_weight_does_not_crash():
    out = _run(agents=[{"id": "a", "pending": 1, "weight": float("inf")}], slots=2)
    assert out.startswith("ERROR")


def test_infinite_pending_and_slots_do_not_crash():
    assert _run(agents=[{"id": "a", "pending": float("inf")}], slots=2).startswith("ERROR")
    assert _run(agents=[{"id": "a", "pending": 1}], slots=float("inf")).startswith("ERROR")
