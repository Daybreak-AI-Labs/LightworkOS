"""Private task titles and approval cards stay scoped in secondary surfaces."""
from types import SimpleNamespace

from maverick_dashboard import immune_actions_api


def test_canary_source_never_samples_another_employees_card():
    own = SimpleNamespace(id=1, requested_by="user:a", goal_id=1)
    other = SimpleNamespace(id=2, requested_by="user:b", goal_id=2)
    mismatched_goal = SimpleNamespace(id=3, requested_by="user:a", goal_id=2)
    world = SimpleNamespace(list_approvals=lambda **_: [own, other, mismatched_goal],
        get_goal=lambda key: SimpleNamespace(owner="user:a" if key == 1 else "user:b"))
    assert immune_actions_api._OwnedApprovals(world, "user:a").list_approvals(limit=500) == [own]


def test_shoring_measurement_forwards_exact_owner():
    from maverick.shoring import _measure
    calls = []
    def aggregate(department, **kwargs):
        calls.append((department, kwargs))
        return {"delivered": 0, "blocked": 0}
    _measure("finance", SimpleNamespace(shoring_measurements=aggregate), window_days=30, now=1, owner="user:a")
    assert calls[0][1]["owner"] == "user:a"
