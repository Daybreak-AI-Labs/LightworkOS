"""Memory must not turn observational patterns into automatic habits."""
from __future__ import annotations

from maverick import procedural_memory as pm
from maverick.trajectory_store import TrajectoryStep


def _ep(eid, domain, tool, outcome):
    return [
        TrajectoryStep(ts=1.0, goal_id=1, episode_id=eid, step=0, role="coder",
                       tool=tool, domain=domain),
        TrajectoryStep(ts=1.0, goal_id=1, episode_id=eid, step=1, role="coder",
                       tool="log", domain=domain, is_final=True, outcome=outcome),
    ]


def _corpus(good_tool="Y"):
    """`good_tool` causally helps (+0.5) in both domains; `slow` does nothing."""
    steps, eid = [], 0
    for domain in ("fin", "ops"):
        for _ in range(12):
            eid += 1
            steps += _ep(eid, domain, good_tool, 0.9)
        for _ in range(12):
            eid += 1
            steps += _ep(eid, domain, "slow", 0.4)
    return steps


def test_observed_difference_does_not_create_a_habit():
    mems = pm.consolidate(_corpus("Y"))
    assert mems == []


def test_observed_difference_does_not_reinforce_an_existing_habit():
    first = [pm.Memory("Y", 0.5, pm._BASE)]
    second = pm.consolidate(_corpus("Y"), prior=first)
    assert second[0].strength < first[0].strength


def test_unreinforced_memory_decays_and_is_forgotten():
    # Previously accepted memories fade without controlled reinforcement.
    mems = [pm.Memory("Y", 0.5, pm._BASE)]
    neutral = []  # nothing beneficial in an empty corpus
    cycle1 = pm.consolidate(neutral, prior=mems)
    assert pm.MemoryStore(path=None) is not None  # store import smoke
    # base 0.5 - decay 0.25 = 0.25 (survives one cycle)...
    assert any(m.action == "Y" for m in cycle1)
    cycle2 = pm.consolidate(neutral, prior=cycle1)
    # ...0.25 - 0.25 = 0.0 < retire floor -> forgotten (no catastrophic loss of
    # anything still useful; only the stale habit fades).
    assert not any(m.action == "Y" for m in cycle2)


def test_store_recall_and_roundtrip(tmp_path):
    path = tmp_path / "m.json"
    store = pm.MemoryStore(path=path)
    store.update([pm.Memory("Y", 0.5, pm._BASE)])
    assert store.recall()[0].action == "Y"
    assert store.strength_of("Y") == pm._BASE
    assert pm.MemoryStore(path=path).recall()[0].action == "Y"  # persisted
    from maverick.file_lock import private_path_is_restricted
    assert private_path_is_restricted(path)


def test_store_ignores_valid_json_with_wrong_shape(tmp_path):
    path = tmp_path / "m.json"
    path.write_text("42", encoding="utf-8")
    assert pm.MemoryStore(path=path).recall() == []


def test_recall_empty_store_is_noop(tmp_path):
    assert pm.MemoryStore(path=tmp_path / "m.json").recall() == []


def test_recall_prompt_surfaces_habits(tmp_path):
    store = pm.MemoryStore(path=tmp_path / "m.json")
    assert pm.recall_prompt(store=store) == ""        # empty -> no prompt change
    store.update([pm.Memory("Y", 0.5, pm._BASE)])
    prompt = pm.recall_prompt(store=store)
    assert "Learned habits" in prompt and "prefer 'Y'" in prompt
