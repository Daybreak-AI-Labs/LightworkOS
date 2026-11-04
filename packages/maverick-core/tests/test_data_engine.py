"""The Cognitive Data Engine's triage must rank failure classes by CAUSAL impact
on outcome -- a harmful action over a merely-frequent, harmless one -- and
deconfound by domain.
"""
from __future__ import annotations

from maverick import data_engine as de
from maverick.trajectory_store import TrajectoryStep


def _ep(eid, domain, tool, outcome):
    """A 2-step episode: a tool call, then a final step carrying the real outcome.
    `log` rides along on every episode (frequent but harmless)."""
    return [
        TrajectoryStep(ts=1.0, goal_id=1, episode_id=eid, step=0, role="coder",
                       tool=tool, domain=domain),
        TrajectoryStep(ts=1.0, goal_id=1, episode_id=eid, step=1, role="coder",
                       tool="log", domain=domain, is_final=True, outcome=outcome),
    ]


def _corpus():
    steps, eid = [], 0
    for domain in ("fin", "ops"):
        for _ in range(12):  # "X" present -> bad outcome (causally harmful)
            eid += 1
            steps += _ep(eid, domain, "X", 0.3)
        for _ in range(12):  # "X" absent ("read") -> good outcome
            eid += 1
            steps += _ep(eid, domain, "read", 0.8)
    return steps


def test_triage_ranks_causally_harmful_action_first():
    classes = de.triage(_corpus())
    assert classes, "expected at least one harmful class"
    top = classes[0]
    assert top.action == "X"
    assert top.causal_effect < 0 and top.ci_high < 0   # confidently harmful
    assert not top.trustworthy  # observational triage ranks hypotheses, not proven causes
    assert top.count > 0 and top.exemplars              # failing exemplars for the fix-miner


def test_frequent_but_harmless_actions_are_not_flagged():
    classes = de.triage(_corpus())
    flagged = {c.action for c in classes}
    # 'log' rides on every episode (no control arm) and 'read' helps -> neither is
    # a harmful class. Only the causally-harmful 'X' makes the queue.
    assert "log" not in flagged
    assert "read" not in flagged
    assert flagged == {"X"}


def test_empty_corpus():
    assert de.triage([]) == []


def test_enabled_off_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_DATA_ENGINE", raising=False)
    monkeypatch.setattr("maverick.config.get_data_engine", lambda: {"enable": False})
    assert de.enabled() is False
    monkeypatch.setenv("MAVERICK_DATA_ENGINE", "1")
    assert de.enabled() is True
