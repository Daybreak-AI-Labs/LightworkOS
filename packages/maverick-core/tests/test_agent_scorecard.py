"""Per-agent scorecard: value/cost/efficiency grouped by the pack a goal ran
as, from existing episode signals."""
from __future__ import annotations

from types import SimpleNamespace

from maverick import agent_scorecard as sc


class _FakeWorld:
    """Minimal world stub: episodes carry goal_id + cost + outcome; goals
    carry the domain (the specialist pack that ran)."""

    def __init__(self, episodes, goal_domains, signoffs=None):
        self._episodes = episodes
        self._domains = goal_domains
        self._signoffs = signoffs or {}

    def list_episodes(self, limit=5000):
        return self._episodes

    def get_goal(self, goal_id):
        return SimpleNamespace(domain=self._domains.get(goal_id, ""), status="done")

    def signoff_for(self, goal_id):
        decision = self._signoffs.get(goal_id)
        return {"decision": decision} if decision else None


def _ep(goal_id, cost, outcome, started):
    return SimpleNamespace(goal_id=goal_id, cost_dollars=cost, outcome=outcome,
                           started_at=started, input_tokens=1000,
                           output_tokens=2000)


def test_only_approved_goals_count_as_delivered_and_value_needs_assumption():
    import time
    now = time.time()
    world = _FakeWorld(
        episodes=[
            _ep(1, 0.50, "done", now - 100),
            _ep(2, 0.30, "done", now - 200),
            _ep(3, 0.40, "failed", now - 300),   # finance_ap, not delivered
            _ep(4, 0.20, "done", now - 400),      # hr_onboarding
        ],
        goal_domains={1: "finance_ap", 2: "finance_ap",
                      3: "finance_ap", 4: "hr_onboarding"},
        signoffs={1: "approved", 4: "rejected"})
    scores = {s.agent: s for s in sc.compute(world, now=now)}
    ap = scores["finance_ap"]
    assert (ap.runs, ap.completed, ap.reviewed, ap.delivered) == (3, 2, 1, 1)
    assert ap.cost == 0.50 + 0.30 + 0.40
    assert ap.value is None and ap.roi_multiple is None
    assert ap.approval_rate == 100.0
    d = ap.to_dict()
    assert d["cost_avoided"] is None and d["value_basis"] is None
    assert d["success_rate"] is None and d["approval_rate"] == 100.0
    assert scores["hr_onboarding"].completed == 1
    assert scores["hr_onboarding"].delivered == 0
    assert scores["hr_onboarding"].approval_rate == 0.0

    assumed = sc.for_agent(world, "finance_ap", human_cost=120.0, now=now)
    assert assumed.value == 120.0
    assert assumed.roi_multiple == round(120.0 / 1.20, 1)


def test_window_excludes_old_episodes():
    import time
    now = time.time()
    world = _FakeWorld(
        episodes=[_ep(1, 1.0, "done", now - 10 * 86400),
                  _ep(2, 1.0, "done", now - 200 * 86400)],
        goal_domains={1: "finance_ap", 2: "finance_ap"})
    ap = sc.for_agent(world, "finance_ap", window_days=90, now=now)
    assert ap.runs == 1        # the 200-day-old run is outside the window


def test_empty_and_defensive():
    assert sc.compute(None) == []           # no world -> empty, no raise
    empty = sc.for_agent(None, "finance_ap")
    assert empty.agent == "finance_ap" and empty.runs == 0
    assert empty.roi_multiple is None and empty.approval_rate is None
