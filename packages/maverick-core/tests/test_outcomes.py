"""Outcome metrics: delivery rolled up from the Operating Record."""
from __future__ import annotations

import pytest
from maverick import outcomes
from maverick.world_model import WorldModel


@pytest.fixture()
def world(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    # finance_sox: two goals, one done one blocked.
    g1 = w.create_goal("Reconcile the ledger", domain="finance_sox")
    e1 = w.start_episode(g1)
    w.end_episode(e1, "done", "success")
    w.set_goal_status(g1, "done", result="tied out")
    g2 = w.create_goal("Close Q3 books", domain="finance_sox")
    w.set_goal_status(g2, "blocked", result="missing invoices")
    # gtm_demand_gen: one goal done.
    g3 = w.create_goal("Plan launch campaign", domain="gtm_demand_gen")
    w.set_goal_status(g3, "done", result="shipped")
    # a human approval (no department).
    aid = w.create_approval("bank_transfer", risk="high", detail="Q3 batch")
    w.decide_approval(aid, "approved", decided_by="user:cfo")
    return w


def test_by_worker_rolls_up_goals_per_specialist(world):
    cards = {c.worker: c for c in outcomes.worker_cards(world)}
    assert set(cards) == {"finance_sox", "gtm_demand_gen"}
    fin = cards["finance_sox"]
    assert fin.goals_total == 2 and fin.goals_completed == 1
    assert fin.completion_rate == 0.5
    assert fin.suite == "finance" and fin.suite_title == "Finance"
    assert "1 of 2 goals completed" in fin.headline()


def test_worker_cards_sorted_by_delivery_and_top(world):
    cards = outcomes.worker_cards(world)
    completed = [c.goals_completed for c in cards]
    assert completed == sorted(completed, reverse=True)
    assert len(outcomes.worker_cards(world, top=1)) == 1


def test_firm_totals_include_approvals_and_human_decisions(world):
    from maverick.operating_record import assemble
    t = outcomes.firm_totals(assemble(world))
    assert t.goals_total == 3 and t.goals_completed == 2
    assert t.approvals == 1 and t.human_decisions == 1


def test_empty_record_is_honest_not_fabricated(tmp_path):
    w = WorldModel(tmp_path / "empty.db")
    assert outcomes.worker_cards(w) == []
    t = outcomes.firm_totals([])
    assert t.to_dict()["goals_completed"] == 0


def test_outcome_to_dict_is_serializable(world):
    card = outcomes.worker_cards(world)[0]
    d = card.to_dict()
    assert set(d) >= {"worker", "suite", "goals_completed", "headline"}
