"""Governed department performance reviews."""
from __future__ import annotations

import pytest
from maverick import worker_review
from maverick.departments import get_department
from maverick.world_model import WorldModel


@pytest.fixture(autouse=True)
def _isolate_live_learned_store(tmp_path, monkeypatch):
    """Pin the LIVE learned store to an empty per-test dir.

    ``worker_review.review`` measures learning coverage with
    ``hindsight.coverage_under(..., None)`` against the process-global live
    store. A reflexion/insight/skill written by an earlier test in the full
    suite would otherwise leak in and make the "fresh world -> 0 covered"
    assertion order-dependent (it has). Isolating the live-store paths makes
    coverage hermetic without touching the snapshot-directory path behaviour.
    """
    from maverick import hindsight
    empty = tmp_path / "live-learned"
    real = hindsight._store_paths

    def _patched(directory):
        if directory is None:
            return {
                "reflexions": empty / "reflexions.ndjson",
                "insights": empty / "insights.ndjson",
                "skills": empty / "learned-skills",
            }
        return real(directory)

    monkeypatch.setattr(hindsight, "_store_paths", _patched)


@pytest.fixture()
def world(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    # Two finance goals; one done, one blocked.
    g1 = w.create_goal("Reconcile the ledger", domain="finance_sox")
    w.set_goal_status(g1, "done", result="tied out")
    g2 = w.create_goal("Close Q3 books", domain="finance_sox")
    w.set_goal_status(g2, "blocked", result="missing invoices")
    return w


def test_review_composes_all_sections(world):
    r = worker_review.review(world, "finance")
    assert r is not None
    assert set(r) == {"department", "delivery", "authority", "learning",
                      "governance_note"}
    assert r["department"]["title"] == "Finance"
    assert r["department"]["headcount"] > 0


def test_delivery_rolls_up_department_goals(world):
    r = worker_review.review(world, "finance")
    d = r["delivery"]
    assert d["goals_total"] == 2 and d["goals_completed"] == 1
    assert d["completion_rate"] == 0.5
    assert d["active_workers"] == 1
    assert d["workers"][0]["worker"] == "finance_sox"


def test_authority_reads_the_capability_envelope(world):
    auth = worker_review.review(world, "finance")["authority"]
    assert auth["max_risk"] in {"low", "medium", "high"}
    assert isinstance(auth["allow_tools"], list)
    assert isinstance(auth["can_write_files"], bool)
    assert "risk" in auth["summary"].lower()


def test_learning_is_honest_when_no_learned_state(world):
    learning = worker_review.review(world, "finance")["learning"]
    # Goals exist but no learned state in a fresh world -> evaluated, 0 covered.
    assert learning["goals_evaluated"] == 2
    assert learning["covered"] == 0
    assert learning["coverage_rate"] == 0.0


def test_learning_insufficient_data_when_no_goals(tmp_path):
    w = WorldModel(tmp_path / "empty.db")
    r = worker_review.review(w, "finance")
    assert r["learning"]["status"] == "insufficient_data"
    assert r["delivery"]["goals_total"] == 0


def test_unknown_department_is_none(world):
    assert worker_review.review(world, "not_a_department") is None


def test_governance_note_present(world):
    note = worker_review.review(world, "finance")["governance_note"]
    assert "audit log" in note and "shield" in note
    # Sanity: the department actually exists in the catalog.
    assert get_department("finance") is not None
