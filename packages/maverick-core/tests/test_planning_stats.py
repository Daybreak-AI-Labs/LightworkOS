"""Learned planning-topology selection ([planning] mode = "auto")."""
from __future__ import annotations

from maverick import planning_stats
from maverick.orchestrator import _budget_task_class


class TestRecordAndPrefer:
    def test_explores_undersampled_mode_first(self, tmp_path):
        p = tmp_path / "planning_stats.json"
        # Nothing recorded: both at 0 runs -> tie keeps the cheaper default.
        assert planning_stats.prefer_tree_of_thought("fix", path=p) is False
        # Default has samples, ToT none -> explore ToT.
        for _ in range(3):
            planning_stats.record("default", "fix", True, path=p)
        assert planning_stats.prefer_tree_of_thought("fix", path=p) is True

    def test_exploits_higher_win_rate_after_min_runs(self, tmp_path):
        p = tmp_path / "planning_stats.json"
        for _ in range(3):
            planning_stats.record("default", "fix", False, path=p)
            planning_stats.record("tree_of_thought", "fix", True, path=p)
        assert planning_stats.prefer_tree_of_thought("fix", path=p) is True
        # And the inverse on another class: ToT losing keeps the default.
        for _ in range(3):
            planning_stats.record("default", "deploy", True, path=p)
            planning_stats.record("tree_of_thought", "deploy", False, path=p)
        assert planning_stats.prefer_tree_of_thought("deploy", path=p) is False

    def test_tie_keeps_default(self, tmp_path):
        p = tmp_path / "planning_stats.json"
        for _ in range(3):
            planning_stats.record("default", "fix", True, path=p)
            planning_stats.record("tree_of_thought", "fix", True, path=p)
        assert planning_stats.prefer_tree_of_thought("fix", path=p) is False

    def test_unknown_mode_is_ignored(self, tmp_path):
        p = tmp_path / "planning_stats.json"
        planning_stats.record("debate", "fix", True, path=p)
        assert not p.exists()


class TestBudgetTaskClass:
    def test_department_scopes_the_class(self):
        class _G:
            title = "Reconcile the ledger"
        assert _budget_task_class(_G()) == "reconcile"
        assert _budget_task_class(_G(), "finance_sox") == "finance_sox::reconcile"

    def test_junk_title_falls_back(self):
        class _G:
            title = "1234 !!"
        assert _budget_task_class(_G()) == "default"


def test_record_is_concurrency_safe(tmp_path):
    """Concurrent record() must not lose win/loss updates that bias topology
    selection."""
    import threading

    p = tmp_path / "planning_stats.json"
    n, per = 16, 30

    def worker():
        for _ in range(per):
            planning_stats.record("default", "fix", True, path=p)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    import json
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["default::fix"]["runs"] == n * per
    assert data["default::fix"]["wins"] == n * per
