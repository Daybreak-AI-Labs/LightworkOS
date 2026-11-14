"""Workforce value report: throughput + economics + compounding + governance."""
from __future__ import annotations

from types import SimpleNamespace

from maverick import workforce_value


class _World:
    def __init__(self, episodes, goal_domains):
        self._eps = episodes
        self._domains = goal_domains

    def list_episodes(self, limit=5000, goal_id=None):
        return self._eps[:limit]

    def get_goal(self, goal_id):
        dom = self._domains.get(goal_id)
        return SimpleNamespace(domain=dom) if dom is not None else None


def _ep(goal_id, *, cost, outcome, started_at=1000.0):
    return SimpleNamespace(id=goal_id, goal_id=goal_id, started_at=started_at,
                           ended_at=started_at + 1, outcome=outcome,
                           cost_dollars=cost, input_tokens=0, output_tokens=0,
                           tool_calls=0)


class TestEconomics:
    def test_cost_avoided_and_roi(self):
        world = _World(
            episodes=[
                _ep(1, cost=2.0, outcome="success"),
                _ep(2, cost=3.0, outcome="success"),
                _ep(3, cost=1.0, outcome="failure"),  # cost counts, no deliverable
            ],
            goal_domains={1: "finance_sox", 2: "finance_sox", 3: "legal_x"},
        )
        v = workforce_value.compute(world, window_days=365, human_cost=50.0,
                                    now=2000.0)
        assert v.deliverables == 2
        assert v.agent_cost == 6.0           # 2+3+1
        assert v.human_baseline == 100.0     # 2 deliverables * 50
        assert v.cost_avoided == 94.0
        assert round(v.roi_multiple, 2) == round(100.0 / 6.0, 2)

    def test_window_excludes_old_episodes(self):
        world = _World(
            episodes=[
                _ep(1, cost=1.0, outcome="success", started_at=100.0),   # old
                _ep(2, cost=1.0, outcome="success", started_at=1_000_000.0),
            ],
            goal_domains={1: "x", 2: "x"},
        )
        v = workforce_value.compute(world, window_days=1, now=1_000_050.0)
        assert v.deliverables == 1

    def test_department_breakdown_sorted_by_avoided(self):
        world = _World(
            episodes=[
                _ep(1, cost=1.0, outcome="success"),
                _ep(2, cost=1.0, outcome="success"),
                _ep(3, cost=1.0, outcome="success"),
            ],
            goal_domains={1: "finance_sox", 2: "finance_sox", 3: "gtm_x"},
        )
        v = workforce_value.compute(world, window_days=365, human_cost=50.0,
                                    now=2000.0)
        assert v.by_department[0].department == "finance_sox"
        assert v.by_department[0].deliverables == 2

    def test_unattributed_when_no_domain(self):
        world = _World([_ep(1, cost=1.0, outcome="success")], goal_domains={})
        v = workforce_value.compute(world, window_days=365, now=2000.0)
        assert v.by_department[0].department == "(unattributed)"


class TestCompounding:
    def test_improvement_from_hindsight_ledger(self, tmp_path, monkeypatch):
        import maverick.dreaming as dreaming
        ledger = tmp_path / "hindsight.ndjson"
        ledger.write_text(
            '{"ts": 1000.0, "covered_now": 3}\n'
            '{"ts": 2000.0, "covered_now": 5}\n'
            '{"ts": 3000.0, "covered_now": 8}\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(dreaming, "_tenant_path", lambda name, legacy: ledger)
        world = _World([], {})
        v = workforce_value.compute(world, window_days=365, now=3001.0 + 0)
        # now must be close enough that 1000.0 is within the window:
        v = workforce_value.compute(world, window_days=100000, now=3001.0)
        assert len(v.coverage_trend) == 3
        assert v.improvement == 5  # 8 - 3

    def test_malformed_ledger_lines_are_skipped(self, tmp_path, monkeypatch):
        """Regression: valid JSON of the wrong shape raised out of compute()."""
        import maverick.dreaming as dreaming
        ledger = tmp_path / "hindsight.ndjson"
        ledger.write_text(
            '[]\n{"ts": "x"}\n{"ts": NaN}\n{"ts": 2000.0, "covered_now": "y"}\n'
            '{"ts": 2000.0, "covered_now": 4}\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(dreaming, "_tenant_path", lambda name, legacy: ledger)
        v = workforce_value.compute(_World([], {}), window_days=100000, now=3001.0)
        assert len(v.coverage_trend) == 1

    def test_improvement_none_without_history(self):
        v = workforce_value.compute(_World([], {}), window_days=90)
        assert v.improvement is None


class TestRender:
    def test_report_is_executive_readable(self):
        world = _World([_ep(1, cost=2.0, outcome="success")],
                       {1: "finance_sox"})
        v = workforce_value.compute(world, window_days=365, human_cost=50.0,
                                    now=2000.0)
        text = workforce_value.format_report(v)
        assert "AI Workforce" in text
        assert "Cost avoided" in text
        assert "finance_sox" in text

    def test_to_dict_roundtrips_key_numbers(self):
        world = _World([_ep(1, cost=2.0, outcome="success")], {1: "x"})
        v = workforce_value.compute(world, window_days=365, human_cost=50.0,
                                    now=2000.0)
        d = workforce_value.to_dict(v)
        assert d["deliverables"] == 1
        assert d["cost_avoided"] == 48.0
        assert d["by_department"][0]["department"] == "x"

class TestGovernance:
    def test_governance_does_not_claim_unsigned_audit_chain(self, tmp_path, monkeypatch):
        from maverick.audit import signing

        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        monkeypatch.setattr(signing, "_have_crypto", lambda: True)
        monkeypatch.setattr(
            signing,
            "verify_chain",
            lambda path: [signing.ChainBreak(1, "unsigned", "audit signing disabled")],
        )
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        (audit_dir / "2026-06-13.ndjson").write_text(
            '{"kind":"test","ts":1}\n', encoding="utf-8",
        )

        summary = workforce_value._governance_summary()

        assert summary["chain_verifiable"] is False
        assert "signed audit chain present" not in workforce_value.format_report(
            workforce_value.WorkforceValue(governance=summary),
        )

    def test_governance_claims_chain_only_after_verifier_passes(self, tmp_path, monkeypatch):
        from maverick.audit import signing

        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        monkeypatch.setattr(signing, "_have_crypto", lambda: True)
        monkeypatch.setattr(signing, "verify_chain", lambda path: [])
        monkeypatch.setattr(signing, "verify_anchors", lambda audit_dir: [])
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        (audit_dir / "2026-06-13.ndjson").write_text(
            '{"hash":"h","sig":"s","key_id":"k"}\n', encoding="utf-8",
        )

        summary = workforce_value._governance_summary()

        assert summary["chain_verifiable"] is True


def test_runs_read_with_their_goal_domain_skip_a_second_goal_read(tmp_path, monkeypatch):
    # A goal without a domain was read again for each of its runs' departments
    # (500 such runs: 500 goal reads on every Savings page).
    import pytest
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    wm = WorldModel(tmp_path / "w.db")
    for domain in ("finance_ap", "", "finance_ap"):
        goal = wm.create_goal("task", "", domain=domain)
        episode = wm.start_episode(goal)
        wm.end_episode(episode, "summary", "success", cost_dollars=1.0)
    reread = workforce_value.compute(wm)
    monkeypatch.setattr(wm, "get_goal", lambda *_: pytest.fail("the goal was read again"))
    value = workforce_value.compute(wm)
    assert {d.department: d.deliverables for d in value.by_department} == {
        "finance_ap": 2, "(unattributed)": 1}
    assert value.by_department == reread.by_department


def test_runs_at_the_reports_own_clock_reading_both_count(tmp_path, monkeypatch):
    # A coarse wall clock (Windows) can read the same value when a run starts
    # and when the report is built. The window's end is inclusive: both runs count.
    import time as clock

    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(clock, "time", lambda: 1_800_000_000.0)
    wm = WorldModel(tmp_path / "w.db")
    try:
        for _ in range(2):
            goal = wm.create_goal("task", "", domain="finance_ap")
            episode = wm.start_episode(goal)
            wm.end_episode(episode, "summary", "success", cost_dollars=1.0)
        value = workforce_value.compute(wm)
        assert {d.department: d.deliverables for d in value.by_department} == {"finance_ap": 2}
    finally:
        wm.close()


def test_a_run_started_after_the_reports_reading_is_not_counted(tmp_path, monkeypatch):
    # The report covers up to its own reading: a run started later belongs to a
    # later report. The history reader and a list-only adapter both enforce it.
    import time as clock

    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    wm = WorldModel(tmp_path / "w.db")
    try:
        monkeypatch.setattr(clock, "time", lambda: 1_800_000_000.0)
        goal = wm.create_goal("task", "", domain="finance_ap")
        episode = wm.start_episode(goal)
        wm.end_episode(episode, "summary", "success", cost_dollars=1.0)
        monkeypatch.setattr(clock, "time", lambda: 1_800_000_060.0)
        later = wm.start_episode(goal)
        wm.end_episode(later, "summary", "success", cost_dollars=5.0)
        value = workforce_value.compute(wm, now=1_800_000_000.0)
        assert value.agent_cost == 1.0
        assert {d.department: d.deliverables for d in value.by_department} == {"finance_ap": 1}
    finally:
        wm.close()
    legacy = _World([_ep(1, cost=5.0, outcome="success", started_at=1_800_000_060.0)], {1: "finance_ap"})
    assert workforce_value.compute(legacy, now=1_800_000_000.0).deliverables == 0
