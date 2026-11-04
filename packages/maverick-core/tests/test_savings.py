"""Savings report: the client's own cost/value inputs vs real completed work."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from maverick import savings, workforce_value
from maverick.config import get_value, reset_config_cache


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


CFG = {
    "enable": True, "hourly_rate": 100.0, "hours_per_task": 2.0,
    "currency": "USD",
    "departments": {"legal_privacy": {"hourly_rate": 300.0,
                                      "hours_per_task": 1.0}},
}


class TestAssumptions:
    def test_department_override_wins(self):
        assert savings.assumptions_for("legal_privacy", CFG) == (300.0, 1.0)

    def test_unknown_department_gets_global(self):
        assert savings.assumptions_for("gtm_x", CFG) == (100.0, 2.0)

    def test_partial_override_inherits_the_other_axis(self):
        cfg = dict(CFG, departments={"finance_ap": {"hourly_rate": 80.0}})
        assert savings.assumptions_for("finance_ap", cfg) == (80.0, 2.0)


class TestCompute:
    def test_savings_math_per_department(self):
        world = _World(
            episodes=[
                _ep(1, cost=2.0, outcome="success"),   # finance: 2h x $100
                _ep(2, cost=0.5, outcome="success"),   # legal: 1h x $300
                _ep(3, cost=1.0, outcome="failure"),   # cost counts, no deliverable
            ],
            goal_domains={1: "finance_ap", 2: "legal_privacy", 3: "finance_ap"},
        )
        r = savings.compute(world, window_days=365, cfg=CFG, now=2000.0)
        assert r.deliverables == 2
        assert r.agent_cost == 3.5
        assert r.human_cost == 500.0     # 2*100 + 1*300
        assert r.human_hours == 3.0      # 2 + 1
        assert r.saved == 496.5
        assert round(r.roi_multiple, 2) == round(500.0 / 3.5, 2)
        # Sorted by saved, descending: legal (299.5) over finance (197.0).
        assert [d.department for d in r.by_department] == \
            ["legal_privacy", "finance_ap"]

    def test_zero_history_reports_zero_not_error(self):
        r = savings.compute(_World([], {}), window_days=90, cfg=CFG)
        assert r.deliverables == 0
        assert r.saved == 0.0
        assert r.roi_multiple == 0.0

    def test_to_dict_carries_assumptions_and_department_math(self):
        world = _World([_ep(1, cost=1.0, outcome="success")],
                       {1: "legal_privacy"})
        d = savings.to_dict(
            savings.compute(world, window_days=365, cfg=CFG, now=2000.0))
        assert d["assumptions"] == {"hourly_rate": 100.0, "hours_per_task": 2.0}
        dept = d["by_department"][0]
        assert dept["department"] == "legal_privacy"
        assert dept["hourly_rate"] == 300.0
        assert dept["human_cost"] == 300.0
        assert dept["saved"] == 299.0


class TestWorkforceValueHook:
    def test_per_department_human_cost_callable(self):
        world = _World(
            episodes=[_ep(1, cost=0.0, outcome="success"),
                      _ep(2, cost=0.0, outcome="success")],
            goal_domains={1: "a", 2: "b"},
        )
        v = workforce_value.compute(
            world, window_days=365, human_cost=50.0,
            human_cost_for=lambda dept: 10.0 if dept == "a" else 20.0,
            now=2000.0)
        assert v.human_baseline == 30.0

    def test_raising_callable_falls_back_to_flat_cost(self):
        world = _World([_ep(1, cost=0.0, outcome="success")], {1: "a"})

        def boom(_dept):
            raise RuntimeError("bad override")

        v = workforce_value.compute(world, window_days=365, human_cost=50.0,
                                    human_cost_for=boom, now=2000.0)
        assert v.human_baseline == 50.0


class TestConfig:
    @pytest.fixture(autouse=True)
    def _fresh_config(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.toml"
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
        monkeypatch.delenv("MAVERICK_VALUE_HOURLY_RATE", raising=False)
        monkeypatch.delenv("MAVERICK_VALUE_HOURS", raising=False)
        reset_config_cache()
        yield cfg
        reset_config_cache()

    def test_defaults_are_conservative(self, _fresh_config):
        v = get_value()
        assert v["enable"] is True
        assert v["hourly_rate"] == 75.0
        assert v["hours_per_task"] == 2.0
        assert v["currency"] == "USD"
        assert v["departments"] == {}

    def test_reads_section_with_department_tables(self, _fresh_config):
        _fresh_config.write_text(
            '[value]\nhourly_rate = 120\nhours_per_task = 3.5\n'
            'currency = "eur"\n'
            '[value.departments.finance_ap]\nhourly_rate = 95\n',
            encoding="utf-8")
        reset_config_cache()
        v = get_value()
        assert v["hourly_rate"] == 120.0
        assert v["currency"] == "EUR"
        # A partial override inherits the global hours.
        assert v["departments"]["finance_ap"] == {
            "hourly_rate": 95.0, "hours_per_task": 3.5}

    def test_junk_and_negative_values_fall_back(self, _fresh_config):
        _fresh_config.write_text(
            '[value]\nhourly_rate = "lots"\nhours_per_task = -3\n',
            encoding="utf-8")
        reset_config_cache()
        v = get_value()
        assert v["hourly_rate"] == 75.0
        assert v["hours_per_task"] == 2.0

    def test_env_override_wins(self, _fresh_config, monkeypatch):
        _fresh_config.write_text("[value]\nhourly_rate = 10\n", encoding="utf-8")
        monkeypatch.setenv("MAVERICK_VALUE_HOURLY_RATE", "250")
        reset_config_cache()
        assert get_value()["hourly_rate"] == 250.0
