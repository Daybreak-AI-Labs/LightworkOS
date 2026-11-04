"""Terminal charts — ASCII core, data assemblers, dashboard composition."""
from __future__ import annotations

import sys

import pytest
from maverick import tool_latency
from maverick.quotas import UsageLedger
from maverick.terminal_charts import (
    bar_chart,
    goal_throughput,
    latency_rows,
    render_dashboard,
    render_dashboard_rich,
    render_latency,
    render_spend,
    render_throughput,
    sparkline,
    spend_per_day,
)
from maverick.world_model import WorldModel

TODAY = "2025-06-15"


@pytest.fixture
def world(tmp_path):
    w = WorldModel(tmp_path / "world.db")
    yield w
    w.close()


@pytest.fixture
def ledger(tmp_path):
    return UsageLedger(path=tmp_path / "usage" / "ledger.json")


@pytest.fixture(autouse=True)
def _fresh_latency():
    tool_latency.reset()
    yield
    tool_latency.reset()


# ----- sparkline / bar chart core -----

def test_sparkline_maps_min_to_low_and_max_to_high():
    out = sparkline([0, 1, 2, 3, 4, 5, 6, 7])
    assert out == "▁▂▃▄▅▆▇█"


def test_sparkline_flat_and_empty_series():
    assert sparkline([]) == ""
    assert sparkline([0, 0, 0]) == "▁▁▁"
    assert sparkline([5, 5]) == "▄▄"


def test_sparkline_clamps_negatives():
    assert sparkline([-3, 0]) == "▁▁"


def test_bar_chart_scales_and_floors_nonzero():
    out = bar_chart([("bash", 100.0), ("read", 1.0), ("noop", 0.0)], width=10)
    lines = out.split("\n")
    assert lines[0].count("█") == 10
    assert lines[1].count("█") == 1  # tiny but nonzero still visible
    assert lines[2].count("█") == 0
    assert "100" in lines[0]


def test_bar_chart_empty():
    assert bar_chart([]) == ""


# ----- spend per day (usage ledger) -----

def test_spend_per_day_sums_principals_across_window(ledger):
    ledger.record("alice", 1.0, 1, 1, day="2025-06-15")
    ledger.record("bob", 2.0, 1, 1, day="2025-06-15")
    ledger.record("alice", 5.0, 1, 1, day="2025-06-13")
    ledger.record("alice", 9.0, 1, 1, day="2025-01-01")  # outside window
    rows = spend_per_day(ledger, days=3, today=TODAY)
    assert rows == [("2025-06-13", 5.0), ("2025-06-14", 0.0), ("2025-06-15", 3.0)]


def test_spend_per_day_empty_ledger(ledger):
    rows = spend_per_day(ledger, days=2, today=TODAY)
    assert rows == [("2025-06-14", 0.0), ("2025-06-15", 0.0)]


def test_render_spend_empty_state(ledger):
    out = render_spend(spend_per_day(ledger, days=7, today=TODAY))
    assert "no spend recorded" in out


def test_render_spend_with_data(ledger):
    ledger.record("alice", 4.0, 1, 1, day=TODAY)
    out = render_spend(spend_per_day(ledger, days=7, today=TODAY))
    assert "total $4.00" in out
    assert "█" in out
    assert "today: $4.00" in out


# ----- goal throughput (world model) -----

def _finish_goal_on_day(world, title, status, day_ts):
    gid = world.create_goal(title)
    world.set_goal_status(gid, status)
    # Tests place terminal transitions on specific days by adjusting the
    # timestamp the bucketing reads (updated_at).
    with world._writing() as conn:  # noqa: SLF001
        conn.execute("UPDATE goals SET updated_at = ? WHERE id = ?", (day_ts, gid))
    return gid


def test_goal_throughput_buckets_done_and_blocked_by_day(world):
    day_15 = 1_750_000_000.0  # 2025-06-15 UTC
    day_14 = day_15 - 86400.0
    _finish_goal_on_day(world, "a", "done", day_15)
    _finish_goal_on_day(world, "b", "done", day_15)
    _finish_goal_on_day(world, "c", "blocked", day_14)
    _finish_goal_on_day(world, "d", "cancelled", day_15)  # neither done nor failed
    rows = goal_throughput(world, days=2, today=TODAY)
    assert rows == [("2025-06-14", 0, 1), ("2025-06-15", 2, 0)]


def test_goal_throughput_empty_world(world):
    rows = goal_throughput(world, days=2, today=TODAY)
    assert rows == [("2025-06-14", 0, 0), ("2025-06-15", 0, 0)]


def test_render_throughput_empty_state(world):
    out = render_throughput(goal_throughput(world, days=7, today=TODAY))
    assert "no finished goals" in out


def test_render_throughput_with_data(world):
    _finish_goal_on_day(world, "a", "done", 1_750_000_000.0)
    out = render_throughput(goal_throughput(world, days=7, today=TODAY))
    assert "1 done, 0 failed" in out
    assert "done" in out and "failed" in out


# ----- tool latency -----

def test_latency_rows_from_live_profile():
    for ms in (10, 20, 30, 1000):
        tool_latency.record("bash", ms)
    tool_latency.record("read", 1)
    rows = latency_rows()
    assert rows[0][0] == "bash"  # slowest p95 first
    assert len(rows) == 2
    assert rows[0][2] >= rows[1][2]


def test_latency_rows_caps_at_ten():
    report = [
        {"tool": f"t{i}", "p50_ms": 1.0, "p95_ms": float(100 - i), "p99_ms": 1.0}
        for i in range(15)
    ]
    assert len(latency_rows(report)) == 10


def test_render_latency_empty_state():
    assert "no tool latency samples" in render_latency(latency_rows([]))


def test_render_latency_with_data():
    tool_latency.record("bash", 50)
    out = render_latency(latency_rows())
    assert "bash" in out
    assert "p95" in out
    assert "█" in out


# ----- dashboard composition -----

def test_render_dashboard_all_empty_states(world, ledger):
    out = render_dashboard(world, ledger, [], today=TODAY)
    assert "no spend recorded" in out
    assert "no finished goals" in out
    assert "no tool latency samples" in out


def test_render_dashboard_with_data(world, ledger):
    ledger.record("alice", 2.5, 1, 1, day=TODAY)
    _finish_goal_on_day(world, "a", "done", 1_750_000_000.0)
    tool_latency.record("bash", 42)
    out = render_dashboard(world, ledger, today=TODAY)
    assert "Spend per day" in out
    assert "Goal throughput" in out
    assert "Tool latency" in out
    assert "$2.50" in out


def test_rich_wrapper_falls_back_to_ascii_without_rich(world, ledger, monkeypatch):
    # Forcing the import to fail exercises the documented fallback even on
    # machines that do have rich installed.
    monkeypatch.setitem(sys.modules, "rich", None)
    monkeypatch.setitem(sys.modules, "rich.console", None)
    monkeypatch.setitem(sys.modules, "rich.panel", None)
    out = render_dashboard_rich(world, ledger, [], today=TODAY)
    assert isinstance(out, str)
    assert "no spend recorded" in out


def test_rich_wrapper_uses_rich_when_available(world, ledger):
    pytest.importorskip("rich")
    out = render_dashboard_rich(world, ledger, [], today=TODAY)
    assert not isinstance(out, str)  # a rich renderable (Group of Panels)
