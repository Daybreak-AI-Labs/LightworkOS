"""Regression cases for complete scoped reporting. Authored; execution deferred."""
import sqlite3
from types import SimpleNamespace

from maverick import savings, workforce_value
from maverick.episode_reporting import iter_episodes


class History:
    def __init__(self, count=5101):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript("""
            CREATE TABLE goals(id INTEGER, owner TEXT, domain TEXT);
            CREATE TABLE episodes(id INTEGER, goal_id INTEGER, started_at REAL,
                ended_at REAL, outcome TEXT, cost_dollars REAL,
                input_tokens INTEGER, output_tokens INTEGER, tool_calls INTEGER);
            INSERT INTO goals VALUES(1, 'alice', 'research'), (2, 'bob', 'research');
        """)
        self.db.executemany("INSERT INTO episodes VALUES(?, 1, 1000, 1001, 'success', 1, 3, 2, 0)",
                            [(n,) for n in range(1, count + 1)])
        self.db.execute("INSERT INTO episodes VALUES(?, 2, 1000, 1001, 'success', 99, 3, 2, 0)", (count + 1,))

    def query(self, sql, params=()):
        return self.db.execute(sql, params).fetchall()


def test_complete_owner_population_exceeds_old_5000_cap():
    history = History()
    rows = list(iter_episodes(history, owner="alice", since=999, until=1002, finished_only=True))
    assert len(rows) == 5101
    assert sum(row.cost_dollars for row in rows) == 5101
    assert {row.goal_id for row in rows} == {1}


def test_initial_ceiling_excludes_inserts_during_paging():
    history = History(501)
    stream = iter_episodes(history, owner="alice")
    first = next(stream)
    history.db.execute("INSERT INTO episodes VALUES(9999, 1, 1000, 1001, 'success', 4, 0, 0, 0)")
    assert len([first, *stream]) == 501


def test_running_attempt_excluded_and_unknown_finished_cost_preserved():
    history = History(1)
    history.db.execute("UPDATE episodes SET cost_dollars = NULL WHERE id = 1")
    history.db.execute("INSERT INTO episodes VALUES(3, 1, 1000, NULL, NULL, 20, 0, 0, 0)")
    rows = list(iter_episodes(history, owner="alice", finished_only=True))
    assert len(rows) == 1 and rows[0].cost_dollars is None
    report = workforce_value.to_dict(workforce_value.compute(history, owner="alice", now=2000))
    assert report["available"] is False
    assert report["agent_cost"] is None and report["deliverables"] is None


def test_storage_failure_is_unavailable_not_zero():
    class Broken:
        def query(self, *args):
            raise OSError("disk unreadable")
    report = workforce_value.to_dict(workforce_value.compute(Broken(), now=2000))
    assert report["available"] is False
    assert report["human_baseline"] is None


def test_unsupported_owner_adapter_refuses_unscoped_read():
    world = SimpleNamespace(list_episodes=lambda **kw: (_ for _ in ()).throw(AssertionError("must not read")))
    assert workforce_value.compute(world, owner="alice").available is False


def test_non_usd_assumptions_require_review_without_relabelling_costs():
    cfg = {"currency": "EUR", "hourly_rate": 100, "hours_per_task": 2, "departments": {}}
    result = savings.to_dict(savings.compute(History(1), cfg=cfg, owner="alice", now=2000))
    assert result["available"] is False
    assert result["saved"] is None
