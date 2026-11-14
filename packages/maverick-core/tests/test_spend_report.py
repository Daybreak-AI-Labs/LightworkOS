"""Tests for the spend_report tool (maverick.tools.spend_report)."""
from __future__ import annotations

# ---------- Spend report tool ----------

class _FakeEp:
    def __init__(self, id, role, cost, finished_at):
        self.id = id
        self.role = role
        self.cost_dollars = cost
        self.finished_at = finished_at


def _patch_world(monkeypatch, episodes):
    class _W:
        def list_episodes(self, limit=200, owner=None):
            return episodes[:limit]

    import maverick.world_model
    monkeypatch.setattr(maverick.world_model, "WorldModel", lambda: _W())
    monkeypatch.setattr("maverick.memory_ownership.current_owner", lambda **_: "")


def test_spend_recent_empty(monkeypatch):
    _patch_world(monkeypatch, [])
    from maverick.tools.spend_report import spend_report
    out = spend_report().fn({"op": "recent"})
    assert "no episodes" in out


def test_spend_recent_renders(monkeypatch):
    import time as _time
    now = _time.time()
    eps = [
        _FakeEp(1, "orchestrator", 0.05, now - 60),
        _FakeEp(2, "proposer", 0.01, now - 30),
    ]
    _patch_world(monkeypatch, eps)
    from maverick.tools.spend_report import spend_report
    out = spend_report().fn({"op": "recent", "limit": 10})
    assert "orchestrator" in out and "proposer" in out
    assert "0.0500" in out


def test_spend_by_role_aggregates(monkeypatch):
    eps = [
        _FakeEp(1, "orchestrator", 0.05, 0),
        _FakeEp(2, "orchestrator", 0.03, 0),
        _FakeEp(3, "proposer", 0.01, 0),
    ]
    _patch_world(monkeypatch, eps)
    from maverick.tools.spend_report import spend_report
    out = spend_report().fn({"op": "by_role"})
    assert "orchestrator" in out
    assert "0.0800" in out  # 0.05 + 0.03
    assert "0.0100" in out


def test_spend_anomalies_flags_outliers(monkeypatch):
    eps = [
        _FakeEp(1, "p", 0.01, 0),
        _FakeEp(2, "p", 0.01, 0),
        _FakeEp(3, "p", 0.01, 0),
        _FakeEp(4, "p", 0.01, 0),
        _FakeEp(5, "p", 0.50, 0),  # 50× the median
    ]
    _patch_world(monkeypatch, eps)
    from maverick.tools.spend_report import spend_report
    out = spend_report().fn({"op": "anomalies"})
    assert "median" in out
    assert "$0.5000" in out or "0.5000" in out


def test_spend_total_renders(monkeypatch):
    import time as _time
    now = _time.time()
    eps = [
        _FakeEp(1, "p", 1.0, now - 30),       # in last hour
        _FakeEp(2, "p", 2.0, now - 7200),     # in last 24h
        _FakeEp(3, "p", 3.0, now - 86400 * 5),  # older
    ]
    _patch_world(monkeypatch, eps)
    from maverick.tools.spend_report import spend_report
    out = spend_report().fn({"op": "total"})
    assert "lifetime:" in out and "6.0000" in out
    assert "last 24h:" in out and "3.0000" in out
    assert "last 1h:" in out and "1.0000" in out


def test_spend_report_is_scoped_to_the_current_owner(monkeypatch):
    seen = {}

    class _W:
        def list_episodes(self, limit=200, owner=None):
            seen["owner"] = owner
            return [{"id": 1, "role": "p", "cost_dollars": 0.25, "ended_at": 0}]

    monkeypatch.setattr("maverick.tools.spend_report._world", lambda: _W())
    monkeypatch.setattr("maverick.memory_ownership.current_owner", lambda **_: "alice")
    from maverick.tools.spend_report import spend_report
    out = spend_report().fn({"op": "by_role"})
    assert seen["owner"] == "alice"
    assert "0.2500" in out  # dict-shaped episodes keep their cost
