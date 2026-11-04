"""Autonomous Shoring: the Book of Work store + measured SLA computation.

Store round-trip and tenant isolation, upsert/remove, SLA met/at-risk/breached
from a stub Operating Record, the exception-desk lens, and the enable knob.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import pytest
from maverick import shoring
from maverick.shoring import Function, SLATarget


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_SHORING", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    yield


# --------------------------------------------------------------------------- #
# Stub Operating Record world
# --------------------------------------------------------------------------- #
@dataclass
class _Goal:
    id: int
    domain: str
    status: str
    updated_at: float
    title: str = "seeded goal"


@dataclass
class _Episode:
    goal_id: int
    cost_dollars: float = 1.0


@dataclass
class _Approval:
    id: int
    action: str
    risk: str = "high"
    scope: str | None = None
    detail: str | None = None
    provenance: str | None = None
    status: str = "pending"
    requested_at: float = 0.0
    decided_at: float | None = None
    decided_by: str | None = None
    requested_by: str | None = None
    claimed_by: str | None = None
    department: str = ""


class _World:
    def __init__(self, goals=None, approvals=None, pending=None):
        self._goals = goals or []
        self._approvals = approvals or []
        self._pending = pending or []

    def list_goals(self, *, limit=500, order="desc", owner=None, domain=None):
        return [g for g in self._goals if domain is None or g.domain == domain][:limit]

    def list_episodes(self, *, limit=2000, owner=None):
        return [_Episode(g.id) for g in self._goals]

    def list_approvals(self, limit=500):
        return list(self._approvals)[:limit]

    def pending_approvals(self):
        return list(self._pending)


# --------------------------------------------------------------------------- #
# Store round-trip + tenant isolation
# --------------------------------------------------------------------------- #
def test_store_round_trip():
    fn = Function(key="ap", name="Accounts Payable", department="finance_ap",
                  scope="Invoice intake to payment", status="running",
                  owner="cfo",
                  slas=[SLATarget("Throughput", "throughput_per_day", 5.0)])
    shoring.upsert(fn)
    loaded = shoring.load()
    assert len(loaded) == 1
    got = loaded[0]
    assert got.key == "ap"
    assert got.name == "Accounts Payable"
    assert got.department == "finance_ap"
    assert got.status == "running"
    assert got.slas[0].metric == "throughput_per_day"
    assert got.updated_at > 0


def test_tenant_isolation(monkeypatch):
    from maverick import paths
    tok = paths.set_tenant("acme")
    try:
        shoring.upsert(Function(key="ap", name="AP", department="finance_ap"))
    finally:
        paths.reset_tenant(tok)
    tok = paths.set_tenant("globex")
    try:
        assert shoring.load() == []  # globex sees nothing of acme's book
        shoring.upsert(Function(key="sup", name="Support", department="support"))
        assert [f.key for f in shoring.load()] == ["sup"]
    finally:
        paths.reset_tenant(tok)
    tok = paths.set_tenant("acme")
    try:
        assert [f.key for f in shoring.load()] == ["ap"]  # unchanged
    finally:
        paths.reset_tenant(tok)


def test_upsert_replaces_by_key():
    shoring.upsert(Function(key="ap", name="AP v1", department="finance_ap"))
    shoring.upsert(Function(key="ap", name="AP v2", department="finance_ap"))
    book = shoring.load()
    assert len(book) == 1
    assert book[0].name == "AP v2"


def test_remove():
    shoring.upsert(Function(key="ap", name="AP", department="finance_ap"))
    assert shoring.remove("ap") is True
    assert shoring.load() == []
    assert shoring.remove("ap") is False  # idempotent: nothing to remove


def test_upsert_rejects_bad_key():
    with pytest.raises(ValueError):
        shoring.upsert(Function(key="Bad Key!", name="x"))


def test_malformed_rows_are_skipped(tmp_path):
    # A hand-edited/partial book still opens: junk rows are dropped, not fatal.
    path = shoring._book_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '[{"key": "ok", "name": "Good"}, {"name": "no key"}, "garbage"]',
        encoding="utf-8")
    book = shoring.load()
    assert [f.key for f in book] == ["ok"]


# --------------------------------------------------------------------------- #
# SLA met / at-risk / breached
# --------------------------------------------------------------------------- #
def _fn(slas):
    return Function(key="ap", name="AP", department="finance_ap", slas=slas)


def test_sla_throughput_met():
    now = time.time()
    # 10 delivered over a 5-day window = 2.0/day, target 1.0/day -> met.
    goals = [_Goal(i, "finance_ap", "done", now) for i in range(10)]
    world = _World(goals=goals)
    fn = _fn([SLATarget("Throughput", "throughput_per_day", 1.0)])
    [row] = shoring.sla_status(fn, world, window_days=5, now=now)
    assert row["actual"] == 2.0
    assert row["status"] == "met"


def test_sla_throughput_breached():
    now = time.time()
    # 1 delivered over 100 days = 0.01/day vs target 1.0/day -> breached.
    world = _World(goals=[_Goal(1, "finance_ap", "done", now)])
    fn = _fn([SLATarget("Throughput", "throughput_per_day", 1.0)])
    [row] = shoring.sla_status(fn, world, window_days=100, now=now)
    assert row["status"] == "breached"


def test_sla_exception_rate_bands():
    now = time.time()
    # 9 done + 1 blocked = 10% exception rate.
    goals = [_Goal(i, "finance_ap", "done", now) for i in range(9)]
    goals.append(_Goal(99, "finance_ap", "blocked", now))
    world = _World(goals=goals)

    met = shoring.sla_status(
        _fn([SLATarget("Exceptions", "max_exception_rate_pct", 20.0)]),
        world, now=now)[0]
    assert met["actual"] == 10.0 and met["status"] == "met"

    at_risk = shoring.sla_status(
        _fn([SLATarget("Exceptions", "max_exception_rate_pct", 9.0)]),
        world, now=now)[0]
    # 10/9 = 1.11x -> within the amber shoulder.
    assert at_risk["status"] == "at_risk"

    breached = shoring.sla_status(
        _fn([SLATarget("Exceptions", "max_exception_rate_pct", 5.0)]),
        world, now=now)[0]
    # 10/5 = 2.0x over -> breached.
    assert breached["status"] == "breached"


def test_sla_no_data_is_not_a_false_breach():
    now = time.time()
    world = _World(goals=[])  # a scoping-stage function with no work yet
    fn = _fn([
        SLATarget("Exceptions", "max_exception_rate_pct", 5.0),
        SLATarget("Turnaround", "max_turnaround_hours", 24.0),
    ])
    rows = {r["metric"]: r for r in shoring.sla_status(fn, world, now=now)}
    assert rows["max_exception_rate_pct"]["status"] == "no_data"
    assert rows["max_turnaround_hours"]["status"] == "no_data"
    assert rows["max_turnaround_hours"]["actual"] is None


def test_measurement_scoped_by_department():
    now = time.time()
    goals = [
        _Goal(1, "finance_ap", "done", now),
        _Goal(2, "support", "done", now),  # different department, excluded
    ]
    world = _World(goals=goals)
    fn = _fn([SLATarget("Throughput", "throughput_per_day", 1.0)])
    st = shoring.function_status(fn, world, window_days=1, now=now)
    assert st["delivered"] == 1  # only finance_ap counted


# --------------------------------------------------------------------------- #
# Exception desk
# --------------------------------------------------------------------------- #
def test_exception_desk_filters_by_department():
    pending = [
        _Approval(1, "wire.transfer", department="finance_ap"),
        _Approval(2, "post.tweet", department="marketing", detail="mentions finance_ap"),
        _Approval(3, "vendor.add", department="finance_ap"),
        _Approval(4, "vendor.add", scope="finance_ap", provenance="finance_ap"),
    ]
    world = _World(pending=pending)
    fn = _fn([])
    st = shoring.function_status(fn, world, now=time.time())
    assert st["exception_count"] == 2
    assert {e["id"] for e in st["exceptions"]} == {1, 3}
    assert st["unassigned_exception_count"] == 1


def test_overall_rolls_up_worst_sla():
    now = time.time()
    # 1 delivered over 90 days = ~0.011/day.
    world = _World(goals=[_Goal(1, "finance_ap", "done", now)])
    fn = _fn([
        SLATarget("Low bar", "throughput_per_day", 0.001),   # 11x target -> met
        SLATarget("High bar", "throughput_per_day", 100.0),  # far under -> breached
    ])
    st = shoring.function_status(fn, world, window_days=90, now=now)
    assert st["overall"] == "breached"


# --------------------------------------------------------------------------- #
# The knob
# --------------------------------------------------------------------------- #
def test_enabled_defaults_on():
    assert shoring.enabled() is True


def test_env_override_off(monkeypatch):
    monkeypatch.setenv("MAVERICK_SHORING", "0")
    assert shoring.enabled() is False


def test_config_knob_off(monkeypatch):
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"shoring": {"enable": False}})
    assert shoring.enabled() is False


def test_env_override_beats_config(monkeypatch):
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"shoring": {"enable": False}})
    monkeypatch.setenv("MAVERICK_SHORING", "1")
    assert shoring.enabled() is True
