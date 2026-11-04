"""Cross-run anomaly detection: novel kinds, volume + error-rate spikes,
cold-deployment silence."""
from __future__ import annotations

import types

from maverick.cross_run_anomaly import (
    Anomaly,
    baseline,
    detect,
    gather_runs,
    profile_run,
    score_run,
)


def _ev(kind):
    return types.SimpleNamespace(kind=kind)


def _normal_run(gid, n=10, errors=1):
    events = [_ev("finding")] * (n - errors) + [_ev("error")] * errors
    return profile_run(gid, events)


def test_profile_counts():
    p = profile_run(1, [_ev("plan"), _ev("finding"), _ev("error")])
    assert p.events == 3 and p.errors == 1 and p.kinds["plan"] == 1
    assert abs(p.error_rate - 1 / 3) < 1e-9


def test_cold_baseline_never_flags():
    base = baseline([_normal_run(i) for i in range(3)])  # < MIN_BASELINE_RUNS
    weird = profile_run(99, [_ev("exfil")] * 100)
    assert score_run(weird, base) == []


def test_novel_event_kind_flagged_high():
    base = baseline([_normal_run(i) for i in range(8)])
    run = profile_run(99, [_ev("finding")] * 9 + [_ev("shell_breakout")])
    anomalies = score_run(run, base)
    kinds = {a.kind: a for a in anomalies}
    assert "novel_event_kind" in kinds
    assert kinds["novel_event_kind"].severity == "high"
    assert "shell_breakout" in kinds["novel_event_kind"].detail


def test_volume_spike_flagged():
    runs = [_normal_run(i, n=10 + (i % 3)) for i in range(10)]  # ~10-12 events
    base = baseline(runs)
    big = profile_run(99, [_ev("finding")] * 200)
    kinds = {a.kind for a in score_run(big, base)}
    assert "event_volume" in kinds


def test_error_rate_spike_flagged():
    runs = []
    for i in range(10):
        # ~10% error rate with a little variance so stdev > 0
        runs.append(_normal_run(i, n=20, errors=2 + (i % 2)))
    base = baseline(runs)
    bad = _normal_run(99, n=20, errors=18)
    kinds = {a.kind for a in score_run(bad, base)}
    assert "error_rate" in kinds


def test_normal_run_clean():
    runs = [_normal_run(i, n=10 + (i % 4), errors=1) for i in range(10)]
    base = baseline(runs)
    assert score_run(_normal_run(99, n=11, errors=1), base) == []


def test_detect_excludes_target_from_baseline():
    class _W:
        def list_goals(self, limit=50, order="desc"):
            return [types.SimpleNamespace(id=i, status="done") for i in range(1, 11)]

        def goal_events(self, gid, limit=10_000):
            if gid == 5:  # the target: novel kind
                return [_ev("finding")] * 9 + [_ev("never_before")]
            return [_ev("finding")] * 10 + [_ev("error")]

    anomalies = detect(_W(), 5)
    assert any(a.kind == "novel_event_kind" for a in anomalies)
    assert all(isinstance(a, Anomaly) for a in anomalies)


def test_gather_runs_scopes_by_owner_before_reading_events():
    class _W:
        def __init__(self):
            self.events_read = []

        def list_goals(self, limit=50, order="desc", owner=None):
            goals = [
                types.SimpleNamespace(id=1, status="done", owner="user:alice"),
                types.SimpleNamespace(id=2, status="done", owner="user:bob"),
                types.SimpleNamespace(id=3, status="running", owner="user:alice"),
                types.SimpleNamespace(id=4, status="done", owner="user:alice"),
            ]
            if owner is not None:
                goals = [g for g in goals if g.owner == owner]
            return goals[:limit]

        def goal_events(self, gid, limit=10_000):
            self.events_read.append(gid)
            return [_ev("finding")] * 10

    world = _W()
    profiles = gather_runs(world, owner="user:alice")

    assert [p.goal_id for p in profiles] == [1, 4]
    assert world.events_read == [1, 4]


def test_detect_owner_scope_excludes_other_tenants_from_baseline():
    class _W:
        def list_goals(self, limit=50, order="desc", owner=None):
            goals = [
                types.SimpleNamespace(id=i, status="done", owner="user:bob")
                for i in range(1, 6)
            ] + [types.SimpleNamespace(id=6, status="done", owner="user:alice")]
            if owner is not None:
                goals = [g for g in goals if g.owner == owner]
            return goals[:limit]

        def goal_events(self, gid, limit=10_000):
            if gid == 6:
                return [_ev("alice_only_kind")] * 10
            return [_ev("finding")] * 10

    assert detect(_W(), 6, owner="user:alice") == []
    assert any(a.kind == "novel_event_kind" for a in detect(_W(), 6))
