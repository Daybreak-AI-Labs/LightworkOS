"""Tests for the offline bundle (and the glance summary it embeds).

Offline + deterministic: a fake in-memory world, fixed ``now`` timestamps,
no network, no real DB.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import SimpleNamespace

from maverick.offline_bundle import (
    EVENT_FIELDS,
    GOAL_FIELDS,
    SCHEMA,
    build_bundle,
)
from maverick.offline_bundle import (
    build_offline_glance as build_glance,
)


@dataclass
class FakeGoal:
    id: int
    title: str
    status: str = "active"
    created_at: float = 100.0
    updated_at: float = 200.0
    result: str | None = None
    owner: str = ""


@dataclass
class FakeEvent:
    id: int
    goal_id: int
    agent: str = "planner"
    kind: str = "tool"
    content: str = "ran a tool"
    ts: float = 150.0


@dataclass
class FakeWorld:
    goals: list[FakeGoal] = field(default_factory=list)
    events: dict[int, list[FakeEvent]] = field(default_factory=dict)
    approvals: list[object] = field(default_factory=list)
    questions: list[object] = field(default_factory=list)
    spend: dict = field(default_factory=lambda: {"dollars": 1.25, "runs": 3})

    def list_goals(self, status=None, *, owner=None, limit=None, offset=0, order="asc"):
        out = [g for g in self.goals
               if (status is None or g.status == status)
               and (owner is None or g.owner == owner)]
        out.sort(key=lambda g: g.id, reverse=(order == "desc"))
        return out[offset:offset + limit] if limit is not None else out

    def recent_goal_events(self, goal_id, limit=200):
        return sorted(self.events.get(goal_id, []), key=lambda e: e.id)[-limit:]

    def pending_approvals(self):
        return list(self.approvals)

    def open_questions(self, goal_id=None):
        return list(self.questions)

    def total_spend(self):
        return dict(self.spend)


def make_world(n_goals=5, events_per_goal=4) -> FakeWorld:
    w = FakeWorld()
    for i in range(1, n_goals + 1):
        w.goals.append(FakeGoal(id=i, title=f"goal {i}", status="active" if i % 2 else "done",
                                result=None if i % 2 else f"result {i}"))
        w.events[i] = [
            FakeEvent(id=i * 100 + j, goal_id=i, ts=float(i * 10 + j))
            for j in range(events_per_goal)
        ]
    return w


# ---------- glance ----------


def test_glance_shape_and_bounds():
    w = make_world(n_goals=60)
    g = build_glance(w, now=1234.0)
    assert g["as_of"] == 1234.0
    assert set(g) == {"as_of", "active", "counts", "spend"}
    assert len(g["active"]) <= 25
    assert g["counts"]["active"] == len(g["active"])
    assert g["spend"] == {"dollars": 1.25, "runs": 3}
    assert all(set(a) == {"id", "title", "status", "updated_at"} for a in g["active"])


def test_glance_truncates_titles():
    w = FakeWorld(goals=[FakeGoal(id=1, title="x" * 999)])
    g = build_glance(w, now=1.0)
    assert len(g["active"][0]["title"]) == 120


# ---------- bundle ----------


def test_bundle_schema_and_determinism(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_global_config", dict)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: {})
    w = make_world()
    a = build_bundle(w, now=1000.0)
    b = build_bundle(w, now=1000.0)
    assert a == b  # deterministic for a fixed world + now
    assert a["schema"] == SCHEMA == "maverick-offline/1"
    assert a["as_of"] == 1000.0
    assert a["glance"]["as_of"] == 1000.0
    assert set(a) == {"schema", "as_of", "glance", "goals", "recent_events", "cache_policy"}
    policy = a["cache_policy"]
    assert set(policy) == {"allowed", "max_age_seconds", "max_bytes", "revision", "message"}
    assert policy["allowed"] is True
    assert policy["max_age_seconds"] == 86400
    assert policy["max_bytes"] == 2 * 1024 * 1024
    assert len(policy["revision"]) == 64 and policy["message"]


def test_bundle_exact_field_sets():
    bundle = build_bundle(make_world(), now=1.0)
    for g in bundle["goals"]:
        assert tuple(g) == GOAL_FIELDS
    for e in bundle["recent_events"]:
        assert tuple(e) == EVENT_FIELDS
    assert bundle["goals"][0]["id"] == 5  # newest first


def test_bundle_bounds_goals_and_events():
    w = make_world(n_goals=30, events_per_goal=20)
    bundle = build_bundle(w, now=1.0, max_goals=7, max_events=9)
    assert len(bundle["goals"]) == 7
    assert len(bundle["recent_events"]) == 9
    # Newest first by (ts, id).
    ts = [e["ts"] for e in bundle["recent_events"]]
    assert ts == sorted(ts, reverse=True)


def test_bundle_clamps_silly_bounds():
    w = make_world()
    bundle = build_bundle(w, now=1.0, max_goals=10**9, max_events=-5)
    assert len(bundle["goals"]) <= 1000
    assert len(bundle["recent_events"]) == 1


def test_bundle_truncates_long_text():
    w = FakeWorld(goals=[FakeGoal(id=1, title="t" * 999, status="done", result="r" * 999)])
    w.events[1] = [FakeEvent(id=1, goal_id=1, content="c" * 999)]
    bundle = build_bundle(w, now=1.0)
    assert len(bundle["goals"][0]["title"]) == 200
    assert len(bundle["goals"][0]["result"]) == 400
    assert len(bundle["recent_events"][0]["content"]) == 400


def test_bundle_owner_scoping():
    w = make_world()
    w.goals[0].owner = "alice"
    bundle = build_bundle(w, now=1.0, owner="alice")
    assert [g["id"] for g in bundle["goals"]] == [w.goals[0].id]


def test_bundle_owner_scopes_embedded_glance():
    # alice owns goal 1, bob owns goal 2. An owner-scoped bundle must not leak
    # bob's active title or his open question into alice's embedded glance.
    # Approvals are a global operator queue with no goal linkage, so their count
    # stays global (a bare number, never another owner's titles).
    w = FakeWorld(
        goals=[
            FakeGoal(id=1, title="alice run", owner="alice"),
            FakeGoal(id=2, title="bob secret", owner="bob"),
        ],
        approvals=[SimpleNamespace(id=1)],
        questions=[SimpleNamespace(goal_id=1), SimpleNamespace(goal_id=2)],
    )
    bundle = build_bundle(w, now=1.0, owner="alice")

    assert [g["title"] for g in bundle["glance"]["active"]] == ["alice run"]
    assert "bob secret" not in json.dumps(bundle["glance"])
    assert bundle["glance"]["counts"] == {
        "active": 1,
        "pending_approvals": 1,  # global operator queue, not owner-scoped
        "open_questions": 1,  # only alice's goal-1 question
    }


def test_bundle_empty_world():
    bundle = build_bundle(FakeWorld(), now=1.0)
    assert bundle["goals"] == [] and bundle["recent_events"] == []
    assert bundle["glance"]["counts"]["active"] == 0


def test_bundle_contains_no_secrets(monkeypatch):
    """The bundle must never leak tokens/keys/env values."""
    sentinel = "sk-SENTINEL-NEVER-IN-BUNDLE"
    monkeypatch.setenv("ANTHROPIC_API_KEY", sentinel)
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", sentinel)
    blob = json.dumps(build_bundle(make_world(), now=1.0))
    assert sentinel not in blob
    for needle in ("api_key", "token", "secret", "authorization", "password"):
        assert needle not in blob.lower(), needle


def test_bundle_json_serialisable():
    blob = json.dumps(build_bundle(make_world(), now=1.0))
    assert json.loads(blob)["schema"] == "maverick-offline/1"
