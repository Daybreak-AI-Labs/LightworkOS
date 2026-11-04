"""gRPC goal service (transport-agnostic; no grpc required)."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import pytest
from maverick.grpc_api.service import EventDTO, GoalService


@dataclass
class _Goal:
    id: int
    status: str = "pending"
    result: str | None = None
    owner: str = ""
    execution_principal: str = ""


@dataclass
class _Event:
    id: int
    goal_id: int
    agent: str
    kind: str
    content: str
    ts: float


class _FakeWorld:
    """In-memory stand-in for WorldModel covering the service's surface."""

    def __init__(self, shared: dict):
        self.s = shared  # shared across the fresh-per-call instances

    def create_goal(
        self,
        title,
        description="",
        *,
        owner="",
        execution_principal="",
    ):
        self.s["seq"] += 1
        gid = self.s["seq"]
        self.s["goals"][gid] = _Goal(
            id=gid,
            owner=owner,
            execution_principal=execution_principal,
        )
        self.s["titles"][gid] = title
        return gid

    def get_goal(self, goal_id):
        return self.s["goals"].get(goal_id)

    def set_goal_status(self, goal_id, status, *, result=None):
        g = self.s["goals"].get(goal_id)
        if g:
            g.status = status
            g.result = result

    def bind_goal_execution_principal(self, goal_id, principal):
        g = self.s["goals"].get(goal_id)
        if g is None or (
            g.execution_principal and g.execution_principal != principal
        ):
            return False
        g.execution_principal = principal
        return True

    def claim_goal_for_run(self, goal_id, *, expected_owner=None):
        self.s.setdefault("claim_owners", []).append(expected_owner)
        g = self.s["goals"].get(goal_id)
        if g is None or g.status != "pending":
            return False
        if expected_owner is not None and g.owner != expected_owner:
            return False
        g.status = "active"
        return True

    def goal_events(self, goal_id, since_id=0, limit=200):
        return [e for e in self.s["events"] if e.goal_id == goal_id and e.id > since_id]

    def close(self):
        self.s["closes"] += 1


def _shared():
    return {"seq": 0, "goals": {}, "titles": {}, "events": [], "closes": 0}


def _service(shared, **kw):
    return GoalService(
        world_factory=lambda: _FakeWorld(shared),
        dispatch=lambda gid, **k: shared.setdefault("dispatched", []).append((gid, k)),
        spawn=lambda fn: fn(),  # run inline
        sleep=lambda _s: None,
        **kw,
    )


def test_start_goal_creates_and_dispatches():
    shared = _shared()
    svc = _service(shared)
    gid = svc.start_goal("Do the thing", "details", max_dollars=2.0, user_id="u1")
    assert gid == 1
    assert shared["titles"][1] == "Do the thing"
    assert shared["goals"][1].owner == "user:u1"
    assert shared["goals"][1].execution_principal == "user:u1"
    assert shared["dispatched"] == [
        (1, {
            "max_dollars": 2.0,
            "max_wall_seconds": None,
            "channel": None,
            "user_id": "u1",
            "capability": None,
        })
    ]
    assert shared["closes"] >= 1  # world closed after create


def test_start_goal_rejects_blank_title():
    svc = _service(_shared())
    with pytest.raises(ValueError):
        svc.start_goal("   ")


def test_start_goal_preserves_distinct_owner_and_runtime_principal():
    from maverick.capability import Capability

    shared = _shared()
    svc = _service(shared)

    gid = svc.start_goal(
        "Do the thing",
        owner="user:alice",
        capability=Capability(principal="agent:bob"),
    )

    assert shared["goals"][gid].owner == "user:alice"
    assert shared["goals"][gid].execution_principal == "agent:bob"
    assert shared["dispatched"][0][0] == gid


def test_stream_episode_yields_events_then_terminal_status():
    shared = _shared()
    shared["goals"][7] = _Goal(id=7, status="active")
    shared["events"] = [
        _Event(1, 7, "orchestrator", "plan", "step one", 1.0),
        _Event(2, 7, "coder", "tool", "ran tests", 2.0),
    ]

    # After the service reads events once, flip the goal terminal so the loop ends.
    calls = {"n": 0}
    orig = _FakeWorld.get_goal

    def get_goal(self, goal_id):
        calls["n"] += 1
        if calls["n"] >= 1:
            self.s["goals"][7].status = "done"
            self.s["goals"][7].result = "ok"
        return orig(self, goal_id)

    svc = _service(shared)
    # Patch get_goal on the fake to terminate after first poll.
    _FakeWorld.get_goal = get_goal
    try:
        out = list(svc.stream_episode(7))
    finally:
        _FakeWorld.get_goal = orig

    kinds = [e.kind for e in out]
    assert kinds == ["plan", "tool", "status"]
    assert isinstance(out[-1], EventDTO)
    assert out[-1].content == "done"  # terminal status carried as final event
    assert shared["closes"] >= 1


def test_stream_episode_drains_backlog_past_one_page_before_terminal():
    # Regression: a terminal goal with >200 pending events must not drop the
    # tail. goal_events here honours the LIMIT (like the real world model), so a
    # naive single-read would stream only the first 200 and emit the synthetic
    # status, stranding events 201..N.
    shared = _shared()
    shared["goals"][7] = _Goal(id=7, status="done", result="ok")
    shared["events"] = [
        _Event(i, 7, "worker", "tool", f"step {i}", float(i))
        for i in range(1, 251)
    ]

    class _PagedWorld(_FakeWorld):
        def goal_events(self, goal_id, since_id=0, limit=200):
            rows = [
                e for e in self.s["events"]
                if e.goal_id == goal_id and e.id > since_id
            ]
            return rows[:limit]

    svc = GoalService(
        world_factory=lambda: _PagedWorld(shared),
        dispatch=lambda gid, **k: None,
        spawn=lambda fn: fn(),
        sleep=lambda _s: None,
    )
    out = list(svc.stream_episode(7))

    tool_events = [e for e in out if e.kind == "tool"]
    assert len(tool_events) == 250  # all backlog drained, none dropped
    assert [e.id for e in tool_events] == list(range(1, 251))
    assert out[-1].kind == "status" and out[-1].content == "done"


def test_stream_episode_stops_on_missing_goal():
    shared = _shared()  # goal 99 never created
    svc = _service(shared)
    assert list(svc.stream_episode(99)) == []


def test_cancel_marks_cancellable_goal():
    shared = _shared()
    shared["goals"][3] = _Goal(id=3, status="active")
    svc = _service(shared)
    assert svc.cancel(3) is True
    assert shared["goals"][3].status == "cancelled"


def test_cancel_noop_on_terminal_or_missing():
    shared = _shared()
    shared["goals"][4] = _Goal(id=4, status="done")
    svc = _service(shared)
    assert svc.cancel(4) is False  # already terminal
    assert svc.cancel(123) is False  # missing


def test_status_reports_goal():
    shared = _shared()
    shared["goals"][5] = _Goal(id=5, status="active", result=None)
    svc = _service(shared)
    st = svc.status(5)
    assert st is not None and st.status == "active"
    assert svc.status(404) is None


def test_run_goal_retry_returns_status_without_duplicate_dispatch():
    shared = _shared()
    shared["goals"][8] = _Goal(id=8, status="pending")
    dispatches = []

    def dispatch(gid, **_kwargs):
        dispatches.append(gid)
        shared["goals"][gid].status = "done"
        shared["goals"][gid].result = "finished"

    svc = GoalService(
        world_factory=lambda: _FakeWorld(shared),
        dispatch=dispatch,
        spawn=lambda fn: fn(),
    )

    first = svc.run_goal(8)
    retry = svc.run_goal(8)  # models a client retry after losing first response

    assert dispatches == [8]
    assert first is not None and first.status == "done"
    assert retry is not None and retry.status == "done"
    assert retry.result == "finished"


def test_run_goal_refuses_execution_principal_mismatch_before_claim():
    shared = _shared()
    shared["goals"][8] = _Goal(
        id=8,
        status="pending",
        owner="user:human-owner",
        execution_principal="user:alice",
    )
    svc = _service(shared)

    result = svc.run_goal(8, user_id="bob")

    assert result is None
    assert shared["goals"][8].status == "pending"
    assert shared["goals"][8].owner == "user:human-owner"
    assert shared["goals"][8].execution_principal == "user:alice"
    assert "dispatched" not in shared


def test_run_goal_preserves_human_owner_for_bound_agent_execution():
    from maverick.capability import Capability

    shared = _shared()
    shared["goals"][8] = _Goal(
        id=8,
        status="pending",
        owner="user:human-owner",
        execution_principal="agent:worker",
    )

    def dispatch(gid, **_kwargs):
        shared["goals"][gid].status = "done"
        shared["goals"][gid].result = "finished"

    svc = GoalService(
        world_factory=lambda: _FakeWorld(shared),
        dispatch=dispatch,
    )
    result = svc.run_goal(
        8,
        capability=Capability(principal="agent:worker"),
        expected_execution_principal="agent:worker",
    )

    assert result is not None and result.status == "done"
    assert result.owner == "user:human-owner"
    assert shared["goals"][8].owner == "user:human-owner"
    assert shared["goals"][8].execution_principal == "agent:worker"
    assert shared["claim_owners"] == ["user:human-owner"]


def test_per_agent_cannot_adopt_unbound_human_goal():
    from maverick.capability import Capability

    shared = _shared()
    shared["goals"][8] = _Goal(
        id=8,
        status="pending",
        owner="user:human-owner",
    )
    svc = _service(shared)

    result = svc.run_goal(
        8,
        capability=Capability(principal="agent:worker"),
        expected_execution_principal="agent:worker",
    )

    assert result is None
    assert shared["goals"][8].status == "pending"
    assert shared["goals"][8].execution_principal == ""
    assert "claim_owners" not in shared


def test_run_goal_fails_closed_when_execution_principal_binding_is_unavailable():
    shared = _shared()
    shared["goals"][8] = _Goal(id=8, status="pending")

    class _BrokenBindingWorld(_FakeWorld):
        def bind_goal_execution_principal(self, goal_id, principal):
            raise OSError("database unavailable")

    svc = GoalService(
        world_factory=lambda: _BrokenBindingWorld(shared),
        dispatch=lambda gid, **kwargs: shared.setdefault(
            "dispatched", [],
        ).append((gid, kwargs)),
    )

    result = svc.run_goal(8, user_id="alice")

    assert result is None
    assert shared["goals"][8].status == "pending"
    assert shared["goals"][8].execution_principal == ""
    assert "dispatched" not in shared


@pytest.mark.parametrize("status", ["active", "done", "blocked", "failed", "cancelled"])
def test_run_goal_rejects_already_active_and_terminal_rows(status):
    shared = _shared()
    shared["goals"][9] = _Goal(id=9, status=status, result="prior")
    svc = _service(shared)

    current = svc.run_goal(9)

    assert current is not None and current.status == status
    assert "dispatched" not in shared


def test_run_goal_claim_is_atomic_across_world_connections(tmp_path):
    """Two worker RPCs racing on one shared DB execute the goal only once."""
    from maverick.world_model import WorldModel

    db = tmp_path / "grpc-claim.db"
    seed = WorldModel(db)
    goal_id = seed.create_goal("run once")
    seed.close()

    dispatches = []
    dispatch_lock = threading.Lock()

    def dispatch(gid, **_kwargs):
        with dispatch_lock:
            dispatches.append(gid)

    svc = GoalService(world_factory=lambda: WorldModel(db), dispatch=dispatch)
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda _i: svc.run_goal(goal_id), range(2)))

    assert dispatches == [goal_id]
    assert all(status is not None and status.status == "active" for status in statuses)


def test_world_claim_binds_owner_inside_compare_and_swap(tmp_path):
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "owner-claim.db")
    try:
        goal_id = world.create_goal("owned", owner="agent:alice")
        assert not world.claim_goal_for_run(
            goal_id, expected_owner="agent:bob",
        )
        assert world.get_goal(goal_id).status == "pending"
        assert world.claim_goal_for_run(
            goal_id, expected_owner="agent:alice",
        )
        assert world.get_goal(goal_id).status == "active"
        assert not world.claim_goal_for_run(
            goal_id, expected_owner="agent:alice",
        )
    finally:
        world.close()


def test_per_agent_owner_scope_blocks_cross_goal_access():
    shared = _shared()
    shared["goals"].update({
        1: _Goal(id=1, status="done", result="alice result", owner="agent:alice"),
        2: _Goal(id=2, status="active", result="bob secret", owner="agent:bob"),
    })
    shared["events"] = [
        _Event(1, 2, "worker", "tool", "bob private event", 1.0),
    ]
    svc = _service(shared)

    # Missing and wrong-owner ids are deliberately indistinguishable on every
    # read/control/execute path, and a denied RunGoal is never dispatched.
    assert svc.status(2, expected_owner="agent:alice") is None
    assert list(svc.stream_episode(2, expected_owner="agent:alice")) == []
    assert svc.cancel(2, expected_owner="agent:alice") is False
    assert shared["goals"][2].status == "active"
    assert svc.run_goal(2, expected_owner="agent:alice") is None
    assert "dispatched" not in shared

    # Alice can still read and run her own goal.  The shared operator scope
    # (None) retains administrative access to Bob's goal for compatibility.
    own = svc.status(1, expected_owner="agent:alice")
    assert own is not None and own.result == "alice result"
    assert svc.run_goal(1, expected_owner="agent:alice") is not None
    assert svc.status(2, expected_owner=None) is not None
