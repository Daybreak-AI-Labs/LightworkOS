"""Per-peer request-rate limiting on inbound federation delegations.

The sibling gRPC API pairs maximum_concurrent_rpcs (in-flight cap) with a
per-caller request-rate cap; federation had only the former. Each accepted
DelegateGoal spawns a real goal run, so an authenticated-but-flooding peer
could launch goals unthrottled. _fed_rate_ok caps delegations per peer over a
sliding 60s window. MAVERICK_FEDERATION_RATE_LIMIT=0 disables it.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from maverick import federation as fed
from maverick import federation_admission as admission
from maverick.federation import FederationService, Peer
from maverick.grpc_api.service import GoalService
from maverick.paths import data_dir
from maverick.world_model import WorldModel


@pytest.fixture(autouse=True)
def _clear(monkeypatch):
    fed._fed_rate_hits.clear()
    monkeypatch.delenv("MAVERICK_FEDERATION_RATE_LIMIT", raising=False)
    yield
    fed._fed_rate_hits.clear()


class _Goals(GoalService):
    def __init__(self):
        self.started = 0
        self.path = data_dir().parent / f"test-federation-{uuid4().hex}" / "world.db"
        super().__init__(world_factory=lambda: WorldModel(self.path),
                         dispatch=self._run, spawn=lambda fn: fn())

    def _run(self, goal_id, **kw):
        with WorldModel(self.path) as world:
            admission.require_execution(
                world, goal_id, capability=kw["capability"],
                max_dollars=kw["max_dollars"],
                max_wall_seconds=kw["max_wall_seconds"], consume=True,
            )
            self.started += 1
            world.set_goal_status(goal_id, "done", result="ok")


def test_delegate_goal_refuses_over_cap(monkeypatch):
    """End-to-end: a peer flooding DelegateGoal is refused after the cap, and
    no further goal runs are spawned."""
    monkeypatch.setenv("MAVERICK_FEDERATION_RATE_LIMIT", "2")
    goals = _Goals()
    svc = FederationService(
        node="B", peers=[Peer("A", "a:1", "tok")],
        local_grant=None, goal_service=goals,
    )

    def _call(i):
        return svc.call("DelegateGoal", {
            "goal_title": "t", "goal_description": "d",
            "auth_token": "tok", "correlation_id": f"c{i}",
        })

    assert _call(1)["accepted"] is True
    assert _call(2)["accepted"] is True
    refused = _call(3)
    assert refused["accepted"] is False
    assert "rate limit" in refused["reason"]
    assert goals.started == 2  # the throttled call never reached goal creation


def test_authenticated_malformed_requests_hit_ingress_gate_first(monkeypatch):
    """A token holder cannot bypass ingress limits with invalid identifiers."""
    checked: list[str] = []
    monkeypatch.setattr(
        fed,
        "_fed_auth_rate_ok",
        lambda peer: checked.append(peer) or False,
    )
    goals = _Goals()
    svc = FederationService(
        node="B", peers=[Peer("A", "a:1", "tok")],
        local_grant=None, goal_service=goals,
    )

    refused = svc.delegate_goal({
        "auth_token": "tok",
        "correlation_id": "x" * (fed._MAX_CORRELATION_ID_BYTES + 1),
        "goal_title": "t",
    })

    assert refused["accepted"] is False
    assert "rate limit" in refused["reason"]
    assert checked == ["A"]
    assert goals.started == 0


def test_disabled_when_zero(monkeypatch):
    monkeypatch.setenv("MAVERICK_FEDERATION_RATE_LIMIT", "0")
    for _ in range(1000):
        assert fed._fed_rate_ok("peer:alpha") is True


def test_blocks_over_cap(monkeypatch):
    monkeypatch.setenv("MAVERICK_FEDERATION_RATE_LIMIT", "2")
    assert fed._fed_rate_ok("peer:alpha")
    assert fed._fed_rate_ok("peer:alpha")
    assert fed._fed_rate_ok("peer:alpha") is False


def test_rate_limit_survives_process_memory_reset(monkeypatch):
    monkeypatch.setenv("MAVERICK_FEDERATION_RATE_LIMIT", "1")
    assert fed._fed_rate_ok("peer:durable", now=1000.0)
    fed._fed_rate_hits.clear()  # simulate a new worker/restarted process

    assert fed._fed_rate_ok("peer:durable", now=1001.0) is False


def test_buckets_independent(monkeypatch):
    monkeypatch.setenv("MAVERICK_FEDERATION_RATE_LIMIT", "1")
    assert fed._fed_rate_ok("peer:alpha")
    assert fed._fed_rate_ok("peer:alpha") is False
    assert fed._fed_rate_ok("peer:beta") is True


def test_window_slides(monkeypatch):
    """A hit older than the 60s window no longer counts against the cap."""
    monkeypatch.setenv("MAVERICK_FEDERATION_RATE_LIMIT", "1")
    now = 1_000.0
    assert fed._fed_rate_ok("peer:alpha", now=now) is True
    assert fed._fed_rate_ok("peer:alpha", now=now + 1) is False
    assert fed._fed_rate_ok("peer:alpha", now=now + 61) is True  # first hit aged out


def test_idle_buckets_are_swept(monkeypatch):
    """Idle per-peer buckets are reclaimed when the map exceeds the cap."""
    from collections import deque
    monkeypatch.setenv("MAVERICK_FEDERATION_RATE_LIMIT", "5")
    monkeypatch.setattr(fed, "_FED_RATE_MAX_KEYS", 10)
    old = fed.time.monotonic() - 120.0
    for i in range(50):
        fed._fed_rate_hits[f"peer:stale{i}"] = deque([old])
    assert fed._fed_rate_ok("peer:active") is True
    assert len(fed._fed_rate_hits) < 50
    assert "peer:active" in fed._fed_rate_hits


def test_invalid_signed_identity_does_not_consume_delegate_quota(monkeypatch):
    """Token-only requests must not spend the quota for signed delegations."""
    pytest.importorskip("cryptography")
    from maverick import agent_trust
    from maverick.agent_trust import TrustedAgent
    from maverick.audit import signing as asig
    _, pub, _ = asig._load_or_create_keypair()
    registry = {
        "a": TrustedAgent(
            id="a", pubkey=pub.hex(), allow_tools=frozenset({"read_file"})
        )
    }
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (True, registry))
    fed._seen_sigs.clear()
    monkeypatch.setenv("MAVERICK_FEDERATION_RATE_LIMIT", "1")

    goals = _Goals()
    svc = FederationService(
        node="b", peers=[Peer("a", "a:1", "tok")],
        local_grant=None, goal_service=goals, record=lambda *a, **k: True,
    )

    unsigned = svc.delegate_goal({
        "auth_token": "tok", "correlation_id": "poison",
        "goal_title": "do it", "requested_tools": ["read_file"],
    })
    assert unsigned["accepted"] is False
    assert "signature" in unsigned["reason"].lower()
    assert len(fed._fed_rate_hits.get("peer:a", ())) == 0

    corr = "legit"
    signed = fed._sign_delegation(
        "a", "b", corr, "do it", "", ["read_file"], None, 1000
    )
    accepted = svc.delegate_goal({
        "auth_token": "tok", "correlation_id": corr, "goal_title": "do it",
        "goal_description": "", "requested_tools": ["read_file"],
        "max_risk": "", "deadline_ms": 1000, **signed,
    })
    assert accepted["accepted"] is True
    assert goals.started == 1
    assert len(fed._fed_rate_hits["peer:a"]) == 1
