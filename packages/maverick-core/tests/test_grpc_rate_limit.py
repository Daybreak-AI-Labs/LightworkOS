"""Per-caller request rate limiting on the gRPC API.

Complements maximum_concurrent_rpcs (in-flight cap) with a per-caller
request-rate cap, bucketed by Agent Trust agent id (else hashed peer address), applied
at the auth chokepoint. MAVERICK_GRPC_RATE_LIMIT=0 disables it.
"""
from __future__ import annotations

import pytest
from maverick.grpc_api import server as gs


@pytest.fixture(autouse=True)
def _clear(monkeypatch):
    gs._GRPC_RATE_HITS.clear()
    monkeypatch.delenv("MAVERICK_GRPC_RATE_LIMIT", raising=False)
    yield
    gs._GRPC_RATE_HITS.clear()


class _Ctx:
    def __init__(self, peer="ipv4:10.0.0.7:5"):
        self._peer = peer

    def peer(self):
        return self._peer


class _Agent:
    id = "vega"


def test_disabled_when_zero(monkeypatch):
    monkeypatch.setenv("MAVERICK_GRPC_RATE_LIMIT", "0")
    for _ in range(1000):
        assert gs._grpc_rate_ok("agent:x") is True


def test_blocks_over_cap(monkeypatch):
    monkeypatch.setenv("MAVERICK_GRPC_RATE_LIMIT", "2")
    assert gs._grpc_rate_ok("agent:a")
    assert gs._grpc_rate_ok("agent:a")
    assert gs._grpc_rate_ok("agent:a") is False


def test_buckets_independent(monkeypatch):
    monkeypatch.setenv("MAVERICK_GRPC_RATE_LIMIT", "1")
    assert gs._grpc_rate_ok("agent:a")
    assert gs._grpc_rate_ok("agent:a") is False
    assert gs._grpc_rate_ok("agent:b") is True


def test_key_prefers_agent_then_peer_address():
    assert gs._grpc_rate_key(_Ctx(), _Agent()) == "agent:vega"
    key = gs._grpc_rate_key(_Ctx("ipv4:10.0.0.7:5"), None)
    assert key.startswith("peer:")
    # Distinct peer addresses get distinct buckets.
    assert key != gs._grpc_rate_key(_Ctx("ipv4:10.0.0.8:5"), None)


def test_peer_key_ignores_tcp_source_port():
    assert gs._grpc_rate_key(_Ctx("ipv4:10.0.0.7:50001"), None) == gs._grpc_rate_key(
        _Ctx("ipv4:10.0.0.7:50002"), None
    )
    assert gs._grpc_rate_key(_Ctx("ipv6:[2001:db8::1]:50001"), None) == gs._grpc_rate_key(
        _Ctx("ipv6:[2001:db8::1]:50002"), None
    )


def test_idle_buckets_are_swept(monkeypatch):
    """Idle per-caller buckets are reclaimed when the map exceeds the cap."""
    from collections import deque
    monkeypatch.setenv("MAVERICK_GRPC_RATE_LIMIT", "5")
    monkeypatch.setattr(gs, "_GRPC_RATE_MAX_KEYS", 10)
    old = gs.time.monotonic() - 120.0
    for i in range(50):
        gs._GRPC_RATE_HITS[f"agent:stale{i}"] = deque([old])
    assert gs._grpc_rate_ok("agent:active") is True
    assert len(gs._GRPC_RATE_HITS) < 50
    assert "agent:active" in gs._GRPC_RATE_HITS


def test_fresh_buckets_are_hard_capped(monkeypatch):
    """The map is bounded even when every bucket is freshly active.

    Idle-only sweeping cannot reclaim continuously-fresh keys (e.g. a single
    client opening many short-lived connections from many ephemeral ports), so
    the least-recently-active buckets are evicted to keep the map hard-capped.
    """
    monkeypatch.setenv("MAVERICK_GRPC_RATE_LIMIT", "600")
    monkeypatch.setattr(gs, "_GRPC_RATE_MAX_KEYS", 10)
    for i in range(100):
        assert gs._grpc_rate_ok(f"peer:{i}") is True
    assert len(gs._GRPC_RATE_HITS) <= gs._GRPC_RATE_MAX_KEYS + 1
    # The most recently added key survives.
    assert "peer:99" in gs._GRPC_RATE_HITS
