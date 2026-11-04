"""Per-caller rate limiting on the MCP HTTP transport.

An authenticated caller could otherwise spam goal-spawning RPCs with unbounded
concurrency. The sliding-window limiter buckets by bearer token (else client IP)
and returns 429 over the per-minute cap; MAVERICK_MCP_RATE_LIMIT=0 disables it.
"""
from __future__ import annotations

import pytest
from maverick_mcp import http_transport as ht


@pytest.fixture(autouse=True)
def _clear(monkeypatch):
    ht._RATE_HITS.clear()
    monkeypatch.delenv("MAVERICK_MCP_RATE_LIMIT", raising=False)
    yield
    ht._RATE_HITS.clear()


class _Req:
    class client:  # noqa: N801 - mimic starlette request.client.host
        host = "10.0.0.9"


def test_disabled_when_zero(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_RATE_LIMIT", "0")
    for _ in range(1000):
        assert ht._rate_ok("tok:x") is True


def test_blocks_over_cap(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_RATE_LIMIT", "3")
    assert ht._rate_ok("tok:a")
    assert ht._rate_ok("tok:a")
    assert ht._rate_ok("tok:a")
    assert ht._rate_ok("tok:a") is False          # 4th in the window -> blocked


def test_buckets_are_independent(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_RATE_LIMIT", "1")
    assert ht._rate_ok("tok:a")
    assert ht._rate_ok("tok:a") is False
    # A different caller has its own budget.
    assert ht._rate_ok("tok:b") is True


def test_key_prefers_bearer_then_ip():
    req = _Req()
    assert ht._rate_key("Bearer sekret", req).startswith("tok:")  # pragma: allowlist secret
    assert ht._rate_key(None, req) == "ip:10.0.0.9"


def test_idle_buckets_are_swept(monkeypatch):
    """Stale callers must not leak: when the map exceeds the cap, buckets with
    no hits inside the window are evicted (memory ~ active callers, not total)."""
    from collections import deque
    monkeypatch.setenv("MAVERICK_MCP_RATE_LIMIT", "5")
    monkeypatch.setattr(ht, "_RATE_MAX_KEYS", 10)
    old = ht.time.monotonic() - 120.0  # outside the 60s window -> idle
    for i in range(50):
        ht._RATE_HITS[f"ip:stale{i}"] = deque([old])
    assert ht._rate_ok("ip:active") is True       # triggers the sweep
    assert len(ht._RATE_HITS) < 50                # idle buckets reclaimed
    assert "ip:active" in ht._RATE_HITS
