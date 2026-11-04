"""Cross-replica goal-creation rate limit via the shared store."""
from __future__ import annotations

import maverick_dashboard.app as app_mod
import pytest

fastapi = pytest.importorskip("fastapi")


class _FakeRateWorld:
    """In-memory stand-in for the world store's rate-event window."""

    def __init__(self):
        self.events: list[tuple[str, float]] = []

    def record_rate_event(self, rl_key, ts=None):
        import time
        self.events.append((rl_key, ts if ts is not None else time.time()))

    def count_rate_events(self, rl_key, since):
        return sum(1 for k, t in self.events if k == rl_key and t >= since)

    def reserve_rate_events(self, key, cap, global_key, global_cap, ts=None):
        import time
        now = ts if ts is not None else time.time()
        cutoff = now - 60.0
        if self.count_rate_events(global_key, cutoff) >= global_cap:
            return "global"
        if self.count_rate_events(key, cutoff) >= cap:
            return "key"
        self.record_rate_event(global_key, now)
        self.record_rate_event(key, now)
        return None


def test_in_process_when_no_postgres(monkeypatch):
    from maverick import world_model_backends
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: False)
    # No shared backend -> the shared check defers (returns False).
    assert app_mod._shared_rate_limit_check("ip:1.2.3.4", 5, 50) is False


def test_shared_admits_then_429s_per_client(monkeypatch):
    from fastapi import HTTPException
    from maverick import world_model_backends
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    fake = _FakeRateWorld()
    monkeypatch.setattr(app_mod, "_world", lambda: fake)

    key = "principal:alice"
    # First 3 admitted under a cap of 3.
    for _ in range(3):
        assert app_mod._shared_rate_limit_check(key, cap=3, global_cap=100) is True
    # 4th over the per-client cap -> 429.
    with pytest.raises(HTTPException) as ei:
        app_mod._shared_rate_limit_check(key, cap=3, global_cap=100)
    assert ei.value.status_code == 429
    # Recorded events landed under the per-client key + the global bucket.
    assert sum(1 for k, _ in fake.events if k == key) == 3
    assert sum(1 for k, _ in fake.events if k == app_mod._RL_GLOBAL_KEY) == 3


def test_shared_enforces_global_ceiling(monkeypatch):
    from fastapi import HTTPException
    from maverick import world_model_backends
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    fake = _FakeRateWorld()
    monkeypatch.setattr(app_mod, "_world", lambda: fake)

    # Distinct clients, generous per-client cap, tiny global ceiling of 2.
    assert app_mod._shared_rate_limit_check("ip:a", cap=100, global_cap=2) is True
    assert app_mod._shared_rate_limit_check("ip:b", cap=100, global_cap=2) is True
    with pytest.raises(HTTPException) as ei:
        app_mod._shared_rate_limit_check("ip:c", cap=100, global_cap=2)
    assert ei.value.status_code == 429
    assert "total" in ei.value.detail


def test_falls_back_when_store_errors(monkeypatch):
    from maverick import world_model_backends
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)

    def _boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(app_mod, "_world", _boom)
    # A store blip must not fail the request closed -> defer to in-process.
    assert app_mod._shared_rate_limit_check("ip:x", 5, 50) is False
