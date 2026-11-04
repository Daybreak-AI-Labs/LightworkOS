"""Tests for provider health tracking (maverick.provider_health)."""
from __future__ import annotations

import time

from maverick.provider_health import ProviderStat

# --- provider_health must cap distinct keys ---

def test_provider_health_caps_keys():
    from maverick.provider_health import ProviderHealth

    ph = ProviderHealth()
    ph._MAX_KEYS = 5
    for i in range(40):
        ph.record("openai", f"model-{i}", latency_ms=1.0)
    assert len(ph._stats) <= 5


# ---------- provider_health p95 small-window ----------

def test_p95_small_window_never_overstates_max():
    # With only a few samples, quantiles(n=20) would interpolate a p95 ABOVE
    # every observed latency. Nearest-rank must stay <= the slowest observation.
    st = ProviderStat(provider="p", model="m")
    for v in (10.0, 20.0, 1000.0):
        st.latencies_ms.append(v)
    p95 = st.p95()
    assert p95 == 1000.0  # ceil(0.95*3)=3 -> the max, a real observation
    assert p95 <= max(st.latencies_ms)


def test_p95_single_sample():
    st = ProviderStat(provider="p", model="m")
    st.latencies_ms.append(42.0)
    assert st.p95() == 42.0


def test_p95_empty_is_none():
    assert ProviderStat(provider="p", model="m").p95() is None


def test_p95_full_window_uses_interpolation():
    # >=20 samples: the interpolated quantile path runs and lands in range.
    st = ProviderStat(provider="p", model="m")
    for v in range(1, 41):  # 1..40 ms
        st.latencies_ms.append(float(v))
    p95 = st.p95()
    assert 36.0 <= p95 <= 40.0


# ---------- provider health ----------

def test_provider_health_records_calls():
    from maverick.provider_health import ProviderHealth
    ph = ProviderHealth()
    ph.record("openai", "gpt-5", latency_ms=120, dollars=0.001)
    ph.record("openai", "gpt-5", latency_ms=200, dollars=0.002)
    ph.record("openai", "gpt-5", latency_ms=180, dollars=0.001, error=True)

    snap = ph.snapshot()
    assert len(snap) == 1
    row = snap[0]
    assert row["provider"] == "openai"
    assert row["model"] == "gpt-5"
    assert row["calls"] == 3
    assert row["errors"] == 1
    assert abs(row["error_rate"] - (1 / 3)) < 1e-6
    assert row["p50_ms"] == 180.0  # median of [120, 200, 180]
    assert row["total_dollars"] > 0
    assert row["last_seen"] > 0


def test_provider_health_snapshot_sorts_by_calls():
    from maverick.provider_health import ProviderHealth
    ph = ProviderHealth()
    for _ in range(2):
        ph.record("a", "m1", latency_ms=10)
    for _ in range(5):
        ph.record("b", "m2", latency_ms=20)
    snap = ph.snapshot()
    assert [r["provider"] for r in snap] == ["b", "a"]


def test_provider_health_reset_clears():
    from maverick.provider_health import ProviderHealth
    ph = ProviderHealth()
    ph.record("x", "y", latency_ms=1)
    assert ph.snapshot()
    ph.reset()
    assert ph.snapshot() == []


def test_provider_health_singleton_is_shared():
    from maverick.provider_health import get
    a = get()
    b = get()
    assert a is b


# ---------- LLM call records provider health ----------

def test_llm_complete_records_provider_health(monkeypatch):
    """A successful LLM call updates provider_health."""
    from maverick.budget import Budget
    from maverick.llm import LLM
    from maverick.provider_health import get as _h

    _h().reset()

    class _FakeResp:
        text = "ok"
        thinking = None
        tool_calls = []
        stop_reason = "end_turn"
        cache_creation_tokens = 0
        cache_read_tokens = 0
        raw = None
        thinking_blocks = []
        thinking_signature = None

    class _FakeClient:
        def complete(self, **kwargs):
            time.sleep(0.005)
            return _FakeResp()

    llm = LLM(model="anthropic:claude-haiku-4-5-20251001",
              api_key="dummy")
    monkeypatch.setattr(llm, "_get_client", lambda provider: _FakeClient())

    budget = Budget(max_dollars=1.0)
    llm.complete(system="s", messages=[{"role": "user", "content": "hi"}],
                 budget=budget)
    snap = _h().snapshot()
    assert len(snap) == 1
    assert snap[0]["provider"] == "anthropic"
    assert snap[0]["calls"] == 1
    assert snap[0]["errors"] == 0
    assert snap[0]["p50_ms"] is not None


def test_llm_complete_records_error(monkeypatch):
    from maverick.llm import LLM
    from maverick.provider_health import get as _h

    _h().reset()

    class _Boom:
        def complete(self, **kwargs):
            raise RuntimeError("provider down")

    llm = LLM(model="anthropic:claude-haiku-4-5-20251001",
              api_key="dummy")
    monkeypatch.setattr(llm, "_get_client", lambda provider: _Boom())

    try:
        llm.complete(system="s", messages=[{"role": "user", "content": "x"}])
    except RuntimeError:
        pass
    snap = _h().snapshot()
    assert len(snap) == 1
    assert snap[0]["errors"] == 1
