"""Telemetry this process computes must reach the surface operators scrape.

Two gaps, both silent:

* ``tool_latency`` keeps per-tool p50/p95/p99 and ``provider_health`` keeps
  per-provider error rates, and neither was ever exported. An operator scraping
  /metrics could not see the two numbers they would actually alert on, on a
  platform that computes both.
* ``latency_budget.note_elapsed`` called ``record_metric`` with the name
  ``tool_latency_budget_exceeded``, which was never registered --
  ``record_metric`` returns silently for an unknown metric, so every breach was
  recorded into nothing.

These tests assert the values appear in a real scrape rather than that a
function was called, because "we call record_metric" was true the whole time
the metric did not exist.
"""

from __future__ import annotations

import pytest

prometheus_client = pytest.importorskip(
    "prometheus_client", reason="observability extra not installed")


@pytest.fixture(autouse=True)
def _clean_profiles(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    from maverick import latency_budget, provider_health, tool_latency

    tool_latency._samples.clear()
    latency_budget.reset()
    provider_health.get().reset()
    yield
    tool_latency._samples.clear()
    latency_budget.reset()
    provider_health.get().reset()


def _scrape() -> str:
    """Render the computed collector exactly as a Prometheus scrape would."""
    from maverick import observability
    from prometheus_client import CollectorRegistry, generate_latest

    reg = CollectorRegistry()
    # Build the collector through the production path, then register it on an
    # isolated registry so the test does not depend on, or pollute, the global.
    captured = []
    monkey = type("R", (), {"register": lambda _self, c: captured.append(c)})()
    real_registry = None
    try:
        import prometheus_client

        real_registry = prometheus_client.REGISTRY
        prometheus_client.REGISTRY = monkey
        observability._register_computed_collector()
    finally:
        if real_registry is not None:
            prometheus_client.REGISTRY = real_registry
    assert captured, "the computed collector was not registered"
    reg.register(captured[0])
    return generate_latest(reg).decode("utf-8")


def test_tool_latency_percentiles_are_exported() -> None:
    from maverick import tool_latency

    for ms in (10.0, 20.0, 300.0):
        tool_latency.record("wire_transfer", ms)

    out = _scrape()
    assert "maverick_tool_latency_ms" in out
    assert 'tool="wire_transfer"' in out
    for q in ("0.5", "0.95", "0.99", "max"):
        assert f'quantile="{q}"' in out, q
    # The sample count is what tells an operator whether a percentile is
    # meaningful or computed from three data points.
    assert "maverick_tool_latency_samples" in out
    assert 'maverick_tool_latency_samples{tool="wire_transfer"} 3' in out


def test_provider_health_is_exported_with_latency_units() -> None:
    from maverick import provider_health

    ph = provider_health.get()
    ph.record("anthropic", "claude-opus-5", latency_ms=100.0)
    ph.record("anthropic", "claude-opus-5", latency_ms=50.0, error=True)

    out = _scrape()
    assert "maverick_provider_error_rate" in out
    assert 'provider="anthropic"' in out
    assert 'model="claude-opus-5"' in out
    assert (
        'maverick_provider_latency_ms{model="claude-opus-5",'
        'provider="anthropic",quantile="0.5"} 75.0'
    ) in out
    assert (
        'maverick_provider_latency_ms{model="claude-opus-5",'
        'provider="anthropic",quantile="0.95"} 100.0'
    ) in out


def test_latency_budget_breaches_are_exported(monkeypatch) -> None:
    from maverick import latency_budget

    monkeypatch.setenv("MAVERICK_TOOL_LATENCY_BUDGET_MS", "10")
    latency_budget.note_elapsed("slow_tool", 500.0)
    assert latency_budget.breaches(), "precondition: a breach was recorded"

    out = _scrape()
    assert "maverick_tool_latency_budget_breaches" in out
    assert "maverick_tool_latency_budget_breaches 1.0" in out


def test_an_empty_process_still_exports_the_series() -> None:
    """Zero-valued series from boot, so an alert can distinguish 0 from absent.

    A metric that only appears once it has a non-zero value cannot be alerted
    on: "no data" and "nothing wrong" render identically in a dashboard.
    """
    out = _scrape()
    for name in ("maverick_tool_latency_ms", "maverick_provider_error_rate",
                 "maverick_tool_latency_budget_breaches"):
        assert f"# HELP {name}" in out, name


def test_the_collector_never_raises_into_a_scrape(monkeypatch) -> None:
    """A broken profile must degrade the scrape, not break it.

    /metrics is what an operator reaches for when things are already going
    wrong; a collector that raises takes the observability surface down at
    exactly the moment it is needed.
    """
    from maverick import tool_latency

    monkeypatch.setattr(tool_latency, "report",
                        lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    out = _scrape()
    # Other families still render.
    assert "maverick_provider_error_rate" in out


def test_the_budget_counter_is_registered_not_silently_dropped(monkeypatch) -> None:
    """record_metric returns silently for an unknown name.

    So "latency_budget calls record_metric" was true for the whole period the
    metric did not exist and every breach went nowhere. Assert the registration,
    not the call.
    """
    from maverick import observability

    # A port value of "0" explicitly disables Prometheus. Use a nonzero
    # setting and an isolated real registry, without starting an HTTP server.
    registry = prometheus_client.CollectorRegistry()
    counter, histogram = prometheus_client.Counter, prometheus_client.Histogram
    monkeypatch.setenv("MAVERICK_PROMETHEUS_PORT", "12345")
    monkeypatch.setattr(prometheus_client, "REGISTRY", registry)
    monkeypatch.setattr(prometheus_client, "start_http_server", lambda *args, **kwargs: None)
    monkeypatch.setattr(prometheus_client, "Counter", lambda *args, **kwargs: counter(*args, registry=registry, **kwargs))
    monkeypatch.setattr(prometheus_client, "Histogram", lambda *args, **kwargs: histogram(*args, registry=registry, **kwargs))
    monkeypatch.setattr(observability, "_sentry_enabled", lambda: False)
    monkeypatch.setattr(observability, "_otel_enabled", lambda: False)
    monkeypatch.setattr(observability, "_initialized", False)
    monkeypatch.setattr(observability, "_metrics", {})
    observability._initialize()
    observability.record_metric("tool_latency_budget_exceeded", labels={"tool": "slow_tool"})
    assert registry.get_sample_value(
        "maverick_tool_latency_budget_exceeded_total", {"tool": "slow_tool"},
    ) == 1.0
