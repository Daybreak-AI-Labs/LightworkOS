"""The always-on runtime metrics registry: bounded, thread-safe, honest.

The assertions that matter: counters accumulate per label set; the
series cap drops overflow and counts the drops; gauges compute at render
and a broken gauge never breaks the scrape; render is valid Prometheus
text; concurrent increments lose nothing.
"""
from __future__ import annotations

import threading

import pytest
from maverick import runtime_metrics as rm


@pytest.fixture(autouse=True)
def _fresh():
    rm.reset_for_tests()
    yield
    rm.reset_for_tests()


def test_counters_accumulate_per_label_set():
    rm.increment("probe_total", route="/a", help_text="probe")
    rm.increment("probe_total", route="/a")
    rm.increment("probe_total", route="/b", amount=2.5)
    text = rm.render()
    assert '# TYPE probe_total counter' in text
    assert 'probe_total{route="/a"} 2.0' in text
    assert 'probe_total{route="/b"} 2.5' in text


def test_label_values_are_escaped_for_the_exposition_format():
    rm.increment("probe_total", route='a"b\\c\nd')
    assert 'probe_total{route="a\\"b\\\\c\\nd"} 1.0\n' in rm.render()


def test_series_cap_drops_and_counts():
    for index in range(rm.MAX_SERIES_PER_METRIC + 25):
        rm.increment("burst_total", key=str(index))
    text = rm.render()
    assert text.count("burst_total{") == rm.MAX_SERIES_PER_METRIC
    assert "lightwork_metrics_dropped_series_total 25.0" in text


def test_gauges_compute_at_render_and_fail_soft():
    rm.register_gauge("depth", lambda: 7, help_text="queue depth")
    rm.register_gauge("broken", lambda: 1 / 0)
    text = rm.render()
    assert "depth 7.0" in text
    assert "broken" not in text
    assert "lightwork_uptime_seconds" in text


def test_concurrent_increments_lose_nothing():
    def spin():
        for _ in range(1000):
            rm.increment("race_total")

    threads = [threading.Thread(target=spin) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert "race_total 8000.0" in rm.render()
