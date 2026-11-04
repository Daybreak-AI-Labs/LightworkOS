"""Network egress accounting."""
from __future__ import annotations

import pytest
from maverick import egress_accounting as eg


@pytest.fixture(autouse=True)
def _clean():
    eg.reset()
    yield
    eg.reset()


def test_record_and_report():
    eg.record("api.example.com", sent=100, received=2000)
    eg.record("api.example.com", sent=50, received=1000)
    eg.record("cdn.example.com", received=500)
    rep = eg.report()
    assert rep[0]["host"] == "api.example.com"  # largest total first
    assert rep[0]["sent_bytes"] == 150
    assert rep[0]["recv_bytes"] == 3000
    assert rep[0]["requests"] == 2
    assert rep[0]["total_bytes"] == 3150


def test_totals():
    eg.record("a.com", sent=10, received=20)
    eg.record("b.com", sent=5, received=5)
    t = eg.totals()
    assert t == {"sent_bytes": 15, "recv_bytes": 25, "requests": 2,
                 "total_bytes": 40, "hosts": 2}


def test_host_normalised_and_negatives_clamped():
    eg.record("API.Example.COM ", received=-100, sent=10)
    rep = eg.report()
    assert rep[0]["host"] == "api.example.com"
    assert rep[0]["recv_bytes"] == 0  # negative clamped
    assert rep[0]["sent_bytes"] == 10


def test_overflow_bucket(monkeypatch):
    monkeypatch.setattr(eg, "_MAX_HOSTS", 2)
    eg.record("a.com", received=1)
    eg.record("b.com", received=1)
    eg.record("c.com", received=1)  # exceeds cap -> (other)
    hosts = {r["host"] for r in eg.report()}
    assert "(other)" in hosts
