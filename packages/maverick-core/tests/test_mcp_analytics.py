"""Opt-in MCP-client language analytics."""
from __future__ import annotations

import pytest
from maverick import mcp_analytics as ma


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_MCP_ANALYTICS", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)


@pytest.mark.parametrize("ua,expected", [
    ("python-httpx/0.27", "python"),
    ("Python/3.12 aiohttp/3.9", "python"),
    ("node-fetch/3.0", "typescript"),
    ("undici", "typescript"),
    ("Go-http-client/2.0", "go"),
    ("reqwest/0.12 (rust)", "rust"),
    ("okhttp/4.12", "java"),
    (".NET/8.0 HttpClient", "csharp"),
    ("curl/8.0", "unknown"),
    ("", "unknown"),
    (None, "unknown"),
])
def test_classify_user_agent(ua, expected):
    assert ma.classify_user_agent(ua) == expected


def test_record_is_noop_when_disabled():
    # Consent off (default): nothing recorded.
    ma.record_client("python-httpx/0.27")
    assert ma.client_language_counts() == {}


def test_record_tallies_when_enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_ANALYTICS", "1")
    ma.record_client("python-httpx/0.27")
    ma.record_client("Python/3.12")
    ma.record_client("node-fetch/3.0")
    ma.record_client("Go-http-client/2.0")
    counts = ma.client_language_counts()
    assert counts == {"python": 2, "typescript": 1, "go": 1}


def test_non_python_share(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_ANALYTICS", "1")
    for _ in range(8):
        ma.record_client("python-httpx")
    ma.record_client("node-fetch")
    ma.record_client("Go-http-client")
    # 2 of 10 non-python.
    assert ma.non_python_share() == 0.2


def test_non_python_share_zero_when_empty():
    assert ma.non_python_share() == 0.0


def test_concurrent_records_do_not_lose_counts(monkeypatch):
    import threading

    monkeypatch.setenv("MAVERICK_MCP_ANALYTICS", "1")
    threads = [threading.Thread(target=ma.record_client, args=("python-httpx",))
               for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert ma.client_language_counts() == {"python": 16}
