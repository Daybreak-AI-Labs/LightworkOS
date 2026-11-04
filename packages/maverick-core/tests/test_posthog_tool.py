"""Tests for the PostHog tool (maverick.tools.posthog_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _posthog_capture_url(monkeypatch, env):
    """Run a capture with the given env and return the URL events were POSTed to."""
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    captured = {"url": None, "json": None}

    def _post(url, *a, **k):
        captured["url"] = url
        captured["json"] = k.get("json")
        m = MagicMock()
        m.status_code = 200
        m.text = "1"
        return m

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = _post
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.posthog_tool import posthog_tool
    out = posthog_tool().fn({
        "op": "capture", "event": "goal_done",
        "distinct_id": "user-1", "properties": {"cost": 0.42},
    })
    return out, captured


# ---------- PostHog tool ----------

def test_posthog_requires_op():
    from maverick.tools.posthog_tool import posthog_tool
    assert "op is required" in posthog_tool().fn({})


def test_posthog_capture_missing_key(monkeypatch):
    monkeypatch.delenv("POSTHOG_API_KEY", raising=False)
    fake_httpx = types.ModuleType("httpx")
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.posthog_tool import posthog_tool
    out = posthog_tool().fn({
        "op": "capture", "event": "x", "distinct_id": "u",
    })
    assert "POSTHOG_API_KEY" in out


def test_posthog_capture_posts(monkeypatch):
    out, captured = _posthog_capture_url(monkeypatch, {"POSTHOG_API_KEY": "phc_xx"})
    assert "captured 'goal_done'" in out
    assert captured["json"]["event"] == "goal_done"
    assert captured["json"]["api_key"] == "phc_xx"
    # Default US region: events ingest on the dedicated i.posthog.com host.
    assert captured["url"] == "https://us.i.posthog.com/capture/"


def test_posthog_capture_uses_eu_ingestion_host(monkeypatch):
    _out, captured = _posthog_capture_url(monkeypatch, {
        "POSTHOG_API_KEY": "phc_xx", "POSTHOG_HOST": "https://eu.posthog.com",
    })
    assert captured["url"] == "https://eu.i.posthog.com/capture/"


def test_posthog_capture_honours_explicit_ingestion_host(monkeypatch):
    _out, captured = _posthog_capture_url(monkeypatch, {
        "POSTHOG_API_KEY": "phc_xx",
        "POSTHOG_HOST": "https://eu.posthog.com",
        "POSTHOG_INGESTION_HOST": "https://ph.internal.example.com",
    })
    assert captured["url"] == "https://ph.internal.example.com/capture/"


def test_posthog_capture_selfhosted_uses_same_host(monkeypatch):
    _out, captured = _posthog_capture_url(monkeypatch, {
        "POSTHOG_API_KEY": "phc_xx",
        "POSTHOG_HOST": "https://posthog.mycorp.internal",
    })
    # Self-hosted instances ingest on the same host (no i-subdomain split).
    assert captured["url"] == "https://posthog.mycorp.internal/capture/"


def test_posthog_insights_requires_keys(monkeypatch):
    monkeypatch.delenv("POSTHOG_PERSONAL_API_KEY", raising=False)
    monkeypatch.delenv("POSTHOG_PROJECT_ID", raising=False)
    fake_httpx = types.ModuleType("httpx")
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.posthog_tool import posthog_tool
    out = posthog_tool().fn({"op": "insights"})
    assert "POSTHOG_PERSONAL_API_KEY" in out
