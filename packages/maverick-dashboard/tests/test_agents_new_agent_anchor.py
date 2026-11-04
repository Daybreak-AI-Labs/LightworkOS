"""'+ New custom agent' reloads /agents?new=1; without a fragment the new page
opens at the top and the revealed form sits below the fold, so the click looks
like it did nothing."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_new_custom_agent_links_land_on_the_form(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    text = _client().get("/agents").text
    assert 'href="/agents?new=1"' not in text
    assert 'href="/agents?new=1#agent-form"' in text
    creating = _client().get("/agents?new=1").text
    assert 'id="agent-form"' in creating and 'data-creating="1"' in creating
