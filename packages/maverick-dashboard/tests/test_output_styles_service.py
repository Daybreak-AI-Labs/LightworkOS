"""/styles page: list built-in output styles and set/clear the active one
(persisted to the dashboard runtime overlay)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def overlay(tmp_path, monkeypatch):
    from maverick import runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")


def test_page_lists_styles():
    t = client.get("/styles").text
    assert "Response styles" in t
    assert "concise" in t and "executive" in t
    assert "Default" in t  # the clear/none option


def test_set_then_active_shown():
    r = client.post("/styles/set", data={"name": "concise"}, follow_redirects=False)
    assert r.status_code == 303
    from maverick import runtime_overrides as ro
    assert ro.style_override() == "concise"
    page = client.get("/styles").text
    assert "In use now: Concise" in page
    from test_support.plain_language import developer_terms
    assert developer_terms(page) == []


def test_clear_with_empty_value():
    client.post("/styles/set", data={"name": "formal"}, follow_redirects=False)
    client.post("/styles/set", data={"name": ""}, follow_redirects=False)
    from maverick import runtime_overrides as ro
    assert ro.style_override() is None


def test_unknown_style_400():
    r = client.post("/styles/set", data={"name": "bogus"}, follow_redirects=False)
    assert r.status_code == 400
