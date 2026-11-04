"""A2A Agent Card discovery.

Lightwork advertises itself as an A2A (Agent2Agent) agent by serving a
standards-shaped Agent Card at /.well-known/agent-card.json -- the
discovery primitive that lets other agents find and describe it. Off by
default (outward-facing surface); opt in via MAVERICK_A2A_ENABLED=1.
"""
from __future__ import annotations

import pytest
from maverick import a2a


@pytest.fixture
def _clean(monkeypatch):
    monkeypatch.delenv("MAVERICK_A2A_ENABLED", raising=False)
    monkeypatch.delenv("MAVERICK_A2A_BASE_URL", raising=False)
    monkeypatch.setenv("HOME", "/nonexistent-a2a-test")


def test_card_has_required_a2a_fields(_clean):
    card = a2a.build_agent_card()
    for key in ("protocolVersion", "name", "description", "url", "version",
                "capabilities", "defaultInputModes", "defaultOutputModes",
                "skills"):
        assert key in card, f"missing A2A field: {key}"
    assert card["protocolVersion"] == "0.3.0"
    assert card["name"] == "Lightwork"
    assert isinstance(card["skills"], list) and card["skills"]
    for skill in card["skills"]:
        assert {"id", "name", "description", "tags"} <= set(skill)


def test_base_url_override(_clean, monkeypatch):
    monkeypatch.setenv("MAVERICK_A2A_BASE_URL", "https://maverick.example.com/")
    card = a2a.build_agent_card()
    # trailing slash stripped; path appended.
    assert card["url"] == "https://maverick.example.com/a2a/v1"


def test_disabled_by_default(_clean):
    assert a2a.a2a_enabled() is False


def test_enable_gate_parsing(_clean, monkeypatch):
    for v in ("1", "true", "yes", "on", "TRUE"):
        monkeypatch.setenv("MAVERICK_A2A_ENABLED", v)
        assert a2a.a2a_enabled() is True
    for v in ("0", "false", "no", "off"):
        monkeypatch.setenv("MAVERICK_A2A_ENABLED", v)
        assert a2a.a2a_enabled() is False


def test_route_absent_when_disabled(_clean):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    app = fastapi.FastAPI()
    a2a.mount(app)  # disabled -> no route
    client = TestClient(app)
    assert client.get("/.well-known/agent-card.json").status_code == 404


def test_route_served_when_enabled(_clean, monkeypatch):
    monkeypatch.setenv("MAVERICK_A2A_ENABLED", "1")
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    app = fastapi.FastAPI()
    a2a.mount(app)
    client = TestClient(app)
    r = client.get("/.well-known/agent-card.json")
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "Lightwork"
    assert body["protocolVersion"] == "0.3.0"
    # legacy alias also served
    assert client.get("/.well-known/agent.json").status_code == 200
