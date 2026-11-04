"""Agent Factory searches its specialists instead of shipping all of them.

The page sent every prebuilt specialist (2,031) as one picker list: 477 KB of
its 568 KB of HTML on every visit. The picker is now a search box that asks
/agents/picker for the best matches as you type. The endpoint lives under the
page's own path, so the page's role visibility applies to it, it is scoped to
the caller's departments like the page, and it answers with at most 20
matches by default (50 at most).
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _as(monkeypatch, principal, role=None):
    from maverick_dashboard import api, auth, rbac

    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    if role:
        rbac.set_role(principal, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(api, "caller_principal", lambda request: principal)


def _roster():
    from maverick.domain_edit import list_agents

    return list_agents()


def test_page_has_a_search_box_not_the_whole_roster(client):
    page = client.get("/agents").text
    assert "<datalist" not in page and "data-name=" not in page
    picker = re.search(r'<input id="agent-picker"[^>]*>', page).group(0)
    for attribute in ('role="combobox"', 'aria-autocomplete="list"', 'aria-expanded="false"',
                      'aria-controls="agent-picker-list"', 'data-picker-src="/agents/picker"'):
        assert attribute in picker
    assert re.search(r'<ul id="agent-picker-list"[^>]*role="listbox"', page)
    assert 'id="agent-picker-status" role="status"' in page
    assert "/static/lightwork-agent-picker.js" in page
    assert re.search(r"search [\d,]+ agents and specialists", page)
    assert len(page.encode()) < 250_000  # it was 568 KB


def test_answers_are_limited_and_ready_specialists_come_first(client):
    roster = _roster()
    ready = [agent for agent in roster if agent["readiness"]["state"] == "action_ready"]
    body = client.get("/agents/picker").json()
    assert len(body["items"]) == 20 and body["total"] == len(ready)
    assert all(item["ready"] for item in body["items"])
    assert set(body["items"][0]) == {"name", "label", "ready", "readiness"}
    assert len(client.get("/agents/picker", params={"limit": 500}).json()["items"]) == 50
    assert len(client.get("/agents/picker", params={"limit": 0}).json()["items"]) == 1
    everyone = client.get("/agents/picker", params={"setup": "1"}).json()
    assert everyone["total"] == len(roster)


def test_search_matches_the_words_people_see(client):
    roster = _roster()
    target = next(agent for agent in roster if agent["readiness"]["state"] == "action_ready" and agent["description"])
    found = client.get("/agents/picker", params={"q": target["description"].upper()}).json()
    assert found["items"][0]["name"] == target["name"]
    # The label is the page's unambiguous "description · name" (custom packs marked).
    assert found["items"][0]["label"].startswith(target["description"] + " · ")
    assert found["items"][0]["label"].endswith(" (custom)") == bool(target["is_override"])
    # The exact pack name works too, as the old picker allowed.
    by_name = client.get("/agents/picker", params={"q": target["name"]}).json()
    assert target["name"] in [item["name"] for item in by_name["items"]]
    # A word that starts a label ranks before a match inside a word.
    word = client.get("/agents/picker", params={"q": "plan", "setup": "1", "limit": 50}).json()["items"]
    starts = [bool(re.search(r"(?:^|\W)plan", item["label"], re.IGNORECASE) or item["name"].startswith("plan")) for item in word]
    assert starts == sorted(starts, reverse=True)
    assert client.get("/agents/picker", params={"q": "zzzz-no-such-specialist"}).json() == {
        "items": [], "total": 0, "limit": 20}


def test_roster_is_read_and_ranked_off_the_event_loop(client, monkeypatch):
    """Search-as-you-type must not run ~2,000 specialists' work on the loop."""
    import asyncio

    from maverick import domain_edit

    seen = []
    plain = domain_edit.list_agents

    def list_agents(*args, **kwargs):
        try:
            asyncio.get_running_loop()
            seen.append("event loop")
        except RuntimeError:
            seen.append("worker thread")
        return plain(*args, **kwargs)

    monkeypatch.setattr(domain_edit, "list_agents", list_agents)
    assert client.get("/agents/picker", params={"q": "plan"}).status_code == 200
    assert seen == ["worker thread"]


def test_needs_setup_specialists_only_when_asked(client):
    needs_setup = next(agent for agent in _roster() if agent["readiness"]["state"] != "action_ready")
    hidden = client.get("/agents/picker", params={"q": needs_setup["name"]}).json()
    assert needs_setup["name"] not in [item["name"] for item in hidden["items"]]
    shown = client.get("/agents/picker", params={"q": needs_setup["name"], "setup": "1"}).json()
    item = next(item for item in shown["items"] if item["name"] == needs_setup["name"])
    assert item["ready"] is False and item["readiness"] == needs_setup["readiness"]["label"]


def test_endpoint_follows_the_pages_role_visibility(client, monkeypatch):
    _as(monkeypatch, "user:viewer-person", "viewer")
    assert client.get("/agents", headers={"Accept": "text/html"}).status_code == 403
    assert client.get("/agents/picker", params={"q": "finance"}).status_code == 403
    _as(monkeypatch, "user:operator-person", "operator")
    assert client.get("/agents").status_code == 200
    assert client.get("/agents/picker", params={"q": "finance"}).status_code == 200


def test_endpoint_is_scoped_to_the_callers_departments(client, monkeypatch):
    from maverick_dashboard import suite_grants

    suite_grants.set_suites("user:fin", ["finance"])
    _as(monkeypatch, "user:fin", role="operator")
    items = client.get("/agents/picker", params={"setup": "1", "limit": 50, "q": "finance_ap"}).json()["items"]
    assert "finance_ap" in [item["name"] for item in items]
    legal = client.get("/agents/picker", params={"setup": "1", "limit": 50, "q": "legal_contracts"}).json()
    assert legal["items"] == [] and legal["total"] == 0
    roster = {agent["name"]: agent for agent in _roster()}
    every = client.get("/agents/picker", params={"setup": "1", "limit": 50}).json()
    assert every["total"] < len(roster)
    for item in every["items"]:
        assert set(roster[item["name"]]["suites"]) <= {"finance"}
