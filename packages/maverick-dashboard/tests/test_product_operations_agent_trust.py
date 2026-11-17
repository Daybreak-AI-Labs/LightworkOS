"""Copilot reads the Agent trust page and makes its changes through the
page's own functions: the same permission checks, the same setting record,
the same saved result, and a replayed review changes nothing."""
from __future__ import annotations

import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

COPILOT = "/api/v1/copilot/product-operations"


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import agent_trust, config, world_model
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import product_operations as registry

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_AGENT_TRUST", "MAVERICK_TENANT", "MAVERICK_CLIENT_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(agent_trust, "managed_path", lambda: tmp_path / "agent_trust.json")
    # Copilot actions on, with the family the trust operations are in.
    monkeypatch.setattr(registry, "_gate", lambda request: None)
    monkeypatch.setattr(registry, "enabled_families", lambda: {"connections"})
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()
    dash_app._world_cache.clear()


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: rows.append({"kind": kind, **payload}) or True)
    return rows


def _as(monkeypatch, role: str, who: str):
    from maverick_dashboard import auth, rbac

    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _catalog(client) -> dict:
    listed = client.post(f"{COPILOT}/catalog", json={"page": "/trust", "selection": {}})
    assert listed.status_code == 200, listed.text
    return listed.json()


def _review(client, operation: str, arguments: dict):
    listed = _catalog(client)
    row = next(item for item in listed["operations"] if item["id"] == operation)
    assert row["available"], row
    return client.post(f"{COPILOT}/prepare", json={
        "page": "/trust", "selection": {}, "operation": operation, "context": listed["context"],
        "revision": row["revision"], "arguments": arguments})


def _execute(client, review: dict):
    return client.post(f"{COPILOT}/execute", json={"token": review["token"], "confirmed": True})


def _register(client, agent_id: str, **extra):
    entry = {"id": agent_id, "direction": "inbound", "allow_tools": ["research"], "max_risk": "low",
             "max_dollars": 2.0, "pubkey": "ab" * 32, **extra}
    assert client.post("/api/v1/trust/agents", json=entry).status_code == 201


def _request():
    return Request({"type": "http", "method": "POST", "path": "/trust",
                    "headers": [(b"host", b"127.0.0.1")], "client": ("127.0.0.1", 1)})


def test_copilot_turns_blocking_on_and_off_like_the_page(client, monkeypatch, audit_rows):
    from maverick import agent_trust, config
    from maverick.audit import EventKind
    from maverick_dashboard import product_operations_agent_trust as ops

    _as(monkeypatch, "admin", "user:ada")
    review = _review(client, "trust.enforcement.set", {"enforced": True})
    assert review.status_code == 200, review.text
    assert review.json()["changes"] == [{"field": "Blocking unlisted agents", "before": "Off", "after": "On"}]
    done = _execute(client, review.json())
    assert done.status_code == 200 and done.json()["status"] == "confirmed", done.text
    assert done.json()["details"] == {"Blocking unlisted agents": "On"}
    config.reset_config_cache()
    assert agent_trust.agent_trust_enforced() is True
    changed = [r for r in audit_rows if r["kind"] == EventKind.SETTING_CHANGED]
    (row,) = changed
    assert row["kind"] == EventKind.SETTING_CHANGED and row["actor"] == "user:ada"
    assert (row["section"], row["key"], row["old"], row["new"]) == ("agent_trust", "enforce", False, True)
    # The same review again changes nothing and writes no second record.
    assert _execute(client, review.json()).status_code == 409
    assert [r for r in audit_rows if r["kind"] == EventKind.SETTING_CHANGED] == changed

    # Turning it off lowers a protection: like the page, it needs confirming.
    refused = _review(client, "trust.enforcement.set", {"enforced": False})
    assert refused.status_code == 409 and "Confirm" in refused.json()["detail"]
    off = _review(client, "trust.enforcement.set", {"enforced": False, "confirmed": True})
    assert _execute(client, off.json()).json()["details"] == {"Blocking unlisted agents": "Off"}
    changed = [r for r in audit_rows if r["kind"] == EventKind.SETTING_CHANGED]
    assert (changed[-1]["old"], changed[-1]["new"], changed[-1]["confirmed"]) == (True, False, True)

    # A person who may only look is never offered it and cannot run it.
    _as(monkeypatch, "viewer", "user:bob")
    assert "trust.enforcement.set" not in {o["id"] for o in _catalog(client)["operations"]}
    adapter = {a.id: a for a in ops.entries()}["trust.enforcement.set"]
    with pytest.raises(HTTPException) as error:
        adapter.execute(_request(), {}, {"enforced": True, "confirmed": False}, {}, "a" * 32)
    assert error.value.status_code == 403
    config.reset_config_cache()
    assert agent_trust.agent_trust_enforced() is False
    assert [r for r in audit_rows if r["kind"] == EventKind.SETTING_CHANGED] == changed


def test_copilot_edits_an_agents_limits_like_the_page(client, monkeypatch, tmp_path, audit_rows):
    from maverick_dashboard import product_operations_agent_trust as ops

    _as(monkeypatch, "admin", "user:ada")
    for agent_id in ("by-copilot", "by-page"):
        _register(client, agent_id)
    saved = json.loads((tmp_path / "agent_trust.json").read_text())
    for entry in saved:
        entry["a2a_token"] = "kept-token-value"  # pragma: allowlist secret
    (tmp_path / "agent_trust.json").write_text(json.dumps(saved))

    limits = {"direction": "both", "allow_tools": ["research", "read_file"], "deny_tools": ["shell"],
              "max_risk": "medium", "max_dollars": 5.0, "data_scopes": []}
    review = _review(client, "trust.agents.edit", {"agent": "by-copilot", **limits, "max_minutes": 10.0})
    assert review.status_code == 200, review.text
    assert {"field": "Direction", "before": "It may contact us", "after": "Both ways"} in review.json()["changes"]
    assert {"field": "Time limit per task", "before": "No limit", "after": "10 minutes"} in review.json()["changes"]
    done = _execute(client, review.json())
    assert done.status_code == 200 and done.json()["status"] == "confirmed", done.text
    assert done.json()["details"]["Highest-risk actions allowed"] == "Up to medium risk"
    page = client.put("/api/v1/trust/agents/by-page", json={**limits, "pubkey": "ab" * 32, "max_wall_seconds": 600})
    assert page.status_code == 200, page.text

    assert [c for c in _changes(audit_rows) if c[0] == "limits_changed"] == [
        ("limits_changed", "by-copilot", "user:ada"), ("limits_changed", "by-page", "user:ada")]
    # The same saved result as the page, connection tokens and key kept.
    entries = {e["id"]: e for e in json.loads((tmp_path / "agent_trust.json").read_text())}
    assert {**entries["by-copilot"], "id": "by-page"} == entries["by-page"]
    assert entries["by-copilot"]["a2a_token"] == "kept-token-value"  # pragma: allowlist secret
    assert entries["by-copilot"]["pubkey"] == "ab" * 32
    # The same review again changes nothing.
    before = (tmp_path / "agent_trust.json").read_text()
    assert _execute(client, review.json()).status_code == 409
    assert (tmp_path / "agent_trust.json").read_text() == before

    # A person who may only look is never offered it and cannot run it.
    _as(monkeypatch, "viewer", "user:bob")
    assert "trust.agents.edit" not in {o["id"] for o in _catalog(client)["operations"]}
    adapter = {a.id: a for a in ops.entries()}["trust.agents.edit"]
    with pytest.raises(HTTPException) as error:
        adapter.execute(_request(), {}, ops.Limits(agent="by-copilot", direction="outbound").model_dump(),
                        {}, "a" * 32)
    assert error.value.status_code == 403
    assert (tmp_path / "agent_trust.json").read_text() == before


def test_copilot_shows_the_page_and_checks_access_like_the_page(client, monkeypatch):
    from maverick import agent_trust
    from maverick_dashboard import product_operations_agent_trust as ops
    from maverick_dashboard import trust_page_api

    _as(monkeypatch, "admin", "user:ada")
    _register(client, "partner-copilot", max_risk="medium", allow_tools=["web_search"])
    monkeypatch.setattr(agent_trust, "local_pubkey", lambda: "cd" * 32)
    _as(monkeypatch, "viewer", "user:bob")
    shown = _review(client, "trust.agents.show", {}).json()
    assert shown["read_only"] is True and "token" not in shown
    assert shown["details"]["Blocking unlisted agents"] == "Off"
    assert shown["details"]["Our security key"] == "cd" * 32
    (agent,) = shown["details"]["Outside agents"]
    assert agent["Agent"] == "Partner copilot" and agent["Status"] == "Active"
    assert agent["Highest-risk actions allowed"] == "Up to medium risk"

    for asked in ({"direction": "inbound", "tools": ["web_search"], "risk": "low"}, {"direction": "outbound"}):
        on_page = client.post("/api/v1/trust/agents/partner-copilot/check", json=asked).json()
        tool = (asked.get("tools") or [""])[0]
        checked = _review(client, "trust.agents.check", {
            "agent": "partner-copilot", "direction": asked["direction"], "tool": tool,
            "risk": asked.get("risk")}).json()
        assert checked["read_only"] is True and "token" not in checked
        assert checked["details"] == {"Agent": "Partner copilot", "Allowed": on_page["allowed"],
                                      "Reason": on_page["reason"]}
        assert checked["summary"] == on_page["reason"]

    def deny(request, permission):
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(trust_page_api, "require_permission", deny)
    adapter = {a.id: a for a in ops.entries()}["trust.agents.check"]
    with pytest.raises(HTTPException) as error:
        adapter.prepare(_request(), {}, {"agent": "partner-copilot", "direction": "inbound", "tool": "", "risk": None})
    assert error.value.status_code == 403


def _changes(rows):
    from maverick.audit import EventKind

    return [(r["action"], r["trusted_agent"], r["actor"]) for r in rows if r["kind"] == EventKind.AGENT_TRUST_CHANGED]


def test_copilot_adds_and_removes_an_agent_like_the_page(client, monkeypatch, tmp_path, audit_rows):
    from maverick_dashboard import product_operations_agent_trust as ops

    _as(monkeypatch, "admin", "user:ada")
    limits = {"direction": "inbound", "allow_tools": ["research"], "deny_tools": [], "max_risk": "low",
              "max_dollars": 2.0, "data_scopes": [], "pubkey": "ab" * 32}
    review = _review(client, "trust.agents.add", {"name": "Partner Copilot", **limits, "max_minutes": None})
    assert review.status_code == 200, review.text
    assert {"field": "Direction", "before": "", "after": "It may contact us"} in review.json()["changes"]
    done = _execute(client, review.json())
    assert done.status_code == 200 and done.json()["status"] == "confirmed", done.text
    assert done.json()["details"]["Status"] == "Active"
    assert client.post("/api/v1/trust/agents", json={"id": "by-page", **limits}).status_code == 201
    entries = {e["id"]: e for e in json.loads((tmp_path / "agent_trust.json").read_text())}
    assert {**entries["partner-copilot"], "id": "by-page"} == entries["by-page"]
    assert _execute(client, review.json()).status_code == 409   # the same review again
    taken = _review(client, "trust.agents.add", {"name": "Partner Copilot", **limits, "max_minutes": None})
    assert taken.status_code == 409 and "already on the list" in taken.json()["detail"]

    # Removing says what stops working and needs confirming.
    unconfirmed = _review(client, "trust.agents.remove", {"agent": "partner-copilot"})
    assert unconfirmed.status_code == 409 and "Confirm" in unconfirmed.json()["detail"]
    removal = _review(client, "trust.agents.remove", {"agent": "partner-copilot", "confirmed": True})
    assert "turned away" in removal.json()["summary"] and "deleted" in removal.json()["summary"]
    gone = _execute(client, removal.json())
    assert gone.status_code == 200 and gone.json()["details"] == {"On the list": "No"}, gone.text
    assert client.delete("/api/v1/trust/agents/by-page").status_code == 204
    assert json.loads((tmp_path / "agent_trust.json").read_text()) == []
    assert _execute(client, removal.json()).status_code == 409
    assert _changes(audit_rows) == [("added", "partner-copilot", "user:ada"), ("added", "by-page", "user:ada"),
                                    ("removed", "partner-copilot", "user:ada"), ("removed", "by-page", "user:ada")]

    _register(client, "kept-agent")
    _as(monkeypatch, "viewer", "user:bob")
    offered = {o["id"] for o in _catalog(client)["operations"]}
    assert not offered & {"trust.agents.add", "trust.agents.remove"}
    by_id = {a.id: a for a in ops.entries()}
    for operation, arguments in (("trust.agents.add", ops.NewAgent(name="Other").model_dump()),
                                 ("trust.agents.remove", {"agent": "kept-agent", "confirmed": True})):
        with pytest.raises(HTTPException) as error:
            by_id[operation].execute(_request(), {}, arguments, {}, "a" * 32)
        assert error.value.status_code == 403
    assert [e["id"] for e in json.loads((tmp_path / "agent_trust.json").read_text())] == ["kept-agent"]


def test_copilot_blocks_and_unblocks_an_agent_like_the_page(client, monkeypatch, tmp_path, audit_rows):
    from maverick import agent_trust
    from maverick_dashboard import product_operations_agent_trust as ops

    _as(monkeypatch, "admin", "user:ada")
    _register(client, "partner-copilot")
    unconfirmed = _review(client, "trust.agents.block", {"agent": "partner-copilot"})
    assert unconfirmed.status_code == 409 and "Confirm" in unconfirmed.json()["detail"]
    review = _review(client, "trust.agents.block", {"agent": "partner-copilot", "confirmed": True})
    assert "turned away" in review.json()["summary"]
    assert review.json()["changes"] == [{"field": "Partner copilot", "before": "Active", "after": "Blocked"}]
    done = _execute(client, review.json())
    assert done.status_code == 200 and done.json()["details"] == {"Status": "Blocked"}, done.text
    assert agent_trust.decide_inbound("partner-copilot", enforced=True).rule == "revoked"
    assert _execute(client, review.json()).status_code == 409   # the same review again

    restore = _review(client, "trust.agents.unblock", {"agent": "partner-copilot"})
    assert restore.json()["changes"] == [{"field": "Partner copilot", "before": "Blocked", "after": "Active"}]
    assert _execute(client, restore.json()).json()["details"] == {"Status": "Active"}
    assert not json.loads((tmp_path / "agent_trust.json").read_text())[0]["revoked"]
    assert _changes(audit_rows) == [("added", "partner-copilot", "user:ada"), ("blocked", "partner-copilot", "user:ada"),
                                    ("unblocked", "partner-copilot", "user:ada")]

    _as(monkeypatch, "viewer", "user:bob")
    offered = {o["id"] for o in _catalog(client)["operations"]}
    assert not offered & {"trust.agents.block", "trust.agents.unblock"}
    adapter = {a.id: a for a in ops.entries()}["trust.agents.block"]
    with pytest.raises(HTTPException) as error:
        adapter.execute(_request(), {}, {"agent": "partner-copilot", "confirmed": True}, {}, "a" * 32)
    assert error.value.status_code == 403
    assert not json.loads((tmp_path / "agent_trust.json").read_text())[0]["revoked"]
