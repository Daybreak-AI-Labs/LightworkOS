"""Agent Trust Plane management from the app: register / revoke / restore /
remove external agents via the admin API, writing the managed overlay
(agent_trust.json) -- never the operator's config file."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


@pytest.fixture(autouse=True)
def managed(tmp_path, monkeypatch):
    """Point the managed registry overlay at a per-test file."""
    from maverick import agent_trust
    monkeypatch.setattr(agent_trust, "managed_path",
                        lambda: tmp_path / "agent_trust.json")


def _register(**overrides):
    entry = {"id": "partner-copilot", "direction": "inbound",
             "allow_tools": ["research"], "max_risk": "low",
             "max_dollars": 2.0}
    entry.update(overrides)
    return client.post("/api/v1/trust/agents", json=entry)


def test_register_and_list_roundtrip():
    r = _register()
    assert r.status_code == 201
    assert r.json() == {"ok": True, "id": "partner-copilot"}
    agents = client.get("/api/v1/trust/agents").json()["agents"]
    (a,) = [x for x in agents if x["id"] == "partner-copilot"]
    assert a["direction"] == "inbound"
    assert a["allow_tools"] == ["research"]
    assert a["max_risk"] == "low"
    assert a["max_dollars"] == 2.0
    assert a["revoked"] is False


def test_register_rejects_bad_entries():
    # malformed pubkey -> clear 400, not a silent drop
    assert _register(pubkey="not-hex").status_code in (400, 422)
    # bad id charset -> validation failure (pydantic or registry)
    assert _register(id="No Spaces Allowed").status_code in (400, 422)
    # bad direction is schema-gated
    assert _register(direction="sideways").status_code == 422


def test_revoke_restore_and_remove():
    assert _register().status_code == 201
    r = client.post("/api/v1/trust/agents/partner-copilot/revoke",
                    json={"revoked": True})
    assert r.status_code == 200
    agents = client.get("/api/v1/trust/agents").json()["agents"]
    assert [a["revoked"] for a in agents if a["id"] == "partner-copilot"] == [True]

    r = client.post("/api/v1/trust/agents/partner-copilot/revoke",
                    json={"revoked": False})
    assert r.status_code == 200
    agents = client.get("/api/v1/trust/agents").json()["agents"]
    assert [a["revoked"] for a in agents if a["id"] == "partner-copilot"] == [False]

    assert client.delete("/api/v1/trust/agents/partner-copilot").status_code == 204
    agents = client.get("/api/v1/trust/agents").json()["agents"]
    assert not [a for a in agents if a["id"] == "partner-copilot"]


def test_unmanaged_agent_actions_explain_the_config_file():
    # No managed entry: revoke/remove 404 with a human explanation instead of
    # silently succeeding (config-file entries are not editable from the app).
    r = client.post("/api/v1/trust/agents/config-only/revoke",
                    json={"revoked": True})
    assert r.status_code == 404
    assert "config" in r.json()["detail"]
    assert client.delete("/api/v1/trust/agents/config-only").status_code == 404


def test_remove_that_would_lift_a_revocation_is_a_conflict(monkeypatch):
    from maverick import agent_trust

    def _refuse(agent_id):
        raise agent_trust.RevokedAgentRemovalRefused("would make it trusted again")

    monkeypatch.setattr(agent_trust, "remove_agent", _refuse)
    for url in ("/api/v1/trust/agents/partner-copilot",
                "/api/v1/external-agents/partner-copilot"):
        r = client.delete(url)
        assert r.status_code == 409
        assert r.json()["detail"] == "would make it trusted again"


def test_trust_page_has_register_form_and_row_actions():
    _register()
    page = client.get("/trust").text
    assert "Add an outside agent" in page
    assert 'id="trust-add"' in page
    assert "data-trust-revoke" in page
    assert "data-trust-remove" in page
    assert "data-tr-edit" in page and "data-tr-check" in page
    # Tools and data areas are chosen, not typed; no raw key hint or config talk.
    assert 'name="allow_tools" value="research"' in page
    assert "comma-separated" not in page and "config file" not in page
    assert "Turn on blocking" in page and "Copy our key" in page
    from test_support.plain_language import developer_terms

    assert developer_terms(page) == []


def test_mutations_are_csrf_gated():
    # no Origin/Referer on a mutating call in no-token mode -> blocked
    bare = TestClient(app, base_url="http://127.0.0.1")
    assert bare.post("/api/v1/trust/agents",
                     json={"id": "x"}).status_code == 403


def test_edit_keeps_connection_tokens_and_block_state(tmp_path):
    import json

    from maverick import agent_trust

    assert _register().status_code == 201
    entries = json.loads((tmp_path / "agent_trust.json").read_text())
    entries[0]["a2a_token"] = "kept-token-value"  # pragma: allowlist secret
    entries[0]["revoked"] = True
    (tmp_path / "agent_trust.json").write_text(json.dumps(entries))
    r = client.put("/api/v1/trust/agents/partner-copilot", json={
        "direction": "both", "allow_tools": ["research", "read_file"], "deny_tools": ["shell"],
        "max_risk": "medium", "max_dollars": 5.0, "max_wall_seconds": 600, "data_scopes": []})
    assert r.status_code == 200, r.text
    saved = json.loads((tmp_path / "agent_trust.json").read_text())[0]
    assert saved["a2a_token"] == "kept-token-value"  # pragma: allowlist secret
    assert saved["revoked"] is True
    agent = agent_trust._agent_from_entry(saved)
    assert agent.direction == "both" and agent.max_risk == "medium"
    assert "shell" in agent.deny_tools and agent.max_wall_seconds == 600


def test_edit_refuses_installation_defined_agents():
    r = client.put("/api/v1/trust/agents/config-only", json={"direction": "both"})
    assert r.status_code == 404
    assert "installation" in r.json()["detail"]


def test_check_access_replays_the_decision_in_plain_words():
    # A deliberately rated read-only tool: an unrated name is treated as high
    # risk and would be refused under this medium ceiling.
    assert _register(max_risk="medium", allow_tools=["web_search"]).status_code == 201
    ok = client.post("/api/v1/trust/agents/partner-copilot/check",
                     json={"direction": "inbound", "tools": ["web_search"], "risk": "low"})
    assert ok.status_code == 200 and ok.json()["allowed"] is True
    denied = client.post("/api/v1/trust/agents/partner-copilot/check",
                         json={"direction": "outbound"})
    assert denied.json() == {"allowed": False,
                             "reason": "This agent is not allowed to connect in that direction."}
    unknown = client.post("/api/v1/trust/agents/nobody/check", json={})
    assert unknown.json()["allowed"] is False


def test_enforcement_switch_writes_the_setting(tmp_path, monkeypatch):
    from maverick import agent_trust, config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_AGENT_TRUST", raising=False)
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    config.reset_config_cache()
    assert agent_trust.agent_trust_enforced() is False
    assert client.post("/api/v1/trust/enforcement", json={"enforced": True}).status_code == 200
    config.reset_config_cache()
    assert agent_trust.agent_trust_enforced() is True
    assert client.post("/api/v1/trust/enforcement",
                       json={"enforced": False, "confirm": True}).status_code == 200
    config.reset_config_cache()
    assert agent_trust.agent_trust_enforced() is False
    monkeypatch.setenv("MAVERICK_AGENT_TRUST", "1")
    assert client.post("/api/v1/trust/enforcement",
                       json={"enforced": False, "confirm": True}).status_code == 409
    config.reset_config_cache()


def test_enforcement_switch_needs_an_administrator(monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import trust_page_api

    def deny(request, permission):
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(trust_page_api, "require_global_permission", deny)
    assert client.post("/api/v1/trust/enforcement", json={"enforced": True}).status_code == 403


def test_public_key_is_offered(monkeypatch):
    from maverick import agent_trust

    monkeypatch.setattr(agent_trust, "local_pubkey", lambda: "ab" * 32)
    assert client.get("/api/v1/trust/pubkey").json() == {"key": "ab" * 32}
    monkeypatch.setattr(agent_trust, "local_pubkey", lambda: None)
    assert client.get("/api/v1/trust/pubkey").status_code == 503


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def test_turning_blocking_off_needs_confirmation_and_is_recorded(tmp_path, monkeypatch, audit_rows):
    from maverick import agent_trust, config
    from maverick.audit import EventKind
    from maverick_dashboard import auth

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_AGENT_TRUST", raising=False)
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:ada")
    from maverick_dashboard import rbac
    rbac.set_role("user:ada", "admin")
    audit_rows.clear()
    config.reset_config_cache()
    # Turning blocking on needs no confirmation, and is recorded.
    assert client.post("/api/v1/trust/enforcement", json={"enforced": True}).status_code == 200
    assert audit_rows[-1]["kind"] == EventKind.SETTING_CHANGED
    assert audit_rows[-1]["actor"] == "user:ada"
    assert (audit_rows[-1]["section"], audit_rows[-1]["key"]) == ("agent_trust", "enforce")
    assert (audit_rows[-1]["old"], audit_rows[-1]["new"]) == (False, True)
    audit_rows.clear()
    # Turning it off without confirming is refused, and nothing changes.
    r = client.post("/api/v1/trust/enforcement", json={"enforced": False})
    assert r.status_code == 409
    assert r.json()["confirm"][0]["id"] == "agent_trust.enforce"
    config.reset_config_cache()
    assert agent_trust.agent_trust_enforced() is True
    assert audit_rows == []
    # Confirmed, it changes and the record names who did it.
    r = client.post("/api/v1/trust/enforcement", json={"enforced": False, "confirm": True})
    assert r.status_code == 200
    config.reset_config_cache()
    assert agent_trust.agent_trust_enforced() is False
    (row,) = audit_rows
    assert row["kind"] == EventKind.SETTING_CHANGED and row["actor"] == "user:ada"
    assert (row["old"], row["new"], row["confirmed"]) == (True, False, True)
