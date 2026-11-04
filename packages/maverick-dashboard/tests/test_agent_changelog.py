"""Each agent keeps a short record of who changed its instructions or model, when, and what."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick import paths
from maverick_dashboard import agent_changelog as changelog
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr("maverick.config.dashboard_overrides_path", lambda: tmp_path / "dashboard.toml")


def _view(**fields):
    base = {"name": "proc_po_chaser", "description": "Chases POs", "persona": "You are the PO Confirmation Chaser.",
            "allow_tools": ["read_file"], "deny_tools": [], "max_risk": "medium", "knowledge_sources": [],
            "models": {}, "workflow": [{"name": "read", "instruction": "Read the POs", "tools": ["read_file"], "gate": ""}],
            "output": {"shape": "table"}}
    base.update(fields)
    return base


def test_pack_changes_are_described_in_plain_words():
    before = _view()
    after = _view(persona="You are a stricter PO chaser.", models={"orchestrator": "openai:gpt-5.4"},
                  allow_tools=["read_file", "web_search"])
    changes = changelog.describe_agent_change(before, after)
    assert "Changed its instructions" in changes
    assert "Changed what it is allowed to do" in changes
    assert any(c.startswith("Changed the AI model it uses for the Planner") and "GPT-5.4" in c for c in changes)
    assert changelog.describe_agent_change(before, before) == []
    assert changelog.describe_agent_change(None, after) == ["Created this agent"]


def test_entries_are_newest_first_and_include_workspace_wide_changes():
    changelog.record("proc_po_chaser", ["Changed its instructions"], by="user:alice")
    changelog.record(changelog.EVERY_AGENT, ["Changed the default AI model for every agent and specialist"], by="user:bob")
    changelog.record("legal_nda_desk", ["Changed its instructions"], by="user:carol")
    rows = changelog.entries("proc_po_chaser")
    assert [row["changes"][0] for row in rows] == [
        "Changed the default AI model for every agent and specialist", "Changed its instructions"]
    assert rows[1]["by"] == "user:alice"
    assert changelog.record("proc_po_chaser", [], by="user:alice") is None


def test_entries_sharing_a_clock_reading_are_still_newest_first(monkeypatch):
    # Windows clocks can give two saves the same timestamp; the later save
    # must still come first, and a genuinely later timestamp still wins.
    clock = {"now": 1_800_000_000.0}
    monkeypatch.setattr(changelog.time, "time", lambda: clock["now"])
    changelog.record("proc_po_chaser", ["Changed its instructions"], by="user:alice")
    changelog.record(changelog.EVERY_AGENT, ["Changed the default AI model for every agent and specialist"],
                     by="user:bob")
    clock["now"] += 1
    changelog.record("proc_po_chaser", ["Changed what it is allowed to do"], by="user:carol")
    assert [row["by"] for row in changelog.entries("proc_po_chaser")] == ["user:carol", "user:bob", "user:alice"]


def test_changelog_rows_stay_in_their_workspace():
    with paths.tenant_scope(tenant="alpha"):
        changelog.record("proc_po_chaser", ["Changed its instructions"], by="user:alice")
    with paths.tenant_scope(tenant="beta"):
        assert changelog.entries("proc_po_chaser") == []


def test_version_label_names_the_agent_and_the_last_change_before_the_answer():
    changelog.record("proc_po_chaser", ["Changed its instructions"], by="user:alice")
    row = changelog.entries("proc_po_chaser")[0]
    label = changelog.version_label("proc_po_chaser", answered_at=row["ts"] + 60)
    assert label["agent"] == "PO Confirmation Chaser"
    assert label["updated_at"] == row["ts"]
    assert label["changed_since"] == []
    later = changelog.version_label("proc_po_chaser", answered_at=row["ts"] - 60)
    assert later["updated_at"] is None
    assert later["changed_since"][0]["changes"] == ["Changed its instructions"]
    general = changelog.version_label("", answered_at=row["ts"] + 60)
    assert general["agent"] == "Lightwork"
    assert (label["kind"], general["kind"]) == ("specialist", "agent")


def test_built_in_packs_are_specialists_and_everything_else_is_an_agent():
    # Owner glossary: a built-in pack (even a customized copy) is a specialist;
    # a customer-built agent, and the general assistant, is an agent.
    assert changelog.agent_kind("proc_po_chaser") == "specialist"
    assert changelog.agent_kind("acme_invoice_helper") == "agent"
    assert changelog.agent_kind("") == "agent"
    assert changelog.version_label("acme_invoice_helper", answered_at=None)["kind"] == "agent"


def test_saving_and_resetting_an_agent_writes_the_changelog(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setattr("maverick.agent_publish_policy.require_passing_tests", lambda: False)  # changelog only, not the publish gate
    from test_support.agent_drafts import publish as _publish

    # Publishing a reviewed complete draft is the only way a definition changes.
    r = _publish("proc_po_chaser", {"persona": "You are the strict PO Confirmation Chaser."}, reason="")
    assert r.status_code == 200 and r.json()["confirmed"], r.text
    rows = changelog.entries("proc_po_chaser", include_workspace=False)
    assert rows and rows[0]["changes"] == ["Changed its instructions"]
    generation = client.get("/api/v1/agents/proc_po_chaser").json()["generation"]
    # A reset without the complete review changes nothing.
    bare = client.delete("/api/v1/agents/proc_po_chaser/override", params={"expected_generation": generation})
    assert bare.status_code == 409 and "Nothing was changed" in bare.text
    assert changelog.entries("proc_po_chaser", include_workspace=False)[0]["changes"] == ["Changed its instructions"]
    # The reviewed reset names the version it replaces (a stale one is refused).
    context = client.get("/api/v1/agent-override-changes").json()["context"]
    review = client.post("/api/v1/agent-override-changes/review",
                         json={"name": "proc_po_chaser", "action": "reset_builtin", "context": context})
    assert review.status_code == 200, review.text
    r = client.request("DELETE", "/api/v1/agents/proc_po_chaser/override", params={"expected_generation": generation},
                       json={"token": review.json()["token"], "confirmed": True})
    assert r.status_code == 200, r.text
    assert changelog.entries("proc_po_chaser", include_workspace=False)[0]["changes"] == ["Reset to the built-in version"]


def test_role_and_default_model_changes_are_recorded_for_every_agent(monkeypatch):
    r = client.post("/api/v1/roles/orchestrator/override",
                    json={"system_addendum": "Always answer in British English."})
    assert r.status_code == 200, r.text
    rows = changelog.entries(changelog.EVERY_AGENT)
    assert rows[0]["changes"] == ["Changed the instructions the Planner follows for every agent and specialist"]
    r = client.post("/settings/models", data={"model": "anthropic:claude-sonnet-4-6"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    newest = changelog.entries(changelog.EVERY_AGENT)[0]["changes"][0]
    assert newest.startswith("Changed the default AI model for every agent and specialist")


def test_the_agent_editor_shows_who_changed_it_when_and_what(monkeypatch):
    changelog.record("proc_po_chaser", ["Changed its instructions"], by="user:alice@example.com")
    body = client.get("/agents?name=proc_po_chaser").text
    history = body.split('id="agent-changelog"', 1)[1].split("</section>", 1)[0]
    assert "Change history" in history
    assert "alice@example.com" in history and "Changed its instructions" in history
    assert "This specialist" in history and "This agent" not in history


def test_people_who_are_not_administrators_see_that_an_administrator_changed_it(monkeypatch):
    from maverick_dashboard import app as app_module

    monkeypatch.setattr(app_module, "has_global_permission", lambda request, permission: False)
    changelog.record("proc_po_chaser", ["Changed its instructions"], by="user:alice@example.com")
    history = client.get("/agents?name=proc_po_chaser").text.split('id="agent-changelog"', 1)[1]
    history = history.split("</section>", 1)[0]
    assert "alice" not in history and "An administrator" in history
