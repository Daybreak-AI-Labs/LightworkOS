"""Suggested edits to AI use rules, decided by a person (NOT-4).

An agent, a colleague or the AI assistant proposes new wording for one part
of the rules. It is stored as a suggestion and never applied by itself. A
signed-in person accepts it (saved as the next version through the same
route and permission check as editing by hand) or rejects it; both are in
the activity record.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
ANA = "user:ana@corp.com"
DANA = "user:dana@corp.com"
VIC = "user:vic@corp.com"
AGENT = "agent:policy-reviewer"
ROLES = {ANA: "operator", DANA: "admin", VIC: "viewer", AGENT: "operator"}
RULES = "/api/v1/security/assurance/ai-policy-management/policies"
EU = "AI must not send customer data outside the EU."


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config
    from maverick.audit import writer as audit_writer

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_TENANT", "suggestions-test")
    (tmp_path / "config.toml").write_text("[ai_policy_management]\nenable = true\n", encoding="utf-8")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_OIDC_ENABLED",
                 "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT_BY_USER"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    from maverick_dashboard.app import app

    yield TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()


def _as(monkeypatch, principal):
    from maverick_dashboard import auth, rbac

    role = ROLES[principal]
    allowed = lambda request, perm, **kw: perm in rbac.permissions_for(role)  # noqa: E731
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: principal)
    monkeypatch.setattr(auth, "role_for_principal", lambda p: ROLES.get(p))
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p: ROLES.get(p))
    monkeypatch.setattr(auth, "has_permission", allowed)
    monkeypatch.setattr(auth, "has_global_permission", allowed)


def _rules(client, monkeypatch):
    _as(monkeypatch, ANA)
    made = client.post(RULES, json={
        "policy_id": "customer-data", "title": "Customer data rules", "description": "How AI may use customer data.",
        "statements": [{"statement_id": "no-export", "text": EU, "effect": "prohibit"}]})
    assert made.status_code == 201, made.text
    return made.json()


def _versions(client):
    return client.get(RULES + "/customer-data").json()["versions"]


def _kinds():
    from maverick.audit.reader import iter_events

    return [e.get("kind") for e in iter_events()]


def test_an_agent_proposes_a_change_that_is_kept_as_a_suggestion_and_never_applied(client, monkeypatch):
    _rules(client, monkeypatch)
    _as(monkeypatch, AGENT)
    made = client.post("/api/v1/policy-suggestions", json={
        "id": "customer-data", "field": "statement:no-export",
        "text": "AI must not send customer data outside the EU or the UK.", "reason": "Cover the UK too."})
    assert made.status_code == 201, made.text
    view = made.json()
    assert view["proposer_kind"] == "agent" and view["proposed_by"] and view["reason"] == "Cover the UK too."
    assert view["field_label"] == "Rule: no export" and view["document_title"] == "Customer data rules"
    assert [(d["op"], d["text"]) for d in view["diff"] if d["op"] != "same"] == [("del", "EU."), ("ins", "EU or the UK.")]
    assert len(_versions(client)) == 1  # nothing changed in the rules
    listed = client.get("/api/v1/policy-suggestions").json()
    assert [s["id"] for s in listed["suggestions"]] == [view["id"]]
    assert listed["can_decide"] is True
    assert listed["rules"] == [{"id": "customer-data", "title": "Customer data rules", "parts": [
        {"field": "title", "label": "Title"}, {"field": "description", "label": "Description"},
        {"field": "statement:no-export", "label": "Rule: no export"}]}]
    assert "policy_suggestion_proposed" in _kinds()


def test_a_person_accepts_through_the_rules_own_save_path_and_it_is_audited(client, monkeypatch):
    _rules(client, monkeypatch)
    sid = client.post("/api/v1/policy-suggestions", json={
        "id": "customer-data", "field": "description", "text": "How AI may use and keep customer data."}).json()["id"]
    _as(monkeypatch, DANA)
    accepted = client.post(f"/api/v1/policy-suggestions/{sid}/accept", json={"reason": "Agreed in review."})
    assert accepted.status_code == 200, accepted.text
    body = accepted.json()
    assert body["suggestion"]["state"] == "accepted" and body["suggestion"]["applied_version"] == 2
    assert body["suggestion"]["decided_by"] == DANA and body["suggestion"]["decision_reason"] == "Agreed in review."
    versions = _versions(client)
    assert [v["description"] for v in versions] == ["How AI may use customer data.",
                                                    "How AI may use and keep customer data."]
    assert versions[1]["statements"][0]["text"] == EU  # the other parts are carried over unchanged
    assert versions[1]["authored_by"]  # saved under the deciding person, by the same save path
    assert client.get(RULES + "/customer-data").json()["active_version"] in (None, 0)  # not turned on
    assert {"policy_suggestion_accept_requested", "policy_suggestion_accepted"} <= set(_kinds())
    again = client.post(f"/api/v1/policy-suggestions/{sid}/accept", json={})
    assert again.status_code == 409


def test_a_rejection_is_recorded_with_its_reason_and_changes_nothing(client, monkeypatch):
    _rules(client, monkeypatch)
    sid = client.post("/api/v1/policy-suggestions", json={
        "id": "customer-data", "field": "title", "text": "Client data rules"}).json()["id"]
    rejected = client.post(f"/api/v1/policy-suggestions/{sid}/reject", json={"reason": "We say customer."})
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["suggestion"]["state"] == "rejected"
    assert len(_versions(client)) == 1
    recent = client.get("/api/v1/policy-suggestions").json()
    assert recent["suggestions"] == [] and recent["recent"][0]["decision_reason"] == "We say customer."
    assert "policy_suggestion_rejected" in _kinds()


def test_a_suggestion_made_on_older_wording_cannot_overwrite_a_newer_edit(client, monkeypatch):
    rules = _rules(client, monkeypatch)
    sid = client.post("/api/v1/policy-suggestions", json={
        "id": "customer-data", "field": "description", "text": "Older idea."}).json()["id"]
    edited = client.post(RULES + "/customer-data/versions", json={
        "title": "Customer data rules", "description": "Rewritten by hand.",
        "statements": [{"statement_id": "no-export", "text": EU, "effect": "prohibit"}],
        "expected_revision": rules["revision"]})
    assert edited.status_code == 200, edited.text
    assert client.get("/api/v1/policy-suggestions").json()["suggestions"][0]["outdated"] is True
    refused = client.post(f"/api/v1/policy-suggestions/{sid}/accept", json={})
    assert refused.status_code == 409 and "changed since this was suggested" in refused.json()["detail"]
    assert [v["description"] for v in _versions(client)][-1] == "Rewritten by hand."


def test_viewers_and_agents_cannot_decide(client, monkeypatch):
    _rules(client, monkeypatch)
    sid = client.post("/api/v1/policy-suggestions", json={
        "id": "customer-data", "field": "title", "text": "Client data rules"}).json()["id"]
    _as(monkeypatch, VIC)
    assert client.post(f"/api/v1/policy-suggestions/{sid}/accept", json={}).status_code == 403
    assert client.post("/api/v1/policy-suggestions", json={
        "id": "customer-data", "field": "title", "text": "Other"}).status_code == 403
    assert client.get("/api/v1/policy-suggestions").json()["can_decide"] is False
    _as(monkeypatch, AGENT)
    refused = client.post(f"/api/v1/policy-suggestions/{sid}/reject", json={})
    assert refused.status_code == 403 and "signed-in person" in refused.json()["detail"]


class _FakeLLM:
    calls: list = []

    def __init__(self, model=None, **_kw):
        self.model = model

    def complete(self, system, messages, budget=None, max_tokens=4096, **_kw):
        from maverick.llm import LLMResponse

        _FakeLLM.calls.append({"system": system, "message": messages[0]["content"], "budget": budget})
        return LLMResponse(text=json.dumps({"text": "AI must not send customer data outside the EU or the UK.",
                                            "why": "The request asked to cover the UK."}),
                           thinking=None, tool_calls=[], stop_reason="end_turn")


def test_the_ai_assistant_drafts_a_suggestion_within_a_capped_budget(client, monkeypatch):
    import maverick.llm
    from maverick_dashboard import _shared

    _rules(client, monkeypatch)
    _FakeLLM.calls = []
    monkeypatch.setattr(maverick.llm, "LLM", _FakeLLM)
    monkeypatch.setattr(_shared, "require_provider_or_400", lambda **_kw: None)
    made = client.post("/api/v1/policy-suggestions/ai", json={
        "id": "customer-data", "field": "statement:no-export", "instruction": "Cover the UK as well."})
    assert made.status_code == 201, made.text
    view = made.json()
    assert view["proposer_kind"] == "ai" and view["proposed_by"].startswith("AI assistant")
    assert view["reason"] == "The request asked to cover the UK."
    call = _FakeLLM.calls[0]
    assert call["budget"] is not None and call["budget"].max_dollars <= 0.25
    assert EU in call["message"] and "Cover the UK as well." in call["message"]
    assert len(_versions(client)) == 1  # a suggestion only


def test_ai_suggestions_follow_their_setting(client, monkeypatch, tmp_path):
    from maverick import config

    _rules(client, monkeypatch)
    (tmp_path / "config.toml").write_text("[ai_policy_management]\nenable = true\n[collaboration]\nai_suggestions = false\n",
                                          encoding="utf-8")
    config.reset_config_cache()
    refused = client.post("/api/v1/policy-suggestions/ai", json={
        "id": "customer-data", "field": "title", "instruction": "Shorter."})
    assert refused.status_code == 403 and "turned off" in refused.json()["detail"]
    assert client.get("/api/v1/policy-suggestions").json()["ai_on"] is False


def test_the_rules_panel_shows_suggestions_inline_unless_turned_off(client, monkeypatch, tmp_path):
    from maverick import config

    _as(monkeypatch, DANA)
    page = client.get("/security/assurance").text
    panel = page[page.index('id="ai-policy-management-panel"'):]
    assert panel.index("data-policy-suggestions") < panel.index("Exceptions to the rules")
    assert "/static/lightwork-policy-suggestions.js" in page
    (tmp_path / "config.toml").write_text("[ai_policy_management]\nenable = true\n[collaboration]\nsuggestions = false\n",
                                          encoding="utf-8")
    config.reset_config_cache()
    assert "data-policy-suggestions" not in client.get("/security/assurance").text
    refused = client.get("/api/v1/policy-suggestions")
    assert refused.status_code == 403 and "turned off" in refused.json()["detail"]


def test_an_unreadable_ai_answer_saves_nothing_and_says_so(client, monkeypatch):
    import maverick.llm
    from maverick_dashboard import _shared

    class Prose(_FakeLLM):
        def complete(self, *args, **kwargs):
            from maverick.llm import LLMResponse

            return LLMResponse(text="Sure, here is a shorter title.", thinking=None, tool_calls=[], stop_reason="end_turn")

    _rules(client, monkeypatch)
    monkeypatch.setattr(maverick.llm, "LLM", Prose)
    monkeypatch.setattr(_shared, "require_provider_or_400", lambda **_kw: None)
    refused = client.post("/api/v1/policy-suggestions/ai", json={
        "id": "customer-data", "field": "title", "instruction": "Shorter."})
    assert refused.status_code == 409 and "no suggestion was saved" in refused.json()["detail"]
    assert client.get("/api/v1/policy-suggestions").json()["suggestions"] == []
