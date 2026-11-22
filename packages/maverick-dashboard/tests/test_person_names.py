"""People, not sign-in identifiers, in approvals, settings history and the Activity log.

Live (round 2): approvals, settings history and the Activity log named every
Google sign-in only as "Google account"; the Activity log's Person filter
listed "system:finance-scheduler:<hex>" and "pe_content_writing-0"; and the
approval history's heading was the raw tool name "code_exec".
"""
from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

GOOGLE = "user:google-oauth2|104857600123456789"
OTHER = "user:google-oauth2|200000000000000000002"
DIRECTORY = "user:waad|5e1f0c2a-0000-4000-8000-00000000abcd"


@pytest.fixture
def known(monkeypatch):
    """An invitation accepted by GOOGLE; a company directory entry for DIRECTORY."""
    from maverick_dashboard import invites, scim, subject_directory

    monkeypatch.setattr(invites, "list_invites", lambda: [
        SimpleNamespace(used_by=GOOGLE, email="dana@northwind.example"),
        SimpleNamespace(used_by=None, email="unused@northwind.example")])
    monkeypatch.setattr(scim, "_load", lambda: {"a" * 32: {
        "id": "a" * 32, "externalId": "ext-1", "userName": "riley", "displayName": "Riley Chen",
        "email": "riley@northwind.example", "active": True}})
    monkeypatch.setattr(subject_directory, "load_index", lambda: {"ignored": True})
    monkeypatch.setattr(subject_directory, "subs_in", lambda index, ids:
                        {DIRECTORY.removeprefix("user:")} if "ext-1" in ids else set())


def _request(principal=None, **claims):
    return SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(principal=principal, claims=claims)
                                                 if principal else None))


def test_a_person_reads_as_the_name_or_address_the_installation_knows(known):
    from maverick_dashboard.person_names import labeler

    label = labeler(_request(OTHER, verified_email="me@northwind.example"))
    assert label(GOOGLE) == "dana@northwind.example"          # accepted invitation
    assert label(DIRECTORY) == "Riley Chen"                    # company directory
    assert label(OTHER) == "me@northwind.example"              # the viewer's own sign-in
    stranger = labeler(_request())("user:google-oauth2|300000000000000000003")
    assert stranger == "Google account" and "300000" not in stranger


def test_lightwork_workers_and_ai_specialists_read_as_what_they_are(known):
    from maverick_dashboard.person_names import labeler

    label = labeler()
    assert label("system:finance-scheduler:" + "0f" * 16) == "Finance scheduler (Lightwork)"
    assert label("pe_content_writing-0") == "Content & UX-Writing Specialist (AI)"
    assert label("orchestrator-0") == "Planner (AI)"
    assert label("alice-2") == "alice-2"  # not a known role: shown as recorded
    # Live: the Activity log's Person filter listed "system".
    assert label("system") == "Lightwork (automatic)"


def test_an_unreadable_directory_still_names_the_account_kind(monkeypatch):
    from maverick_dashboard import invites, scim
    from maverick_dashboard.person_names import labeler

    def broken():
        raise OSError("store unavailable")
    monkeypatch.setattr(invites, "list_invites", broken)
    monkeypatch.setattr(scim, "_load", broken)
    assert labeler()(GOOGLE) == "Google account"


def test_settings_history_names_the_person(known):
    from maverick_dashboard.person_names import labeler
    from maverick_dashboard.settings_experience import _who

    assert _who(GOOGLE, labeler()) == "dana@northwind.example"
    assert _who(None) == "Unknown"


def test_the_activity_log_names_people_and_workers(known):
    from maverick_dashboard.audit_actions_api import event_details, page_helpers

    helpers = page_helpers(_request())
    row = {"kind": "approval_decision", "decided_by": GOOGLE, "status": "denied", "approval_id": 3}
    assert helpers["event_who"](row) == "dana@northwind.example"
    assert dict((label, text) for _key, label, text in helpers["event_details"](row))["Decided by"] == "dana@northwind.example"
    assert helpers["person_label"]("system:finance-scheduler:" + "ab" * 16) == "Finance scheduler (Lightwork)"
    # Without a page's directory the account kind still shows, never the identifier.
    assert dict((label, text) for _key, label, text in event_details(row))["Decided by"] == "Google account"


def test_the_activity_log_person_filter_lists_plain_labels(known, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from maverick import audit, world_model

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for actor in (GOOGLE, "system:finance-scheduler:" + "c4" * 16, "pe_content_writing-0"):
        assert audit.audit_event("control_plane_action", agent="dashboard", action="settings_saved", actor=actor)
    from maverick_dashboard.app import app

    page = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get("/audit")
    assert page.status_code == 200, page.text[:500]
    assert ">dana@northwind.example</option>" in page.text
    assert ">Finance scheduler (Lightwork)</option>" in page.text
    assert ">Content &amp; UX-Writing Specialist (AI)</option>" in page.text
    assert ">pe_content_writing-0</option>" not in page.text and "c4c4c4c4</option>" not in page.text


def _card(world, goal_id):
    from maverick.approval_cards import build_approval_card, encode_approval_detail
    from maverick.logging_config import reset_goal_context, set_goal_context

    card = build_approval_card(
        action="code_exec", summary="Run one Python script and its declared tool calls.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"code": "print(1)"}, parameter_summary=["Runs this exact script once."],
        actor=OTHER, workspace="local", role="operator", authority_versions={}, input_versions={},
        credential_versions={}, budget={}, expires_at=time.time() + 300, known_effects=["The script runs once."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=True)
    token = set_goal_context(goal_id=goal_id)
    try:
        return world.create_approval("code_exec", requested_by=OTHER, detail=encode_approval_detail(card))
    finally:
        reset_goal_context(token)


def test_approval_history_names_the_decider_and_the_action(known, monkeypatch, tmp_path):
    from maverick.world_model import WorldModel
    from maverick_dashboard import api, auth

    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(api, "_world", lambda: world)
    monkeypatch.setattr(api, "_supervisor", lambda _: OTHER)
    monkeypatch.setattr(api, "require_permission", lambda *_: None)
    monkeypatch.setattr(auth, "can_access_goal", lambda *_: True)
    goal = world.create_goal("Task", owner=OTHER)
    approval = _card(world, goal)
    assert world.decide_approval(approval, "denied", decided_by=GOOGLE)
    (row,) = api.requested_approval_history(_request(OTHER))["items"]
    assert row["decided_by_name"] == "dana@northwind.example"
    assert row["action"] == "Run one Python script and its declared tool calls"
    assert "code_exec" not in json.dumps({key: row[key] for key in ("action", "decided_by_name", "summary")})
    world.close()


def test_the_activity_log_names_a_person_actor_and_record_types_in_words(known, monkeypatch, tmp_path):
    # Live: the "Agent or specialist" filter listed "User:owner@..." and rows
    # read "Record type settings_catalog_request".
    import re

    from fastapi.testclient import TestClient
    from maverick import audit, world_model
    from maverick_dashboard.audit_actions_api import value_text

    assert value_text("record_type", "settings_catalog_request") == "Settings catalog request"
    from maverick_dashboard import audit_search

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    assert audit.audit_event("control_plane_action", agent="dashboard", action="settings_saved", actor=GOOGLE)
    real = audit_search.search_events

    def with_person_actor(*args, **kwargs):
        # A governed record change records the person as its actor.
        result = real(*args, **kwargs)
        return {**result, "agents": {*result["agents"], GOOGLE}}

    monkeypatch.setattr(audit_search, "search_events", with_person_actor)
    from maverick_dashboard.app import app

    page = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get("/audit")
    assert page.status_code == 200, page.text[:500]
    agents = re.search(r'<select id="aud-agent".*?</select>', page.text, re.DOTALL).group(0)
    assert ">dana@northwind.example</option>" in agents and "User:" not in agents
