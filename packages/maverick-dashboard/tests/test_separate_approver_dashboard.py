"""A second person approves high-risk actions when one is available: who
counts as another approver, and what the Approvals page, the API, Teams, the
task page and My work say and do about it.

An eligible approver is someone who could decide the request now by the rules
each surface already enforces: on the Approvals page, a person holding
``operate`` in this workspace who can open the request (its owner, or a
current, reviewed read grant for exactly this card); in Slack or Teams, when
approval cards are posted there, a linked person holding ``operate``. A
deprovisioned person never counts.
"""
from __future__ import annotations

import html
import re
import time

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
SAM = "user:sam.lee@northwind.example"          # the employee who asked
DANA = "user:dana.admin@northwind.example"      # their manager
VERA = "user:vera.viewer@northwind.example"     # can read, can't decide
GONE = "user:gone@northwind.example"            # deprovisioned
ROLES = {SAM: "operator", DANA: "operator", VERA: "viewer", GONE: "operator"}
ANOTHER = "Another approver is available, so someone else must approve this."
ALWAYS = "You asked for this, so someone else must approve it."


@pytest.fixture
def env(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("")
    for name in ("MAVERICK_SEPARATE_APPROVER", "MAVERICK_ALLOW_SELF_APPROVAL",
                 "MAVERICK_APPROVALS_REQUIRED", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = WorldModel(tmp_path / "world.db")
    from maverick_dashboard.app import app

    yield TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN), world
    world.close()
    config.reset_config_cache()


def _config(tmp_path, text):
    from maverick import config

    (tmp_path / "config.toml").write_text(text)
    config.reset_config_cache()


def _roles(monkeypatch):
    from maverick_dashboard import auth, rbac, scim_groups

    monkeypatch.setattr(auth, "role_for_principal", lambda p: ROLES.get(p, "operator"))
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p: ROLES.get(p, "operator"))
    monkeypatch.setattr(rbac, "list_users", lambda: dict(ROLES))
    monkeypatch.setattr(scim_groups, "active_for_principal", lambda p: p != GONE)


def _as(monkeypatch, principal):
    from maverick_dashboard import api, auth

    _roles(monkeypatch)
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: principal)
    monkeypatch.setattr(api, "_supervisor", lambda request: principal)


def _others(monkeypatch, people):
    from maverick_dashboard import approval_decisions

    monkeypatch.setattr(approval_decisions, "other_eligible_approvers",
                        lambda world, approval, requester: list(people))


def _grants(monkeypatch, world, approval_id, readers):
    """Current, reviewed read grants for exactly this card."""
    from maverick_dashboard import content_access

    resource = content_access.approval_resource(world.get_approval(approval_id), world)
    rows = [{"id": f"ECA-{n}", "tenant": content_access.tenant(), "requester": reader,
             "owner": resource["owner"], "resource_kind": "approval",
             "resource_id": resource["resource_id"],
             "resource_revision": resource["resource_revision"], "status": "approved",
             "expires_at": time.time() + 600, "purpose": "approval_review",
             "reviewed_by": "user:admin"} for n, reader in enumerate(readers)]
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access, "_reviewer_current", lambda grant: True)
    monkeypatch.setattr(content_access.STORE, "list", lambda: list(rows))


def _approval(world, *, risk="high", required=1, owner=SAM):
    from maverick.approval_cards import build_approval_card, encode_approval_detail
    from maverick.logging_config import reset_goal_context, set_goal_context

    card = build_approval_card(
        action="shell", summary="Run one command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": "ls"},
        parameter_summary=["Runs the command once."], actor=owner, workspace="local",
        role="operator", authority_versions={}, input_versions={}, credential_versions={},
        budget={}, expires_at=time.time() + 600, known_effects=["Runs one command."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=True,
    )
    goal_id = world.create_goal("Archive the stale drafts", owner=owner)
    tokens = set_goal_context(goal_id=goal_id)
    try:
        approval_id = world.create_approval("shell", risk=risk, scope="sandbox:/work",
                                            detail=encode_approval_detail(card),
                                            approvals_required=required, requested_by=owner)
    finally:
        reset_goal_context(tokens)
    return approval_id, goal_id, {"X-Lightwork-Approval-Binding": card["binding_sha256"]}


def _card_markup(page, approval_id):
    start = re.search(rf'<article class="approval-item"[^>]*data-id="{approval_id}"', page)
    assert start is not None
    card = page[start.start():]
    return card[:card.index("</article>")]


def _approve_button(card):
    button = re.search(r'<button[^>]*data-action="approve"[^>]*>', card)
    assert button is not None
    return html.unescape(button.group(0))


# ------------------------------------------------------- who else can decide

def test_eligible_approvers_can_open_the_request_and_hold_operate(env, monkeypatch):
    from maverick_dashboard.approval_decisions import eligible_approvers, other_eligible_approvers

    _client, world = env
    _roles(monkeypatch)
    approval_id, _goal, _headers = _approval(world)
    _grants(monkeypatch, world, approval_id, [DANA, VERA, GONE])
    approval = world.get_approval(approval_id)
    assert eligible_approvers(world, approval) == {SAM, DANA}
    assert other_eligible_approvers(world, approval, SAM) == [DANA]


def test_with_exceptional_access_off_only_the_requester_can_open_it(env, monkeypatch):
    from maverick_dashboard.approval_decisions import other_eligible_approvers

    _client, world = env
    _roles(monkeypatch)
    approval_id, _goal, _headers = _approval(world)
    assert other_eligible_approvers(world, world.get_approval(approval_id), SAM) == []


def test_a_grant_for_another_card_opens_nothing(env, monkeypatch):
    from maverick_dashboard.approval_decisions import other_eligible_approvers

    _client, world = env
    _roles(monkeypatch)
    approval_id, _goal, _headers = _approval(world)
    other_id, _other_goal, _ = _approval(world)
    _grants(monkeypatch, world, other_id, [DANA])
    assert other_eligible_approvers(world, world.get_approval(approval_id), SAM) == []


def test_linked_chat_approvers_count_where_cards_are_posted(env, monkeypatch):
    from maverick import approval_notify, channel_approvals, channel_identities, teams_identity
    from maverick_dashboard.approval_decisions import other_eligible_approvers

    _client, world = env
    _roles(monkeypatch)
    approval_id, _goal, _headers = _approval(world)
    approval = world.get_approval(approval_id)
    monkeypatch.setattr(channel_identities, "all_links", lambda: {
        DANA: [{"channel": "slack", "external_id": "U2", "linked_at": 1.0}],
        VERA: [{"channel": "slack", "external_id": "U3", "linked_at": 1.0}],
    })
    monkeypatch.setattr(teams_identity, "approver_links", lambda: [
        {"teams_id": "aad-9", "principal": GONE}, {"teams_id": "aad-8", "principal": SAM}])
    monkeypatch.setattr(channel_approvals, "slack_announcements_configured", lambda: False)
    monkeypatch.setattr(approval_notify, "teams_approvals_enabled", lambda cfg=None: False)
    assert other_eligible_approvers(world, approval, SAM) == []
    monkeypatch.setattr(channel_approvals, "slack_announcements_configured", lambda: True)
    assert other_eligible_approvers(world, approval, SAM) == [DANA]
    monkeypatch.setattr(teams_identity, "approver_links", lambda: [
        {"teams_id": "aad-7", "principal": "user:tom@northwind.example"}])
    monkeypatch.setattr(approval_notify, "teams_approvals_enabled", lambda cfg=None: True)
    assert other_eligible_approvers(world, approval, SAM) == [DANA, "user:tom@northwind.example"]


def test_with_company_sign_in_chat_links_count_nobody(env, monkeypatch):
    # With OIDC a chat decision resolves through the sign-in bridge, not these
    # links, so they can't show that anyone else could decide.
    from maverick import channel_approvals, channel_identities, oidc
    from maverick_dashboard.approval_decisions import other_eligible_approvers

    _client, world = env
    _roles(monkeypatch)
    approval_id, _goal, _headers = _approval(world)
    monkeypatch.setattr(channel_identities, "all_links", lambda: {
        DANA: [{"channel": "slack", "external_id": "U2", "linked_at": 1.0}]})
    monkeypatch.setattr(channel_approvals, "slack_announcements_configured", lambda: True)
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: True)
    assert other_eligible_approvers(world, world.get_approval(approval_id), SAM) == []


def test_protected_settings_requests_never_count_chat_approvers(env, monkeypatch):
    from maverick import channel_approvals, channel_identities
    from maverick_dashboard.approval_decisions import eligible_approvers

    _client, world = env
    _roles(monkeypatch)
    approval_id = world.create_approval("settings.change", risk="high", requested_by=SAM,
                                        provenance="settings_quorum")
    monkeypatch.setattr(channel_identities, "all_links", lambda: {
        DANA: [{"channel": "slack", "external_id": "U2", "linked_at": 1.0}]})
    monkeypatch.setattr(channel_approvals, "slack_announcements_configured", lambda: True)
    assert DANA not in eligible_approvers(world, world.get_approval(approval_id))


# ---------------------------------------------------------- the Approvals page

def test_the_requester_cannot_approve_when_another_approver_is_available(env, monkeypatch):
    client, world = env
    approval_id, _goal, headers = _approval(world)
    _as(monkeypatch, SAM)
    _others(monkeypatch, [DANA])

    card = _card_markup(client.get("/approvals").text, approval_id)
    button = _approve_button(card)
    assert "disabled" in button and f'title="{ANOTHER}"' in button
    # Screen readers hear the reason with the disabled button.
    assert f'aria-describedby="approval-own-note-{approval_id}"' in button
    assert f'id="approval-own-note-{approval_id}">{ANOTHER}' in html.unescape(card)

    response = client.post(f"/api/v1/approvals/{approval_id}/approve",
                           json={"acknowledged": True}, headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"] == ANOTHER
    assert world.get_approval(approval_id).status == "pending"

    state = client.get(f"/api/v1/approvals/{approval_id}/state").json()
    assert state["requested_by_you"] is True
    assert state["self_approval_counts"] is False
    assert state["own_request_note"] == ANOTHER


def test_a_refused_self_approval_records_no_confirmation(env, monkeypatch):
    from maverick import audit

    client, world = env
    approval_id, _goal, headers = _approval(world)
    _as(monkeypatch, SAM)
    _others(monkeypatch, [DANA])
    seen = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **fields: seen.append(fields) or True)
    response = client.post(f"/api/v1/approvals/{approval_id}/approve",
                           json={"acknowledged": True}, headers=headers)
    assert response.status_code == 403
    assert not [f for f in seen if f.get("action") == "approval_confirmation"]


def test_the_other_approver_can_approve(env, monkeypatch):
    client, world = env
    approval_id, _goal, headers = _approval(world)
    _as(monkeypatch, DANA)
    _others(monkeypatch, [DANA])
    monkeypatch.setattr("maverick_dashboard.content_access.can_read_approval",
                        lambda request, approval, world=None: True)
    response = client.post(f"/api/v1/approvals/{approval_id}/approve",
                           json={"acknowledged": True}, headers=headers)
    assert response.status_code == 204, response.text
    assert world.get_approval(approval_id).decided_by == DANA


def test_a_requester_who_is_the_only_approver_may_approve_their_own(env, monkeypatch):
    client, world = env
    approval_id, _goal, headers = _approval(world)
    _as(monkeypatch, SAM)
    _others(monkeypatch, [])

    card = _card_markup(client.get("/approvals").text, approval_id)
    assert "disabled" not in _approve_button(card)
    assert 'data-own-request="yes"' in card
    state = client.get(f"/api/v1/approvals/{approval_id}/state").json()
    assert state["self_approval_counts"] is True and state["own_request_note"] == ""
    response = client.post(f"/api/v1/approvals/{approval_id}/approve",
                           json={"acknowledged": True}, headers=headers)
    assert response.status_code == 204, response.text


def test_always_keeps_the_requester_from_approving_even_alone(env, monkeypatch, tmp_path):
    client, world = env
    _config(tmp_path, '[approval]\nseparate_approver = "always"\n')
    approval_id, _goal, headers = _approval(world, risk="critical")
    _as(monkeypatch, SAM)
    _others(monkeypatch, [])

    card = _card_markup(client.get("/approvals").text, approval_id)
    assert f'title="{ALWAYS}"' in _approve_button(card)
    response = client.post(f"/api/v1/approvals/{approval_id}/approve",
                           json={"acknowledged": True, "confirmation": "approve"}, headers=headers)
    assert response.status_code == 403 and response.json()["detail"] == ALWAYS


def test_never_lets_the_requester_approve_with_others_available(env, monkeypatch, tmp_path):
    client, world = env
    _config(tmp_path, '[approval]\nseparate_approver = "never"\n')
    approval_id, _goal, headers = _approval(world)
    _as(monkeypatch, SAM)
    _others(monkeypatch, [DANA])
    assert "disabled" not in _approve_button(_card_markup(client.get("/approvals").text, approval_id))
    response = client.post(f"/api/v1/approvals/{approval_id}/approve",
                           json={"acknowledged": True}, headers=headers)
    assert response.status_code == 204, response.text


def test_two_person_approval_keeps_its_own_words(env, monkeypatch):
    client, world = env
    monkeypatch.setenv("MAVERICK_ALLOW_SELF_APPROVAL", "0")
    approval_id, _goal, _headers = _approval(world, required=2)
    _as(monkeypatch, SAM)
    _others(monkeypatch, [DANA])
    card = _card_markup(client.get("/approvals").text, approval_id)
    assert 'title="You asked for this, so other people must approve it."' in _approve_button(card)


# ---------------------------------------------------------------------- Teams

def test_teams_obeys_the_rule(env, monkeypatch):
    from maverick_dashboard.approval_decisions import ApprovalDecisionRefused, decide_from_channel

    _client, world = env
    approval_id, _goal, headers = _approval(world)
    _roles(monkeypatch)
    _others(monkeypatch, [DANA])
    binding = headers["X-Lightwork-Approval-Binding"]
    with pytest.raises(ApprovalDecisionRefused) as refused:
        decide_from_channel(approval_id=approval_id, status="approved", principal=SAM,
                            binding=binding, channel="teams", channel_user="aad-1",
                            confirmed=True, acknowledgement={"acknowledged": True}, world=world)
    assert refused.value.status_code == 403 and refused.value.detail == ANOTHER
    assert world.get_approval(approval_id).status == "pending"
    result = decide_from_channel(approval_id=approval_id, status="approved", principal=DANA,
                                 binding=binding, channel="teams", channel_user="aad-2",
                                 confirmed=True, acknowledgement={"acknowledged": True},
                                 world=world)
    assert result["status"] == "approved" and result["decided_by"] == DANA


# ------------------------------------------------- the task page and My work

def test_the_task_page_says_someone_else_must_approve(env, monkeypatch):
    client, world = env
    approval_id, goal_id, _headers = _approval(world)
    _as(monkeypatch, SAM)
    _others(monkeypatch, [DANA])
    (item,) = client.get(f"/api/v1/goals/{goal_id}/approval-wait").json()["waiting"]
    assert item["id"] == approval_id and item["who"] == "others" and item["remaining"] == 1
    _others(monkeypatch, [])
    (item,) = client.get(f"/api/v1/goals/{goal_id}/approval-wait").json()["waiting"]
    assert item["who"] == "you"


def test_my_work_says_other_people_must_decide(env, monkeypatch):
    client, world = env
    approval_id, _goal, _headers = _approval(world)
    _as(monkeypatch, SAM)
    _others(monkeypatch, [DANA])
    body = client.get("/api/v1/me/work").json()
    (row,) = [r for r in body["digest"]["approvals"] if r["id"] == approval_id]
    assert row["waiting_on"] == "others"
    assert body["digest"]["counts"]["approvals"] == 0
