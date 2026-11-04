"""A designated approver sees every request waiting, even a private one.

A request from a colleague's private task shows as a card with only who
asked, the action and its risk, the agent or specialist, the deadline and why
the viewer sees it. Its summary, target, command and fingerprints stay
behind the exact-read flow, and the card has no decision buttons. Someone the
rules let decide it in Slack or Teams is told so, and it counts as waiting
on them on the badge and on My work.
"""
from __future__ import annotations

import html
import re
import time

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
COMMAND = "mkdir -p archive && echo moved > archive/README.txt"
SAM = "user:sam.lee@northwind.example"
DANA = "user:dana.admin@northwind.example"
SHELL_BUDGET = {
    "runtime": {"currency": "USD", "external_effect_cost": "unmeasured",
                "authority_sha256": "5ac93412c16f5f3723303a3784b956b2cd9fe81eafd414a6adbc660b6595a5c0"},  # pragma: allowlist secret
    "operation": {"timeout_seconds": None},
}


@pytest.fixture
def env(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("")
    config.reset_config_cache()
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = WorldModel(tmp_path / "world.db")
    from maverick_dashboard.app import app

    yield TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN), world
    world.close()
    config.reset_config_cache()


def _as(monkeypatch, principal, role="operator"):
    from maverick_dashboard import api, auth, rbac

    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: principal)
    monkeypatch.setattr(auth, "role_for_principal", lambda p: role)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p: role)
    monkeypatch.setattr(rbac, "list_users", lambda: {principal: role})
    monkeypatch.setattr(api, "_supervisor", lambda request: principal)


def _shell_approval(world, *, owner=SAM):
    from maverick.approval_cards import build_approval_card, encode_approval_detail

    card = build_approval_card(
        action="shell", summary="Run a command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": COMMAND, "timeout_seconds": None},
        parameter_summary=["Runs this exact command once; nothing else is approved.",
                           "Time limit: the sandbox's usual limit."],
        actor=owner, workspace="local", role="operator", authority_versions={},
        input_versions={}, credential_versions={}, budget=SHELL_BUDGET,
        expires_at=time.time() + 300, known_effects=["The command runs in the sandbox folder."],
        unresolved_assumptions=[], before="The command has not run.",
        after="The command has run once; its changes stay.", irreversible=True,
        display_command=COMMAND,
    )
    goal_id = world.create_goal("Archive the stale drafts", owner=owner)
    from maverick.logging_config import reset_goal_context, set_goal_context

    tokens = set_goal_context(goal_id=goal_id)
    try:
        approval_id = world.create_approval("shell", risk="high", scope="sandbox:/work",
                                            detail=encode_approval_detail(card), requested_by=owner)
    finally:
        reset_goal_context(tokens)
    return approval_id


def _visible(markup):
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", markup)))


def _card(page, approval_id):
    start = page.index(f'id="approval-{approval_id}"')
    return page[start:page.index("</article>", start)]


def _linked_in_slack(monkeypatch, principal):
    from maverick import channel_approvals, channel_identities

    monkeypatch.setattr(channel_identities, "all_links", lambda: {
        principal: [{"channel": "slack", "external_id": "U2", "linked_at": 1.0}]})
    monkeypatch.setattr(channel_approvals, "slack_announcements_configured", lambda: True)


def test_a_private_request_shows_a_card_with_only_safe_facts(env, monkeypatch):
    client, world = env
    approval_id = _shell_approval(world)
    goal_id = world.get_approval(approval_id).goal_id
    world.set_goal_domain(goal_id, "aero_avionics")
    _as(monkeypatch, DANA)
    page = client.get("/approvals").text
    card = _card(page, approval_id)
    words = _visible(card)
    assert "Shell" in words and "High risk" in words
    assert "Asked by sam.lee@northwind.example" in words
    assert "Specialist Aero avionics" in words
    assert "Decide by" in words and "Not stated" not in words
    assert "Why you see this:" in words and "Operator" in words
    assert "can't open or decide it here" in words
    # Nothing private, and no way to decide from here.
    for secret in (COMMAND, "Archive the stale drafts", "Run a command in the sandbox",
                   "sandbox:/work", "5ac93412"):
        assert secret not in card
    assert 'data-action="approve"' not in card and "<button" not in card
    assert "All clear" not in page


def test_a_task_without_a_specialist_names_the_general_agent(env, monkeypatch):
    client, world = env
    approval_id = _shell_approval(world)
    _as(monkeypatch, DANA)
    words = _visible(_card(client.get("/approvals").text, approval_id))
    assert "Agent Lightwork's general agent" in words


def test_the_api_lists_the_same_safe_facts(env, monkeypatch):
    client, world = env
    approval_id = _shell_approval(world)
    _as(monkeypatch, DANA)
    body = client.get("/api/v1/approvals").json()
    assert body["approvals"] == []
    (row,) = body["private_requests"]
    assert set(row) == {"id", "action", "risk", "risk_label", "requested_by", "worker",
                        "expires_at", "in_chat"}
    assert row["id"] == approval_id and row["in_chat"] is False
    assert COMMAND not in str(row)


def test_someone_who_decides_in_chat_is_told_where_and_counted(env, monkeypatch):
    client, world = env
    approval_id = _shell_approval(world)
    _as(monkeypatch, DANA)
    _linked_in_slack(monkeypatch, DANA)
    page = client.get("/approvals").text
    words = _visible(_card(page, approval_id))
    assert "Waiting on you" in words
    assert "Decide there with the buttons on the card." in words
    hero = _visible(page[page.index("Current state"):][:1500])
    assert "Action needed" in hero and "All clear" not in hero
    assert client.get("/api/v1/approvals/waiting-count").json()["waiting"] == 1
    me = client.get("/me").text
    row = me[me.index(f"#{approval_id} "):]
    assert "You (decide in Slack or Teams)" in _visible(row[:row.index("</tr>")])
    assert client.get("/api/v1/me/work").json()["digest"]["counts"]["approvals"] == 1


def test_without_a_chat_link_the_badge_counts_only_what_waits_on_you(env, monkeypatch):
    client, world = env
    _shell_approval(world)
    _as(monkeypatch, DANA)
    assert client.get("/api/v1/approvals/waiting-count").json()["waiting"] == 0


def test_the_requester_still_sees_the_full_card(env, monkeypatch):
    client, world = env
    approval_id = _shell_approval(world)
    _as(monkeypatch, SAM)
    page = client.get("/approvals").text
    assert "Requests you can't open" not in page
    assert re.search(r'data-action="approve"', _card(page, approval_id))


def test_my_work_never_says_all_clear_beside_a_waiting_request(env, monkeypatch):
    client, world = env
    _shell_approval(world)
    _as(monkeypatch, DANA)
    page = client.get("/me").text
    hero = _visible(page[page.index("Right now"):][:600])
    assert "All clear" not in hero and "Waiting on others" in hero


def test_the_badge_count_stays_linear_in_the_waiting_requests(env, monkeypatch):
    # The badge is read on every page load; with thousands of waiting
    # requests it must not compare each one with every other, nor re-read the
    # chat links once per private request.
    from maverick import world_model
    from maverick_dashboard import approval_decisions

    client, world = env
    for _ in range(40):
        _shell_approval(world)               # Sam's: private to Dana, decided in chat
    for _ in range(40):
        _shell_approval(world, owner=DANA)   # Dana's own: she opens these
    _as(monkeypatch, DANA)
    _linked_in_slack(monkeypatch, DANA)
    compared, link_reads = [], []
    real_eq, real_links = world_model.Approval.__eq__, approval_decisions._chat_approvers

    def eq(self, other):
        compared.append(1)
        return real_eq(self, other)

    def links(approval):
        link_reads.append(approval.id)
        return real_links(approval)

    monkeypatch.setattr(world_model.Approval, "__eq__", eq)
    monkeypatch.setattr(approval_decisions, "_chat_approvers", links)
    assert client.get("/api/v1/approvals/waiting-count").json()["waiting"] == 80
    assert compared == [] and len(link_reads) <= 1
