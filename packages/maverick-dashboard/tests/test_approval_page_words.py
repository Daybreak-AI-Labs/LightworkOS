"""The Approvals page and My work say what will happen and what is waiting.

* A card shows the exact command to the people allowed to read it; hashes and
  fingerprints sit under Technical details; spending is a sentence.
* The summary never says "All clear" while a request is waiting, even one the
  viewer can't open, and only links to Content access when it is turned on.
* My work never says a request is waiting on you when you can't open it.
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


def _hero(html):
    start = html.index("Current state")
    return _visible(html[start:start + 1500])


# --------------------------------------------------------------- what happens

def test_the_card_shows_the_exact_command_to_the_person_who_may_read_it(env, monkeypatch):
    client, world = env
    approval_id = _shell_approval(world)
    _as(monkeypatch, SAM)
    page = client.get("/approvals").text
    card = page[page.index(f'id="approval-{approval_id}"'):]
    card = card[:card.index("</article>")]
    assert "Command it will run" in card
    assert "mkdir -p archive &amp;&amp; echo moved &gt; archive/README.txt" in card
    assert "SHA-256" not in _visible(card)
    technical = card.index("Technical details")
    assert "5ac93412" not in card[:technical]
    assert "5ac93412" in card[technical:]
    spending = re.search(r"<dt>Spending</dt><dd>(.*?)</dd>", card, re.DOTALL)
    assert spending is not None
    assert "{" not in spending.group(1) and "sha256" not in spending.group(1).lower()
    assert "spending limit still applies" in spending.group(1)


def test_my_work_spending_reads_as_a_sentence(env, monkeypatch):
    client, world = env
    approval_id = _shell_approval(world)
    _as(monkeypatch, SAM)
    page = client.get("/me").text
    row = page[page.index(f"#{approval_id} "):]
    row = row[:row.index("</tr>")]
    assert "{" not in row and "authority_sha256" not in row and "None" not in row
    assert "No separate amount for this step." in _visible(row)
    assert COMMAND not in row


# ----------------------------------------------------------- never all clear

def test_a_private_request_is_never_summarised_as_all_clear(env, monkeypatch):
    client, world = env
    _shell_approval(world)
    _as(monkeypatch, DANA)
    page = client.get("/approvals").text
    hero = _hero(page)
    assert "All clear" not in hero
    assert "1 request is waiting that you can't open here" in hero
    words = _visible(page)
    assert "contain private employee content" not in words
    assert "The person who asked can open and decide their own request." in words
    # Content access is off, so there is no link to a page that would say so.
    assert 'href="/content-access"' not in page
    assert "An installation administrator can turn on" in words


def test_several_private_requests_read_in_the_plural(env, monkeypatch):
    client, world = env
    _shell_approval(world)
    _shell_approval(world)
    _as(monkeypatch, DANA)
    hero = _hero(client.get("/approvals").text)
    assert "2 requests are waiting that you can't open here" in hero


def test_the_content_access_link_appears_only_when_requests_are_on(env, monkeypatch):
    client, world = env
    from maverick_dashboard import content_access

    monkeypatch.setattr(content_access, "enabled", lambda: True)
    _shell_approval(world)
    _as(monkeypatch, DANA)
    page = client.get("/approvals").text
    assert 'href="/content-access"' in page
    assert "An installation administrator can turn on" not in _visible(page)


def test_an_empty_queue_is_still_all_clear(env, monkeypatch):
    client, _world = env
    _as(monkeypatch, DANA)
    hero = _hero(client.get("/approvals").text)
    assert "All clear" in hero


def test_my_work_does_not_say_a_private_request_is_waiting_on_you(env, monkeypatch):
    client, world = env
    approval_id = _shell_approval(world)
    _as(monkeypatch, DANA)
    page = client.get("/me").text
    row = page[page.index(f"#{approval_id} "):]
    row = _visible(row[:row.index("</tr>")])
    assert "The person who asked" in row
    assert not row.rstrip().endswith("You")
    body = client.get("/api/v1/me/work").json()
    assert body["digest"]["counts"]["approvals"] == 0


def test_my_work_says_your_own_request_is_yours_to_decide(env, monkeypatch):
    client, world = env
    approval_id = _shell_approval(world)
    _as(monkeypatch, SAM)
    page = client.get("/me").text
    row = page[page.index(f"#{approval_id} "):]
    row = _visible(row[:row.index("</tr>")])
    assert "You (your own request)" in row
