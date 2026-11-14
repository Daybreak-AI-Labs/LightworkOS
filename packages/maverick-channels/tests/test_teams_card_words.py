"""A Teams approval card says what will happen in the dashboard's words."""
from __future__ import annotations

import time

import pytest
from maverick.approval_cards import build_approval_card
from maverick.channel_approvals import spending_text
from maverick_channels.teams_cards import approval_card, budget_text

SHELL_BUDGET = {
    "runtime": {"currency": "USD", "external_effect_cost": "unmeasured",
                "authority_sha256": "5ac93412c16f5f3723303a3784b956b2cd9fe81eafd414a6adbc660b6595a5c0"},  # pragma: allowlist secret
    "operation": {"timeout_seconds": None},
}


@pytest.mark.timeout(5)
def test_unclosed_mention_tags_do_not_rescan_the_remaining_message():
    from maverick_channels.teams_cards import strip_mentions_text

    unclosed = "<at>" * 100_000
    assert strip_mentions_text(" <at>Ada</at> " + unclosed + " ") == "Ada " + unclosed
    assert strip_mentions_text("<at>outer <at>inner</at> end</at>") == "outer <at>inner end</at>"


def test_spending_is_the_shared_sentence_not_a_mapping():
    assert budget_text(SHELL_BUDGET) == spending_text(SHELL_BUDGET)
    assert "{" not in budget_text(SHELL_BUDGET) and "sha256" not in budget_text(SHELL_BUDGET).lower()
    assert budget_text({"currency": "USD", "maximum": 2.0}) == "Up to $2.00"
    assert budget_text(None) == "Not stated"


def test_the_command_stays_off_the_shared_room_card():
    command = "mkdir -p archive && echo moved > archive/README.txt"
    card = build_approval_card(
        action="shell", summary="Run a command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": command},
        parameter_summary=["Runs this exact command once; nothing else is approved."],
        actor="user:sam", workspace="local", role="operator", authority_versions={},
        input_versions={}, credential_versions={}, budget=SHELL_BUDGET,
        expires_at=time.time() + 300, known_effects=["Runs one command."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=True,
        display_command=command,
    )
    rendered = str(approval_card({"id": 7, "action": "shell", "risk": "high", "scope": "sandbox:/work"}, card))
    assert command not in rendered
    assert "5ac93412" not in rendered
    assert "The exact command is shown on the Approvals page." in rendered


def test_the_card_says_why_the_approver_gets_it_and_opens_the_exact_card():
    """NOT-1: a reason, the decide-by time and a link to that approval card."""
    card = build_approval_card(
        action="shell", summary="Run a command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": "ls"},
        parameter_summary=["Runs this exact command once; nothing else is approved."],
        actor="user:sam", workspace="local", role="operator", authority_versions={},
        input_versions={}, credential_versions={}, budget=SHELL_BUDGET,
        expires_at=time.time() + 300, known_effects=["Runs one command."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=False,
        display_command="ls",
    )
    rendered = approval_card({"id": 7, "action": "shell", "risk": "high", "scope": "sandbox:/work"}, card,
                             dashboard_url="https://lw.test/")
    text = str(rendered)
    assert "You get this because you are linked to Lightwork as an approver." in text
    assert "Decide by" in text
    opens = [a for a in rendered.get("actions", []) if a.get("type") == "Action.OpenUrl"]
    assert opens and opens[0]["url"] == "https://lw.test/approvals#approval-7"
    # Without a known dashboard address the card still decides in place.
    assert not [a for a in approval_card({"id": 7, "action": "shell", "risk": "high"}, card).get("actions", [])
                if a.get("type") == "Action.OpenUrl"]


def test_untrusted_approval_text_cannot_create_markdown_links():
    from maverick_channels.teams_cards import approval_card

    result = approval_card(
        {"id": 7, "action": "shell", "risk": "high", "detail": "[Open](https://attacker.example)"},
        None,
    )
    values = [block.get("text", "") for block in result["body"]]
    assert r"\[Open\]\(https://attacker.example\)" in values
