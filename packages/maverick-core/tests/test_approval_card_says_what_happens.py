"""An approval card says what will happen, in words a person can check.

The exact command a shell step will run is bound into its card, so the person
allowed to read the card sees it (with any secret masked); fingerprints stay
technical detail; the spending line is a sentence, never a raw mapping; and
the text sent to shared chat rooms and the daily summary stays content-minimal
-- it points to the Approvals page instead of carrying the command.
"""
from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick.approval_cards import (
    ApprovalCardError,
    build_approval_card,
    encode_approval_detail,
    validate_approval_card,
)

COMMAND = "mkdir -p archive && echo moved > archive/README.txt"
SHELL_BUDGET = {
    "runtime": {"currency": "USD", "external_effect_cost": "unmeasured",
                "authority_sha256": "5ac93412c16f5f3723303a3784b956b2cd9fe81eafd414a6adbc660b6595a5c0"},  # pragma: allowlist secret
    "operation": {"timeout_seconds": None},
}


def _card(**overrides):
    values = dict(
        action="shell", summary="Run a command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": COMMAND},
        parameter_summary=["Runs this exact command once; nothing else is approved."],
        actor="user:sam", workspace="local", role="operator", authority_versions={},
        input_versions={}, credential_versions={}, budget=SHELL_BUDGET,
        expires_at=time.time() + 300, known_effects=["Runs one command."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=True,
    )
    values.update(overrides)
    return build_approval_card(**values)


def test_the_exact_command_is_bound_into_the_card():
    card = _card(display_command=COMMAND)
    assert card["display"] == {"command": COMMAND}
    assert validate_approval_card(card)["display"]["command"] == COMMAND
    tampered = dict(card, display={"command": "rm -rf /"})
    with pytest.raises(ApprovalCardError):
        validate_approval_card(tampered)


def test_multi_line_commands_keep_their_lines():
    script = "cd archive\nls -la\n"
    assert _card(display_command=script)["display"]["command"] == script


def test_a_secret_in_the_command_is_masked_on_the_card():
    secret = "sk-ant-api03-" + "A" * 80  # pragma: allowlist secret
    card = _card(display_command=f"curl -H 'x-api-key: {secret}' https://example.test")
    assert secret not in card["display"]["command"]
    assert "REDACTED" in card["display"]["command"]
    validate_approval_card(card)


def test_cards_without_a_command_still_validate_and_unknown_fields_do_not():
    validate_approval_card(_card())
    card = _card(display_command=COMMAND)
    widened = dict(card, display={"command": COMMAND, "note": "x"})
    with pytest.raises(ApprovalCardError):
        validate_approval_card(widened)
    with pytest.raises(ApprovalCardError):
        _card(display_command="x" * 5000)


def test_spending_reads_as_a_sentence_never_a_mapping():
    from maverick.channel_approvals import spending_text

    text = spending_text(SHELL_BUDGET)
    assert "{" not in text and "sha256" not in text.lower() and "None" not in text
    assert text == ("No separate amount for this step. The task's spending limit still applies, "
                    "and costs outside Lightwork aren't measured.")
    assert spending_text({"currency": "USD", "maximum": 2.0}) == "Up to $2.00"
    assert spending_text({"state": "governed_again_at_execution"}) == "Checked again when it runs"
    assert spending_text({"runtime": {"currency": "USD", "maximum": 1.5}, "operation": {"state": "not_applicable"}}) == "Up to $1.50"
    assert spending_text({"weird": {"nested": [1, 2]}}) == "No separate amount for this step."
    assert spending_text({}) == "Not stated"


def test_shared_rooms_get_the_plain_card_without_the_command(tmp_path, monkeypatch):
    from maverick import world_model
    from maverick.channel_approvals import card_content
    from maverick.world_model import WorldModel

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = WorldModel(tmp_path / "world.db")
    approval_id = world.create_approval("shell", risk="high", scope="sandbox:/work",
                                        detail=encode_approval_detail(_card(display_command=COMMAND)))
    content = card_content(world.get_approval(approval_id))
    assert COMMAND not in str(content)
    assert "The exact command is shown on the Approvals page." in content["what_it_will_do"]
    assert content["spending"].startswith("No separate amount")


def test_the_shell_step_asks_about_its_exact_command_in_plain_words(tmp_path, monkeypatch):
    import maverick.safety.consent as consent
    from maverick.sandbox import LocalBackend
    from maverick.tools.shell import shell

    seen = {}

    def approve(*_args, **kwargs):
        seen.update(kwargs)
        return SimpleNamespace(granted=True, source="dashboard", actor="user:reviewer")

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(consent, "require_consent", approve)
    out = shell(LocalBackend(workdir=Path(tmp_path))).fn({"cmd": "echo plain-words"})
    assert "plain-words" in out
    card = seen["approval_card"]
    assert card["display"]["command"] == "echo plain-words"
    words = " ".join([card["summary"], *card["parameters"]["summary"],
                      *card["consequences"]["known_effects"], card["preview"]["before"],
                      card["preview"]["after"]])
    assert "SHA-256" not in words and "character" not in words and "reviewed" not in words
    assert seen["detail"] == "Run a command in the sandbox."
