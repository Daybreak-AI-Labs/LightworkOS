"""The wizard must collect the per-sender allowlist that channels require.

discord/telegram/slack/signal/matrix/email/bluesky/mastodon raise ValueError
without an allowlist, so a wizard that never prompted for one would produce
channels that silently fail to start (server.py logs + continues).
pick_channels collects it.
"""
from __future__ import annotations


def test_pick_channels_collects_discord_allowlist(monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: False)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda msg, choices: ["discord  - Discord"])
    # discord's only _q_text prompt is the allowlist.
    monkeypatch.setattr(wizard, "_q_text", lambda msg, default="": "111, 222")

    channels, _ = wizard.pick_channels("vps")
    assert channels["discord"]["allowed_user_ids"] == ["111", "222"]


def test_pick_channels_voice_collects_optional_callers(monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: False)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda msg, choices: ["voice  - Voice"])
    # voice prompts: provider, phone_number, assistant_id, port, allowed_callers.
    answers = iter(["vapi", "", "", "8770", "+12025550111"])
    monkeypatch.setattr(wizard, "_q_text", lambda msg, default="": next(answers))

    channels, _ = wizard.pick_channels("vps")
    assert channels["voice"]["allowed_callers"] == ["+12025550111"]


def test_pick_channels_voice_collects_provider_specific_api_key(monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: False)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda msg, choices: ["voice  - Voice"])
    # voice prompts: provider, phone_number, assistant_id, port, allowed_callers.
    answers = iter(["retell", "", "", "8770", ""])
    monkeypatch.setattr(wizard, "_q_text", lambda msg, default="": next(answers))

    channels, envs = wizard.pick_channels("vps")

    assert channels["voice"]["api_key"] == "${RETELL_API_KEY}"
    # the chosen provider's key is collected for the secret prompt; the
    # VAPI-only catalog entry does not leak in for non-vapi providers.
    assert "RETELL_API_KEY" in envs
    assert "VAPI_API_KEY" not in envs
    assert "VAPI_WEBHOOK_TOKEN" in envs


def test_pick_channels_no_allowlist_channel_unaffected(monkeypatch):
    """imessage has no allowlist requirement -> no allowed_user_ids key added."""
    from maverick_installer import wizard

    # imessage is experimental, so opt in before it can be selected.
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda msg, choices: ["imessage  - iMessage"])
    monkeypatch.setattr(wizard, "_q_text", lambda msg, default="": "")

    channels, _ = wizard.pick_channels("vps")
    assert "allowed_user_ids" not in channels["imessage"]
    assert channels["imessage"]["enabled"] is True
