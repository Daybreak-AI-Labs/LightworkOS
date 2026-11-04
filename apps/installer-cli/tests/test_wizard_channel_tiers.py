"""pick_channels must be honest about channel maturity.

Production channels (telegram/discord/slack/... — fully working from a
wizard-only setup) are offered by default. Experimental scaffolds
(whatsapp/sms/imessage) need a Twilio account + public webhook or macOS +
Full Disk Access, so picking them in the flat checkbox led to a runtime
dead end. They're now gated behind an explicit confirm and labelled
"[experimental]" when shown.
"""
from __future__ import annotations


def _capture_choices(monkeypatch, *, show_experimental: bool) -> list[str]:
    """Drive pick_channels, answer the experimental gate, return the
    channel choices the checkbox was offered (and pick nothing)."""
    from maverick_installer import wizard

    seen: list[str] = []

    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: show_experimental)

    def fake_checkbox(msg, choices):
        seen.extend(choices)
        return []

    monkeypatch.setattr(wizard, "_q_checkbox", fake_checkbox)
    wizard.pick_channels("vps")
    return seen


def _ids(choices: list[str]) -> set[str]:
    return {c.split()[0] for c in choices}


def test_production_channels_offered_by_default(monkeypatch):
    choices = _capture_choices(monkeypatch, show_experimental=False)
    ids = _ids(choices)
    # A representative set of fully-implemented channels is present.
    for ch in ("telegram", "discord", "slack", "signal", "email", "voice"):
        assert ch in ids, f"{ch} should be offered by default"


def test_experimental_channels_hidden_by_default(monkeypatch):
    choices = _capture_choices(monkeypatch, show_experimental=False)
    ids = _ids(choices)
    for ch in ("whatsapp", "whatsapp_cloud", "sms", "imessage", "threads", "rcs"):
        assert ch not in ids, f"{ch} must not be offered unless opted in"


def test_experimental_channels_shown_and_marked_when_opted_in(monkeypatch):
    choices = _capture_choices(monkeypatch, show_experimental=True)
    ids = _ids(choices)
    for ch in ("whatsapp", "whatsapp_cloud", "sms", "imessage", "threads", "rcs"):
        assert ch in ids, f"{ch} should appear after opting in"
    # Production channels are still there too.
    assert "telegram" in ids
    # Experimental entries are clearly labelled.
    exp = [c for c in choices if c.split()[0] in {"whatsapp", "whatsapp_cloud", "sms", "imessage", "threads", "rcs"}]
    assert exp and all("[experimental]" in c for c in exp)
    # Production channels are not falsely marked experimental.
    prod = [c for c in choices if c.split()[0] not in {"whatsapp", "whatsapp_cloud", "sms", "imessage", "threads", "rcs"}]
    assert all("[experimental]" not in c for c in prod)


def test_experimental_set_matches_catalog(monkeypatch):
    from maverick_installer.wizard import CHANNELS, EXPERIMENTAL_CHANNELS

    catalog_ids = {c[0] for c in CHANNELS}
    assert catalog_ids >= EXPERIMENTAL_CHANNELS
    assert {"whatsapp", "whatsapp_cloud", "sms", "imessage", "threads", "rcs"} == EXPERIMENTAL_CHANNELS
