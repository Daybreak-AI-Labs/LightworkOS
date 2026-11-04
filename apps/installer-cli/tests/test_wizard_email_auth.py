"""Email setup cannot silently enable unauthenticated inbound work."""
from __future__ import annotations


def test_email_step_saves_the_incoming_sender_check_server(monkeypatch):
    from maverick_installer import wizard

    answers = iter(["imap.example.com", "smtp.example.com", "465", "mx.example.com"])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(answers))
    cfg = wizard._channel_base_cfg("email", set())
    assert cfg["enabled"] is True
    assert cfg["trusted_authserv_id"] == "mx.example.com"


def test_email_step_leaves_channel_off_until_sender_check_is_set(monkeypatch):
    from maverick_installer import wizard

    answers = iter(["imap.example.com", "smtp.example.com", "465", ""])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(answers))
    cfg = wizard._channel_base_cfg("email", set())
    assert cfg["enabled"] is False
    assert "trusted_authserv_id" not in cfg
