"""The wizard asks where handed-off conversations go and writes the ``[contact_centre]``
keys the kernel reads (``maverick.config.get_contact_centre``). It never asks for or
writes the Zendesk API token or the webhook signing secret."""
from __future__ import annotations

ZENDESK_TOKEN = "tok-WIZARD-SECRET-999"  # pragma: allowlist secret


def _answers(monkeypatch, choice, texts):
    from maverick_installer import wizard

    replies = iter(texts)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, **kw: choice)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(replies))
    return wizard


def test_off_writes_nothing(monkeypatch):
    wizard = _answers(monkeypatch, "off", [])
    assert wizard.pick_contact_centre() == ({}, [])


def test_zendesk_answers_become_the_keys_the_kernel_reads(monkeypatch, tmp_path):
    from maverick import config

    wizard = _answers(monkeypatch, "zendesk", ["acme-support", "agent@acme.example",
                                                "https://lightwork.acme.example"])
    cfg, envs = wizard.pick_contact_centre()
    assert cfg == {"provider": "zendesk", "zendesk_subdomain": "acme-support",
                   "zendesk_email": "agent@acme.example", "dashboard_url": "https://lightwork.acme.example"}
    assert envs == []
    path = tmp_path / "config.toml"
    path.write_text("\n".join(wizard._cfg_table("contact_centre", cfg)) + "\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    config.reset_config_cache()
    try:
        policy = config.get_contact_centre()
        assert policy["provider"] == "zendesk" and policy["zendesk_subdomain"] == "acme-support"
        assert policy["zendesk_email"] == "agent@acme.example" and policy["max_messages"] == 20
    finally:
        config.reset_config_cache()


def test_webhook_answers_are_kept_and_no_secret_is_requested(monkeypatch):
    wizard = _answers(monkeypatch, "webhook", ["https://hooks.acme.example/lightwork", ""])
    assert wizard.pick_contact_centre() == ({"provider": "webhook",
                                             "webhook_url": "https://hooks.acme.example/lightwork"}, [])


def test_unsafe_answers_are_skipped(monkeypatch):
    wizard = _answers(monkeypatch, "zendesk", ["Acme.Support", "agent@acme.example"])
    assert wizard.pick_contact_centre() == ({}, [])
    wizard = _answers(monkeypatch, "webhook", ["http://hooks.acme.example/lightwork"])
    assert wizard.pick_contact_centre() == ({}, [])


def test_the_token_never_reaches_the_config_text(monkeypatch):
    wizard = _answers(monkeypatch, "zendesk", ["acme-support", "agent@acme.example", ""])
    cfg, _envs = wizard.pick_contact_centre()
    rendered = "\n".join(wizard._cfg_table("contact_centre", cfg))
    assert ZENDESK_TOKEN not in rendered
    assert "token" not in rendered.lower()
