"""The wizard's "Daily summary and chat approvals" step: off unless asked,
writes [my_work] / [notifications.email] and the Slack extras the kernel
reads back."""
from __future__ import annotations


def _write(cfg_dir, monkeypatch, **extra):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", cfg_dir / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", cfg_dir / "config.toml")
    from maverick_installer.wizard import write_config
    write_config(
        providers=["anthropic"], role_models={},
        channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={}, capabilities={}, **extra,
    )
    return (cfg_dir / "config.toml").read_text()


def test_step_is_listed():
    from maverick_installer import wizard
    assert ("daily_summary", "Daily summary and chat approvals") in wizard.STEPS


def test_default_answer_is_no(monkeypatch):
    from maverick_installer import wizard
    defaults = []
    monkeypatch.setattr(wizard, "_q_confirm", lambda m, default=True: defaults.append(default) or default)
    assert wizard.pick_daily_summary({}) == ({}, {}, {}, [])
    assert defaults == [False]


def test_summary_with_email_and_slack_extras(monkeypatch):
    from maverick_installer import wizard
    answers = iter([True, True, True, True])
    texts = iter(["7", "smtp.example.com", "587", "Lightwork <lw@example.com>", "C0ABC"])
    monkeypatch.setattr(wizard, "_q_confirm", lambda m, default=True: next(answers))
    monkeypatch.setattr(wizard, "_q_text", lambda m, default="": next(texts))
    my_work, mail, slack, envs = wizard.pick_daily_summary({"slack": {"enabled": True}})
    assert my_work == {"digest_enable": True, "digest_hour": 7}
    assert mail["host"] == "smtp.example.com" and mail["password"] == "${MAVERICK_SMTP_PASSWORD}"
    assert slack == {"approvals_channel": "C0ABC", "signing_secret": "${SLACK_SIGNING_SECRET}"}
    assert envs == ["MAVERICK_SMTP_USER", "MAVERICK_SMTP_PASSWORD", "SLACK_SIGNING_SECRET"]


def test_written_config_is_read_back_by_the_kernel(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    text = _write(tmp_path, monkeypatch,
                  my_work={"digest_enable": True, "digest_hour": 7},
                  notifications_email={"host": "smtp.example.com", "port": 587, "tls": "starttls",
                                       "from_address": "lw@example.com"})
    assert "[my_work]" in text and "[notifications.email]" in text
    from maverick import config
    config.reset_config_cache()
    try:
        section = config.get_my_work()
        assert section["digest_enable"] is True and section["digest_hour"] == 7
        from maverick.notifications import _email_config
        mail = _email_config()
        assert mail["host"] == "smtp.example.com" and mail["port"] == 587
    finally:
        config.reset_config_cache()


def test_declined_writes_nothing(tmp_path, monkeypatch):
    text = _write(tmp_path, monkeypatch, my_work={}, notifications_email={})
    assert "[my_work]" not in text and "[notifications.email]" not in text


def _email_answers(monkeypatch, port: str, sender: str):
    from maverick_installer import wizard
    answers = iter([True, True])
    texts = iter(["8", "smtp.example.com", port, sender])
    monkeypatch.setattr(wizard, "_q_confirm", lambda m, default=True: next(answers))
    monkeypatch.setattr(wizard, "_q_text", lambda m, default="": next(texts))
    return wizard.pick_daily_summary({})


def test_port_465_uses_implicit_tls(monkeypatch):
    # The step always wrote STARTTLS, which cannot talk to a port-465 server:
    # TLS starts with the first byte there.
    _, mail, _, _ = _email_answers(monkeypatch, "465", "lw@example.com")
    assert mail["port"] == 465 and mail["tls"] == "ssl"
    _, mail, _, _ = _email_answers(monkeypatch, "587", "lw@example.com")
    assert mail["port"] == 587 and mail["tls"] == "starttls"


def test_a_missing_sender_leaves_email_off(monkeypatch, capsys):
    # Without a sender the kernel ignores this server and falls back to the
    # platform mailer, so the answers only looked saved.
    _, mail, _, envs = _email_answers(monkeypatch, "587", "")
    assert mail == {} and envs == []
    assert "need a sender address" in capsys.readouterr().out
