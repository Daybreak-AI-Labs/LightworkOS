"""The running email channel's Microsoft pin matches the saved settings it was
built from, including the parts the channel reads from the environment."""
from __future__ import annotations

import pytest
from maverick import config, microsoft_mail
from maverick.server import _wire_email

EMAIL = """[channels.email]
enabled = true
email_auth = "microsoft"
imap_host = "outlook.office365.com"
smtp_host = "smtp.office365.com"
smtp_port = 587
imap_user = "bot@corp.com"
smtp_user = "bot@corp.com"
oauth_account = "mail:0123456789abcdef0123456789abcdef"
oauth_tenant = "default"
oauth_principal = "user:admin@corp.com"
"""


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("EMAIL_ALLOWED_USER_IDS", raising=False)
    monkeypatch.delenv("EMAIL_TRUSTED_AUTHSERV_ID", raising=False)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _save(tmp_path, extra=""):
    (tmp_path / "config.toml").write_text(EMAIL + extra, encoding="utf-8")
    config.reset_config_cache()


def _running_channel():
    added = []

    class Server:
        _handle_message = staticmethod(lambda _: None)
        add_channel = staticmethod(added.append)

    _wire_email(Server, config.load_global_config()["channels"]["email"])
    return added[0]


def test_people_and_server_from_the_environment_match_the_saved_settings(isolated, monkeypatch):
    monkeypatch.setenv("EMAIL_ALLOWED_USER_IDS", "Alice@corp.com, bob@corp.com")
    monkeypatch.setenv("EMAIL_TRUSTED_AUTHSERV_ID", "mx.corp.com")
    _save(isolated)
    microsoft_mail._saved_configuration(_running_channel()._mail_cfg)


def test_saved_people_or_server_that_differ_from_the_running_channel_are_refused(isolated, monkeypatch):
    monkeypatch.setenv("EMAIL_ALLOWED_USER_IDS", "alice@corp.com")
    monkeypatch.setenv("EMAIL_TRUSTED_AUTHSERV_ID", "mx.corp.com")
    _save(isolated)
    running = _running_channel()._mail_cfg
    for extra in ('allowed_user_ids = ["mallory@corp.com"]\n', 'trusted_authserv_id = "mx.other.com"\n'):
        _save(isolated, extra)
        with pytest.raises(PermissionError, match="settings changed"):
            microsoft_mail._saved_configuration(running)


def test_saved_people_and_server_match_the_channel_built_from_them(isolated):
    _save(isolated, 'allowed_user_ids = ["alice@corp.com"]\ntrusted_authserv_id = "mx.corp.com"\n')
    microsoft_mail._saved_configuration(_running_channel()._mail_cfg)


def test_xoauth2_greets_the_server_again_after_starttls(monkeypatch):
    # STARTTLS discards the server's EHLO answer. login() greets again on its
    # own; auth() does not, so XOAUTH2 went out before any EHLO in the TLS
    # session and servers that require one refused it ("send hello first").
    import smtplib
    from contextlib import contextmanager

    @contextmanager
    def token(_cfg):
        yield "access-token"  # pragma: allowlist secret

    monkeypatch.setattr(microsoft_mail, "credential", token)
    sent = []
    smtp = smtplib.SMTP()  # not connected: the state right after starttls()
    smtp.helo_resp = smtp.ehlo_resp = None
    monkeypatch.setattr(smtp, "ehlo", lambda name="": sent.append("EHLO") or (250, b"ok"))
    monkeypatch.setattr(smtp, "docmd", lambda cmd, args="": sent.append(cmd) or (235, b"accepted"))
    microsoft_mail.authenticate_smtp(smtp, {"email_auth": "microsoft", "smtp_user": "bot@corp.com"})
    assert sent == ["EHLO", "AUTH"]
