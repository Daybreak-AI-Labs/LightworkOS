"""Platform mailer: [email]/env config reuse, header-injection guard, kill
switch, and the injectable transport. See maverick/mailer.py."""
from __future__ import annotations

import pytest
from maverick import mailer


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("EMAIL_USER", "EMAIL_APP_PASSWORD", "EMAIL_SMTP_HOST",
                "EMAIL_SMTP_PORT", "MAVERICK_EMAIL_DISABLE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def _creds(monkeypatch, **extra):
    monkeypatch.setenv("EMAIL_USER", "sender@daybreak.example")
    monkeypatch.setenv("EMAIL_APP_PASSWORD", "app-pw")  # pragma: allowlist secret
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def test_unconfigured_by_default():
    assert mailer.configured() is False
    with pytest.raises(mailer.MailerError, match="no sending account"):
        mailer.send("to@x.co", "hi", "body")


def test_env_credentials_configure_it(monkeypatch):
    _creds(monkeypatch)
    assert mailer.configured() is True


def test_config_table_credentials_configure_it(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {
        "email": {"user": "sender@daybreak.example",
                  "app_password": "pw",  # pragma: allowlist secret
                  "smtp_host": "mail.example", "smtp_port": 587}})
    assert mailer.configured() is True
    seen = {}

    def transport(host, port, user, pw, msg):
        seen.update(host=host, port=port, user=user, to=msg["To"])
    mailer.send("to@x.co", "hi", "body", transport=transport)
    assert seen == {"host": "mail.example", "port": 587,
                    "user": "sender@daybreak.example", "to": "to@x.co"}


def test_kill_switch_wins(monkeypatch):
    _creds(monkeypatch)
    monkeypatch.setenv("MAVERICK_EMAIL_DISABLE", "1")
    assert mailer.configured() is False
    with pytest.raises(mailer.MailerError, match="disabled"):
        mailer.send("to@x.co", "hi", "body", transport=lambda *a: None)


def test_header_injection_blocked(monkeypatch):
    _creds(monkeypatch)
    boom = []
    for to, subject, field in (("v@x.co\nBcc: evil@x.co", "hi", "to"),
                               ("v@x.co", "hi\r\nBcc: evil@x.co", "subject")):
        # Refused before any effect: the typed "not sent" outcome.
        with pytest.raises(mailer.MailerNotSent, match=f"Invalid email {field}"):
            mailer.send(to, subject, "b", transport=lambda *a: boom.append(1))
    assert not boom                       # transport never reached


def test_smtp_failure_surfaces_as_mailer_error(monkeypatch):
    _creds(monkeypatch)

    def transport(*a):
        raise ConnectionRefusedError("nope")
    with pytest.raises(mailer.MailerError, match=r"Email sending failed \(ConnectionRefusedError\)") as caught:
        mailer.send("to@x.co", "hi", "body", transport=transport)
    assert "nope" not in str(caught.value)  # provider detail is not echoed


def test_message_content(monkeypatch):
    _creds(monkeypatch)
    got = {}

    def transport(host, port, user, pw, msg):
        got["msg"] = msg
    mailer.send("to@x.co", "Subject line", "the body\n", transport=transport)
    msg = got["msg"]
    assert msg["From"] == "sender@daybreak.example"
    assert msg["Subject"] == "Subject line"
    assert "the body" in msg.get_content()


@pytest.mark.parametrize("port", ["465", "587"])
def test_smtp_verifies_the_server_certificate_before_login(monkeypatch, port):
    # smtplib's own default context (no `context=`) skips certificate and host
    # checks, so the app password would go to any server on the path.
    import smtplib
    import ssl
    _creds(monkeypatch, EMAIL_SMTP_HOST="mail.example", EMAIL_SMTP_PORT=port)
    contexts = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context=None):
            contexts.append(context)

        def login(self, user, password):
            assert len(contexts) == 1, "logged in before TLS was set up"

        def send_message(self, message):
            return {}

    class FakeSMTPSSL(FakeSMTP):
        def __init__(self, host, port, timeout=None, context=None):
            contexts.append(context)

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTPSSL)
    mailer.send("to@x.co", "hi", "body")
    (context,) = contexts
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_kill_switch_holds_on_unreadable_config_and_true_env(monkeypatch):
    _creds(monkeypatch)
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "config_source_errors", lambda **_k: {"config.toml": "bad"})
    assert mailer.sending_disabled() is True
    assert mailer.unavailable_reason() == "configuration unreadable"
    with pytest.raises(mailer.MailerNotSent, match="configuration unreadable"):
        mailer.send("to@x.co", "hi", "body", transport=lambda *a: None)
    monkeypatch.setattr(cfg, "config_source_errors", lambda **_k: {})
    monkeypatch.setenv("MAVERICK_EMAIL_DISABLE", "true")
    assert mailer.sending_disabled() is True
    monkeypatch.setattr(cfg, "config_source_errors", lambda **_k: {"config.toml": "bad"})
    assert mailer.unavailable_reason() == "sending disabled"
    monkeypatch.setattr(cfg, "config_source_errors", lambda **_k: {})
    monkeypatch.setenv("MAVERICK_EMAIL_DISABLE", "0")
    assert mailer.sending_disabled() is False


def test_send_refuses_more_than_one_recipient(monkeypatch):
    _creds(monkeypatch)
    sent = []
    with pytest.raises(mailer.MailerNotSent, match="single recipient"):
        mailer.send("victim@x.com, attacker@y.com", "hi", "body",
                    transport=lambda *a: sent.append(a))
    assert sent == []
