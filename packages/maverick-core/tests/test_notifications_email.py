"""The email notification backend: SMTP through a fake server, the secret
provider for the password, the platform-mailer fallback, and notify()."""
from __future__ import annotations

import pytest


class FakeSMTP:
    """Records what a real smtplib.SMTP would have been told."""

    instances: list = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.started_tls = False
        self.login_args = None
        self.sent = []
        self.refuse = False
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        self.started_tls = True

    def login(self, user, password):
        self.login_args = (user, password)

    def send_message(self, message):
        self.sent.append(message)
        return {"x@example.com": (550, b"no")} if self.refuse else {}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    import smtplib

    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_SMTP_PASSWORD", raising=False)
    monkeypatch.delenv("EMAIL_USER", raising=False)
    monkeypatch.delenv("EMAIL_APP_PASSWORD", raising=False)
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    FakeSMTP.instances = []
    config.reset_config_cache()
    yield
    config.reset_config_cache()


CFG = {"email": {"host": "smtp.example.test", "port": 2525, "user": "alerts",
                 "password": "saved-pw",  # pragma: allowlist secret
                 "from_address": "Lightwork <alerts@example.test>", "tls": "starttls",
                 "to": "ops@example.test"}}


def test_send_email_uses_starttls_login_and_html_alternative():
    from maverick.notifications import email_configured, send_email

    assert email_configured(CFG) is True
    ok = send_email("Bob <bob@example.test>", "Subject\nline", "plain text",
                    html_body="<p>hi</p>", cfg=CFG)
    assert ok is True
    smtp = FakeSMTP.instances[-1]
    assert (smtp.host, smtp.port) == ("smtp.example.test", 2525)
    assert smtp.started_tls is True and smtp.login_args == ("alerts", "saved-pw")
    message = smtp.sent[0]
    assert message["To"] == "Bob <bob@example.test>"
    assert message["Subject"] == "Subject line"  # header injection stripped
    assert message["From"] == "Lightwork <alerts@example.test>"
    parts = [p.get_content_type() for p in message.iter_parts()]
    assert parts == ["text/plain", "text/html"]


def test_password_from_secret_provider_wins_and_ssl_mode(monkeypatch):
    from maverick.notifications import send_email

    monkeypatch.setenv("MAVERICK_SMTP_PASSWORD", "env-pw")
    cfg = {"email": {**CFG["email"], "tls": "ssl", "port": 465}}
    assert send_email("bob@example.test", "s", "b", cfg=cfg) is True
    smtp = FakeSMTP.instances[-1]
    assert smtp.login_args == ("alerts", "env-pw") and smtp.started_tls is False


def test_refusals_bad_recipients_and_failures_never_raise(monkeypatch):
    import smtplib

    from maverick.notifications import send_email

    assert send_email("not-an-address", "s", "b", cfg=CFG) is False
    assert send_email("", "s", "b", cfg=CFG) is False

    class Refusing(FakeSMTP):
        def send_message(self, message):
            return {"bob@example.test": (550, b"no")}

    monkeypatch.setattr(smtplib, "SMTP", Refusing)
    assert send_email("bob@example.test", "s", "b", cfg=CFG) is False

    class Broken(FakeSMTP):
        def __init__(self, *a, **kw):
            raise OSError("connection refused")

    monkeypatch.setattr(smtplib, "SMTP", Broken)
    assert send_email("bob@example.test", "s", "b", cfg=CFG) is False


def test_falls_back_to_the_platform_mailer_when_no_alert_server(monkeypatch):
    from maverick import mailer
    from maverick.notifications import email_configured, send_email

    assert email_configured({}) is False
    assert send_email("bob@example.test", "s", "b", cfg={}) is False
    sent = []
    monkeypatch.setattr(mailer, "configured", lambda: True)
    monkeypatch.setattr(mailer, "send", lambda to, subject, body, transport=None: sent.append((to, subject, body)))
    assert email_configured({}) is True
    assert send_email("bob@example.test", "s", "b", html_body="<p>x</p>", cfg={}) is True
    assert sent == [("bob@example.test", "s", "b")]
    monkeypatch.setattr(mailer, "send", lambda *a, **k: (_ for _ in ()).throw(mailer.MailerError("x")))
    assert send_email("bob@example.test", "s", "b", cfg={}) is False


def test_notify_email_backend_uses_the_default_recipient(monkeypatch):
    from maverick import notifications

    monkeypatch.setattr(notifications, "_load_config", lambda: {"backend": "email", **CFG})
    assert notifications.notify("Run 42 finished", title="Lightwork", async_dispatch=False) == 1
    message = FakeSMTP.instances[-1].sent[0]
    assert message["To"] == "ops@example.test" and message["Subject"] == "Lightwork"
    monkeypatch.setattr(notifications, "_load_config",
                        lambda: {"backend": "email", "email": {**CFG["email"], "to": ""}})
    assert notifications.notify("Run 43 finished", async_dispatch=False) == 0


# ---- "unknown" only once the message may be on the wire --------------------

def _checked(cfg, to="bob@example.test"):
    """(sent, may_have_been_sent) for one email through the real ``send_email``."""
    from maverick.notifications import send_checked, send_email

    return send_checked(lambda: send_email(to, "s", "b", cfg=cfg))


def test_failures_before_the_message_is_handed_over_are_definite(monkeypatch):
    import smtplib
    import ssl

    class AuthFails(FakeSMTP):
        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

    class TlsFails(FakeSMTP):
        def starttls(self, context=None):
            raise ssl.SSLError("handshake failure")

    class ConnectionRefused(FakeSMTP):
        def __init__(self, *a, **kw):
            raise ConnectionRefusedError("refused")

    class NoSuchHost(FakeSMTP):
        def __init__(self, *a, **kw):
            raise OSError("name or service not known")

    for fake in (AuthFails, TlsFails, ConnectionRefused, NoSuchHost):
        monkeypatch.setattr(smtplib, "SMTP", fake)
        assert _checked(CFG) == (False, False), fake.__name__


def test_a_server_that_refuses_the_message_sent_nothing(monkeypatch):
    import smtplib

    for refusal in (smtplib.SMTPRecipientsRefused({"bob@example.test": (550, b"no such user")}),
                    smtplib.SMTPSenderRefused(553, b"sender not allowed", "alerts@example.test"),
                    smtplib.SMTPDataError(554, b"message rejected")):
        class Refuses(FakeSMTP):
            def send_message(self, message, _refusal=refusal):
                raise _refusal

        monkeypatch.setattr(smtplib, "SMTP", Refuses)
        assert _checked(CFG) == (False, False), type(refusal).__name__


def test_a_timeout_or_lost_connection_during_the_hand_over_is_unconfirmed(monkeypatch):
    import smtplib

    class TimesOutInData(FakeSMTP):
        def send_message(self, message):
            raise TimeoutError("no reply after the message body")

    class DropsInData(FakeSMTP):
        def send_message(self, message):
            raise smtplib.SMTPServerDisconnected("connection unexpectedly closed")

    class QuitFailsAfterSending(FakeSMTP):
        def __exit__(self, *exc):
            raise smtplib.SMTPResponseException(421, b"closing channel")

    for fake in (TimesOutInData, DropsInData, QuitFailsAfterSending):
        monkeypatch.setattr(smtplib, "SMTP", fake)
        assert _checked(CFG) == (False, True), fake.__name__
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    assert _checked(CFG) == (True, False)


def test_http_channels_that_never_connect_are_definite_failures_and_later_ones_unconfirmed(monkeypatch):
    """Like the email channel: a send that could not even connect delivered
    nothing and may be retried; once the request may have gone out it may not."""
    import httpx
    from maverick import notifications as n

    senders = {
        "ntfy": lambda: n._send_ntfy("t", "b", "default", "https://ntfy.example", "topic"),
        "pushover": lambda: n._send_pushover("t", "b", "default", {"user_key": "u", "app_token": "a"}),
        "discord": lambda: n._send_discord("t", "b", "https://discord.example/hook"),
        "slack": lambda: n._send_slack("t", "b", "https://hooks.example/slack"),
    }

    def raising(error):
        def post(*args, **kwargs):
            raise error
        return post

    for name, send in senders.items():
        for error in (httpx.ConnectError("refused"), httpx.ConnectTimeout("no route"),
                      httpx.PoolTimeout("busy"), httpx.UnsupportedProtocol("ftp")):
            monkeypatch.setattr(httpx, "post", raising(error))
            assert n.send_checked(send) == (False, False), (name, type(error).__name__)
        for error in (httpx.ReadTimeout("no reply"), httpx.RemoteProtocolError("closed mid-reply"),
                      httpx.ReadError("reset")):
            monkeypatch.setattr(httpx, "post", raising(error))
            assert n.send_checked(send) == (False, True), (name, type(error).__name__)


def test_the_platform_mailer_separates_not_sent_from_maybe_sent(monkeypatch):
    from maverick import mailer

    monkeypatch.setattr(mailer, "configured", lambda: True)
    for failure, expected in ((mailer.MailerNotSent("Email was not sent."), (False, False)),
                              (mailer.MailerError("Email sending failed (TimeoutError)."), (False, True))):
        def send(*args, _failure=failure, **kwargs):
            raise _failure
        monkeypatch.setattr(mailer, "send", send)
        assert _checked({}) == expected, type(failure).__name__


def test_the_platform_mailers_own_transport_login_connect_and_data_failures(monkeypatch):
    import smtplib

    monkeypatch.setenv("EMAIL_USER", "alerts@example.test")
    monkeypatch.setenv("EMAIL_APP_PASSWORD", "expired-app-password")  # pragma: allowlist secret

    class LoginFails(FakeSMTP):
        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

    class ConnectionRefused(FakeSMTP):
        def __init__(self, *a, **kw):
            raise ConnectionRefusedError("refused")

    class RecipientRefused(FakeSMTP):
        def send_message(self, message):
            raise smtplib.SMTPRecipientsRefused({"bob@example.test": (550, b"no such user")})

    class TimesOutInData(FakeSMTP):
        def send_message(self, message):
            raise TimeoutError("no reply after the message body")

    for fake, expected in ((LoginFails, (False, False)), (ConnectionRefused, (False, False)),
                           (RecipientRefused, (False, False)), (TimesOutInData, (False, True)),
                           (FakeSMTP, (True, False))):
        monkeypatch.setattr(smtplib, "SMTP", fake)
        monkeypatch.setattr(smtplib, "SMTP_SSL", fake)
        assert _checked({}) == expected, fake.__name__


# ---- ntfy titles, receipts and batching ------------------------------------------------

def test_a_non_ascii_ntfy_title_is_sent_as_an_rfc2047_word_not_a_local_encoding_error(monkeypatch):
    """httpx writes header text as ASCII, so a raw "Zürich" title would fail
    before any request existed and be recorded as an unknown outcome."""
    from email.header import decode_header, make_header

    import httpx
    from maverick import notifications as n

    sent = []

    def post(url, content=None, headers=None, timeout=None):
        httpx.Request("POST", url, content=content, headers=headers)        # what httpx itself would build
        sent.append(headers)
        return httpx.Response(200)

    monkeypatch.setattr(httpx, "post", post)
    assert n._send_ntfy("Due soon: José from Zürich", "body", "default", "https://ntfy.example", "topic") is True
    title = sent[0]["Title"]
    assert title.isascii()
    assert str(make_header(decode_header(title))) == "Due soon: José from Zürich"
    assert n._send_ntfy("Plain title", "body", "default", "https://ntfy.example", "topic") is True
    assert sent[1]["Title"] == "Plain title"


def test_a_delivered_notification_whose_receipt_cannot_be_updated_is_still_delivered(monkeypatch):
    from maverick import notifications as n

    class Receipts:
        def update(self, ident, state, message, **kwargs):
            if state in ("delivered", "failed", "unknown"):
                raise OSError("receipt file locked")

    monkeypatch.setattr(n, "_dispatch", lambda backend, **kwargs: True)
    monkeypatch.setattr(n, "_load_config", dict)
    states = []
    result = n._tracked("ntfy", "id", cfg={}, title="t", body="b", priority="default",
                        receipts=Receipts(), authorize=None, states=states)
    assert result is True and states == ["delivered"]


def test_a_send_that_needs_an_authority_check_is_never_batched(monkeypatch):
    import maverick.notification_batcher as nb
    from maverick import notifications as n

    class Batcher:
        def submit(self, *args, **kwargs):
            raise AssertionError("an authorized send must not wait in a batch that skips its check")

    checked = []
    monkeypatch.setattr(nb, "shared", lambda: Batcher())
    monkeypatch.setattr(n, "_load_config", lambda: {"backends": ["ntfy"], "delivery_receipts": False})
    monkeypatch.setattr(n, "_requested", lambda cfg, backends: ["none"])
    n.notify("hi", async_dispatch=True, authorize=lambda: checked.append(True))
