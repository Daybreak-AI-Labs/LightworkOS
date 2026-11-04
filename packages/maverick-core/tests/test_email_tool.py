"""Email tool: IMAP UID correctness + charset-honoring body decode.

Regressions:
- list_inbox / fetch used m.search() / m.fetch(), which operate on volatile
  message SEQUENCE numbers, while the tool contract promises UIDs. Any
  EXPUNGE between list and fetch renumbered the mailbox, so fetch silently
  returned a completely different email with status OK.
- fetch decoded every body as hard-coded utf-8, turning windows-1252 /
  ISO-8859-1 / ISO-2022-JP mail into mojibake returned as success.
"""
from __future__ import annotations

import imaplib
from unittest.mock import MagicMock, patch


def _creds(monkeypatch):
    monkeypatch.setenv("EMAIL_USER", "me@example.com")
    monkeypatch.setenv("EMAIL_APP_PASSWORD", "pw")


def _fake_imap(monkeypatch, uid_responses):
    """Wire a fake IMAP4_SSL whose .uid() replays the given responses."""
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    conn.login.return_value = ("OK", [b""])
    conn.select.return_value = ("OK", [b"1"])
    conn.uid = MagicMock(side_effect=uid_responses)
    monkeypatch.setattr(imaplib, "IMAP4_SSL", MagicMock(return_value=conn))
    return conn


_HEADER = (
    b"From: alice@example.com\r\n"
    b"Subject: Invoice from Acme\r\n"
    b"Date: Wed, 01 Jul 2026 10:00:00 +0000\r\n\r\n"
)


def test_list_inbox_uses_uid_commands(monkeypatch):
    _creds(monkeypatch)
    conn = _fake_imap(monkeypatch, [
        ("OK", [b"101 205 309"]),  # UID SEARCH result: real UIDs
        ("OK", [(b"3 (UID 309 BODY[HEADER] {90}", _HEADER)]),
        ("OK", [(b"2 (UID 205 BODY[HEADER] {90}", _HEADER)]),
        ("OK", [(b"1 (UID 101 BODY[HEADER] {90}", _HEADER)]),
    ])
    from maverick.tools.email_tool import _list_inbox
    out = _list_inbox({"limit": 10})
    # Sequence-number commands must never be issued.
    conn.search.assert_not_called()
    conn.fetch.assert_not_called()
    assert conn.uid.call_args_list[0].args == ("search", None, "ALL")
    assert conn.uid.call_args_list[1].args[0] == "fetch"
    assert conn.uid.call_args_list[1].args[1] == b"309"  # newest first
    assert "309" in out and "Invoice from Acme" in out


def test_list_inbox_skips_expunged_uid(monkeypatch):
    _creds(monkeypatch)
    _fake_imap(monkeypatch, [
        ("OK", [b"101 205"]),
        ("OK", [None]),  # UID 205 expunged mid-listing: OK + no data
        ("OK", [(b"1 (UID 101 BODY[HEADER] {90}", _HEADER)]),
    ])
    from maverick.tools.email_tool import _list_inbox
    out = _list_inbox({"limit": 10})
    assert not out.startswith("ERROR")
    assert "101" in out and "205" not in out


def test_fetch_uses_uid_fetch(monkeypatch):
    _creds(monkeypatch)
    raw = (
        b"From: alice@example.com\r\n"
        b"Subject: hello\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"plain body"
    )
    conn = _fake_imap(monkeypatch, [
        ("OK", [(b"7 (UID 42 BODY[] {96}", raw), b")"]),
    ])
    from maverick.tools.email_tool import _fetch
    out = _fetch({"uid": "42"})
    conn.fetch.assert_not_called()
    assert conn.uid.call_args_list[0].args[:2] == ("fetch", "42")
    assert "plain body" in out


def test_fetch_missing_uid_errors_cleanly(monkeypatch):
    _creds(monkeypatch)
    _fake_imap(monkeypatch, [("OK", [None])])  # expunged UID: OK + no data
    from maverick.tools.email_tool import _fetch
    out = _fetch({"uid": "42"})
    assert out.startswith("ERROR")


def test_fetch_honors_declared_charset(monkeypatch):
    _creds(monkeypatch)
    raw = (
        b"From: r@example.com\r\n"
        b"Subject: reunion\r\n"
        b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\n"
        b"R\xe9union \xe0 10h - caf\xe9"
    )
    _fake_imap(monkeypatch, [("OK", [(b"1 (UID 9 BODY[] {96}", raw)])])
    from maverick.tools.email_tool import _fetch
    out = _fetch({"uid": "9"})
    assert "Réunion à 10h - café" in out
    assert "�" not in out


def test_fetch_multipart_part_charset(monkeypatch):
    _creds(monkeypatch)
    raw = (
        b"From: r@example.com\r\n"
        b"Subject: multi\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/alternative; boundary=B\r\n\r\n"
        b"--B\r\n"
        b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\n"
        b"caf\xe9 au lait\r\n"
        b"--B\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<p>x</p>\r\n"
        b"--B--\r\n"
    )
    _fake_imap(monkeypatch, [("OK", [(b"1 (UID 9 BODY[] {220}", raw)])])
    from maverick.tools.email_tool import _fetch
    out = _fetch({"uid": "9"})
    assert "café au lait" in out
    assert "�" not in out


def test_fetch_unknown_charset_falls_back_to_utf8(monkeypatch):
    _creds(monkeypatch)
    raw = (
        b"From: r@example.com\r\n"
        b"Subject: weird\r\n"
        b"Content-Type: text/plain; charset=x-no-such-charset\r\n\r\n"
        b"plain ascii body"
    )
    _fake_imap(monkeypatch, [("OK", [(b"1 (UID 9 BODY[] {80}", raw)])])
    from maverick.tools.email_tool import _fetch
    out = _fetch({"uid": "9"})
    assert not out.startswith("ERROR")
    assert "plain ascii body" in out


def _verifies(context):
    # The stdlib's own default (no context passed) checks neither the
    # certificate nor the host name, so the app password goes to any server.
    import ssl
    return (isinstance(context, ssl.SSLContext) and context.verify_mode == ssl.CERT_REQUIRED
            and context.check_hostname is True)


def test_send_verifies_the_server_certificate_before_login(monkeypatch):
    import smtplib

    from maverick.tools.email_tool import _send
    _creds(monkeypatch)
    for port, constructor in (("465", "SMTP_SSL"), ("587", "SMTP")):
        monkeypatch.setenv("EMAIL_SMTP_PORT", port)
        conn = MagicMock()
        conn.__enter__.return_value = conn
        conn.__exit__.return_value = False
        factory = MagicMock(return_value=conn)
        monkeypatch.setattr(smtplib, constructor, factory)
        out = _send({"to": "bob@example.com", "subject": "hi", "body": "b"})
        assert out.startswith("sent"), out
        if port == "465":
            context = factory.call_args.kwargs.get("context")
        else:
            context = conn.starttls.call_args.kwargs.get("context")
        assert _verifies(context), port


def test_inbox_reads_verify_the_server_certificate_before_login(monkeypatch):
    from maverick.tools.email_tool import _fetch, _list_inbox
    _creds(monkeypatch)
    for read in (lambda: _list_inbox({"limit": 1}), lambda: _fetch({"uid": "9"})):
        _fake_imap(monkeypatch, [("OK", [None])])
        read()
        assert _verifies(imaplib.IMAP4_SSL.call_args.kwargs.get("ssl_context"))


def _email_creds(monkeypatch):
    monkeypatch.setenv("EMAIL_USER", "me@example.com")
    monkeypatch.setenv("EMAIL_APP_PASSWORD", "pw")


def test_email_fetch_requires_numeric_uid(monkeypatch):
    _email_creds(monkeypatch)
    from maverick.tools.email_tool import _fetch
    assert "numeric uid" in _fetch({"uid": "1 2 OR 1=1"})
    assert "numeric uid" in _fetch({"uid": "../etc"})


def test_email_list_rejects_folder_control_chars(monkeypatch):
    _email_creds(monkeypatch)
    from maverick.tools.email_tool import _list_inbox
    assert "invalid folder" in _list_inbox({"folder": "INBOX\r\nA001 DELETE"})


# ---------- email tool ----------

def test_email_requires_op():
    from maverick.tools.email_tool import email_tool
    assert "op is required" in email_tool().fn({})


def test_email_send_requires_recipient(monkeypatch):
    monkeypatch.delenv("MAVERICK_EMAIL_DISABLE", raising=False)
    monkeypatch.setenv("EMAIL_USER", "me@example.com")
    monkeypatch.setenv("EMAIL_APP_PASSWORD", "pw")
    from maverick.tools.email_tool import email_tool
    out = email_tool().fn({"op": "send", "to": ""})
    assert "requires `to`" in out


def test_email_send_kill_switch(monkeypatch):
    monkeypatch.setenv("MAVERICK_EMAIL_DISABLE", "1")
    from maverick.tools.email_tool import email_tool
    out = email_tool().fn({"op": "send", "to": "x@y.com", "subject": "s"})
    assert "disabled" in out


def test_email_send_requires_credentials(monkeypatch):
    monkeypatch.delenv("MAVERICK_EMAIL_DISABLE", raising=False)
    monkeypatch.delenv("EMAIL_USER", raising=False)
    monkeypatch.delenv("EMAIL_APP_PASSWORD", raising=False)
    monkeypatch.setenv("HOME", "/nonexistent-home-for-tests")
    from maverick.tools.email_tool import email_tool
    out = email_tool().fn({
        "op": "send", "to": "x@y.com", "subject": "s", "body": "b",
    })
    assert "EMAIL_USER" in out


def test_email_send_via_smtp_ssl(monkeypatch):
    monkeypatch.delenv("MAVERICK_EMAIL_DISABLE", raising=False)
    monkeypatch.setenv("EMAIL_USER", "me@example.com")
    monkeypatch.setenv("EMAIL_APP_PASSWORD", "pw")
    monkeypatch.setenv("EMAIL_SMTP_HOST", "smtp.test")
    monkeypatch.setenv("EMAIL_SMTP_PORT", "465")

    fake_smtp = MagicMock()
    fake_smtp.__enter__ = MagicMock(return_value=fake_smtp)
    fake_smtp.__exit__ = MagicMock(return_value=False)

    with patch("smtplib.SMTP_SSL", return_value=fake_smtp):
        from maverick.tools.email_tool import email_tool
        out = email_tool().fn({
            "op": "send", "to": "you@example.com",
            "subject": "Hello", "body": "Test",
        })
    assert "sent to you@example.com" in out
    fake_smtp.login.assert_called_once_with("me@example.com", "pw")
    fake_smtp.send_message.assert_called_once()
