"""The email send tool must reject CR/LF in header fields.

Regression: `to` / `cc` / `subject` were assigned straight to
EmailMessage headers. A newline in any of them smuggles extra headers
into the message — e.g. a hidden ``Bcc:`` that silently exfiltrates a
copy of every email the agent sends. Recipients and subjects are always
single-line, so a newline is an injection attempt, not data.
"""
from maverick.tools.email_tool import _send


def _creds(monkeypatch):
    # Get past the credential check so we reach the header validation
    # (which runs before any SMTP connection).
    monkeypatch.setenv("EMAIL_USER", "me@example.com")
    monkeypatch.setenv("EMAIL_APP_PASSWORD", "app-password")


def test_rejects_newline_in_to(monkeypatch):
    _creds(monkeypatch)
    out = _send({
        "to": "victim@example.com\nBcc: evil@example.com",
        "subject": "hi", "body": "x",
    })
    assert "header injection" in out


def test_rejects_newline_in_subject(monkeypatch):
    _creds(monkeypatch)
    out = _send({
        "to": "victim@example.com",
        "subject": "hi\r\nBcc: evil@example.com", "body": "x",
    })
    assert "header injection" in out


def test_rejects_newline_in_cc(monkeypatch):
    _creds(monkeypatch)
    out = _send({
        "to": "victim@example.com", "subject": "hi",
        "cc": "ok@example.com\nBcc: evil@example.com", "body": "x",
    })
    assert "header injection" in out
