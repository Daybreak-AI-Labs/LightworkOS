"""Inbound email must have a trusted, From-aligned sender result."""
from __future__ import annotations

import email

import pytest
from maverick.mail_auth import authenticated_from, valid_trusted_mail_server
from maverick_channels.email import EmailChannel


def _msg(*auth_results: str, sender: str = "alice@example.com"):
    raw = f"From: {sender}\r\n"
    for result in auth_results:
        raw += f"Authentication-Results: {result}\r\n"
    raw += "Subject: hi\r\n\r\nbody\r\n"
    return email.message_from_string(raw)


def test_only_trusted_server_dmarc_pass_for_exact_from_domain_is_admitted():
    assert authenticated_from(
        _msg("mx.example.com; spf=pass smtp.mailfrom=example.com; "
             "dmarc=pass header.from=example.com"), "mx.example.com",
    ) == "alice@example.com"


@pytest.mark.parametrize("result", [
    "mx.example.com; spf=pass smtp.mailfrom=evil.com; dkim=none",
    "mx.example.com; dkim=pass header.d=evil.com; dmarc=fail header.from=example.com",
    "mx.example.com; dmarc=pass header.from=evil.com",
    "other.example.com; dmarc=pass header.from=example.com",
    "mx.example.com; dmarc=none header.from=example.com",
])
def test_unaligned_missing_or_untrusted_results_are_refused(result):
    assert authenticated_from(_msg(result), "mx.example.com") == ""


@pytest.mark.parametrize("result", [
    "mx.example.com; dmarc=fail (attacker; dmarc=pass header.from=example.com)",
    'mx.example.com; spf=pass (google.com: domain of "x; dmarc=pass '
    'header.from=example.com"@evil.com designates 203.0.113.1) '
    'smtp.mailfrom=evil.com; dmarc=fail header.from=example.com',
    'mx.example.com; dmarc=fail reason="fake; dmarc=pass header.from=example.com"',
    "mx.example.com; dmarc=pass (header.from=example.com) header.from=evil.com",
    "mx.example.com; dmarc=pass header.from=example.com@evil.com",
    "mx.example.com; dmarc=pass header.from=example.com/evil",
    "mx.example.com; dmarc=pass header.from=example.com; dmarc=fail header.from=example.com",
    "mx.example.com; dmarc=pass header.from=example.com header.from=evil.com",
    "mx.example.com; dmarc=pass header.from=example.com (unclosed",
    'mx.example.com; dmarc=pass header.from="example.com"',
    "mx.example.com extra; dmarc=pass header.from=example.com",
])
def test_comments_quotes_malformed_and_conflicting_results_do_not_grant_access(result):
    assert authenticated_from(_msg(result), "mx.example.com") == ""


def test_nested_comments_and_folded_results_allow_normal_aligned_pass():
    message = _msg("mx.example.com 1; dmarc=pass (outer (inner \\) text))\r\n"
                   "\theader.from=example.com")
    assert authenticated_from(message, "mx.example.com") == "alice@example.com"


def test_no_result_or_no_configured_server_is_refused():
    assert authenticated_from(_msg(), "mx.example.com") == ""
    assert authenticated_from(
        _msg("mx.example.com; dmarc=pass header.from=example.com"), "",
    ) == ""


def test_forged_lower_pass_cannot_override_topmost_failed_result():
    assert authenticated_from(_msg(
        "mx.example.com; dmarc=fail header.from=example.com",
        "mx.example.com; dmarc=pass header.from=example.com",
    ), "mx.example.com") == ""


def test_forged_header_above_own_server_result_is_refused():
    assert authenticated_from(_msg(
        "relay.evil.com; dmarc=pass header.from=example.com",
        "mx.example.com; dmarc=pass header.from=example.com",
    ), "mx.example.com") == ""


def test_multiple_from_headers_are_refused():
    msg = _msg("mx.example.com; dmarc=pass header.from=example.com")
    msg["From"] = "mallory@example.com"
    assert authenticated_from(msg, "mx.example.com") == ""


def test_server_identity_must_be_configured_before_email_channel_starts(monkeypatch):
    monkeypatch.delenv("EMAIL_TRUSTED_AUTHSERV_ID", raising=False)
    assert valid_trusted_mail_server("mx.example.com")
    assert not valid_trusted_mail_server("mx..example.com")
    with pytest.raises(ValueError, match="incoming mail server identity"):
        EmailChannel(lambda _: None, "imap.example.com", "bot@example.com", "p",
                     "smtp.example.com", "bot@example.com", "p",
                     allowed_user_ids=["alice@example.com"])


def test_server_identity_set_in_the_environment_still_starts_email(monkeypatch):
    # Deployments named their server with EMAIL_TRUSTED_AUTHSERV_ID before the
    # [channels.email] setting existed; that is an explicit identity too.
    from maverick.server import _wire_email

    monkeypatch.setenv("EMAIL_TRUSTED_AUTHSERV_ID", "mx.example.com")
    added = []

    class Server:
        _handle_message = staticmethod(lambda _: None)
        add_channel = staticmethod(added.append)

    cfg = {"imap_host": "imap.example.com", "imap_user": "bot@example.com", "imap_password": "p",
           "smtp_host": "smtp.example.com", "smtp_user": "bot@example.com", "smtp_password": "p",
           "allowed_user_ids": ["alice@example.com"]}
    _wire_email(Server, cfg)
    assert added[0].trusted_authserv_id == "mx.example.com"
    _wire_email(Server, {**cfg, "trusted_authserv_id": "mail.example.com"})
    assert added[1].trusted_authserv_id == "mail.example.com"   # the saved setting wins
    monkeypatch.setenv("EMAIL_TRUSTED_AUTHSERV_ID", "mx..example.com")
    with pytest.raises(ValueError, match="incoming mail server identity"):
        _wire_email(Server, cfg)
