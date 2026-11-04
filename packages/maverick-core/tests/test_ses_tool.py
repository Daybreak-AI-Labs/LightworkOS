"""Tests for the Amazon SES tool (maverick.tools.ses_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def test_ses_dry_run_interpolates_subject(monkeypatch):
    # Build a fake boto3 so the tool imports cleanly; send is dry-run so
    # the client is never used.
    boto3 = types.ModuleType("boto3")
    boto3.client = lambda *a, **k: MagicMock()
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    from maverick.tools.ses_tool import ses_tool
    out = ses_tool().fn({
        "op": "send", "from_": "a@x", "to": ["b@x"],
        "subject": "Q3 report", "body": "hi",
    })
    assert "DRY RUN" in out
    assert "Q3 report" in out  # f-string actually interpolated
    assert "{subject" not in out


# ---------- AWS SES ----------

def _install_fake_boto3_ses(monkeypatch, *, send_id="msg-1",
                            quota=None, verified=None):
    boto3 = types.ModuleType("boto3")

    class _Client:
        def send_email(self, **k):
            return {"MessageId": send_id}

        def get_send_quota(self):
            return quota or {"Max24HourSend": 100, "SentLast24Hours": 5,
                              "MaxSendRate": 1.0}

        def list_verified_email_addresses(self):
            return {"VerifiedEmailAddresses": verified or []}

    boto3.client = lambda *a, **k: _Client()
    monkeypatch.setitem(sys.modules, "boto3", boto3)


def test_ses_requires_op():
    from maverick.tools.ses_tool import ses_tool
    assert "op is required" in ses_tool().fn({})


def test_ses_missing_boto3(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)
    from maverick.tools.ses_tool import ses_tool
    out = ses_tool().fn({"op": "quota"})
    assert "boto3 not installed" in out


def test_ses_send_dry_run(monkeypatch):
    _install_fake_boto3_ses(monkeypatch)
    from maverick.tools.ses_tool import ses_tool
    out = ses_tool().fn({
        "op": "send", "from_": "no-reply@x", "to": ["a@x"],
        "subject": "hi", "body": "yo",
    })
    assert "DRY RUN" in out


def test_ses_send_confirmed(monkeypatch):
    _install_fake_boto3_ses(monkeypatch, send_id="abc-123")
    from maverick.tools.ses_tool import ses_tool
    out = ses_tool().fn({
        "op": "send", "from_": "no-reply@x", "to": ["a@x"],
        "subject": "hi", "body": "yo", "confirm": True,
    })
    assert "abc-123" in out


def test_ses_quota_renders(monkeypatch):
    _install_fake_boto3_ses(monkeypatch)
    from maverick.tools.ses_tool import ses_tool
    out = ses_tool().fn({"op": "quota"})
    assert "max_24h" in out and "100" in out
