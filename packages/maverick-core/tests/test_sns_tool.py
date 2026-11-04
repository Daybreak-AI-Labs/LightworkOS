"""Tests for the Amazon SNS tool (maverick.tools.sns_tool)."""
from __future__ import annotations

import sys
import types

# ---------- AWS SNS ----------

def _install_fake_boto3_sns(monkeypatch, *, topics=None, message_id="m-1"):
    boto3 = types.ModuleType("boto3")

    class _Client:
        def list_topics(self):
            return {"Topics": topics or []}

        def publish(self, **k):
            return {"MessageId": message_id}

        def subscribe(self, **k):
            return {"SubscriptionArn": "arn:sub:1"}

        def unsubscribe(self, **k):
            return {}

    boto3.client = lambda *a, **k: _Client()
    monkeypatch.setitem(sys.modules, "boto3", boto3)


def test_sns_requires_op():
    from maverick.tools.sns_tool import sns_tool
    assert "op is required" in sns_tool().fn({})


def test_sns_publish_dry_run(monkeypatch):
    _install_fake_boto3_sns(monkeypatch)
    from maverick.tools.sns_tool import sns_tool
    out = sns_tool().fn({"op": "publish",
                          "topic_arn": "arn:sns:t1", "message": "hi"})
    assert "DRY RUN" in out


def test_sns_publish_confirmed(monkeypatch):
    _install_fake_boto3_sns(monkeypatch, message_id="abc")
    from maverick.tools.sns_tool import sns_tool
    out = sns_tool().fn({
        "op": "publish", "topic_arn": "arn:sns:t1",
        "message": "hi", "confirm": True,
    })
    assert "abc" in out
