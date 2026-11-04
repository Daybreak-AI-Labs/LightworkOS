"""AWS SNS tool — pub/sub topics + mobile push + SMS.

Standard boto3 auth chain. ``AWS_REGION`` required.

ops:
  - topics()
  - publish(topic_arn, message, subject, confirm)
  - sms(phone, message, confirm)
  - subscribe(topic_arn, protocol, endpoint, confirm)
  - unsubscribe(subscription_arn, confirm)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from . import Tool, as_bool

log = logging.getLogger(__name__)


_SNS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["topics", "publish", "sms", "subscribe", "unsubscribe"],
        },
        "topic_arn": {"type": "string"},
        "message": {"type": "string"},
        "subject": {"type": "string"},
        "phone": {"type": "string"},
        "protocol": {"type": "string"},
        "endpoint": {"type": "string"},
        "subscription_arn": {"type": "string"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _client():
    import boto3
    return boto3.client(
        "sns",
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL") or None,
        region_name=os.environ.get("AWS_REGION") or None,
    )


def _op_topics(_args: dict) -> str:
    r = _client().list_topics()
    topics = r.get("Topics") or []
    if not topics:
        return "(no topics)"
    return "\n".join(f"  {t['TopicArn']}" for t in topics)


def _op_publish(args: dict) -> str:
    arn = (args.get("topic_arn") or "").strip()
    msg = (args.get("message") or "").strip()
    if not arn or not msg:
        return "ERROR: publish requires topic_arn and message"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would publish to {arn}. Re-run with confirm=true."
    kwargs = {"TopicArn": arn, "Message": msg}
    if args.get("subject"):
        kwargs["Subject"] = args["subject"]
    r = _client().publish(**kwargs)
    return f"published (message_id={r.get('MessageId')})"


def _op_sms(args: dict) -> str:
    phone = (args.get("phone") or "").strip()
    msg = (args.get("message") or "").strip()
    if not phone or not msg:
        return "ERROR: sms requires phone and message"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would SMS {phone}. Re-run with confirm=true."
    r = _client().publish(PhoneNumber=phone, Message=msg)
    return f"sent SMS (message_id={r.get('MessageId')})"


def _op_subscribe(args: dict) -> str:
    arn = (args.get("topic_arn") or "").strip()
    proto = (args.get("protocol") or "").strip()
    ep = (args.get("endpoint") or "").strip()
    if not arn or not proto or not ep:
        return "ERROR: subscribe requires topic_arn, protocol, endpoint"
    if not as_bool(args.get("confirm")):
        return (
            f"DRY RUN: would subscribe {proto}:{ep} to {arn}. "
            "Re-run with confirm=true."
        )
    r = _client().subscribe(TopicArn=arn, Protocol=proto, Endpoint=ep)
    return f"subscribed (arn={r.get('SubscriptionArn')})"


def _op_unsubscribe(args: dict) -> str:
    arn = (args.get("subscription_arn") or "").strip()
    if not arn:
        return "ERROR: unsubscribe requires subscription_arn"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would unsubscribe {arn}. Re-run with confirm=true."
    _client().unsubscribe(SubscriptionArn=arn)
    return f"unsubscribed {arn}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import boto3  # noqa: F401
    except ImportError:
        return "ERROR: boto3 not installed. Run: python -m pip install -e './packages/maverick-core[s3]'"
    try:
        return {
            "topics":      _op_topics,
            "publish":     _op_publish,
            "sms":         _op_sms,
            "subscribe":   _op_subscribe,
            "unsubscribe": _op_unsubscribe,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except Exception as e:
        return f"ERROR: SNS request failed: {type(e).__name__}: {e}"


def sns_tool() -> Tool:
    return Tool(
        name="sns",
        description=(
            "AWS SNS pub/sub + SMS. ops: topics, publish (topic_arn "
            "+ message + optional subject; confirm=true), sms "
            "(phone + message; confirm=true), subscribe / "
            "unsubscribe (confirm=true). boto3 chain + AWS_REGION."
        ),
        input_schema=_SNS_SCHEMA,
        fn=_run,
    )
