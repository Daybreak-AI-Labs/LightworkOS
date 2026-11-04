"""AWS SES tool — send transactional email.

Standard boto3 auth chain (env vars / IAM role / ~/.aws/credentials).
``AWS_REGION`` required for SES (no global endpoint).

ops:
  - send(from_, to, subject, body, html, confirm)
  - quota()
  - verified_identities()
"""
from __future__ import annotations

import logging
import os
from typing import Any

from . import Tool, as_bool

log = logging.getLogger(__name__)


_SES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["send", "quota", "verified_identities"]},
        "from_": {"type": "string"},
        "to": {"type": "array", "items": {"type": "string"}},
        "subject": {"type": "string"},
        "body": {"type": "string", "description": "Plain text."},
        "html": {"type": "string", "description": "Optional HTML body."},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _client():
    import boto3
    return boto3.client(
        "ses",
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL") or None,
        region_name=os.environ.get("AWS_REGION") or None,
    )


def _op_send(args: dict) -> str:
    src = (args.get("from_") or "").strip()
    to = [str(x) for x in (args.get("to") or []) if x]
    subject = (args.get("subject") or "").strip()
    body = (args.get("body") or "").strip()
    if not src or not to or not subject or not body:
        return "ERROR: send requires from_, to, subject, body"
    if not as_bool(args.get("confirm")):
        return (
            f"DRY RUN: would send to {len(to)} recipient(s) "
            f"with subject {subject!r}. Re-run with confirm=true."
        )
    msg: dict = {
        "Subject": {"Data": subject},
        "Body": {"Text": {"Data": body}},
    }
    if args.get("html"):
        msg["Body"]["Html"] = {"Data": args["html"]}
    r = _client().send_email(
        Source=src,
        Destination={"ToAddresses": to},
        Message=msg,
    )
    return f"sent (message_id={r.get('MessageId')})"


def _op_quota(_args: dict) -> str:
    r = _client().get_send_quota()
    return (
        f"max_24h:  {r.get('Max24HourSend')}\n"
        f"sent_24h: {r.get('SentLast24Hours')}\n"
        f"max_rate: {r.get('MaxSendRate')} / sec"
    )


def _op_verified(_args: dict) -> str:
    r = _client().list_verified_email_addresses()
    addrs = r.get("VerifiedEmailAddresses") or []
    if not addrs:
        return "(no verified identities)"
    return "\n".join(f"  {a}" for a in addrs)


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
            "send":                _op_send,
            "quota":               _op_quota,
            "verified_identities": _op_verified,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except Exception as e:
        return f"ERROR: SES request failed: {type(e).__name__}: {e}"


def ses_tool() -> Tool:
    return Tool(
        name="ses",
        description=(
            "AWS SES email. ops: send (from_ + to + subject + body "
            "+ optional html; confirm=true), quota, "
            "verified_identities. Uses standard boto3 chain + "
            "AWS_REGION."
        ),
        input_schema=_SES_SCHEMA,
        fn=_run,
    )
