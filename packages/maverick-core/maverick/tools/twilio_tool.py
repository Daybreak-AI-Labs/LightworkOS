"""Twilio tool — send SMS, initiate calls, look up phone numbers.

Distinct from ``maverick-channels`` SMS adapter (which RECEIVES SMS).
This tool lets the agent SEND outbound SMS / voice calls / look up
the carrier + line type for a number — without a separate billing
relationship.

Auth: ``TWILIO_ACCOUNT_SID`` + ``TWILIO_AUTH_TOKEN``.
``TWILIO_FROM_NUMBER`` pre-fills the From address for sends.

ops:
  - sms_send(to, body, from_)
  - sms_list(to, limit)
  - call_create(to, twiml_url, from_)
  - lookup(phone)                — carrier + line type
"""
from __future__ import annotations

import base64
import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_TWILIO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["sms_send", "sms_list", "call_create", "lookup"],
        },
        "to": {"type": "string", "description": "E.164 e.g. '+14155551234'."},
        "from_": {"type": "string"},
        "body": {"type": "string"},
        "twiml_url": {"type": "string"},
        "phone": {"type": "string"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _config() -> tuple[str, str]:
    sid = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
    tok = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
    if not sid or not tok:
        raise RuntimeError(
            "Twilio requires TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN."
        )
    return sid, tok


def _basic_header() -> str:
    sid, tok = _config()
    raw = f"{sid}:{tok}".encode("ascii")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _from_default() -> str:
    return os.environ.get("TWILIO_FROM_NUMBER", "").strip()


def _post(path: str, data: dict) -> tuple[int, Any]:
    import httpx
    sid, _t = _config()
    r = _governed_sender(httpx.post)(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}{path}",
        headers={"Authorization": _basic_header(),
                 "Content-Type": "application/x-www-form-urlencoded"},
        data=data, timeout=30.0,
    )
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _get(path: str, params: dict | None = None, lookups: bool = False) -> tuple[int, Any]:
    import httpx
    sid, _t = _config()
    base = "https://lookups.twilio.com/v2" if lookups else (
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}"
    )
    r = _governed_sender(httpx.get)(f"{base}{path}", headers={"Authorization": _basic_header()},
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _op_sms_send(args: dict) -> str:
    to = (args.get("to") or "").strip()
    body = (args.get("body") or "").strip()
    src = (args.get("from_") or _from_default()).strip()
    if not to or not body:
        return "ERROR: sms_send requires to and body"
    if not src:
        return "ERROR: sms_send requires from_ or TWILIO_FROM_NUMBER"
    if not as_bool(args.get("confirm")):
        return "DRY RUN: would send SMS. Re-run with confirm=true."
    code, data = _post("/Messages.json", {"To": to, "From": src, "Body": body})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: sms_send ({code}): {data}"
    return f"sent (sid={data.get('sid')} status={data.get('status')})"


def _op_sms_list(args: dict) -> str:
    params: dict = {"PageSize": max(1, min(int(args.get("limit") or 25), 100))}
    to = (args.get("to") or "").strip()
    if to:
        params["To"] = to
    code, data = _get("/Messages.json", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: sms_list ({code}): {data}"
    rows = data.get("messages") or []
    if not rows:
        return "no messages"
    return "\n".join(
        f"  {m.get('sid')}  [{m.get('status', '?'):>9}]  "
        f"{m.get('direction', '?'):>10}  {m.get('from', '?')} -> {m.get('to', '?')}  "
        f"{(m.get('body') or '')[:60]}"
        for m in rows
    )


def _op_call_create(args: dict) -> str:
    to = (args.get("to") or "").strip()
    twiml = (args.get("twiml_url") or "").strip()
    src = (args.get("from_") or _from_default()).strip()
    if not to or not twiml:
        return "ERROR: call_create requires to and twiml_url"
    if not src:
        return "ERROR: call_create requires from_ or TWILIO_FROM_NUMBER"
    if not as_bool(args.get("confirm")):
        return "DRY RUN: would create call. Re-run with confirm=true."
    code, data = _post("/Calls.json", {"To": to, "From": src, "Url": twiml})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: call_create ({code}): {data}"
    return f"call created (sid={data.get('sid')} status={data.get('status')})"


def _op_lookup(args: dict) -> str:
    phone = (args.get("phone") or "").strip()
    if not phone:
        return "ERROR: lookup requires phone"
    seg = safe_path_segment(phone)
    if seg is None:
        return "ERROR: lookup requires a valid phone"
    code, data = _get(
        f"/PhoneNumbers/{seg}",
        {"Fields": "line_type_intelligence"},
        lookups=True,
    )
    if code == 404:
        return f"phone {phone!r} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: lookup ({code}): {data}"
    lt = data.get("line_type_intelligence") or {}
    return (
        f"{data.get('phone_number')}  country={data.get('country_code')}  "
        f"valid={data.get('valid')}\n"
        f"  type:    {lt.get('type', '?')}\n"
        f"  carrier: {lt.get('carrier_name', '?')}\n"
        f"  mobile:  {lt.get('mobile_country_code', '?')}-"
        f"{lt.get('mobile_network_code', '?')}"
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        return {
            "sms_send":    _op_sms_send,
            "sms_list":    _op_sms_list,
            "call_create": _op_call_create,
            "lookup":      _op_lookup,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Twilio request failed: {type(e).__name__}: {e}"


def twilio_tool() -> Tool:
    return Tool(
        name="twilio",
        description=(
            "Twilio SMS + voice. ops: sms_send (to + body, confirm=true), "
            "sms_list (optionally filtered by To), call_create "
            "(to + twiml_url, confirm=true), lookup (carrier + line type). "
            "Auth: TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN; "
            "TWILIO_FROM_NUMBER pre-fills From."
        ),
        input_schema=_TWILIO_SCHEMA,
        fn=_run,
    )
