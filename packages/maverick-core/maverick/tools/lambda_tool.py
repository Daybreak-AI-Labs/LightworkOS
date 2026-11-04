"""AWS Lambda tool — list / invoke / list logs.

Standard boto3 auth chain (env, IAM role, ~/.aws/credentials).
Optional ``AWS_ENDPOINT_URL`` (LocalStack), ``AWS_REGION``.

ops:
  - list_functions(limit)
  - invoke(function_name, payload, invocation_type, confirm)
  - get_function(function_name)
  - recent_logs(function_name, minutes)
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from . import Tool, as_bool

log = logging.getLogger(__name__)


_LAMBDA_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["list_functions", "invoke", "get_function", "recent_logs"],
        },
        "function_name": {"type": "string"},
        "payload": {"type": "object"},
        "invocation_type": {
            "type": "string",
            "enum": ["RequestResponse", "Event", "DryRun"],
        },
        "minutes": {"type": "integer"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _client(service: str):
    import boto3
    return boto3.client(
        service,
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL") or None,
        region_name=os.environ.get("AWS_REGION") or None,
    )


def _op_list_functions(args: dict) -> str:
    c = _client("lambda")
    limit = max(1, min(int(args.get("limit") or 50), 200))
    r = c.list_functions(MaxItems=limit)
    fns = r.get("Functions") or []
    if not fns:
        return "no functions"
    return "\n".join(
        f"  {f.get('FunctionName'):<40}  runtime={f.get('Runtime'):<14}  "
        f"mem={f.get('MemorySize')}MB  timeout={f.get('Timeout')}s"
        for f in fns
    )


def _op_invoke(args: dict) -> str:
    name = (args.get("function_name") or "").strip()
    if not name:
        return "ERROR: invoke requires function_name"
    itype = (args.get("invocation_type") or "RequestResponse").strip()
    payload = args.get("payload") if isinstance(args.get("payload"), dict) else {}
    if itype != "DryRun" and not as_bool(args.get("confirm")):
        return (
            f"DRY RUN: would invoke {name} ({itype}). "
            "Re-run with confirm=true OR invocation_type=DryRun."
        )
    c = _client("lambda")
    r = c.invoke(
        FunctionName=name,
        InvocationType=itype,
        Payload=json.dumps(payload).encode("utf-8"),
    )
    status = r.get("StatusCode")
    body = r.get("Payload")
    text = body.read().decode("utf-8", errors="replace")[:3000] if body else ""
    return f"status={status} function_error={r.get('FunctionError')}\n{text}"


def _op_get_function(args: dict) -> str:
    name = (args.get("function_name") or "").strip()
    if not name:
        return "ERROR: get_function requires function_name"
    c = _client("lambda")
    r = c.get_function(FunctionName=name)
    cfg = r.get("Configuration") or {}
    return (
        f"{cfg.get('FunctionName')}  arn={cfg.get('FunctionArn')}\n"
        f"  runtime: {cfg.get('Runtime')}\n"
        f"  handler: {cfg.get('Handler')}\n"
        f"  memory:  {cfg.get('MemorySize')} MB\n"
        f"  timeout: {cfg.get('Timeout')} s\n"
        f"  last:    {cfg.get('LastModified')}"
    )


def _op_recent_logs(args: dict) -> str:
    name = (args.get("function_name") or "").strip()
    if not name:
        return "ERROR: recent_logs requires function_name"
    mins = max(1, min(int(args.get("minutes") or 15), 240))
    logs = _client("logs")
    group = f"/aws/lambda/{name}"
    start = int((time.time() - mins * 60) * 1000)
    try:
        r = logs.filter_log_events(
            logGroupName=group, startTime=start, limit=200,
        )
    except Exception as e:
        return f"ERROR: log group {group} not accessible: {e}"
    events = r.get("events") or []
    if not events:
        return f"no log events in the last {mins} minutes"
    return "\n".join(
        f"  {ev.get('timestamp')}  {(ev.get('message') or '').rstrip()[:200]}"
        for ev in events
    )


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
            "list_functions": _op_list_functions,
            "invoke":         _op_invoke,
            "get_function":   _op_get_function,
            "recent_logs":    _op_recent_logs,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except Exception as e:
        return f"ERROR: Lambda request failed: {type(e).__name__}: {e}"


def lambda_tool() -> Tool:
    return Tool(
        name="lambda",
        description=(
            "AWS Lambda. ops: list_functions, invoke (confirm=true "
            "for RequestResponse/Event; DryRun is free), "
            "get_function, recent_logs (CloudWatch tail). Uses "
            "standard boto3 auth chain + AWS_ENDPOINT_URL override."
        ),
        input_schema=_LAMBDA_SCHEMA,
        fn=_run,
    )
