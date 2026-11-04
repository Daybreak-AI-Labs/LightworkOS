"""Bedrock agent action-group forwarder for the Lightwork BYOA gateway.

Receives Amazon Bedrock agent action-group events (OpenAPI mode), maps the
invoked operation to the matching Lightwork external-gateway route, forwards
it over HTTPS with the per-agent ``rest`` bearer read from AWS Secrets
Manager, and returns the Bedrock action-group response shape.

Stdlib + boto3 only (both ship in the Lambda Python 3.12 runtime), so
``sam build`` needs no requirements step. The endpoint contract is
``bedrock/lightwork-external.json`` — the gateway's own importable OpenAPI
description (``GET /api/v1/external/openapi.json``).
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

#: operationId -> (HTTP method, path template), straight from
#: lightwork-external.json. Bedrock events carry apiPath + httpMethod rather
#: than the operationId, so _BY_ROUTE indexes the same table both ways.
OPERATIONS: dict[str, tuple[str, str]] = {
    "screenAction": ("POST", "/api/v1/external/screen"),
    "reportRun": ("POST", "/api/v1/external/runs"),
    "startRun": ("POST", "/api/v1/external/runs/start"),
    "heartbeatRun": ("POST", "/api/v1/external/runs/{goal_id}/heartbeat"),
    "finishRun": ("POST", "/api/v1/external/runs/{goal_id}/finish"),
    "memoryIngest": ("POST", "/api/v1/external/memory/ingest"),
    "memoryRecall": ("POST", "/api/v1/external/memory/recall"),
    "approvalStatus": ("GET", "/api/v1/external/approvals/{approval_id}"),
    "executeAction": ("POST", "/api/v1/external/execute"),
    "executionStatus": ("GET", "/api/v1/external/executions/{execution_id}"),
    "commitExecution": ("POST", "/api/v1/external/executions/{execution_id}/commit"),
    "evaluateRuntimeContent": ("POST", "/api/v1/external/runtime/evaluate"),
    "pullRedTeamCases": ("GET", "/api/v1/external/red-team/{campaign_id}/cases"),
    "submitRedTeamResult": ("POST", "/api/v1/external/red-team/{campaign_id}/results"),
}
_BY_ROUTE: dict[tuple[str, str], tuple[str, str]] = {
    (method, path): (method, path) for method, path in OPERATIONS.values()
}

_FORWARD_TIMEOUT_SECONDS = 25
_SECRET_TTL_SECONDS = 300.0
_secret_cache: tuple[str, float] | None = None


def _bearer_token(refresh: bool = False) -> str:
    """The Lightwork ``rest`` bearer from Secrets Manager (cached ~5 min).

    Accepts either a raw token string or a JSON object with a ``token``
    key, so ``put-secret-value`` rotation works with both shapes.
    """
    global _secret_cache
    now = time.monotonic()
    if not refresh and _secret_cache and now - _secret_cache[1] < _SECRET_TTL_SECONDS:
        return _secret_cache[0]
    arn = os.environ["LIGHTWORK_TOKEN_SECRET_ARN"]
    value = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"]
    try:
        parsed = json.loads(value)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        value = parsed.get("token") or parsed.get("bearer") or value
    token = value.strip()
    _secret_cache = (token, now)
    return token


def _resolve_route(event: dict) -> tuple[str, str]:
    """(method, path template) for the invoked operation.

    Prefers an explicit operationId when present; otherwise resolves the
    (httpMethod, apiPath) pair Bedrock sends for OpenAPI action groups.
    """
    operation_id = event.get("operationId") or event.get("operation")
    if operation_id in OPERATIONS:
        return OPERATIONS[operation_id]
    method = (event.get("httpMethod") or "POST").upper()
    api_path = event.get("apiPath") or ""
    route = _BY_ROUTE.get((method, api_path))
    if route is None:
        raise KeyError(f"unknown operation: {operation_id or f'{method} {api_path}'}")
    return route


def _path_parameters(event: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for param in event.get("parameters") or []:
        name = param.get("name")
        if name:
            out[str(name)] = str(param.get("value", ""))
    return out


def _coerce(value: object, declared_type: str) -> object:
    """Best-effort cast of Bedrock's stringly-typed property values."""
    kind = (declared_type or "").lower()
    if kind == "object":
        try:
            parsed = json.loads(value) if isinstance(value, str) else value
        except ValueError as err:
            raise ValueError("object property must contain valid JSON") from err
        if not isinstance(parsed, dict):
            raise ValueError("object property must contain a JSON object")
        return parsed
    if not isinstance(value, str):
        return value
    try:
        if kind == "integer":
            return int(value)
        if kind == "number":
            return float(value)
        if kind == "boolean":
            return value.strip().lower() in {"1", "true", "yes"}
        if kind == "array":
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else [value]
    except ValueError:
        return value
    return value


def _request_body(event: dict) -> dict:
    content = (event.get("requestBody") or {}).get("content") or {}
    properties = (content.get("application/json") or {}).get("properties") or []
    body: dict[str, object] = {}
    for prop in properties:
        name = prop.get("name")
        if name:
            try:
                body[str(name)] = _coerce(prop.get("value"), str(prop.get("type") or ""))
            except ValueError as err:
                raise ValueError(f"{name}: {err}") from err
    return body


def _forward(method: str, path: str, body: dict, token: str) -> tuple[int, str]:
    base = os.environ["LIGHTWORK_BASE_URL"].rstrip("/")
    request = urllib.request.Request(
        base + path,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        data=None if method == "GET" else json.dumps(body).encode("utf-8"),
    )
    try:
        with urllib.request.urlopen(request, timeout=_FORWARD_TIMEOUT_SECONDS) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        # Gateway verdicts (401/403/404/429) are responses, not crashes:
        # hand the body back so the agent can read rule/reason/detail.
        return err.code, err.read().decode("utf-8", errors="replace")


def _bedrock_response(event: dict, status: int, text: str) -> dict:
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup", ""),
            "apiPath": event.get("apiPath", ""),
            "httpMethod": event.get("httpMethod", "POST"),
            "httpStatusCode": status,
            "responseBody": {"application/json": {"body": text}},
        },
        "sessionAttributes": event.get("sessionAttributes") or {},
        "promptSessionAttributes": event.get("promptSessionAttributes") or {},
    }


def lambda_handler(event: dict, _context: object) -> dict:
    try:
        method, template = _resolve_route(event)
    except KeyError as err:
        log.warning("unroutable action-group event: %s", err)
        return _bedrock_response(event, 400, json.dumps({"detail": str(err)}))

    path = template
    query = {}
    for name, value in _path_parameters(event).items():
        marker = "{" + name + "}"
        if marker in template:
            path = path.replace(marker, urllib.parse.quote(value, safe=""))
        else:
            query[name] = value
    if query:
        path += "?" + urllib.parse.urlencode(query)
    try:
        body = _request_body(event)
    except ValueError as err:
        return _bedrock_response(event, 400, json.dumps({"detail": str(err)}))

    status, text = _forward(method, path, body, _bearer_token())
    if status == 401:
        # Token likely rotated on /external-agents: re-read the secret once.
        status, text = _forward(method, path, body, _bearer_token(refresh=True))
    log.info("forwarded %s %s -> HTTP %d", method, path, status)
    return _bedrock_response(event, status, text)
