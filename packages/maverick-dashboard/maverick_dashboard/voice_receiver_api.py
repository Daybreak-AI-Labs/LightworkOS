"""Fixed public phone ingress; execution and originals belong to VoiceChannel."""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from maverick import config
from maverick_channels.voice import (
    INBOUND_PROVIDERS,
    configuration_identity,
    configured_callers,
    parse_request,
)

router = APIRouter(tags=["phone calls"])
RECEIVER_PATH = "/api/v1/channels/voice/receive"
MAX_REQUEST_BYTES = 262_144
MAX_RESPONSE_BYTES = 1_048_576


def _settings():
    channels = config.load_global_config().get("channels", {})
    settings = channels.get("voice", {}) if isinstance(channels, dict) else None
    if config.config_source_errors(include_tenant=False) or not isinstance(settings, dict):
        raise HTTPException(503, "Phone call settings need attention in All settings.")
    return settings


def setup(request: Request):
    """Public setup metadata only; a declared HTTPS origin is not a live check."""
    from .integration_readiness import _voice_configuration_problem

    try:
        settings = _settings()
        problem = _voice_configuration_problem(settings)
        enabled = settings.get("enabled") is True
        provider = settings.get("provider") or "vapi"
    except (HTTPException, ValueError, TypeError, AttributeError):
        enabled, provider, problem = False, "", "Phone call settings are unavailable."
    base = str(request.base_url).rstrip("/")
    target = urlsplit(base)
    host = target.hostname or ""
    public = bool(host) and host != "localhost" and not host.endswith((".localhost", ".local"))
    try:
        public = ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    address = base + RECEIVER_PATH if target.scheme == "https" and public and not target.username else ""
    return {"enabled": enabled, "provider": provider, "supported": provider in INBOUND_PROVIDERS,
            "address": address, "problem": problem,
            "status": (problem or ("Phone calls are off." if not enabled else
                       "Saved settings are ready for local setup. Restart the chat service after changes. "
                       "A real provider call and spoken delivery have not been checked."))}


def _current(authorization):
    settings = _settings()
    if settings.get("enabled") is not True:
        raise HTTPException(409, "Incoming phone calls are turned off.")
    provider = settings.get("provider") or "vapi"
    if not isinstance(provider, str) or provider not in INBOUND_PROVIDERS:
        raise HTTPException(409, "This phone service supports outgoing calls only.")
    assistant = settings.get("assistant_id")
    if not isinstance(assistant, str) or not assistant or len(assistant) > 128:
        raise HTTPException(409, "Choose the saved call assistant in All settings.")
    secret = settings.get("webhook_token") or os.environ.get("VAPI_WEBHOOK_TOKEN")
    given = authorization[7:] if isinstance(authorization, str) and authorization.startswith("Bearer ") else ""
    if not isinstance(secret, str) or not secret or not hmac.compare_digest(secret.encode(), given.strip().encode()):
        raise HTTPException(401, "The incoming call check key is invalid.")
    port = settings.get("port", 8770)
    if type(port) is not int or not 1024 <= port <= 65535:
        raise HTTPException(409, "The incoming call port needs attention in All settings.")
    try:
        identity = configuration_identity(settings)
    except (ValueError, TypeError):
        raise HTTPException(409, "Phone call settings need attention in All settings.") from None
    return settings, identity, port


@router.post(RECEIVER_PATH)
async def receive(request: Request):
    authorization = request.headers.get("Authorization")
    settings, identity, port = _current(authorization)
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "A supported phone call message is required.")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_REQUEST_BYTES:
            raise HTTPException(413, "The phone call message is too large.")
        body.extend(chunk)
    try:
        payload = json.loads(body)
        parsed = parse_request(payload, provider=settings.get("provider") or "vapi",
                               assistant_id=settings.get("assistant_id"),
                               callers=configured_callers(settings.get("allowed_callers")))
    except PermissionError:
        raise HTTPException(403, "This caller or call assistant is not currently permitted.") from None
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(400, "The phone call request is missing or unsupported.") from None

    def unchanged():
        if _current(authorization)[1] != identity:
            raise HTTPException(409, "Phone call settings changed. Check the original request before starting another.")

    unchanged()
    result = bytearray()
    try:
        async with httpx.AsyncClient(timeout=120, trust_env=False, follow_redirects=False) as client:
            from maverick.governed_http import admit_client_request

            admit_client_request(client, f"http://127.0.0.1:{port}/webhook/voice")
            async with client.stream("POST", f"http://127.0.0.1:{port}/webhook/voice", content=bytes(body),
                                     headers={"Authorization": authorization, "Content-Type": "application/json"}) as reply:
                unchanged()
                if (300 <= reply.status_code < 400 or
                        reply.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json"):
                    raise HTTPException(503, "The local phone service returned no supported answer. Check the original request.")
                async for chunk in reply.aiter_bytes():
                    if len(result) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise HTTPException(503, "The phone answer is too large for this connection. Check the original request in Lightwork.")
                    result.extend(chunk)
                status = reply.status_code
        unchanged()
        decoded = json.loads(result)
        if not isinstance(decoded, dict):
            raise ValueError("Unsupported local result")
        if status == 200:
            if parsed is None:
                valid = decoded == {}
            elif (settings.get("provider") or "vapi") == "vapi":
                values = decoded.get("results")
                valid = (set(decoded) == {"results"} and isinstance(values, list)
                         and len(values) == len(parsed[2]) and all(
                             isinstance(item, dict) and set(item) == {"name", "toolCallId", "result"}
                             and item["name"] == "lightwork_request" and item["toolCallId"] == original[0]
                             and isinstance(item["result"], str)
                             for item, original in zip(values, parsed[2], strict=True)))
            else:
                valid = set(decoded) == {"result"} and isinstance(decoded["result"], str)
            if not valid:
                raise ValueError("Unsupported local result")
        elif not (400 <= status <= 599 and set(decoded) == {"detail"} and isinstance(decoded["detail"], str)):
            raise ValueError("Unsupported local refusal")
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError, RecursionError):
        raise HTTPException(503, "The phone call response is unconfirmed. Work may already have started; "
                                 "check the original request before starting another request.") from None
    return Response(bytes(result), status_code=status, media_type="application/json",
                    headers={"Cache-Control": "no-store"})
