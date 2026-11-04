"""A hard cap on the size of every request the dashboard accepts.

Routes that read a body already bound what they parse, but a multipart upload
is spooled to temporary disk by the form parser before any route sees it, so an
upload of any size was written in full first. This ASGI middleware refuses a
request whose declared ``Content-Length`` is over the cap before reading it,
and stops a streamed (lengthless) body as soon as it passes the cap.

``[dashboard] max_request_mb`` sets the cap (default 600: above the largest
batch of task attachments a request may carry), overridden by
``MAVERICK_DASHBOARD_MAX_REQUEST_MB``.
"""
from __future__ import annotations

import json
import math
import os

DEFAULT_MAX_REQUEST_MB = 600
_MESSAGE = "That upload is too large. Try a smaller file or fewer files at once."


def max_request_bytes() -> int:
    raw = os.environ.get("MAVERICK_DASHBOARD_MAX_REQUEST_MB", "").strip()
    value: object = raw or None
    if value is None:
        try:
            from maverick.config import load_config

            value = ((load_config() or {}).get("dashboard") or {}).get("max_request_mb")
        except Exception:  # noqa: BLE001 -- an unreadable config keeps the default cap
            value = None
    try:
        megabytes = float(value) if value not in (None, "") else DEFAULT_MAX_REQUEST_MB
    except (TypeError, ValueError):
        megabytes = DEFAULT_MAX_REQUEST_MB
    if not math.isfinite(megabytes) or megabytes <= 0:
        megabytes = DEFAULT_MAX_REQUEST_MB
    return int(megabytes * 1024 * 1024)


class _TooLarge(Exception):
    pass


class RequestSizeLimitMiddleware:
    """Refuse requests larger than :func:`max_request_bytes` with a plain 413."""

    def __init__(self, app, *, limit: int | None = None) -> None:
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        limit = self.limit if self.limit is not None else max_request_bytes()
        for name, value in scope.get("headers") or ():
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = -1
                if declared < 0 or declared > limit:
                    return await _refuse(send, 400 if declared < 0 else 413)
        seen = 0
        started = False

        async def counted_receive():
            nonlocal seen
            message = await receive()
            if message.get("type") == "http.request":
                seen += len(message.get("body") or b"")
                if seen > limit:
                    raise _TooLarge
            return message

        async def tracked_send(message):
            nonlocal started
            if message.get("type") == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counted_receive, tracked_send)
        except _TooLarge:
            if not started:
                await _refuse(send, 413)


async def _refuse(send, status: int) -> None:
    detail = _MESSAGE if status == 413 else "The request size could not be read."
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode()),
                            (b"connection", b"close")]})
    await send({"type": "http.response.body", "body": body})
