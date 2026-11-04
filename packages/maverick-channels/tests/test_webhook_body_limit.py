"""Webhook inbound body-size cap (BodySizeLimitMiddleware).

Webhook listeners read the request body before the HMAC/signature check, so an
unauthenticated POST to an exposed webhook port could buffer arbitrary memory.
The middleware rejects an oversized Content-Length early (413) and truncates an
absent/lying-length stream at the cap so the downstream parser never buffers
more than the limit.
"""
from __future__ import annotations

import asyncio

from maverick_channels.base import BodySizeLimitMiddleware


def _run(mw, *, body: bytes, content_length: int | None):
    """Drive the middleware as an ASGI app; return (status, bytes_seen_downstream)."""
    headers = []
    if content_length is not None:
        headers.append((b"content-length", str(content_length).encode()))
    scope = {"type": "http", "headers": headers}

    pending = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return pending.pop(0) if pending else {
            "type": "http.request", "body": b"", "more_body": False}

    sent: list[dict] = []

    async def send(msg):
        sent.append(msg)

    seen = bytearray()

    async def downstream(scope, recv, snd):
        while True:
            m = await recv()
            seen.extend(m.get("body", b""))
            if not m.get("more_body"):
                break
        await snd({"type": "http.response.start", "status": 200, "headers": []})
        await snd({"type": "http.response.body", "body": b"ok"})

    async def main():
        await BodySizeLimitMiddleware(downstream, max_bytes=1024)(scope, receive, send)

    asyncio.run(main())
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    return status, bytes(seen)


def test_small_body_passes_through():
    status, seen = _run(BodySizeLimitMiddleware, body=b"x" * 100, content_length=100)
    assert status == 200
    assert seen == b"x" * 100


def test_oversized_content_length_rejected_early():
    # 413 and the downstream app never runs (no body buffered).
    status, seen = _run(BodySizeLimitMiddleware, body=b"x" * 5000, content_length=5000)
    assert status == 413
    assert seen == b""


def test_lying_content_length_is_truncated_at_cap():
    # Content-Length lies (says small) but the body is huge: the stream is
    # truncated at the cap, so downstream never sees more than max_bytes.
    status, seen = _run(BodySizeLimitMiddleware, body=b"x" * 5000, content_length=10)
    assert len(seen) <= 1024
