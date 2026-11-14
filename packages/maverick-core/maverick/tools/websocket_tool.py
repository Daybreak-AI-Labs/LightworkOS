"""WebSocket tool: one-shot connect / send / receive over ws(s).

For agents that need to talk to a WebSocket endpoint (live APIs, dev servers)
without a full browser. A single ``request`` op connects, optionally sends a
message, reads one reply, and closes. Scheme is restricted to ``ws``/``wss`` and
the host runs through the same SSRF guard as ``http_fetch`` (private/loopback
hosts refused unless ``MAVERICK_FETCH_ALLOW_PRIVATE=1``). The host check runs
*before* importing the optional ``websockets`` dependency, so the SSRF guard is
testable without it. Requires ``python -m pip install -e './packages/maverick-core[websocket]'``.
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from . import Tool

_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "ws:// or wss:// URL"},
        "message": {"type": "string", "description": "Unsupported until human approval is available"},
        "timeout": {"type": "number", "description": "seconds to await a reply (default 30)"},
        "recv": {"type": "boolean", "description": "wait for one reply (default true)"},
    },
    "required": ["url"],
}


def _safe_connector():
    """Use a direct connector that never follows an HTTP redirect."""
    from importlib.metadata import version

    from websockets.legacy.client import Connect

    try:
        major = int(version("websockets").split(".", 1)[0])
    except (ValueError, TypeError):
        raise RuntimeError("installed websockets version is unsupported") from None
    if not 12 <= major < 17 or not hasattr(Connect, "handle_redirect"):
        raise RuntimeError("installed websockets version cannot enforce redirect policy")

    class NoRedirectConnect(Connect):
        def handle_redirect(self, uri):
            raise ValueError("websocket redirects are not allowed")

    return NoRedirectConnect


def _check_url(url: str) -> str | None:
    """Return an error string if the URL is unsafe, else None."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("ws", "wss"):
        return f"ERROR: only ws/wss supported; got scheme={scheme!r}"
    if not parsed.hostname:
        return "ERROR: missing host in URL"
    from .http_fetch import is_blocked_host
    if is_blocked_host(parsed.hostname):
        return (f"ERROR: refusing to connect to {parsed.hostname!r}: resolves to a "
                "private/loopback/reserved address (SSRF guard). "
                "Set MAVERICK_FETCH_ALLOW_PRIVATE=1 to override.")
    return None


def _preflight_egress(url: str, parsed: Any) -> str | None:
    """Enterprise/tenant egress checks, run before any network activity.

    websockets.connect() is not wrapped by egress_guard (that covers
    httpx/httpx2/requests/urllib only), so without this the enterprise tool-
    egress lock never sees a websocket connection at all. Mirrors
    http_fetch._preflight_fetch's ordering: enterprise first (a denied URL
    must not leak via DNS/TLS SNI before the denial is returned), then the
    per-tenant egress policy.

    enterprise_egress_denial's local-endpoint check only recognizes
    http(s) schemes, so ws(s):// is translated the same way for that check
    only ("ws"->"http", "wss"->"https") -- otherwise a genuinely local/loopback
    websocket dev server would always fail the enterprise allow-list.
    """
    from ..enterprise import enterprise_egress_denial
    http_scheme = "https" if parsed.scheme.lower() == "wss" else "http"
    deny = enterprise_egress_denial(parsed._replace(scheme=http_scheme).geturl(),
                                    tool="websocket")
    if deny:
        return f"ERROR: {deny}"
    try:
        from ..tenant.egress import egress_allowed
        if not egress_allowed("websocket", parsed.hostname or ""):
            return (f"ERROR: egress policy blocks websocket from reaching "
                    f"{parsed.hostname!r} (see [egress] / [sandbox.tool.websocket]).")
    except Exception:  # pragma: no cover -- policy never breaks a connection
        pass
    return None


async def _run(args: dict[str, Any]) -> str:
    if args.get("message") is not None:
        return "ERROR: websocket message sending is unavailable until exact human approval is supported"
    url = str(args.get("url") or "").strip()
    if not url:
        return "ERROR: url is required"
    bad = _check_url(url)
    if bad:
        return bad
    bad = _preflight_egress(url, urlparse(url))
    if bad:
        return bad
    try:
        connect = _safe_connector()
    except ImportError:
        return ("ERROR: websockets not installed. "
                "Run: python -m pip install -e './packages/maverick-core[websocket]'")
    except Exception:
        return "ERROR: installed websockets cannot enforce the connection safety policy"
    timeout = float(args.get("timeout") or 30)
    want_recv = args.get("recv", True)
    # SSRF: _check_url resolved the host once to validate it, but
    # websockets.connect(url) would re-resolve the SAME name independently --
    # a DNS-rebinding window (validate -> public IP, connect -> 169.254.169.254
    # / 127.0.0.1). Pin the connection to a single validated public IP (the
    # same defense _ssrf gives http_fetch/pdf_reader/...), keeping the original
    # hostname for the Host header and TLS SNI/cert validation on wss.
    from ._ssrf import BlockedHost, resolve_pinned_ip
    parsed = urlparse(url)
    try:
        pinned_ip = resolve_pinned_ip(parsed.hostname or "")
    except BlockedHost as e:
        return (f"ERROR: refusing to connect to {parsed.hostname!r}: {e} "
                "(SSRF guard). Set MAVERICK_FETCH_ALLOW_PRIVATE=1 to override.")
    scheme = (parsed.scheme or "").lower()
    connect_kwargs: dict[str, Any] = {
        "open_timeout": timeout,
        "host": pinned_ip,
        "port": parsed.port or (443 if scheme == "wss" else 80),
    }
    if scheme == "wss" and parsed.hostname:
        # Connect to the pinned IP but validate the cert against the real name.
        connect_kwargs["server_hostname"] = parsed.hostname
    try:
        async with connect(url, **connect_kwargs) as ws:
            if not want_recv:
                return "connected (no reply requested)"
            reply = await asyncio.wait_for(ws.recv(), timeout=timeout)
            if isinstance(reply, bytes):
                reply = reply.decode("utf-8", errors="replace")
            return str(reply)
    except asyncio.TimeoutError:
        return f"ERROR: timed out after {timeout}s waiting for a reply"
    except Exception as e:
        return f"ERROR: websocket failed: {type(e).__name__}: {e}"


def websocket_tool() -> Tool:
    return Tool(
        name="websocket",
        description=(
            "Connect to a ws:// or wss:// endpoint and read one reply. "
            "Message sending is unavailable pending human approval support. "
            "Refuses private/loopback hosts (SSRF guard)."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )


__all__ = ["websocket_tool", "_check_url"]
