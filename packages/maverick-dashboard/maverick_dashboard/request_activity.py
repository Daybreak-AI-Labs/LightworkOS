"""Whether the dashboard is serving requests right now.

Start-up work that holds the CPU for seconds (the OpenAPI schema build, a
garbage-collection round) waits for a quiet moment instead of slowing the
people using the dashboard. A pure-ASGI middleware counts requests in flight
and notes when the last one started; nothing about the request itself is
kept. Event streams and WebSockets stay open for as long as a page does and
are mostly idle, so they are not counted as in flight.
"""
from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_in_flight = 0
_last_start = 0.0


def started() -> None:
    global _in_flight, _last_start
    with _lock:
        _in_flight += 1
        _last_start = time.monotonic()


def finished() -> None:
    global _in_flight
    with _lock:
        _in_flight = max(0, _in_flight - 1)


def in_flight() -> int:
    return _in_flight


def quiet_for(seconds: float) -> bool:
    """No request in flight and none started in the last ``seconds``."""
    with _lock:
        return _in_flight == 0 and time.monotonic() - _last_start >= seconds


def _is_event_stream(headers, name: bytes) -> bool:
    for key, value in headers or ():
        if key.lower() == name and b"text/event-stream" in value.lower():
            return True
    return False


class RequestActivityMiddleware:
    """Pure ASGI: counts HTTP requests in flight (not event streams or sockets)."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        # A browser's EventSource asks for a stream up front; the response
        # start alone can arrive late, since GZip holds it until the first event.
        if scope["type"] != "http" or _is_event_stream(scope.get("headers"), b"accept"):
            await self.app(scope, receive, send)
            return
        started()
        counted = True

        async def send_and_watch(message) -> None:
            nonlocal counted
            if (
                counted
                and message["type"] == "http.response.start"
                and _is_event_stream(message.get("headers"), b"content-type")
            ):
                counted = False
                finished()  # an open event stream is not work in flight
            await send(message)

        try:
            await self.app(scope, receive, send_and_watch)
        finally:
            if counted:
                finished()
