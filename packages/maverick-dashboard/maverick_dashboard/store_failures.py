"""One redacted log line for a saved-record failure answered with 503.

A 503 from a store wrapper otherwise leaves only the access-log line, so an
operator cannot tell a missing table from an unreadable key. Routers that use
such a wrapper add :func:`remember_route` as a router dependency; the wrapper
calls :func:`log_store_failure` with the exception it is about to hide.
"""
from __future__ import annotations

import contextvars
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import HTTPException, Request

_ROUTE: contextvars.ContextVar[str] = contextvars.ContextVar(
    "maverick_dashboard_store_failure_route", default="",
)
_MESSAGE_LIMIT = 300


async def remember_route(request: Request) -> None:
    """Router dependency: name the route template (not its values) for the log line.

    An async dependency runs in the request's own context, so the value
    reaches the endpoint and the thread pool it runs in.
    """
    route = request.scope.get("route")
    _ROUTE.set(request.method + " " + str(getattr(route, "path", "") or request.url.path))


def _workspace() -> str:
    try:
        from maverick.paths import current_tenant_id

        return current_tenant_id() or "none"
    except Exception:  # noqa: BLE001 - the log line must never replace the 503
        return "unknown"


def _redacted(exc: BaseException) -> str:
    from maverick.secrets import scrub

    text = " ".join(scrub(str(exc)).split())
    return text[:_MESSAGE_LIMIT] + ("..." if len(text) > _MESSAGE_LIMIT else "")


def log_store_failure(log: logging.Logger, exc: BaseException, *, answered: str = "answered 503") -> None:
    """Log the route, workspace, exception classes and redacted message on one line."""
    causes = []
    seen = {id(exc)}
    current = exc.__cause__ or exc.__context__
    while current is not None and id(current) not in seen and len(causes) < 3:
        seen.add(id(current))
        causes.append(type(current).__name__ + ": " + _redacted(current))
        current = current.__cause__ or current.__context__
    log.warning(
        "saved-record store failed; %s: route=%s workspace=%s error=%s: %s%s",
        answered, _ROUTE.get() or "unknown", _workspace(), type(exc).__name__, _redacted(exc),
        (" caused by " + " <- ".join(causes)) if causes else "",
    )


_BUSY_CODES = frozenset({sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED})


def store_busy(exc: BaseException) -> bool:
    """Whether ``exc`` is SQLite giving up on a lock another connection held
    for longer than the busy timeout: the store is momentarily unavailable,
    not broken."""
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int):
        return code & 0xFF in _BUSY_CODES
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def unavailable_if_busy(log: logging.Logger, exc: BaseException, detail: str) -> None:
    """Answer a locked or busy store with the route's own 503, logged with its
    cause. Any other error returns, for the caller to re-raise."""
    if store_busy(exc):
        log_store_failure(log, exc)
        raise HTTPException(status_code=503, detail=detail) from exc


@contextmanager
def unavailable_when_busy(log: logging.Logger, detail: str) -> Iterator[None]:
    """:func:`unavailable_if_busy` for the block it wraps."""
    try:
        yield
    except sqlite3.OperationalError as exc:
        unavailable_if_busy(log, exc, detail)
        raise
