"""Request-local MCP state shared by stdio and concurrent HTTP dispatch."""
from __future__ import annotations

import contextvars
from contextlib import contextmanager

_RESOURCE_SUBSCRIPTIONS_CTX: contextvars.ContextVar[set[str] | None] = contextvars.ContextVar(
    "maverick_mcp_resource_subscriptions", default=None
)
_RESOURCE_PENDING_UPDATES_CTX: contextvars.ContextVar[list[str] | None] = contextvars.ContextVar(
    "maverick_mcp_pending_resource_updates", default=None
)
_NO_OVERRIDE = object()
_STRUCTURED_OVERRIDE_CTX: contextvars.ContextVar[object] = contextvars.ContextVar(
    "maverick_mcp_structured_override", default=_NO_OVERRIDE
)


@contextmanager
def resource_update_scope(subscriptions: set[str]):
    """Keep one HTTP request's notifications and structured result isolated."""
    pending: list[str] = []
    subscription_token = _RESOURCE_SUBSCRIPTIONS_CTX.set(subscriptions)
    pending_token = _RESOURCE_PENDING_UPDATES_CTX.set(pending)
    override_token = _STRUCTURED_OVERRIDE_CTX.set(None)
    try:
        yield
    finally:
        _STRUCTURED_OVERRIDE_CTX.reset(override_token)
        _RESOURCE_PENDING_UPDATES_CTX.reset(pending_token)
        _RESOURCE_SUBSCRIPTIONS_CTX.reset(subscription_token)


def current_subscriptions(default: set[str]) -> set[str]:
    current = _RESOURCE_SUBSCRIPTIONS_CTX.get()
    return default if current is None else current


def current_pending_updates() -> list[str] | None:
    return _RESOURCE_PENDING_UPDATES_CTX.get()


def current_structured_override(default: dict | None) -> dict | None:
    current = _STRUCTURED_OVERRIDE_CTX.get()
    return default if current is _NO_OVERRIDE else current  # type: ignore[return-value]


def set_scoped_structured_override(value: dict | None) -> bool:
    """Set the request slot; return false when no request scope is active."""
    if _STRUCTURED_OVERRIDE_CTX.get() is _NO_OVERRIDE:
        return False
    _STRUCTURED_OVERRIDE_CTX.set(value)
    return True
