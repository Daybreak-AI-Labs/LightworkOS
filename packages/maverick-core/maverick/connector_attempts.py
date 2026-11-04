"""Sanitized connector outcomes and per-invocation retry/deadline ownership.

The public tool contract remains a string. Its internal immutable attempt record
survives wrappers until the registry finishes its operation-aware retry decision.
No request URLs, credential values, headers or upstream failure bodies are stored.
"""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import hashlib
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from . import killswitch
from .budget import BudgetExceeded, UsageAccountingError

CONTROL_ERRORS = (BudgetExceeded, UsageAccountingError, killswitch.Halted)


@dataclass(frozen=True)
class ConnectorLimits:
    max_attempts: int = 3
    total_seconds: float = 60.0
    attempt_seconds: float = 30.0
    wire_bytes: int = 2 * 1024 * 1024
    decoded_bytes: int = 4 * 1024 * 1024
    json_depth: int = 64
    json_items: int = 100_000


def configured_limits() -> ConnectorLimits:
    """Read operator resource limits; malformed settings retain bounded defaults."""
    try:
        from .config import load_config
        configured = (load_config() or {}).get("connector_limits") or {}
    except Exception:
        configured = {}
    if not isinstance(configured, dict):
        configured = {}
    defaults = ConnectorLimits()
    values = {}
    ceilings = {"max_attempts": 5, "total_seconds": 300.0, "attempt_seconds": 120.0,
                "wire_bytes": 64 * 1024 * 1024, "decoded_bytes": 64 * 1024 * 1024,
                "json_depth": 128, "json_items": 1_000_000}
    for field, ceiling in ceilings.items():
        default = getattr(defaults, field)
        try:
            raw = configured.get(field, default)
            if isinstance(raw, bool):
                raise ValueError("boolean limit")
            value = float(raw) if isinstance(default, float) else int(raw)
            if not math.isfinite(value) or value <= 0:
                raise ValueError("non-positive or non-finite limit")
            values[field] = min(value, ceiling)
        except (TypeError, ValueError, OverflowError):
            values[field] = default
    return ConnectorLimits(**values)


class ConnectorDeadlineExceeded(TimeoutError):
    """The finite connector invocation/attempt deadline expired."""


class ConnectorResponseLimit(ValueError):
    """The admitted wire/decoded/parse budget was exceeded."""


@dataclass(frozen=True)
class ConnectorAttempt:
    request_id: str
    attempt: int
    operation: str
    status_code: int | None = None
    error_class: str | None = None
    retry_after: float | None = None
    dispatch_may_have_happened: bool = False
    outcome_unknown: bool = False

    @property
    def retryable(self) -> bool:
        return (self.operation == "safe_read" and not self.outcome_unknown
                and self.error_class in {"rate_limit", "server_5xx", "transient_network"})


class ConnectorResult(str):
    """String-compatible public preview plus immutable internal attempt metadata."""

    __slots__ = ("_attempt",)

    def __new__(cls, preview: str, attempt: ConnectorAttempt):
        result = super().__new__(cls, preview)
        object.__setattr__(result, "_attempt", attempt)
        return result

    @property
    def attempt(self) -> ConnectorAttempt:
        return self._attempt

    def __setattr__(self, name, value):
        raise AttributeError("connector attempt metadata is immutable")


def public_result(result):
    """Drop internal attempt metadata only after the retry decision is final."""
    if not isinstance(result, ConnectorResult):
        return result
    attempt = result.attempt
    if (attempt.outcome_unknown or (attempt.error_class is None
            and attempt.status_code is not None and 200 <= attempt.status_code < 300)):
        from .tool_results import ToolResultText, classify_tool_result

        state = classify_tool_result(result)
        text = str(result)
        # An indeterminate attempt must retain its uncertainty marker even
        # when the legacy prefix already conveys the same classification.
        # Agent audit receipts use that marker to avoid treating the external
        # effect as a known failure.
        if attempt.outcome_unknown or classify_tool_result(text) is not state:
            return ToolResultText(text, state)
        return text
    return str(result)


_BUDGET: contextvars.ContextVar = contextvars.ContextVar("connector_budget", default=None)
_INVOCATION: contextvars.ContextVar = contextvars.ContextVar("connector_invocation", default=None)


@contextlib.contextmanager
def bind_tool_budget(budget):
    token = _BUDGET.set(budget)
    try:
        yield
    finally:
        _BUDGET.reset(token)


class ConnectorInvocation:
    """One logical tool invocation; never retains authentication or caller args."""

    def __init__(self, *, budget=None):
        self.request_id = uuid.uuid4().hex
        self.budget = budget
        self.attempts = 0
        self._limits: ConnectorLimits | None = None
        self._deadline: float | None = None
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self._cancel_callbacks: set = set()
        self._request_fingerprint: str | None = None

    @property
    def limits(self) -> ConnectorLimits:
        with self._lock:
            if self._limits is None:
                self._limits = configured_limits()
                self._deadline = time.monotonic() + self._limits.total_seconds
            return self._limits

    def check(self) -> None:
        if self._cancelled.is_set():
            raise asyncio.CancelledError("connector invocation cancelled")
        killswitch.check()
        if self.budget is not None:
            self.budget.check()

    def remaining(self) -> float:
        self.check()
        _ = self.limits
        remaining = max(0.0, self._deadline - time.monotonic())
        if self.budget is not None:
            remaining = min(remaining, self.budget.remaining_wall())
        return remaining

    def bind_request(self, operation: str, args: dict) -> None:
        """A caller cannot rewrite a request while it waits for retry backoff."""
        canonical = json.dumps([operation, args], sort_keys=True, separators=(",", ":"))
        fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
        with self._lock:
            if self._request_fingerprint is None:
                self._request_fingerprint = fingerprint
            elif self._request_fingerprint != fingerprint:
                raise ValueError("connector request changed between attempts")

    def begin_attempt(self) -> tuple[int, float]:
        remaining = self.remaining()
        if remaining <= 0:
            raise ConnectorDeadlineExceeded("connector invocation deadline reached")
        with self._lock:
            if self.attempts >= self._limits.max_attempts:
                raise ConnectorDeadlineExceeded("connector attempt limit reached")
            self.attempts += 1
            attempt = self.attempts
        return attempt, time.monotonic() + min(remaining, self._limits.attempt_seconds)

    def register_cancel(self, callback):
        with self._lock:
            self._cancel_callbacks.add(callback)
            cancelled = self._cancelled.is_set()
        if cancelled:
            callback()

    def unregister_cancel(self, callback):
        with self._lock:
            self._cancel_callbacks.discard(callback)

    def cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            callbacks = tuple(self._cancel_callbacks)
        for callback in callbacks:
            with contextlib.suppress(Exception):
                callback()


def current_invocation() -> ConnectorInvocation:
    return _INVOCATION.get() or ConnectorInvocation(budget=_BUDGET.get())


@contextlib.contextmanager
def invocation_scope():
    invocation = ConnectorInvocation(budget=_BUDGET.get())
    token = _INVOCATION.set(invocation)
    try:
        yield invocation
    except BaseException:
        invocation.cancel()
        raise
    finally:
        _INVOCATION.reset(token)


def retry_after_seconds(value: object) -> float | None:
    """Parse bounded header syntax, never retain or display the upstream value."""
    if not isinstance(value, str) or len(value) > 128 or any(ord(c) < 32 for c in value):
        return None
    try:
        delay = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            delay = (when - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    if not math.isfinite(delay):
        return None
    # A value larger than the invocation budget prevents a retry; it must not
    # be shortened into an early request that violates upstream Retry-After.
    return max(0.0, min(delay, 86400.0))
