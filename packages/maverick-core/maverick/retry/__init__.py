"""Retry with exponential backoff for transient LLM provider errors.

Tier 1 (SRE reviewer): a single 429 / 503 / connection-reset used to
fail the entire goal. Provider calls now retry with exponential backoff
(1s, 2s, ..., capped at 30 s; 3 attempts by default, set by ``[latency]
retry_attempts``), honoring ``Retry-After`` when the provider returns one.

Errors we retry:
  - anthropic.RateLimitError, anthropic.APIConnectionError,
    anthropic.InternalServerError, anthropic.APITimeoutError
  - openai.RateLimitError, openai.APIConnectionError,
    openai.InternalServerError, openai.APITimeoutError
  - httpx.ReadTimeout, httpx.ConnectError (transport-level)

Anything else propagates immediately so a bug in our code isn't silently
re-tried.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")


_PHYSICAL_ATTEMPT_OBSERVER: ContextVar[object | None] = ContextVar(
    "maverick_physical_attempt_observer",
    default=None,
)


@contextmanager
def observe_physical_attempts(observer: object):
    """Bind accounting callbacks to each provider request made by retry code.

    The observer must expose ``before_attempt()`` and
    ``after_attempt(ticket, response, error)``.  A context variable keeps
    concurrent async tasks isolated while allowing provider adapters to remain
    independent from the provider-cost ledger.
    """

    if not callable(getattr(observer, "before_attempt", None)) or not callable(
        getattr(observer, "after_attempt", None)
    ):
        raise TypeError("physical attempt observer is invalid")
    token = _PHYSICAL_ATTEMPT_OBSERVER.set(observer)
    try:
        yield observer
    finally:
        _PHYSICAL_ATTEMPT_OBSERVER.reset(token)


def _before_physical_attempt() -> tuple[object | None, object | None]:
    observer = _PHYSICAL_ATTEMPT_OBSERVER.get()
    if observer is None:
        return None, None
    return observer, observer.before_attempt()


def _after_physical_attempt(
    observer: object | None,
    ticket: object | None,
    response: object | None,
    error: BaseException | None,
) -> None:
    if observer is not None:
        observer.after_attempt(ticket, response, error)


def sync_physical_attempt(fn: Callable[[], T]) -> T:
    """Run one physical call and notify the current accounting observer."""

    observer, ticket = _before_physical_attempt()
    try:
        result = fn()
    except BaseException as exc:
        _after_physical_attempt(observer, ticket, None, exc)
        raise
    _after_physical_attempt(observer, ticket, result, None)
    return result


async def async_physical_attempt(fn: Callable[[], Awaitable[T]]) -> T:
    """Async twin of :func:`sync_physical_attempt`."""

    observer, ticket = _before_physical_attempt()
    try:
        result = await fn()
    except BaseException as exc:
        _after_physical_attempt(observer, ticket, None, exc)
        raise
    _after_physical_attempt(observer, ticket, result, None)
    return result


# Clamp to >=1: a 0/negative override would make sync_retry/async_retry do
# range(0) -- the wrapped fn is NEVER called, `last` stays None, and the call
# dies on `assert last is not None` with an opaque AssertionError, the provider
# request silently never dispatched. At least one attempt is always made.
# 3 attempts: retries re-generate the FULL output at billed rates, so this is
# the one same-call output-token amplifier — 5 attempts quintupled worst-case
# spend during a provider incident for marginal extra success.
# Each is also a setting ([latency] retry_attempts / retry_base_delay /
# retry_max_delay) read once here at startup; the environment still wins.
def _retry_settings() -> tuple[int, float, float]:
    from ..env_setting import env_or_config_float, env_or_config_int

    return (
        max(1, env_or_config_int("MAVERICK_LLM_RETRY_ATTEMPTS", "latency", "retry_attempts", 3)),
        env_or_config_float("MAVERICK_LLM_RETRY_BASE_DELAY", "latency", "retry_base_delay", 1.0),
        env_or_config_float("MAVERICK_LLM_RETRY_MAX_DELAY", "latency", "retry_max_delay", 30.0),
    )


MAX_ATTEMPTS, BASE_DELAY, MAX_DELAY = _retry_settings()


def _retryable_exception_classes() -> tuple[type, ...]:
    """Resolve retryable exception classes lazily. Optional deps may be missing."""
    classes: list[type] = []
    try:
        import anthropic
        for n in ("RateLimitError", "APIConnectionError", "InternalServerError",
                  "APITimeoutError", "APIStatusError"):
            cls = getattr(anthropic, n, None)
            if cls is not None:
                classes.append(cls)
    except ImportError:
        pass
    try:
        import openai
        for n in ("RateLimitError", "APIConnectionError", "InternalServerError",
                  "APITimeoutError"):
            cls = getattr(openai, n, None)
            if cls is not None:
                classes.append(cls)
    except ImportError:
        pass
    try:
        import httpx
        classes.append(httpx.ReadTimeout)
        classes.append(httpx.ConnectError)
    except ImportError:
        pass
    return tuple(classes) or (Exception,)


def _retry_after_from(exc: Exception) -> float | None:
    """Extract Retry-After (seconds) from a provider exception, if present."""
    response = getattr(exc, "response", None)
    if response is None:
        return None
    headers = getattr(response, "headers", None) or {}
    # Prefer the millisecond header when present: some providers send
    # `retry-after-ms` (sub-second precision) and only fall back to the
    # whole-second `Retry-After`. Without this, an ms hint was ignored and
    # the loop dropped to blind exponential backoff.
    raw_ms = headers.get("retry-after-ms") or headers.get("Retry-After-Ms")
    if raw_ms:
        try:
            return float(raw_ms) / 1000.0
        except (TypeError, ValueError):
            pass
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if not raw:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _compute_delay(attempt: int, exc: Exception) -> float:
    """Honor Retry-After if present; else exponential backoff with jitter.

    A hostile/buggy server returning `Retry-After: -1`
    would feed time.sleep / asyncio.sleep a negative value and raise
    ValueError, killing the retry loop. We clamp to [0, MAX_DELAY].
    """
    explicit = _retry_after_from(exc)
    if explicit is not None:
        return max(0.0, min(explicit, MAX_DELAY))
    delay = min(BASE_DELAY * (2 ** attempt), MAX_DELAY)
    return max(0.0, delay * (0.5 + random.random() * 0.5))


def _is_retryable_status_error(exc: Exception) -> bool:
    """Anthropic APIStatusError covers 429+5xx+4xx; only retry 429/5xx."""
    status = getattr(exc, "status_code", None)
    if status is None:
        return True  # Non-status retryable types are always transient.
    return status == 429 or 500 <= status < 600


# Error classes the taxonomy says must never be retried, even when the
# exception's type/status looked transient: a 401 surfaced as an
# APIStatusError, a content-filter refusal, or a context-overflow won't be
# fixed by waiting. Consulting retry_classifier here is what makes
# threat-model.md's "retry_classifier marks auth errors terminal" true.
_TERMINAL_CLASSES = frozenset({
    "auth", "content_filter", "context_overflow",
})


def _exception_chain(exc: BaseException) -> Iterator[BaseException]:
    """Yield an exception and its explicit/implicit wrappers once each."""
    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        yield current
        # Push context first so an explicit cause is examined first. Traverse
        # suppressed context too: SDK wrappers can hide the transport detail
        # from display, but it must still retain terminal policy semantics.
        context = getattr(current, "__context__", None)
        cause = getattr(current, "__cause__", None)
        if isinstance(context, BaseException):
            pending.append(context)
        if isinstance(cause, BaseException):
            pending.append(cause)


def _is_terminal(exc: Exception) -> bool:
    try:
        from .classifier import classify
    except Exception:  # pragma: no cover - classifier must never break retry
        return False
    try:
        from ..enterprise import EgressBlocked
        egress_types: tuple[type[BaseException], ...] = (EgressBlocked,)
    except Exception:  # pragma: no cover - optional enterprise import safety
        egress_types = ()

    for current in _exception_chain(exc):
        if egress_types and isinstance(current, egress_types):
            return True
        try:
            if classify(current).value in _TERMINAL_CLASSES:
                return True
        except Exception:
            # A hostile provider exception can have a broken ``__str__``.
            # Continue into its cause/context instead of losing a buried
            # fail-closed signal.
            continue
    return False


def sync_retry(fn: Callable[[], T], *, observe_attempts: bool = True) -> T:
    """Retry transient errors; explicit SDK boundaries can own observation."""
    retryable = _retryable_exception_classes()
    last: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        observer, ticket = _before_physical_attempt() if observe_attempts else (None, None)
        try:
            result = fn()
        except retryable as e:
            # Finish accounting from inside this handler. If finalization fails,
            # that failure escapes the retry loop and no further paid call runs.
            _after_physical_attempt(observer, ticket, None, e)
            if not _is_retryable_status_error(e) or _is_terminal(e):
                raise
            last = e
            if attempt == MAX_ATTEMPTS - 1:
                break
            delay = _compute_delay(attempt, e)
            log.warning(
                "LLM call failed (attempt %d/%d): %s; retry in %.1fs",
                attempt + 1, MAX_ATTEMPTS, type(e).__name__, delay,
            )
            time.sleep(delay)
        except BaseException as exc:
            _after_physical_attempt(observer, ticket, None, exc)
            raise
        else:
            _after_physical_attempt(observer, ticket, result, None)
            return result
    assert last is not None
    raise last


async def async_retry(fn: Callable[[], Awaitable[T]], *, observe_attempts: bool = True) -> T:
    """Async retry with the same optional explicit SDK observation boundary."""
    retryable = _retryable_exception_classes()
    last: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        observer, ticket = _before_physical_attempt() if observe_attempts else (None, None)
        try:
            result = await fn()
        except retryable as e:
            _after_physical_attempt(observer, ticket, None, e)
            if not _is_retryable_status_error(e) or _is_terminal(e):
                raise
            last = e
            if attempt == MAX_ATTEMPTS - 1:
                break
            delay = _compute_delay(attempt, e)
            log.warning(
                "LLM call failed (attempt %d/%d): %s; retry in %.1fs",
                attempt + 1, MAX_ATTEMPTS, type(e).__name__, delay,
            )
            await asyncio.sleep(delay)
        except BaseException as exc:
            _after_physical_attempt(observer, ticket, None, exc)
            raise
        else:
            _after_physical_attempt(observer, ticket, result, None)
            return result
    assert last is not None
    raise last
