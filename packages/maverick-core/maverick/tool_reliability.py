"""Shared reliability policy for tool dispatch.

~80 tools are thin API wrappers with no retry/backoff of their own. Rather
than make each author hand-roll a retry loop, ``ToolRegistry.run`` routes
every call through this one policy:

  * Only genuinely *transient* upstream failures are retried -- rate limits,
    network errors, and 5xx -- reusing the classified backoff the LLM path
    already uses (``retry_classifier``). A generic tool exception (bad args,
    missing file, a logic bug) classifies as UNKNOWN and is **not** retried:
    re-running a deterministic failure just burns budget and wall-clock.
  * Ordinary exceptions require a classified low/medium-risk tool. Shared
    connector outcomes additionally identify explicit REST GET operations,
    including a GET on a mixed read/write tool. Writes and arbitrary GraphQL
    documents never qualify for that override. Ambiguous writes require
    reconciliation; each extra attempt spends another bound Agent tool slot.

Fail-open: the risk lookup never blocks a call, and a non-retryable error or
tool re-raises so the registry keeps its own error-to-string handling.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import TypeVar

from .connector_attempts import (
    CONTROL_ERRORS,
    ConnectorResult,
    invocation_scope,
)
from .retry import classifier as retry_classifier

log = logging.getLogger(__name__)

T = TypeVar("T")

# Classes that mean "the upstream was flaky", not "this call is wrong". A
# deterministic tool error (UNKNOWN/MALFORMED/AUTH/...) is left to the caller.
_RETRYABLE = frozenset({
    retry_classifier.ErrorClass.RATE_LIMIT,
    retry_classifier.ErrorClass.TRANSIENT_NETWORK,
    retry_classifier.ErrorClass.SERVER_5XX,
})


def is_retry_safe(name: str) -> bool:
    """Whether a tool may be auto-retried on a transient failure.

    Keyed off the existing per-tool risk tier: low/medium tools are reads /
    lookups / queries (idempotent enough to re-fire); high-risk tools mutate
    external state and must not be retried automatically. Unknown / errored
    classification is treated conservatively as not-retry-safe.
    """
    try:
        from .safety.tool_risk import tool_risk, tool_risk_is_classified
        # An unknown plugin happens to inherit the compatibility display level
        # "medium", but has never been reviewed as read/idempotent. Treat it as
        # non-retry-safe until a built-in or configuration explicitly classifies
        # it; this same predicate drives flow approval/quarantine boundaries.
        return tool_risk_is_classified(name) and tool_risk(name) != "high"
    except Exception:  # pragma: no cover -- classification never blocks a call
        return False


async def run_with_retry(name: str, call: Callable[[], Awaitable[T]]) -> T:
    """Invoke ``call`` (a zero-arg awaitable factory), retrying transient
    failures for retry-safe tools.

    Re-raises the last exception when retries are exhausted, the error isn't
    transient, or the tool isn't retry-safe -- the caller keeps its own
    error handling.
    """
    attempts = 0
    with invocation_scope() as invocation:
        while True:
            try:
                result = await call()
            except CONTROL_ERRORS:
                raise
            except Exception as exc:
                if getattr(exc, "tool_execution_unknown", False):
                    raise  # partial stream/cleanup failure is never replay-safe
                klass = retry_classifier.classify(exc)
                if not is_retry_safe(name) or klass not in _RETRYABLE or not retry_classifier.should_retry(
                    exc, attempts_so_far=attempts
                ):
                    raise
                delay = retry_classifier.next_delay(exc, attempts_so_far=attempts)
            else:
                if not isinstance(result, ConnectorResult) or not result.attempt.retryable:
                    return result
                outcome = result.attempt
                if (outcome.request_id != invocation.request_id
                        or outcome.attempt != invocation.attempts or outcome.attempt < 1):
                    return result  # Foreign, cached or forged attempt metadata.
                if invocation.attempts >= invocation.limits.max_attempts:
                    return result
                # Only a trusted shared engine's explicit safe-read outcome
                # overrides a mixed connector's name-level risk for retry.
                # Arbitrary GraphQL documents and writes never qualify.
                error = _ConnectorRetryError(outcome.error_class, outcome.status_code)
                delay = retry_classifier.next_delay(error, attempts_so_far=attempts)
                if outcome.retry_after is not None:
                    delay = max(delay, outcome.retry_after)
                if delay >= invocation.remaining():
                    return result
            attempts += 1
            log.warning("tool %s transient failure; retry %d in %.1fs", name, attempts, delay)
            await asyncio.sleep(delay)
            invocation.check()
            # The initial tool invocation was already accounted by Agent. Each
            # additional physical attempt must spend another tool-call slot.
            if invocation.budget is not None:
                invocation.budget.record_tool_call()


class _ConnectorRetryError(Exception):
    """Fixed class marker for the existing backoff calculator; no raw error."""

    def __init__(self, error_class: str | None, status_code: int | None):
        self.status_code = status_code
        super().__init__("connection error" if error_class == "transient_network" else error_class)


__all__ = ["is_retry_safe", "run_with_retry"]
