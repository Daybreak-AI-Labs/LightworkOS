"""Error-class taxonomy + retry policy router.

When a provider call fails, we want different retry strategies for
different failure types:

  - rate_limit          -> back off long, respect Retry-After
  - transient_network   -> back off short, retry many times
  - server_5xx          -> back off medium, fewer retries
  - content_filter      -> don't retry; surface to caller (refusal)
  - auth                -> don't retry; user must fix config
  - context_overflow    -> don't retry; need to compact + redo
  - malformed_response  -> retry once with same prompt; could be a fluke
  - unknown             -> conservative: short backoff, 2 retries

This module is a thin classifier + policy table. Existing retry.py
already implements exponential backoff; this gives it shape.
"""
from __future__ import annotations

import logging
import random
import re
from dataclasses import dataclass
from enum import Enum

log = logging.getLogger(__name__)


class ErrorClass(str, Enum):
    RATE_LIMIT        = "rate_limit"
    TRANSIENT_NETWORK = "transient_network"
    SERVER_5XX        = "server_5xx"
    CONTENT_FILTER    = "content_filter"
    AUTH              = "auth"
    CONTEXT_OVERFLOW  = "context_overflow"
    MALFORMED         = "malformed_response"
    UNKNOWN           = "unknown"


@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int
    initial_delay_seconds: float
    backoff_multiplier: float
    max_delay_seconds: float
    retry: bool  # if False, the error is terminal


POLICIES: dict[ErrorClass, RetryPolicy] = {
    ErrorClass.RATE_LIMIT:        RetryPolicy(6, 10.0, 2.0, 120.0, True),
    ErrorClass.TRANSIENT_NETWORK: RetryPolicy(8,  0.5, 2.0,  20.0, True),
    ErrorClass.SERVER_5XX:        RetryPolicy(4,  2.0, 2.0,  30.0, True),
    ErrorClass.CONTENT_FILTER:    RetryPolicy(0,  0.0, 1.0,   0.0, False),
    ErrorClass.AUTH:              RetryPolicy(0,  0.0, 1.0,   0.0, False),
    ErrorClass.CONTEXT_OVERFLOW:  RetryPolicy(0,  0.0, 1.0,   0.0, False),
    ErrorClass.MALFORMED:         RetryPolicy(1,  1.0, 1.0,   2.0, True),
    ErrorClass.UNKNOWN:           RetryPolicy(2,  1.0, 2.0,   8.0, True),
}


# Lower-cased patterns to substring-match against str(exception).
_PATTERNS: list[tuple[ErrorClass, re.Pattern]] = [
    (ErrorClass.RATE_LIMIT,        re.compile(r"\b429\b|rate.?limit|too many requests|quota", re.IGNORECASE)),
    (ErrorClass.AUTH,              re.compile(r"\b401\b|\b403\b|unauthorized|forbidden|invalid.api.key|authentication", re.IGNORECASE)),
    # "refus" alone is too broad (e.g. "Connection refused" is a
    # network error, not a content filter). Require a content-related
    # marker.
    (ErrorClass.CONTENT_FILTER,    re.compile(
        r"content.?(filter|policy)|"
        r"refusal|"
        r"(?:refus(?:ed|ing)?\s+(?:by|due\s+to|because)\s+(?:safety|policy|content))|"
        r"\bharmful\b|disallow|"
        r"safety\s+(?:filter|guidelines?|policy)",
        re.IGNORECASE,
    )),
    (ErrorClass.CONTEXT_OVERFLOW,  re.compile(r"context.{0,4}(length|window|overflow)|prompt.{0,4}too.{0,4}long|maximum context", re.IGNORECASE)),
    # Anchor the bare 5xx number to an HTTP context. The old `\b50[0-9]\b`
    # matched any standalone 500-509 token in a message ("500 tokens",
    # "queued 503 jobs") and mis-classified a non-server error as retryable.
    # Require an HTTP/status/error/code cue near the number; the phrase
    # alternatives (internal server / service unavailable / bad/gateway
    # timeout) stay. The structured `status_code` path in classify() handles
    # the typed case independently.
    (ErrorClass.SERVER_5XX,        re.compile(
        r"(?:\b(?:HTTP|status(?:\s*code)?|error|code|response)\b[^\n]{0,12}?\b50[0-9]\b)"
        r"|(?:\b50[0-9]\b\s*(?:internal|server|service|gateway|error|status))"
        r"|internal[ .]server|service unavailable|bad gateway|gateway time", re.IGNORECASE)),
    (ErrorClass.TRANSIENT_NETWORK, re.compile(r"timeout|timed out|connection (?:reset|refused|aborted|error)|temporary|dns", re.IGNORECASE)),
    (ErrorClass.MALFORMED,         re.compile(r"json.?decode|malformed|invalid response|unexpected.*format", re.IGNORECASE)),
]


def classify(exc: BaseException) -> ErrorClass:
    """Map an exception to an ErrorClass. Substring-based pattern match."""
    if exc is None:
        return ErrorClass.UNKNOWN
    # Some HTTP libraries put the status code on the exception itself.
    code = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    if isinstance(code, int):
        if code == 429:
            return ErrorClass.RATE_LIMIT
        if code in (401, 403):
            return ErrorClass.AUTH
        if 500 <= code < 600:
            return ErrorClass.SERVER_5XX
    text = f"{type(exc).__name__}: {exc}"
    for klass, pat in _PATTERNS:
        if pat.search(text):
            return klass
    return ErrorClass.UNKNOWN


def policy_for(exc: BaseException) -> RetryPolicy:
    """Convenience: ``classify`` + lookup."""
    return POLICIES[classify(exc)]


def should_retry(exc: BaseException, *, attempts_so_far: int) -> bool:
    """True iff the policy for this exception allows another retry."""
    pol = policy_for(exc)
    return pol.retry and attempts_so_far < pol.max_retries


def next_delay(exc: BaseException, *, attempts_so_far: int) -> float:
    """Compute the next backoff delay for the given exception class.

    Includes equal-jitter (50-100% of the computed delay), matching the LLM
    retry path (``retry.__init__._compute_delay``). Without it the backoff is
    fully deterministic, so a provider-wide 429/5xx makes every retry-safe
    caller (this feeds ``tool_reliability.run_with_retry``, the chokepoint for
    ~80 tools) compute the identical 10/20/40/80/120s schedule and re-fire in
    lockstep -- a synchronized retry storm against the recovering dependency.
    Decorrelating the sleeps spreads the herd."""
    pol = policy_for(exc)
    if not pol.retry:
        return 0.0
    # Clamp the exponent before the power: attempts_so_far is caller-supplied
    # and unbounded, and 2.0 ** big raises OverflowError before the min() clamp.
    delay = pol.initial_delay_seconds * (pol.backoff_multiplier ** min(attempts_so_far, 32))
    delay = min(delay, pol.max_delay_seconds)
    return delay * (0.5 + random.random() * 0.5)


__all__ = [
    "ErrorClass",
    "RetryPolicy",
    "POLICIES",
    "classify",
    "policy_for",
    "should_retry",
    "next_delay",
]
