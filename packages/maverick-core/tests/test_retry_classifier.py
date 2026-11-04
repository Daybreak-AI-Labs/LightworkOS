"""Tests for the retry classifier (maverick.retry.classifier)."""
from __future__ import annotations

import pytest
from maverick.retry.classifier import ErrorClass, classify

# ---------- retry classifier 5xx anchoring ----------

class _Err(Exception):
    pass


def test_retry_5xx_no_overmatch_on_bare_number():
    # A standalone 5xx-range token in prose must NOT be classified retryable.
    assert classify(_Err("used 500 tokens")) is not ErrorClass.SERVER_5XX
    assert classify(_Err("queued 503 jobs")) is not ErrorClass.SERVER_5XX


def test_retry_5xx_still_matches_http_context():
    assert classify(_Err("HTTP 503 from upstream")) is ErrorClass.SERVER_5XX
    assert classify(_Err("500 Internal Server Error")) is ErrorClass.SERVER_5XX
    assert classify(_Err("service unavailable")) is ErrorClass.SERVER_5XX


def test_retry_5xx_structured_status_code_unaffected():
    class _H(Exception):
        status_code = 502
    assert classify(_H("boom")) is ErrorClass.SERVER_5XX


# ---------- retry_classifier ----------

@pytest.mark.parametrize("err_msg,expected", [
    ("HTTPError: 429 Too Many Requests",           "rate_limit"),
    ("rate limit exceeded for model",              "rate_limit"),
    ("AuthenticationError: 401 Unauthorized",      "auth"),
    ("invalid api key provided",                   "auth"),
    ("RefusalError: content policy violation",     "content_filter"),
    ("Your request was refused due to safety",     "content_filter"),
    ("HTTPError: 500 Internal Server Error",       "server_5xx"),
    ("503 Service Unavailable",                    "server_5xx"),
    ("TimeoutError: Connection timed out",         "transient_network"),
    ("Connection refused on api.example.com",      "transient_network"),
    ("ContextLengthExceeded: maximum context",     "context_overflow"),
    ("prompt too long for window",                 "context_overflow"),
    ("JSONDecodeError: malformed response",        "malformed_response"),
])
def test_retry_classifier_substring_patterns(err_msg, expected):
    from maverick.retry.classifier import classify
    err = RuntimeError(err_msg)
    assert classify(err).value == expected


def test_retry_classifier_status_code_attr():
    """Some HTTP libraries put the status on the exception."""
    from maverick.retry.classifier import ErrorClass, classify

    class _HttpError(Exception):
        def __init__(self, code: int):
            super().__init__(f"HTTP {code}")
            self.status_code = code

    assert classify(_HttpError(429)) == ErrorClass.RATE_LIMIT
    assert classify(_HttpError(401)) == ErrorClass.AUTH
    assert classify(_HttpError(503)) == ErrorClass.SERVER_5XX


def test_retry_classifier_unknown_defaults():
    from maverick.retry.classifier import ErrorClass, classify
    assert classify(RuntimeError("weird unhelpful message")) == ErrorClass.UNKNOWN


def test_retry_classifier_should_retry_respects_max():
    from maverick.retry.classifier import should_retry
    err = RuntimeError("429 Too Many Requests")
    assert should_retry(err, attempts_so_far=0)
    assert should_retry(err, attempts_so_far=5)
    assert not should_retry(err, attempts_so_far=999)


def test_retry_classifier_terminal_errors_dont_retry():
    """Auth + content filter + context overflow are terminal."""
    from maverick.retry.classifier import should_retry
    assert not should_retry(RuntimeError("401 Unauthorized"), attempts_so_far=0)
    assert not should_retry(RuntimeError("content filter"), attempts_so_far=0)
    assert not should_retry(RuntimeError("context length exceeded"), attempts_so_far=0)


def test_retry_classifier_next_delay_grows():
    from maverick.retry.classifier import next_delay
    err = RuntimeError("Connection reset")  # transient_network
    d0 = next_delay(err, attempts_so_far=0)
    d3 = next_delay(err, attempts_so_far=3)
    assert 0 < d0 < d3


def test_retry_classifier_terminal_zero_delay():
    from maverick.retry.classifier import next_delay
    assert next_delay(RuntimeError("401 Unauthorized"), attempts_so_far=0) == 0.0


def test_retry_classifier_next_delay_is_jittered():
    # No jitter -> every caller hitting the same class at once retries in
    # lockstep (synchronized storm against a recovering provider). Delays must
    # be decorrelated and bounded to (0.5*base, base].
    from maverick.retry.classifier import next_delay
    err = RuntimeError("429 rate limit")  # rate_limit: base 10s at attempt 0
    samples = {next_delay(err, attempts_so_far=0) for _ in range(50)}
    assert len(samples) > 1                 # not deterministic
    assert all(5.0 <= d < 10.0 for d in samples)  # equal-jitter band of 10s
