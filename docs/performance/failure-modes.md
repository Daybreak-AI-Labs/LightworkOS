# Failure-mode taxonomy

Provider calls made by Lightwork agent runs fail in a small set of ways. This
page lists the canonical error classes so that:

1. Every provider error maps to one class.
2. Retries are routed per class (implemented in `maverick/retry/classifier.py`).
3. Failure patterns can be compared across releases.

Tests: the `test_retry_classifier_*` tests in `packages/maverick-core/tests/`.

Retry delays grow exponentially up to the class's cap and are jittered to 50–100%
of the computed value, so many callers retrying after the same outage do not
retry in lockstep.

## Classes

### `rate_limit`
HTTP 429 / explicit "rate limit" / "quota" / "too many requests"
in the error message. Up to 6 retries with long backoff (10 s, doubling, capped
at 120 s); the LLM retry path honours a `Retry-After` header when present.

### `transient_network`
Connection timeouts, DNS failures, connection-reset, connection-
refused. Up to 8 retries with short backoff (0.5 s, doubling, capped at 20 s).

### `server_5xx`
Provider's fault. 500, 502, 503, 504. Up to 4 retries with medium backoff
(2 s, doubling, capped at 30 s). If still failing, fail loud — there's nothing
the agent can do.

### `content_filter`
Provider refused on content-policy grounds. **Terminal**: do not
retry. The refusal is surfaced to the caller so the user can decide
whether the request was actually disallowed or whether the provider
was over-cautious.

### `auth`
401 / 403 / "invalid API key" / "authentication failed". **Terminal**:
do not retry. The user has to fix config.

### `context_overflow`
"context length exceeded" / "prompt too long for window" / "maximum
context". **Terminal**: the retry layer does not retry it as-is; the context
has to be compacted before the request is sent again.

### `malformed_response`
Provider returned a 200 OK but the body didn't parse (truncated
JSON, broken SSE chunk). Retry once after 1 s — usually a fluke.

### `unknown`
Catch-all. Conservative: 2 retries, starting at 1 s and capped at 8 s.

## How errors are classified

`maverick/retry/classifier.py`:

1. If the exception has an integer `status_code` or `code` attribute, map 429,
   401/403 and 5xx by code.
2. Otherwise, regex-match against `f"{type(exc).__name__}: {exc}"`.
3. Default to `unknown`.

Patterns are deliberately permissive: false positives (wrongly
classified) are cheaper than false negatives (mis-routed retry
strategy). Adding a new pattern requires a test in `test_retry_
classifier_substring_patterns`.

The LLM retry path (`maverick/retry/__init__.py`) also consults the classifier:
`auth`, `content_filter` and `context_overflow` are never retried there, even
when the exception type or status looks transient.

## Run-level failure telemetry

Failed runs are recorded separately by `maverick/failure_telemetry.py`, using a
coarser set of run-level modes (`budget`, `timeout`, `network`, `auth`,
`shield`, `sandbox`, `cancelled`, `error`). `maverick failures` summarizes the
local record. Telemetry is on by default and stays on disk; set
`[telemetry] failure_modes = false` or `MAVERICK_FAILURE_TELEMETRY=0` to turn it
off. The retry classes above are not recorded per run.

## Open work

- **Per-class regression tracking**: record the retry class of each failed
  call and compare frequency, retry success rate and time to resolution across
  releases.
- **Provider-specific error class extensions**: some providers expose richer
  error categories (e.g., Anthropic's `overloaded_error` vs `api_error`) that
  currently map to the same class.
- **Adaptive retry policy**: learn per-task-class `max_retries` from observed
  outcomes instead of a static policy table.
- **Cross-provider class-frequency dashboard**: show which providers fail in
  which ways over time, on the dashboard.
