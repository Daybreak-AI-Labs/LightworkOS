"""Provider-failover policy engine.

Layered on :mod:`maverick.provider_failover` (the simple "try each in order"
chain). The policy engine adds the decisions a chain alone can't express:

  * **error classes** — failing over on a 401 wastes paid calls on every model
    in the chain (the key is wrong everywhere); a 429/timeout/5xx is exactly
    what failover is for. ``classify_error`` buckets an exception
    (auth / bad_request / rate_limit / timeout / network / server / other) and
    the policy says which classes fail over.
  * **cooldowns** — a model that just failed N times is skipped for a window
    instead of being retried at the head of every chain.

All opt-in via ``[provider_failover.policy]``; with the table absent the
engine preserves the v1 semantics exactly (any non-control exception fails
over, no cooldowns)::

    [provider_failover.policy]
    failover_on = ["rate_limit", "timeout", "network", "server", "other"]
    cooldown_s = 120        # 0 disables
    cooldown_after = 2      # failures (per model) that trip the cooldown

Pure logic + an injectable clock; unit-tested without a provider.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Callable

from .provider_failover import should_retry_llm_error

log = logging.getLogger(__name__)

CLASSES = ("auth", "bad_request", "rate_limit", "timeout", "network", "server", "other")
_DEFAULT_FAILOVER_ON = frozenset({"rate_limit", "timeout", "network", "server", "other"})

_AUTH_MARKERS = ("401", "403", "unauthorized", "forbidden", "invalid api key",
                 "invalid_api_key", "authentication", "permission")
_BAD_REQUEST_MARKERS = ("400", "404", "422", "invalid_request", "bad request",
                        "not_found_error", "context length", "maximum context")
_RATE_MARKERS = ("429", "rate limit", "rate_limit", "overloaded", "quota")
_TIMEOUT_MARKERS = ("timeout", "timed out", "deadline")
_NETWORK_MARKERS = ("connection", "dns", "unreachable", "refused", "reset by peer",
                    "ssl", "network")
_SERVER_MARKERS = ("500", "502", "503", "504", "server error", "internal error",
                   "api_error", "bad gateway")


def classify_error(exc: BaseException) -> str:
    """Bucket a provider exception into one of :data:`CLASSES`.

    Prefers a numeric ``status_code`` attribute (Anthropic/OpenAI SDK error
    shapes) and falls back to message heuristics. Unknown -> "other".
    """
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        if status in (401, 403):
            return "auth"
        if status == 429:
            return "rate_limit"
        if 400 <= status < 500:
            return "bad_request"
        if status >= 500:
            return "server"
    text = f"{type(exc).__name__}: {exc}".lower()
    if isinstance(exc, TimeoutError) or _mentions(text, _TIMEOUT_MARKERS):
        return "timeout"
    if _mentions(text, _RATE_MARKERS):
        return "rate_limit"
    if _mentions(text, _AUTH_MARKERS):
        return "auth"
    if _mentions(text, _SERVER_MARKERS):
        return "server"
    if isinstance(exc, (ConnectionError, OSError)) or _mentions(text, _NETWORK_MARKERS):
        return "network"
    if _mentions(text, _BAD_REQUEST_MARKERS):
        return "bad_request"
    return "other"


def _mentions(text: str, markers: tuple[str, ...]) -> bool:
    """Whether ``text`` contains a marker. A status code must stand alone, so
    "max_tokens 5000" or "request id 4012" is not a 500 or a 401."""
    return any(
        re.search(rf"(?<!\d){m}(?!\d)", text) if m.isdigit() else m in text
        for m in markers
    )


def _policy_cfg() -> dict:
    try:
        from .config import load_config
        return (((load_config() or {}).get("provider_failover") or {}).get("policy") or {})
    except Exception:  # pragma: no cover -- config never blocks a call
        return {}


def policy_configured() -> bool:
    return bool(_policy_cfg())


def failover_classes() -> frozenset[str]:
    """Configured error classes that may fail over (default set when unset or
    when no listed name is a known class). An explicit empty list means never
    fail over."""
    raw = _policy_cfg().get("failover_on")
    if isinstance(raw, (list, tuple, set)):
        if not raw:
            return frozenset()
        names = {str(c).strip().lower() for c in raw}
        valid = frozenset(n for n in names if n in CLASSES)
        if valid:
            return valid
    return _DEFAULT_FAILOVER_ON


def policy_should_retry(exc: Exception) -> bool:
    """The chain's ``should_retry`` with the policy engine applied.

    Control-plane signals (budget/egress/preflight/consent) never fail over —
    that's :func:`should_retry_llm_error` and it always applies. With no
    ``[provider_failover.policy]`` table the decision stops there (v1
    behavior). With a policy, the exception's class must also be enabled.
    """
    if not should_retry_llm_error(exc):
        return False
    if not policy_configured():
        return True
    return classify_error(exc) in failover_classes()


class CooldownLedger:
    """Per-model failure ledger with a cooldown window.

    ``record_failure(model)`` counts strikes; once a model accrues
    ``threshold`` failures it is in cooldown for ``window_s`` (re-failing while
    cooled re-arms the window). ``record_success(model)`` clears its strikes.
    Thread-safe; the clock is injectable for tests.
    """

    def __init__(self, *, window_s: float, threshold: int = 2,
                 clock: Callable[[], float] = time.monotonic):
        if window_s < 0:
            raise ValueError("window_s must be >= 0")
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        self.window_s = float(window_s)
        self.threshold = int(threshold)
        self._clock = clock
        self._lock = threading.Lock()
        self._strikes: dict[str, int] = {}
        self._cooled_until: dict[str, float] = {}

    def record_failure(self, model: str) -> None:
        if self.window_s <= 0:
            return
        with self._lock:
            n = self._strikes.get(model, 0) + 1
            self._strikes[model] = n
            if n >= self.threshold:
                self._cooled_until[model] = self._clock() + self.window_s

    def record_success(self, model: str) -> None:
        with self._lock:
            self._strikes.pop(model, None)
            self._cooled_until.pop(model, None)

    def in_cooldown(self, model: str) -> bool:
        with self._lock:
            until = self._cooled_until.get(model)
            if until is None:
                return False
            if self._clock() >= until:
                # Window elapsed: lift the cooldown and reset strikes.
                del self._cooled_until[model]
                self._strikes.pop(model, None)
                return False
            return True


_ledger: CooldownLedger | None = None
_ledger_lock = threading.Lock()


def shared_ledger() -> CooldownLedger:
    """Process-wide ledger built from config (rebuilt only on first use)."""
    global _ledger
    with _ledger_lock:
        if _ledger is None:
            cfg = _policy_cfg()
            try:
                window = max(0.0, float(cfg.get("cooldown_s", 0)))
            except (TypeError, ValueError):
                window = 0.0
            try:
                threshold = max(1, int(cfg.get("cooldown_after", 2)))
            except (TypeError, ValueError):
                threshold = 2
            _ledger = CooldownLedger(window_s=window, threshold=threshold)
        return _ledger


def reset_shared_ledger() -> None:
    """Drop the process ledger (tests / config reload)."""
    global _ledger
    with _ledger_lock:
        _ledger = None


def order_chain(candidates: list[str], ledger: CooldownLedger | None = None) -> list[str]:
    """Filter cooled-down models out of a failover chain.

    Keeps order otherwise. If *every* candidate is cooling, the original list
    is returned unchanged — a degraded attempt beats refusing to try at all
    (mirrors the cost router's unhealthy-exclusion philosophy).
    """
    ledger = ledger if ledger is not None else shared_ledger()
    hot = [m for m in candidates if not ledger.in_cooldown(m)]
    return hot or list(candidates)


__all__ = [
    "CLASSES", "classify_error", "failover_classes", "policy_configured",
    "policy_should_retry", "CooldownLedger", "shared_ledger",
    "reset_shared_ledger", "order_chain",
]
