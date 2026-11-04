"""Provider failover (opt-in, default OFF).

Declare fallback model chains so a transient provider failure auto-switches to
the next model instead of failing the call. Off by default; configure::

    [provider_failover]
    chains = { "anthropic:claude-opus-4-8" = ["openai:gpt-4.1", "gemini:gemini-2"] }

The core `failover` / `afailover` helpers are pure "try each until success" over
callables, unit-tested with mocks; `fallback_models` reads the config (returns []
when unset -> failover is a no-op). Wiring lives in `LLM.complete` /
`complete_async`, which skip all of this entirely when no chain is configured.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def fallback_models(primary: str) -> list[str]:
    """Configured fallback chain for ``primary`` (``[]`` when failover is off)."""
    try:
        from .config import load_config
        chains = ((load_config() or {}).get("provider_failover") or {}).get("chains") or {}
        fb = chains.get(primary)
        if isinstance(fb, list):
            return [str(m) for m in fb if str(m) and str(m) != primary]
    except Exception:  # pragma: no cover -- never block a call on a config error
        pass
    return []


def should_retry_llm_error(exc: Exception) -> bool:
    """Return False for LLM control/policy exceptions that failover must not mask.

    Provider failover is meant for transient provider/network failures. Budget,
    egress, preflight, and consent denials are deliberate fail-closed control
    signals; trying another model cannot safely remediate them and may dispatch
    extra paid or disallowed requests.
    """
    non_retryable: list[type[BaseException]] = []
    try:
        from .budget import BudgetExceeded, UsageAccountingError
        non_retryable.append(BudgetExceeded)
        # A gateway that mis-reports usage has already billed the call; another
        # model cannot repair its accounting, so failover must not mask it.
        non_retryable.append(UsageAccountingError)
    except Exception:  # pragma: no cover -- import failure should not block retry policy
        pass
    try:
        from .enterprise import EgressBlocked
        non_retryable.append(EgressBlocked)
    except Exception:  # pragma: no cover
        pass
    try:
        from .preflight import PreflightFailed
        non_retryable.append(PreflightFailed)
    except Exception:  # pragma: no cover
        pass
    try:
        from .provider_cost_cap import ProviderAccountingUnavailable
        non_retryable.append(ProviderAccountingUnavailable)
    except Exception:  # pragma: no cover
        pass
    try:
        from .llm import ModelNotAllowedError
        non_retryable.append(ModelNotAllowedError)
    except Exception:  # pragma: no cover
        pass
    try:
        from .safety.consent import ConsentDenied
        non_retryable.append(ConsentDenied)
    except Exception:  # pragma: no cover
        pass
    if not non_retryable:
        return True
    try:
        from .retry import _exception_chain
        chain = _exception_chain(exc)
    except Exception:  # pragma: no cover - retry helper import is fail-safe
        chain = (exc,)
    terminal = tuple(non_retryable)
    return not any(isinstance(current, terminal) for current in chain)


def _cooldown_ledger():
    """The process cooldown ledger, or None if unavailable. Feeding it here is
    what makes ``order_chain``'s cooldown skip actually fire: without recording
    failures/successes on the live path, ``in_cooldown`` is always False and the
    configured ``cooldown_s``/``cooldown_after`` policy is a dead no-op. The
    ledger itself is a no-op when ``cooldown_s`` is unset (window_s <= 0)."""
    try:
        from .failover_policy import shared_ledger
        return shared_ledger()
    except Exception:  # pragma: no cover -- never block a call on the ledger
        return None


def failover(attempts, *, should_retry=None):
    """Call each ``(label, thunk)`` in order; return the first success.

    On exception, log and try the next — unless ``should_retry(exc)`` is False
    (then re-raise immediately, e.g. for a budget/egress error that another model
    won't fix). Re-raises the last exception if all fail. Empty -> ValueError."""
    attempts = list(attempts)
    if not attempts:
        raise ValueError("failover: no attempts")
    ledger = _cooldown_ledger()
    last: Exception | None = None
    for label, thunk in attempts:
        try:
            result = thunk()
            if ledger is not None:
                ledger.record_success(label)
            return result
        except Exception as e:  # noqa: BLE001 -- failover boundary
            last = e
            if should_retry is not None and not should_retry(e):
                # Control-signal (budget/egress/...), not a provider failure --
                # re-raise without cooling a model that didn't actually fail.
                raise
            if ledger is not None:
                ledger.record_failure(label)
            log.warning("provider failover: %s failed (%s); trying next",
                        label, type(e).__name__)
    assert last is not None
    raise last


async def afailover(attempts, *, should_retry=None):
    """Async `failover`: each thunk returns an awaitable; return the first success."""
    attempts = list(attempts)
    if not attempts:
        raise ValueError("failover: no attempts")
    ledger = _cooldown_ledger()
    last: Exception | None = None
    for label, thunk in attempts:
        try:
            result = await thunk()
            if ledger is not None:
                ledger.record_success(label)
            return result
        except Exception as e:  # noqa: BLE001 -- failover boundary
            last = e
            if should_retry is not None and not should_retry(e):
                raise
            if ledger is not None:
                ledger.record_failure(label)
            log.warning("provider failover: %s failed (%s); trying next",
                        label, type(e).__name__)
    assert last is not None
    raise last


__all__ = ["fallback_models", "should_retry_llm_error", "failover", "afailover"]
