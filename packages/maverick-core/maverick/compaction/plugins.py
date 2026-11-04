"""Compaction plug-in API.

Context compaction is currently one built-in algorithm (:func:`maverick.
compaction.compact_messages`). This is the extension point that lets a
deployment or plugin register its **own** compaction strategy — a graph-
structured one, a domain-specific summarizer, a learned model — and select it
by name, without forking the kernel.

A strategy is any object with a ``name`` and a ``compact(messages, **kw) ->
list[dict]``. Async agent dispatch additionally requires ``compact_async``;
sync-only plugins take the local heuristic path there. The built-in heuristic
registers itself as ``"heuristic"`` (the
default), so unchanged deployments behave exactly as before; ``compact_with``
dispatches to the configured strategy (``[context] compaction_strategy`` / env
``MAVERICK_COMPACTION_STRATEGY``) and **fails safe** to the built-in when the
named strategy is unknown, so a typo degrades to working compaction rather than
to none.

Selection precedence in :func:`compact_with`:

1. an explicit ``strategy=`` argument;
2. an explicitly configured name (env ``MAVERICK_COMPACTION_STRATEGY`` or
   ``[context] compaction_strategy``) — this always beats the hybrid picker,
   with a one-time warning when both are set;
3. the **compaction v6 hybrid picker** (opt-in via ``[compaction] hybrid`` /
   ``MAVERICK_COMPACTION_HYBRID``): the ledger-learned picker
   (:mod:`maverick.compaction.hybrid`) chooses an abstract strategy, which
   maps onto a registered implementation (``_ABSTRACT_TO_LIVE``); the achieved
   shrink is recorded back into the picker's outcome ledger so selection
   improves on this instance's own results — every step fail-open;
4. the built-in ``heuristic``.
"""
from __future__ import annotations

import logging
import os
import threading
from collections import OrderedDict
from typing import Protocol, runtime_checkable

from ..run_outcome import GoalCancelled
from .requests import STOP_ERRORS

STOP_ERRORS = (*STOP_ERRORS, GoalCancelled)

log = logging.getLogger(__name__)


@runtime_checkable
class CompactionStrategy(Protocol):
    name: str

    def compact(self, messages: list[dict], **kwargs) -> list[dict]: ...


class _HeuristicStrategy:
    """The shipping built-in: tool-result digest + recent-turn passthrough."""

    name = "heuristic"

    def compact(self, messages: list[dict], **kwargs) -> list[dict]:
        from . import compact_messages
        allowed = {k: kwargs[k]
                   for k in ("keep_recent", "max_tool_bytes", "max_total_bytes")
                   if k in kwargs}
        return compact_messages(messages, **allowed)


    async def compact_async(self, messages: list[dict], **kwargs) -> list[dict]:
        return self.compact(messages, **kwargs)


_REGISTRY: dict[str, CompactionStrategy] = {}
_DEFAULT = "heuristic"


def register(strategy: CompactionStrategy, *, replace: bool = False) -> None:
    """Register a compaction strategy under ``strategy.name``."""
    name = getattr(strategy, "name", None)
    if not isinstance(name, str) or not name:
        raise ValueError("strategy must have a non-empty string 'name'")
    if not callable(getattr(strategy, "compact", None)):
        raise ValueError(f"strategy {name!r} must have a callable compact()")
    if name in _REGISTRY and not replace:
        raise ValueError(f"compaction strategy {name!r} already registered")
    _REGISTRY[name] = strategy


def get(name: str) -> CompactionStrategy | None:
    return _REGISTRY.get(name)


def available() -> list[str]:
    return sorted(_REGISTRY)


def _configured_name() -> str:
    """The explicitly configured strategy name, or ``""`` when unset."""
    env = os.environ.get("MAVERICK_COMPACTION_STRATEGY", "").strip()
    if env:
        return env
    try:
        from ..config import load_config
        return str(((load_config() or {}).get("context") or {})
                   .get("compaction_strategy", "")).strip()
    except Exception:  # pragma: no cover -- config never blocks compaction
        return ""


# Compaction v6 wiring. The hybrid picker speaks the rule ladder's abstract
# shrink vocabulary (tools/compaction_classifier); this registry speaks
# implementation names. The reconciliation:
#   - truncate / structural -> "heuristic": compact_messages IS the structural
#     shrink (drop-oldest digests + content-addressed refs), and is also the
#     right cheap path when there is too little to gain;
#   - retrieval -> "graph": the entity-relation digest is the index half of
#     "index + fetch on demand"; the structural refs it funnels through keep
#     the re-run-the-tool retrieval half;
#   - summarize -> "learned": the LLM summarizer (degrades deterministically
#     to the structural shrink without an llm seam).
_ABSTRACT_TO_LIVE = {
    "truncate": "heuristic",
    "structural": "heuristic",
    "retrieval": "graph",
    "summarize": "learned",
}

# Outcomes are recorded only for windows the ladder would not call "too small
# to compact" (< ~4000 tokens ~= 16000 chars): a tiny window shrinks under no
# strategy, so recording it would only add uniform noise to every arm.
_HYBRID_RECORD_MIN_CHARS = 16_000

_HYBRID_PICKERS = OrderedDict()
_HYBRID_PICKERS_LOCK = threading.Lock()
_HYBRID_PICKERS_LIMIT = 64
_HYBRID_SHADOWED_WARNED = False


def _hybrid_picker():
    """Reuse a picker only within the current tenant and exact native storage."""
    from ..paths import canonical_tenant_id, current_tenant_id_strict
    from .hybrid import HybridPicker, default_ledger_path, default_weights_path

    tenant = current_tenant_id_strict()
    tenant = canonical_tenant_id(tenant) if tenant is not None else None
    ledger, weights = default_ledger_path(), default_weights_path()
    key = (tenant, os.path.normcase(str(ledger.resolve())),
           os.path.normcase(str(weights.resolve())))
    with _HYBRID_PICKERS_LOCK:
        picker = _HYBRID_PICKERS.get(key)
        if picker is not None:
            _HYBRID_PICKERS.move_to_end(key)
            return picker
    # Native history loading may wait for storage; never hold the cache lock
    # across it, or across actual compaction/outcome writes.
    candidate = HybridPicker(ledger_path=ledger, weights_path=weights)
    with _HYBRID_PICKERS_LOCK:
        picker = _HYBRID_PICKERS.setdefault(key, candidate)
        _HYBRID_PICKERS.move_to_end(key)
        while len(_HYBRID_PICKERS) > _HYBRID_PICKERS_LIMIT:
            _HYBRID_PICKERS.popitem(last=False)
        return picker


def _warn_hybrid_shadowed_once(name: str) -> None:
    """Warn once when ``[compaction] hybrid`` is on but an explicit strategy
    name shadows it — the knob would otherwise look silently dead."""
    global _HYBRID_SHADOWED_WARNED
    if _HYBRID_SHADOWED_WARNED:
        return
    try:
        from .hybrid import enabled as _hybrid_enabled
        if not _hybrid_enabled():
            return
    except Exception:  # pragma: no cover -- never block compaction on this check
        return
    _HYBRID_SHADOWED_WARNED = True
    log.warning(
        "[compaction] hybrid is enabled but %r is explicitly configured "
        "(MAVERICK_COMPACTION_STRATEGY / [context] compaction_strategy); the "
        "explicit strategy wins and the hybrid picker stays inactive", name)


def _hybrid_compact(messages: list[dict], **kwargs) -> list[dict] | None:
    """Compact via the hybrid-picked strategy; ``None`` -> caller's default path.

    Fail-open at every step: any error (picker, mapping, strategy) logs and
    returns ``None`` so :func:`compact_with` proceeds with the built-in
    default — compaction must never crash a run.
    """
    try:
        from . import hybrid
        if not hybrid.enabled():
            return None
        picker = _hybrid_picker()
        abstract, reason = picker.pick(messages)
        live = _ABSTRACT_TO_LIVE.get(abstract, _DEFAULT)
        strat = _REGISTRY.get(live) or _REGISTRY[_DEFAULT]
        before = hybrid.extract_features(messages)["total_chars"]
        try:
            out = strat.compact(messages, **kwargs)
        except STOP_ERRORS:
            raise
        except Exception:
            # A strategy that raises is a real outcome — record the failure
            # before falling open to the default path.
            picker.record(messages, abstract, success=False)
            raise
        if before >= _HYBRID_RECORD_MIN_CHARS:
            after = hybrid.extract_features(out)["total_chars"]
            picker.record(messages, abstract, success=after < before)
        log.debug("compaction hybrid: %s -> %s (%s)", abstract, live, reason)
        return out
    except STOP_ERRORS:
        raise
    except Exception as e:
        log.warning("compaction hybrid failed open to the default strategy: %s", e)
        return None


def compact_with(messages: list[dict], *, strategy: str | None = None,
                 **kwargs) -> list[dict]:
    """Compact ``messages`` with the named/configured/picked strategy.

    Fails safe to the built-in ``heuristic`` when the requested strategy is not
    registered — a misconfiguration degrades to working compaction, never none.
    With no explicit name anywhere and ``[compaction] hybrid`` on, the v6
    picker chooses (see the module docstring for the full precedence).
    """
    name = strategy
    if not name:
        name = _configured_name()
        if name:
            _warn_hybrid_shadowed_once(name)
    if not name:
        out = _hybrid_compact(messages, **kwargs)
        if out is not None:
            return out
        name = _DEFAULT
    strat = _REGISTRY.get(name) or _REGISTRY[_DEFAULT]
    return strat.compact(messages, **kwargs)


async def _invoke_async(strat, messages, kwargs):
    method = getattr(strat, "compact_async", None)
    if not callable(method):
        # A legacy plugin may do arbitrary synchronous I/O. It must explicitly
        # implement the async contract before running on the agent event loop.
        log.warning("compaction plugin %r has no compact_async; using heuristic", strat.name)
        return _HeuristicStrategy().compact(messages, **kwargs)
    return await method(messages, **kwargs)


async def compact_with_async(messages: list[dict], *, strategy: str | None = None,
                             **kwargs) -> list[dict]:
    """Native async dispatch with the same explicit/config/hybrid precedence."""
    name = strategy
    if not name:
        name = _configured_name()
        if name:
            _warn_hybrid_shadowed_once(name)
    if not name:
        try:
            from . import hybrid
            if hybrid.enabled():
                picker = _hybrid_picker()
                abstract, reason = picker.pick(messages)
                live = _ABSTRACT_TO_LIVE.get(abstract, _DEFAULT)
                strat = _REGISTRY.get(live) or _REGISTRY[_DEFAULT]
                before = hybrid.extract_features(messages)["total_chars"]
                try:
                    out = await _invoke_async(strat, messages, kwargs)
                except STOP_ERRORS:
                    raise
                except Exception:
                    picker.record(messages, abstract, success=False)
                    raise
                if before >= _HYBRID_RECORD_MIN_CHARS:
                    after = hybrid.extract_features(out)["total_chars"]
                    picker.record(messages, abstract, success=after < before)
                log.debug("compaction hybrid: %s -> %s (%s)", abstract, live, reason)
                return out
        except STOP_ERRORS:
            raise
        except Exception as exc:
            log.warning("compaction hybrid failed open to the default strategy: %s", exc)
        name = _DEFAULT
    return await _invoke_async(_REGISTRY.get(name) or _REGISTRY[_DEFAULT], messages, kwargs)


class _StrategyAdapter:
    """Adapt one of the v3/v5/v7/v8 strategies (compaction_strategies) to the
    plug-in ``CompactionStrategy`` protocol, so both selection paths share one
    registry. The heavy modules import lazily on first compact()."""

    def __init__(self, name: str):
        self.name = name

    def compact(self, messages: list[dict], **kwargs) -> list[dict]:
        from .strategies import compact_with_strategy
        allowed = {k: kwargs[k] for k in
                   ("llm", "conversation_id", "keep_recent", "max_tool_bytes",
                    "budget", "scope", "run_state")
                   if k in kwargs}
        return compact_with_strategy(messages, strategy=self.name, **allowed)


    async def compact_async(self, messages: list[dict], **kwargs) -> list[dict]:
        from .strategies import compact_with_strategy_async
        allowed = {k: kwargs[k] for k in
                   ("llm", "conversation_id", "keep_recent", "max_tool_bytes",
                    "budget", "scope", "run_state") if k in kwargs}
        return await compact_with_strategy_async(messages, strategy=self.name, **allowed)


# Register the built-in as the default at import, plus the named strategies
# from compaction_strategies so `[context] compaction_strategy` selects any of
# them through this one dispatcher (still fail-safe to heuristic on a typo).
register(_HeuristicStrategy())
for _name in ("learned", "multimodal", "streaming", "graph"):
    register(_StrategyAdapter(_name))


__all__ = ["CompactionStrategy", "register", "get", "available", "compact_with", "compact_with_async"]
