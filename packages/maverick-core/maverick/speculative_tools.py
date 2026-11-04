"""Speculative tool execution: pre-warm the tool-output cache.

An agent's next tool calls are often predictable -- it re-reads the file it
just edited, refreshes the same repo map, polls the same status endpoint.
Each of those re-reads sits on the critical path of a paid model turn. This
module executes *predicted* next calls concurrently, ahead of the model, so
that when the model does ask, the result is already in the tool-output cache
(:mod:`maverick.cache.tool`) and the turn doesn't wait on I/O. A wrong
prediction costs only local work on a side-effect-free read -- never a paid
API call, never a side effect.

Hard rules:
  * Only tools that exist in the registry AND are ``parallel_safe`` (the
    same side-effect-free invariant the agent loop and the cache use) are
    ever speculated; everything else is reported as skipped.
  * Candidates already cached are skipped -- no duplicate work.
  * Results land via ``tool_cache.store_cached``, which never memoizes
    error results, so a speculative failure can't poison a real turn.
  * :func:`speculate` never raises: per-candidate failures are swallowed
    into the report. An optional ``budget_guard`` is consulted before each
    execution so the caller can stop speculation the moment budget is tight.
  * When the tool-output cache itself is disabled the whole call is a no-op:
    there is nowhere to store results, so executing would be pure waste.

Off by default. ``enabled()`` is the opt-in switch the integration point
checks (``MAVERICK_SPECULATIVE_TOOLS=1`` or ``[tools] speculative = true``);
the module itself is a library -- it never runs on its own and
:func:`speculate` does exactly what the caller asked, when asked. The agent
loop is that caller: after each turn that ran tools it predicts from the
agent's own recent calls and warms them through
``ToolRegistry.speculate_reads`` in the background (``Agent._maybe_speculate_reads``).

Distinct from :mod:`maverick.speculative` (the asyncio overlapped-coroutine
primitive): this module is about warming the cross-turn tool cache from
predictions, not overlapping in-flight coroutines.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .cache import tool as tool_cache

log = logging.getLogger(__name__)

# The registry never caches a result longer than this (tools._store_bounded_cached).
_MAX_CACHED_CHARS = 64_000


def _cfg() -> dict:
    try:
        from .config import load_config
        return (load_config() or {}).get("tools", {}) or {}
    except Exception:  # pragma: no cover -- config never blocks
        return {}


def enabled() -> bool:
    """Whether speculative tool execution is on (default OFF).

    ``MAVERICK_SPECULATIVE_TOOLS`` (when set, it wins either way), else
    ``[tools] speculative``.
    """
    raw = os.environ.get("MAVERICK_SPECULATIVE_TOOLS", "").strip().lower()
    if raw:
        return raw in {"1", "true", "yes", "on"}
    return bool(_cfg().get("speculative", False))


@dataclass(frozen=True)
class SpeculationReport:
    executed: list[str] = field(default_factory=list)
    skipped_cached: list[str] = field(default_factory=list)
    # Unknown in the registry OR not parallel_safe -- either way, not runnable.
    skipped_unsafe: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)  # (tool, "Type: msg")


def _canon(args: dict[str, Any]) -> str:
    try:
        return json.dumps(args or {}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(args)


def _lookup(registry: Any, name: str) -> Any:
    """Find a tool in a ``ToolRegistry`` or any mapping; ``None`` when missing."""
    getter = getattr(registry, "get", None)
    if getter is None:
        return None
    try:
        return getter(name)  # ToolRegistry.get raises KeyError; dict.get -> None
    except Exception:
        return None


def _call_tool(tool: Any, args: dict[str, Any], principal: str | None = None) -> Any:
    """Invoke ``tool.fn(args)`` in a worker thread; drain async fns inline.

    ``ToolFn`` may return an awaitable (native-async tools). Worker threads
    have no running event loop, so ``asyncio.run`` is safe here. ``principal``
    is bound for the call exactly as the registry binds it for a real one.
    """
    if principal:
        from .connections import bind_principal

        with bind_principal(principal):
            return _call_tool(tool, args)
    out = tool.fn(args)
    if inspect.isawaitable(out):
        async def _drain() -> Any:
            return await out
        out = asyncio.run(_drain())
    return out


def speculate(
    registry: Any,
    candidates: Iterable[tuple[str, dict[str, Any]]],
    *,
    max_workers: int = 4,
    budget_guard: Callable[[], bool] | None = None,
    namespace: str = "",
    principal: str | None = None,
) -> SpeculationReport:
    """Pre-execute predicted tool calls so their results are already cached.

    ``candidates`` is a list of ``(tool_name, args)`` predictions (e.g. from
    :func:`predict_from_history`). Filters to tools that exist, are
    ``parallel_safe``, and aren't already cached; runs the remainder on a
    thread pool and stores successes in the tool-output cache. Duplicate
    predictions are collapsed to one execution.

    ``budget_guard`` (optional) is called before each execution is started;
    the first falsy answer stops all further speculation (those candidates
    simply don't run -- best-effort, they appear in no report bucket).

    Never raises: per-candidate errors land in ``report.errors``. A no-op
    when the tool-output cache is disabled, since results would have nowhere
    to land. ``namespace`` and ``principal`` are the cache scope and identity
    of the registry that would make the real call (see
    ``ToolRegistry.speculate_reads``), so a warmed result is only ever served
    to that same caller.
    """
    report = SpeculationReport()
    if not tool_cache.enabled():
        return report
    runnable: list[tuple[str, dict[str, Any], Any]] = []
    seen: set[tuple[str, str]] = set()
    for cand in candidates:
        try:
            name, args = cand
        except (TypeError, ValueError):
            continue  # malformed prediction: speculation must never throw
        name = str(name)
        args = dict(args) if isinstance(args, dict) else {}
        key = (name, _canon(args))
        if key in seen:
            continue
        seen.add(key)
        tool = _lookup(registry, name)
        if tool is None or not tool_cache.cacheable(tool):
            report.skipped_unsafe.append(name)
            continue
        hit, _value = tool_cache.get_cached(tool, args, namespace=namespace)
        if hit:
            report.skipped_cached.append(name)
            continue
        runnable.append((name, args, tool))
    if not runnable:
        return report
    workers = max(1, min(int(max_workers), len(runnable)))
    with ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="maverick-speculate"
    ) as pool:
        futures = []
        for name, args, tool in runnable:
            if budget_guard is not None:
                try:
                    allowed = bool(budget_guard())
                except Exception:
                    allowed = False  # a broken guard fails safe: stop spending
                if not allowed:
                    break
            futures.append((name, args, tool, pool.submit(_call_tool, tool, args, principal)))
        for name, args, tool, fut in futures:
            try:
                result = fut.result()
            except Exception as exc:  # speculation must never throw
                report.errors.append((name, f"{type(exc).__name__}: {exc}"))
                continue
            if isinstance(result, str) and len(result) <= _MAX_CACHED_CHARS:
                tool_cache.store_cached(tool, args, result, namespace=namespace)
            report.executed.append(name)
    log.debug(
        "speculative tools: executed=%d cached=%d unsafe=%d errors=%d",
        len(report.executed), len(report.skipped_cached),
        len(report.skipped_unsafe), len(report.errors),
    )
    return report


def predict_from_history(
    recent_calls: Sequence[tuple[str, dict[str, Any]]],
    *,
    top_k: int = 4,
) -> list[tuple[str, dict[str, Any]]]:
    """Predict the next tool calls from this run's recent ones.

    Dependency-free heuristic: a ``(tool, args)`` pair that already recurred
    across turns is a re-read the model is likely to make again (file
    re-reads after edits, repo-map refreshes, status polls). Returns up to
    ``top_k`` pairs that appeared at least twice, most frequent first; ties
    keep first-appearance order, so the output is deterministic. One-off
    calls are never predicted -- warming them would be spend without
    evidence.
    """
    if top_k <= 0:
        return []
    counts: dict[tuple[str, str], int] = {}
    first_args: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for cand in recent_calls:
        try:
            name, args = cand
        except (TypeError, ValueError):
            continue
        args = dict(args) if isinstance(args, dict) else {}
        key = (str(name), _canon(args))
        if key not in counts:
            counts[key] = 0
            first_args[key] = args
            order.append(key)
        counts[key] += 1
    repeated = [k for k in order if counts[k] >= 2]
    repeated.sort(key=lambda k: -counts[k])  # stable: ties stay in seen order
    return [(name, first_args[(name, canon)]) for name, canon in repeated[:top_k]]


__all__ = ["SpeculationReport", "enabled", "predict_from_history", "speculate"]
