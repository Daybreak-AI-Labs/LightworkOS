"""Opt-in compaction strategy selection.

The always-on path is :func:`maverick.compaction.compact_messages`. This
module layers additional opt-in strategies on top of it, selected the same way
``context_compactor`` selects its behavior: an env var override, then the
``[context]`` config section, fail-open to the default.

    [context]
    compaction_strategy = "learned"     # v3: LLM summarizer + outcome ledger
    # or "multimodal"                   # v5: media blocks -> compact text stubs
    # or "streaming"                    # v7: incremental running summary
    # or "graph"                        # v8: entity-relation graph digest

Env override: ``MAVERICK_COMPACTION_STRATEGY``. Unset / unrecognised values
mean "no strategy" and :func:`compact_with_strategy` returns exactly what
``compact_messages`` returns — byte-identical default behavior. A strategy
that raises an ordinary provider error falls back to that same default.
Budget, usage-accounting, halt and cancellation stops always propagate.
"""
from __future__ import annotations

import logging
import os

from ..run_outcome import GoalCancelled
from . import KEEP_RECENT_TURNS, MAX_TOOL_OUTPUT_BYTES, compact_messages
from .requests import STOP_ERRORS

STOP_ERRORS = (*STOP_ERRORS, GoalCancelled)

log = logging.getLogger(__name__)

STRATEGIES = ("learned", "multimodal", "streaming", "graph")

# The digest a strategy puts at index 1. It sits behind the recent window, so
# the shared post-pass truncated it to ``max_tool_bytes`` (2 KiB) right after
# it was produced (and paid for), cutting its ending and closing tag. It is
# exempt from that pass up to this size; everything else is compacted exactly
# as before.
_DIGEST_PREFIXES = ("<learned-digest ", "<graph-digest ", "<stream-summary ")
_MAX_DIGEST_CHARS = 65_536


def _is_digest(msg) -> bool:
    content = msg.get("content") if isinstance(msg, dict) else None
    return (isinstance(content, str) and content.startswith(_DIGEST_PREFIXES)
            and len(content) <= _MAX_DIGEST_CHARS)


def _post_compact(result: list[dict], **kwargs) -> list[dict]:
    """``compact_messages`` over a strategy result, leaving its digest whole."""
    if len(result) > 1 and _is_digest(result[1]):
        rest = compact_messages([result[0], *result[2:]], **kwargs)
        return [rest[0], result[1], *rest[1:]]
    return compact_messages(result, **kwargs)


def configured_strategy() -> str:
    """The configured strategy name, or ``""`` for the default path.

    ``MAVERICK_COMPACTION_STRATEGY`` beats ``[context] compaction_strategy``;
    anything not in :data:`STRATEGIES` (including typos) selects the default
    so a bad config value can never change compaction behavior.
    """
    env = (os.environ.get("MAVERICK_COMPACTION_STRATEGY") or "").strip().lower()
    if env in STRATEGIES:
        return env
    try:
        from ..config import load_config
        raw = load_config().get("context", {}).get("compaction_strategy", "")
    except Exception:  # pragma: no cover -- config never blocks a run
        return ""
    name = str(raw or "").strip().lower()
    return name if name in STRATEGIES else ""


def compact_with_strategy(
    messages: list[dict],
    *,
    llm=None,
    conversation_id: str | None = None,
    keep_recent: int = KEEP_RECENT_TURNS,
    max_tool_bytes: int = MAX_TOOL_OUTPUT_BYTES,
    strategy: str | None = None,
    budget=None,
    scope: str | None = None,
    run_state=None,
) -> list[dict]:
    """Compact ``messages`` with the configured (or given) strategy.

    With no strategy configured this is exactly ``compact_messages(...)``.
    ``llm`` is the injected seam used by the learned / multimodal / streaming /
    graph strategies when present; every strategy degrades deterministically
    without it. ``conversation_id`` keys the streaming strategy's persisted
    cursor. Any strategy error falls back to the default path.
    """
    name = configured_strategy() if strategy is None else strategy
    if name == "learned" and run_state is not None:
        keep_recent, max_tool_bytes = run_state.keep_recent, run_state.max_tool_bytes
    limits = {"max_total_bytes": run_state.max_total_bytes} if name == "learned" and run_state is not None else {}
    if name not in STRATEGIES:
        return compact_messages(
            messages, keep_recent=keep_recent, max_tool_bytes=max_tool_bytes,
        )
    try:
        result = _invoke(name, messages, llm=llm, conversation_id=conversation_id,
                         keep_recent=keep_recent, budget=budget, scope=scope, run_state=run_state)
        result = _post_compact(result, keep_recent=keep_recent, max_tool_bytes=max_tool_bytes, **limits)
        if name == "learned" and run_state is not None:
            run_state.remember(result)
        return result
    except STOP_ERRORS:
        raise
    except Exception as e:
        log.warning("compaction strategy %r failed (%s); using default path", name, e)
        return compact_messages(
            messages, keep_recent=keep_recent, max_tool_bytes=max_tool_bytes,
            **limits,
        )


def _invoke(name, messages, *, llm, conversation_id, keep_recent, budget, scope, run_state=None,
            asynchronous=False):
    """Resolve the same implementation and arguments for both I/O drivers."""
    kwargs = {"keep_recent": keep_recent}
    if name == "learned":
        from .learned import LearnedSummarizer
        obj = (run_state.resolve(messages, llm=llm, budget=budget, scope=scope,
                                 conversation_id=conversation_id) if run_state is not None
               else LearnedSummarizer(llm=llm, budget=budget, scope=scope))
        method = "compact"
    else:
        if name == "multimodal":
            from . import multimodal as obj
            method = "compact_media"
        elif name == "streaming":
            from . import streaming as obj
            method = "compact_streaming"
        else:
            from . import graph as obj
            method = "compact_graph"
        kwargs.update(llm=llm, budget=budget)
        if name == "streaming":
            kwargs["conversation_id"] = conversation_id
    if asynchronous:
        method += "_async"
    return getattr(obj, method)(messages, **kwargs)


async def compact_with_strategy_async(
    messages: list[dict], *, llm=None, conversation_id: str | None = None,
    keep_recent: int = KEEP_RECENT_TURNS, max_tool_bytes: int = MAX_TOOL_OUTPUT_BYTES,
    strategy: str | None = None, budget=None, scope: str | None = None, run_state=None,
) -> list[dict]:
    """Async strategy dispatch; stops escape and ordinary failures use heuristic."""
    name = configured_strategy() if strategy is None else strategy
    if name == "learned" and run_state is not None:
        keep_recent, max_tool_bytes = run_state.keep_recent, run_state.max_tool_bytes
    limits = {"max_total_bytes": run_state.max_total_bytes} if name == "learned" and run_state is not None else {}
    if name in STRATEGIES:
        try:
            result = await _invoke(
                name, messages, llm=llm, conversation_id=conversation_id,
                keep_recent=keep_recent, budget=budget, scope=scope,
                run_state=run_state, asynchronous=True)
            result = _post_compact(result, keep_recent=keep_recent, max_tool_bytes=max_tool_bytes, **limits)
            if name == "learned" and run_state is not None:
                run_state.remember(result)
            return result
        except STOP_ERRORS:
            raise
        except Exception as exc:
            log.warning("compaction strategy %r failed (%s); using default path", name, exc)
    return compact_messages(messages, keep_recent=keep_recent, max_tool_bytes=max_tool_bytes, **limits)


__all__ = ["STRATEGIES", "configured_strategy", "compact_with_strategy",
           "compact_with_strategy_async"]
