"""Per-host concurrency caps for parallel network-read tools.

The agent loop runs a turn's ``parallel_safe`` tool calls concurrently
(asyncio.gather). Idempotent network reads (http_fetch, arxiv, wikipedia,
semantic_scholar, hackernews) are parallel_safe, so a turn that fans out
many reads to the SAME host can hammer it / trip rate limits. This module
gates each network read behind a per-host asyncio.Semaphore so same-host
reads are throttled while cross-host reads stay fully concurrent.

Local reads (read_file / list_dir / repo_map / dep_graph) have no host key
and are never gated. Unknown tools return no host key too, so this is a
strict refinement: anything it doesn't recognise behaves exactly as before.

Tunable: ``MAVERICK_NET_HOST_CONCURRENCY`` (default 4). 0 or negative
disables gating entirely.
"""
from __future__ import annotations

import asyncio
import contextlib
import threading
import weakref
from urllib.parse import urlparse

# Tools whose endpoint host is fixed (not derivable from args). Mapping the
# tool name to a stable host key is enough to serialise same-service fanout.
_FIXED_HOST_TOOLS = {
    "arxiv": "arxiv.org",
    "wikipedia": "wikipedia.org",
    "semantic_scholar": "semanticscholar.org",
    "hackernews": "ycombinator-hn",
}

# Per-event-loop semaphore registries. A Semaphore binds to a loop the first
# time it is awaited, so a single shared registry broke under the platform's OWN
# concurrency: runner.run_goal_in_thread / orchestrator.run_goal_sync run each
# goal under its own asyncio.run() on a worker thread, so two goals are two live
# loops on two threads. The old single `_sem_loop` flip-flopped between them --
# each clear() wiping the other's registry (an unsynchronized data race), and a
# semaphore created for loop A could then be awaited under loop B ("bound to a
# different loop"). We keep one registry PER loop, keyed by the loop in a
# WeakKeyDictionary (auto-evicts a dead loop, so a recycled id() can't alias
# it), and guard all access with a lock -- WeakKeyDictionary mutation is not
# itself thread-safe across the concurrent loops that reach here.
_lock = threading.Lock()
_by_loop: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def _cap() -> int:
    try:
        from .env_setting import env_or_config

        return int(env_or_config("MAVERICK_NET_HOST_CONCURRENCY", "tools",
                                 "net_host_concurrency", "4") or "4")
    except ValueError:
        return 4


def host_key(tool_name: str, args: dict) -> str | None:
    """Return a stable per-host key for a network tool call, or None.

    None means "don't gate" — local/unknown tools, or a URL we can't parse.
    """
    if tool_name == "http_fetch":
        url = (args or {}).get("url") or ""
        try:
            host = urlparse(url).hostname
        except (ValueError, TypeError):
            return None
        return f"http:{host.lower()}" if host else None
    fixed = _FIXED_HOST_TOOLS.get(tool_name)
    return f"svc:{fixed}" if fixed else None


def _get_semaphore(key: str, cap: int) -> asyncio.Semaphore:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:  # pragma: no cover - limit() is only used under a loop
        # No running loop: hand back an uncached semaphore rather than touch the
        # shared registry. It still gates the single call it's used for.
        return asyncio.Semaphore(cap)
    with _lock:
        registry = _by_loop.get(loop)
        if registry is None:
            registry = {}
            _by_loop[loop] = registry
        sem = registry.get(key)
        # Recreate when the requested cap differs from the cached one so
        # MAVERICK_NET_HOST_CONCURRENCY is the live tunable the docstring
        # promises, rather than caching the FIRST cap seen per (loop, host)
        # for that loop's lifetime. The cap is tagged
        # on the semaphore (registry values stay plain Semaphores). A cap change
        # is rare, so the brief window where holders of the prior semaphore
        # overlap the new one is acceptable for a per-host politeness cap.
        if sem is None or getattr(sem, "_mvk_cap", None) != cap:
            sem = asyncio.Semaphore(cap)
            sem._mvk_cap = cap
            registry[key] = sem
        return sem


def limit(tool_name: str, args: dict):
    """Async context manager that caps concurrency for a tool's host.

    Returns a no-op context for non-network/unknown tools or when gating is
    disabled (cap <= 0), so callers can wrap unconditionally.
    """
    cap = _cap()
    if cap <= 0:
        return contextlib.nullcontext()
    key = host_key(tool_name, args)
    if key is None:
        return contextlib.nullcontext()
    return _get_semaphore(key, cap)


def _reset_for_tests() -> None:
    """Clear all per-loop semaphore registries (tests that vary the cap)."""
    with _lock:
        _by_loop.clear()


__all__ = ["host_key", "limit"]
