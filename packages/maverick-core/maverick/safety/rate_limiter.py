"""Per-tool sliding-window rate limiter.

Config (``~/.maverick/config.toml``):

    [rate_limits]
    web_search = "10/60"      # 10 calls per 60 seconds
    http_fetch = "20/60"
    shell      = "30/60"
    "mcp_*"    = "60/60"      # glob -- applies to any matching tool name

Format ``N/T`` means at most ``N`` invocations within a sliding window
of ``T`` seconds. When exceeded, the tool returns
``ERROR: rate limit exceeded for <name> (N/T s)`` without running. The
agent sees this as a normal tool error and can back off.

Process-local: each Python process tracks its own counter. Fine for
single-process kernels; deployments that run many workers should treat
config as a per-worker cap.
"""
from __future__ import annotations

import fnmatch
import inspect
import logging
import re
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any

log = logging.getLogger(__name__)


_LIMIT_RE = re.compile(r"^\s*(\d+)\s*/\s*(\d+(?:\.\d+)?)\s*s?\s*$")


def parse_limit(spec: str) -> tuple[int, float] | None:
    """Parse 'N/T' or 'N/Ts'. Returns (max_calls, window_seconds) or None."""
    if not isinstance(spec, str):
        return None
    m = _LIMIT_RE.match(spec)
    if not m:
        return None
    n = int(m.group(1))
    t = float(m.group(2))
    if n <= 0 or t <= 0:
        return None
    return n, t


def _load_limits() -> dict[str, tuple[int, float]]:
    """Read ``[rate_limits]`` from config. Returns name -> (max, window_s)."""
    try:
        from ..config import load_config
        cfg = load_config() or {}
    except Exception as e:
        log.debug("rate_limiter: cannot load config: %s", e)
        return {}
    section = cfg.get("rate_limits") or {}
    out: dict[str, tuple[int, float]] = {}
    for name, spec in section.items():
        parsed = parse_limit(spec)
        if parsed is None:
            log.warning("rate_limiter: bad limit for %s: %r", name, spec)
            continue
        out[name] = parsed
    return out


class _Limiter:
    """Per-tool sliding-window counter. Thread-safe."""

    def __init__(self, max_calls: int, window_s: float):
        self.max_calls = max_calls
        self.window_s = window_s
        self._hits: deque[float] = deque()
        self._lock = threading.Lock()

    def try_consume(self, now: float | None = None) -> bool:
        now = now if now is not None else time.monotonic()
        with self._lock:
            cutoff = now - self.window_s
            while self._hits and self._hits[0] < cutoff:
                self._hits.popleft()
            if len(self._hits) >= self.max_calls:
                return False
            self._hits.append(now)
            return True


def _resolve_limit(
    tool_name: str,
    limits: dict[str, tuple[int, float]],
) -> tuple[int, float] | None:
    """Exact match first, then glob patterns (e.g. ``mcp_*``)."""
    if tool_name in limits:
        return limits[tool_name]
    for pattern, lim in limits.items():
        if any(ch in pattern for ch in "*?[") and fnmatch.fnmatchcase(tool_name, pattern):
            return lim
    return None


ToolFn = Callable[[dict[str, Any]], str | Awaitable[str]]


def _wrap_fn(name: str, limiter: _Limiter, fn: ToolFn) -> ToolFn:
    """Return a sync-or-async wrapper around ``fn`` that consumes a token."""
    err_msg = (
        f"ERROR: rate limit exceeded for {name} "
        f"({limiter.max_calls}/{int(limiter.window_s)}s)"
    )

    if inspect.iscoroutinefunction(fn):
        async def async_wrapper(args: dict[str, Any]) -> str:
            if not limiter.try_consume():
                return err_msg
            return await fn(args)  # type: ignore[misc]
        return async_wrapper

    def sync_wrapper(args: dict[str, Any]) -> str:
        if not limiter.try_consume():
            return err_msg
        return fn(args)  # type: ignore[return-value]
    return sync_wrapper


def apply_to_registry(reg, limits: dict[str, tuple[int, float]] | None = None) -> int:
    """Wrap every tool in ``reg`` whose name matches a configured limit.

    Returns the count of wrapped tools. Idempotent within a process:
    re-wrapping a tool resets its limiter (acceptable for kernel boot;
    not intended for hot reconfiguration).
    """
    from ..tools import Tool

    limits = _load_limits() if limits is None else limits
    if not limits:
        return 0

    wrapped = 0
    for name, tool in list(reg._tools.items()):
        lim = _resolve_limit(name, limits)
        if lim is None:
            continue
        max_calls, window_s = lim
        limiter = _Limiter(max_calls, window_s)
        reg._tools[name] = Tool(
            name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
            fn=_wrap_fn(name, limiter, tool.fn),
            parallel_safe=tool.parallel_safe,
        )
        wrapped += 1
    if wrapped:
        log.info("rate_limiter: wrapped %d tool(s)", wrapped)
    return wrapped


__all__ = ["apply_to_registry", "parse_limit"]
