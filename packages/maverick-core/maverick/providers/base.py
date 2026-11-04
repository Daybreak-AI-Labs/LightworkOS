"""Provider interface marker.

The Lightwork provider contract is structural (duck-typed): any object
with ``complete()`` and ``complete_async()`` methods that take the
system/messages/tools and return ``LLMResponse`` works. The LLM facade
accepts provider-neutral conversation records and adapts them to the
legacy Anthropic-format boundary before invoking installed providers.
This module exists as a documentation anchor; new providers
don't need to inherit from anything.
"""
from __future__ import annotations

import contextvars
from collections.abc import Callable
from typing import Any, Protocol

from ..budget import Budget
from ..llm import LLMResponse

# Per-context sampling-temperature override. Best-of-N sets this per attempt so
# each re-roll samples at a different temperature. A ContextVar -- not a process
# -global env var -- so concurrent goals on one process never read each other's
# temperature (the old os.environ["MAVERICK_TEMPERATURE"] approach raced). It is
# copied across ``asyncio.to_thread``, so a sync provider running in a worker
# thread still sees the value bound by the awaiting goal task.
_sampling_temperature: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "maverick_sampling_temperature", default=None,
)


def sampling_temperature() -> float | None:
    """The sampling temperature bound to the current context, or None."""
    return _sampling_temperature.get()


def set_sampling_temperature(value: float | None) -> contextvars.Token:
    """Bind the sampling temperature for the current context; returns a token to
    pass to :func:`reset_sampling_temperature`."""
    return _sampling_temperature.set(value)


def reset_sampling_temperature(token: contextvars.Token) -> None:
    """Restore the temperature bound before ``set_sampling_temperature``."""
    try:
        _sampling_temperature.reset(token)
    except (ValueError, LookupError):  # pragma: no cover -- stale/cross-context token
        _sampling_temperature.set(None)


def llm_http_timeout(*, environment=None) -> Any | None:
    """Bounded HTTP timeout for provider SDK clients.

    Without this the anthropic/openai SDKs use a ~10-min per-request
    default, so a hung/half-open connection pins one of the few
    concurrency slots until it expires (and across retries). ``read`` is
    httpx's per-chunk timeout, not a total cap, so long *streamed*
    generations are unaffected — only genuinely stalled sockets trip it.
    Returns None (SDK default) if httpx isn't importable.
    """
    try:
        import httpx

        from .._envparse import env_float
        def value(name, default):
            if environment is None:
                return env_float(name, default)
            try:
                return float(environment.get(name, default))
            except (ValueError, TypeError):
                return default
        return httpx.Timeout(
            value("MAVERICK_LLM_READ_TIMEOUT", 120.0),
            connect=value("MAVERICK_LLM_CONNECT_TIMEOUT", 15.0),
        )
    except Exception:
        return None


def sdk_http_timeout(sdk: Any, *, environment=None) -> Any | None:
    """Return the configured timeout in the provider SDK's native type.

    Current OpenAI and Anthropic releases use ``httpx2`` internally while
    Lightwork also supports integrations that still depend on ``httpx``.
    Passing the latter's ``Timeout`` instance across that boundary can survive
    client construction and fail only when the transport performs arithmetic
    on it. Rebuild the same four timeout components with the class exported by
    the installed SDK; older SDKs without that export receive the read timeout
    as a supported scalar.
    """
    timeout = llm_http_timeout(environment=environment) if environment is not None else llm_http_timeout()
    if timeout is None:
        return None
    sdk_timeout = getattr(sdk, "Timeout", None)
    if sdk_timeout is None:  # pragma: no cover - legacy SDK fallback
        return float(timeout.read)
    return sdk_timeout(
        connect=timeout.connect,
        read=timeout.read,
        write=timeout.write,
        pool=timeout.pool,
    )


class Provider(Protocol):
    """Structural type for a provider client."""

    def complete(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        budget: Budget | None = None,
        max_tokens: int = 4096,
        thinking_budget: int | None = None,
        model: str | None = None,
        on_delta: Callable[[str], None] | None = None,
        tool_choice: dict | None = None,
    ) -> LLMResponse: ...

    async def complete_async(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        budget: Budget | None = None,
        max_tokens: int = 4096,
        thinking_budget: int | None = None,
        model: str | None = None,
        tool_choice: dict | None = None,
    ) -> LLMResponse: ...


# ``tool_choice`` is expressed in Anthropic's vocabulary and translated
# per provider: ``{"type": "auto" | "any" | "tool" | "none", "name": <tool>,
# "disable_parallel_tool_use": bool}``. Providers that cannot honour a forced
# choice clamp it to ``auto`` rather than fail the call.
TOOL_CHOICE_TYPES = frozenset({"auto", "any", "tool", "none"})


def normalize_tool_choice(tool_choice: dict | None) -> dict | None:
    """Validate and copy a caller's ``tool_choice`` (None when unset)."""
    if not tool_choice:
        return None
    if not isinstance(tool_choice, dict):
        raise ValueError("tool_choice must be a dict in Anthropic vocabulary")
    kind = str(tool_choice.get("type") or "").strip().lower()
    if kind not in TOOL_CHOICE_TYPES:
        raise ValueError(
            f"tool_choice.type must be one of {sorted(TOOL_CHOICE_TYPES)}, not {kind!r}"
        )
    out: dict = {"type": kind}
    if kind == "tool":
        name = str(tool_choice.get("name") or "").strip()
        if not name:
            raise ValueError("tool_choice.type='tool' requires a tool name")
        out["name"] = name
    if tool_choice.get("disable_parallel_tool_use"):
        out["disable_parallel_tool_use"] = True
    return out


__all__ = ["Provider", "TOOL_CHOICE_TYPES", "llm_http_timeout",
           "normalize_tool_choice", "sdk_http_timeout"]
