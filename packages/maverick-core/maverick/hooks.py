"""Lifecycle hooks for agent / tool events.

Modeled after Claude Code's hook system. User registers shell-command
or Python callables to fire at well-defined points; failures in a
hook are isolated (logged, not propagated). Hooks can BLOCK a tool
call (Pre*) by returning a falsy "allowed" flag, or annotate the
trace (Post*).

Events:
  - SessionStart:    once at process startup
  - PreToolUse:      before any tool executes (can block)
  - PostToolUse:     after a tool returns (cannot block)
  - UserPromptSubmit: before agent processes a user message
  - Stop:            when the agent decides FINAL
  - SubagentStop:    when a sub-agent completes
  - SessionEnd:      once at process exit

Configure via ~/.maverick/config.toml:

    [[hooks]]
    event = "PreToolUse"
    matcher = "shell"           # tool-name glob; * = any tool
    command = "~/.maverick/hooks/before-shell.sh"
    timeout_ms = 5000

    [[hooks]]
    event = "PostToolUse"
    matcher = "write_file"
    command = "python3 ~/.maverick/hooks/format-on-write.py"

Or programmatically:

    from maverick.hooks import register, HookEvent, HookContext
    register(HookEvent.PRE_TOOL_USE, lambda ctx: not ctx.tool_name.startswith("dangerous_"))
"""
from __future__ import annotations

import asyncio
import fnmatch
import logging
import os
import shlex
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

log = logging.getLogger(__name__)


class HookEvent(str, Enum):
    SESSION_START = "SessionStart"
    PRE_TOOL_USE = "PreToolUse"
    POST_TOOL_USE = "PostToolUse"
    USER_PROMPT_SUBMIT = "UserPromptSubmit"
    STOP = "Stop"
    SUBAGENT_STOP = "SubagentStop"
    SESSION_END = "SessionEnd"


@dataclass
class HookContext:
    """Data delivered to every hook invocation."""
    event: HookEvent
    tool_name: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    tool_result: str | None = None
    goal_id: int | None = None
    agent_role: str = ""
    duration_ms: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class HookSpec:
    event: HookEvent
    matcher: str = "*"
    command: str | None = None
    callable: Callable[[HookContext], Any] | None = None
    timeout_ms: int = 5000

    def matches(self, ctx: HookContext) -> bool:
        if self.event != ctx.event:
            return False
        if self.event in (HookEvent.PRE_TOOL_USE, HookEvent.POST_TOOL_USE):
            return fnmatch.fnmatch(ctx.tool_name or "", self.matcher)
        return True


_registry: list[HookSpec] = []


def register(
    event: HookEvent,
    callable_or_command: Any,
    *,
    matcher: str = "*",
    timeout_ms: int = 5000,
) -> HookSpec:
    """Register a hook. Returns the spec for later unregister/unit-test."""
    if callable(callable_or_command):
        spec = HookSpec(event=event, matcher=matcher,
                        callable=callable_or_command, timeout_ms=timeout_ms)
    else:
        spec = HookSpec(event=event, matcher=matcher,
                        command=str(callable_or_command), timeout_ms=timeout_ms)
    _registry.append(spec)
    return spec


def unregister(spec: HookSpec) -> None:
    try:
        _registry.remove(spec)
    except ValueError:
        pass


def clear() -> None:
    """Drop all registered hooks. Used in tests + on session restart."""
    global _loaded
    _registry.clear()
    _loaded = False


def load_from_config() -> None:
    """Read [[hooks]] entries from ~/.maverick/config.toml and register
    each one. Safe to call multiple times; clear() first if you don't
    want duplicates."""
    try:
        from .config import load_config
        cfg = load_config()
    except Exception as e:  # pragma: no cover
        log.debug("hook config load failed: %s", e)
        return
    for entry in cfg.get("hooks", []) or []:
        try:
            event = HookEvent(entry["event"])
        except (KeyError, ValueError):
            log.warning("invalid hook event: %s", entry)
            continue
        cmd = entry.get("command")
        if not cmd:
            log.warning("hook missing command: %s", entry)
            continue
        register(
            event, cmd,
            matcher=entry.get("matcher", "*"),
            timeout_ms=int(entry.get("timeout_ms", 5000)),
        )


_loaded = False


async def ensure_loaded() -> None:
    """Load operator- and plugin-supplied hooks once per process.

    Nothing in the kernel ever called ``load_from_config()`` /
    ``load_from_entry_points()``, so the ``[[hooks]]`` config section and the
    ``maverick.hooks`` entry-point group were inert -- only hooks registered
    programmatically via :func:`register` ever fired. The orchestrator calls
    this on entry so configured and plugin-contributed hooks actually run.

    Idempotent: the load happens once even across many goals in one process,
    fires ``SessionStart`` once after loading, and arms a best-effort
    ``SessionEnd`` at interpreter shutdown.
    """
    global _loaded
    if _loaded:
        return
    _loaded = True
    try:
        load_from_config()
    except Exception:  # pragma: no cover -- fail-open per kernel rule 1
        log.debug("hooks: load_from_config failed", exc_info=True)
    try:
        load_from_entry_points()
    except Exception:  # pragma: no cover
        log.debug("hooks: load_from_entry_points failed", exc_info=True)
    import atexit
    atexit.register(_emit_session_end)
    await emit(HookEvent.SESSION_START)


async def emit(event: HookEvent, **fields: Any) -> bool:
    """Build a :class:`HookContext` for a non-tool lifecycle event and dispatch
    it. Returns the :func:`dispatch` allow flag (only meaningful for blocking
    events such as ``UserPromptSubmit``). Keeps call sites to one line."""
    return await dispatch(HookContext(event=event, **fields))


def _emit_session_end() -> None:
    """Best-effort ``SessionEnd`` at interpreter shutdown. No-op when no
    ``SessionEnd`` hook is registered, so we never spin up an event loop for
    nothing; failures during teardown are swallowed."""
    if not any(s.event == HookEvent.SESSION_END for s in _registry):
        return
    try:
        asyncio.run(emit(HookEvent.SESSION_END))
    except Exception:  # pragma: no cover -- shutdown is best-effort
        pass


async def dispatch(ctx: HookContext) -> bool:
    """Fire every hook matching this context. Returns False if any
    Pre* hook explicitly blocked the action (exit code != 0 for shell;
    falsy return for callable). Always returns True for Post* events."""
    is_blocking = ctx.event in (HookEvent.PRE_TOOL_USE, HookEvent.USER_PROMPT_SUBMIT)
    allowed = True
    for spec in list(_registry):
        if not spec.matches(ctx):
            continue
        start = time.monotonic()
        try:
            ok = await _run_one(spec, ctx, is_blocking=is_blocking)
        except Exception as e:
            # A hook that raised hasn't vetted the action. A blocking (Pre*)
            # hook must therefore BLOCK rather than wave it through: an attacker
            # who can make a guard hook raise -- e.g. a model-influenced tool arg
            # that trips a callable's parsing -- would otherwise disarm it. Post*
            # hooks have nothing to block, so they stay fail-open. This matches
            # the timeout/missing-binary posture below.
            log.warning(
                "hook %s/%s raised: %s%s", spec.event.value, spec.matcher, e,
                " — BLOCKING the action (fail-closed)" if is_blocking else "",
            )
            ok = not is_blocking
        ctx.duration_ms = (time.monotonic() - start) * 1000
        if is_blocking and not ok:
            allowed = False
            log.info(
                "hook %s/%s BLOCKED %s",
                spec.event.value, spec.matcher, ctx.tool_name or ctx.event.value,
            )
    return allowed


async def _run_one(spec: HookSpec, ctx: HookContext, *, is_blocking: bool = False) -> bool:
    if spec.callable is not None:
        result = spec.callable(ctx)
        if asyncio.iscoroutine(result):
            result = await result
        # Truthy or None = allow; explicit False = block.
        return bool(result) if result is not None else True

    # Shell command. Pass context as JSON on stdin so the hook can
    # parse without parsing argv quirks.
    import json

    from .sandbox.local import scrub_env

    # Hooks are operator-defined but still child processes that fire on every
    # tool call with model-influenced payloads. Don't hand them the kernel's
    # provider keys / tokens; strip secret-shaped vars (same deny-by-pattern
    # policy as the sandbox shell), keep PATH/HOME/etc.
    env = scrub_env()
    env["MAVERICK_HOOK_EVENT"] = spec.event.value
    env["MAVERICK_HOOK_TOOL"] = ctx.tool_name or ""
    payload = json.dumps({
        "event": ctx.event.value,
        "tool_name": ctx.tool_name,
        "tool_args": ctx.tool_args,
        "tool_result": ctx.tool_result,
        "goal_id": ctx.goal_id,
        "agent_role": ctx.agent_role,
    })
    try:
        cmd = shlex.split(os.path.expanduser(spec.command))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(payload.encode()),
                timeout=spec.timeout_ms / 1000.0,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
                # Reap the killed child: without wait() it stays a zombie and
                # its 3 stdio pipe fds are never closed -- a leak on every hook
                # that times out (and hooks fire on every tool call).
                await proc.wait()
            except (ProcessLookupError, OSError):
                pass
            log.warning(
                "hook %s timed out (>%dms)%s", spec.command, spec.timeout_ms,
                " — BLOCKING the action (fail-closed)" if is_blocking else "",
            )
            # A blocking hook that can't finish hasn't vetted the action, so
            # it must block, not wave it through (a slow/large tool arg could
            # otherwise be used to trip the timeout and bypass the guard).
            return not is_blocking
        if stdout:
            log.debug("hook %s stdout: %s", spec.command, stdout.decode(errors="replace")[:500])
        if stderr:
            log.info("hook %s stderr: %s", spec.command, stderr.decode(errors="replace")[:500])
        return proc.returncode == 0
    except FileNotFoundError:
        # A blocking hook whose binary is missing never vetted the action, so it
        # must BLOCK (same posture as the timeout path) -- otherwise an attacker
        # who can delete/rename/chmod-x the hook disarms the guard. A Post* hook
        # that's missing simply doesn't run.
        log.warning(
            "hook command not found: %s%s", spec.command,
            " — BLOCKING the action (fail-closed)" if is_blocking else "",
        )
        return not is_blocking


def installed() -> list[HookSpec]:
    return list(_registry)


def load_from_entry_points() -> int:
    """Discover hooks contributed by third-party plugins.

    Plugins publish entry points under the ``maverick.hooks`` group:

        # In a plugin's pyproject.toml:
        [project.entry-points."maverick.hooks"]
        my_hook = "my_plugin.hooks:register_hooks"

    The referenced object MUST be a callable that takes no arguments
    and returns a list of (event, callable) tuples, or a list of
    HookSpec objects. Like other plugin entry-point groups, hook plugins
    are only imported when explicitly allowlisted via
    ``MAVERICK_PLUGINS_ALLOW`` or ``[plugins].enabled``. We call each
    allowed factory, register what it returned, and isolate failures (one
    broken plugin doesn't disable the rest).

    Gating reuses :func:`maverick.plugins._gate`, so hooks inherit the same
    load-time controls the four plugin slots use: the dist-qualified allowlist,
    the name-squat defense (a ``maverick.hooks`` name published by 2+
    distributions is refused unless pinned ``name@dist``), and manifest
    permission enforcement (a hook plugin whose ``maverick-plugin.toml``
    requests an ungranted permission is skipped, subject to
    ``[plugins] enforce_permissions``).

    Returns the number of hooks registered.
    """
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover -- py<3.10
        return 0
    try:
        eps = list(entry_points(group="maverick.hooks"))
    except TypeError:  # pragma: no cover -- py<3.10 API differences
        eps = list(entry_points().get("maverick.hooks", []))  # type: ignore[assignment]

    from .plugins import (
        _allowed_plugin_names,
        _gate,
        _name_dist_map,
        _permission_policy,
    )

    allow = _allowed_plugin_names()
    name_dists = _name_dist_map(eps)
    granted, enforce = _permission_policy()
    registered = 0
    for ep in eps:
        if not _gate(ep, "maverick.hooks", allow, name_dists, granted, enforce):
            continue
        try:
            register_fn = ep.load()
        except Exception as e:
            log.warning("hooks: cannot load entry point %s: %s", ep.name, e)
            continue
        try:
            items = register_fn() or []
        except Exception as e:
            log.warning("hooks: entry point %s raised on call: %s", ep.name, e)
            continue
        for item in items:
            try:
                if isinstance(item, HookSpec):
                    _registry.append(item)
                    registered += 1
                elif isinstance(item, tuple) and len(item) == 2:
                    event, fn = item
                    register(event, fn)
                    registered += 1
                else:
                    log.warning(
                        "hooks: entry point %s yielded invalid item %r",
                        ep.name, item,
                    )
            except Exception as e:
                log.warning(
                    "hooks: failed to register from %s: %s", ep.name, e,
                )
    log.info("hooks: loaded %d hooks from entry points", registered)
    return registered
