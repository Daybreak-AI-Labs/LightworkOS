"""Tool registry. Sync + async tools; same interface.

Each tool is a name + JSON schema + executor function. The executor may be a
sync function returning str, or an async coroutine returning str.

``base_registry`` accepts an optional list of MCPClient
instances. If provided, every tool the MCP servers expose is
registered as ``mcp_<server>__<tool>`` and routed through the
MCPClient. This is how Lightwork consumes the wider MCP ecosystem.
"""
from __future__ import annotations

import contextlib
import os
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from .. import killswitch
from ..budget import BudgetExceeded, UsageAccountingError
from ..config import load_config
from ..tool_results import ToolOutcome

# Host scope is trusted execution context, never a model-supplied argument.
_TOOL_HOST_SCOPE: ContextVar[tuple[str, ...] | None] = ContextVar("tool_host_scope", default=None)
_TOOL_CAPABILITY_ACTIVE: ContextVar[bool] = ContextVar("tool_capability_active", default=False)


@contextlib.contextmanager
def bind_tool_host_scope(hosts: tuple[str, ...] | None):
    token = _TOOL_HOST_SCOPE.set(hosts)
    try:
        yield
    finally:
        _TOOL_HOST_SCOPE.reset(token)


@contextlib.contextmanager
def bind_tool_capability_active(active: bool):
    token = _TOOL_CAPABILITY_ACTIVE.set(active or _TOOL_CAPABILITY_ACTIVE.get())
    try:
        yield
    finally:
        _TOOL_CAPABILITY_ACTIVE.reset(token)


def tool_capability_active() -> bool:
    return _TOOL_CAPABILITY_ACTIVE.get()


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _hardware_sensors_enabled() -> bool:
    """Opt-in gate for host hardware telemetry.

    The tool reads host state and imports the optional psutil dependency in the
    Lightwork process, so keep it out of the default model-visible registry
    unless an operator enables it explicitly.
    """
    if _env_true("MAVERICK_ENABLE_HARDWARE_SENSORS"):
        return True
    try:
        return bool(load_config().get("tools", {}).get("hardware_sensors", False))
    except Exception:  # pragma: no cover -- config never blocks the registry
        return False


def as_bool(value: Any) -> bool:
    """Strict confirm gate for destructive or costly tool ops.

    Only a real boolean ``True`` authorises a live action. ``bool("false")``
    is ``True`` in Python, so a stringy confirm (from a non-conforming MCP
    client or a loose LLM) must fail closed to a dry run rather than fire a
    refund / delete / send. Shared so every gated tool decides the same way.
    """
    return value is True


def safe_path_segment(value: Any) -> str | None:
    """Percent-encode a model-supplied id/slug for interpolation into a
    connector API path, or ``None`` if it can't be used as one segment.

    httpx (and most HTTP clients) normalizes ``..`` dot-segments in a URL
    path before sending the request. A hand-written connector that does
    ``f"/tasks/{tgid}"`` with an unencoded, model-supplied ``tgid`` lets a
    value like ``"../../api/1.0/goals/123"`` retarget the request to an
    arbitrary endpoint under the same host and credential -- escalating a
    narrowly described op ("complete a task") to any GET/POST/PUT/DELETE the
    token can reach. ``quote(value, safe="")`` percent-encodes ``/`` too, so
    the result is always exactly one opaque path segment: a traversal
    sequence like ``../../x`` becomes the literal, inert text ``..%2F..%2Fx``
    with no path-delimiter meaning left for the client to normalize.
    Rejecting an empty value or a bare ``.``/``..`` (quoting alone leaves
    dots unencoded, since they're RFC 3986 unreserved) closes the remaining
    edge case where the whole id is a no-op segment. Legitimate connector
    ids/slugs -- Asana gids, ClickUp/Confluence/Dynamics ids, Cloudflare
    zone/record ids, Bitbucket workspace/repo slugs -- never need a literal
    ``.`` or ``..`` value, so this never rejects a real one.
    """
    text = str(value or "").strip()
    if not text or text in (".", ".."):
        return None
    from urllib.parse import quote
    return quote(text, safe="")


def scrub_child_env() -> dict[str, Any]:
    """Env for a tool subprocess with secrets stripped.

    Tools that shell out (git/ffmpeg/pandoc/tesseract/adb/...) have no need
    for provider keys or connector tokens; inheriting the full ``os.environ``
    let a prompt-injected agent (or a hostile input file / repo config) read
    them out of the child. Reuse the sandbox's deny-by-pattern scrubber so a
    newly added credential is covered by default.
    """
    from ..sandbox.local import scrub_env
    return scrub_env()


# Media-tool flags that turn "convert a file" into arbitrary code exec or
# arbitrary file/URL read when injected via a freeform args[] array.
_DANGEROUS_MEDIA_FLAGS = (
    "-i", "--input", "-f", "--from", "--lua-filter", "--filter",
    "-lavfi", "-filter_complex", "-vf", "-af", "concat:",
    "--include-in-header", "--include-before-body", "--include-after-body",
    "--template", "--metadata-file", "--resource-path", "--extract-media",
    "--pdf-engine", "--syntax-definition", "--abbreviations", "--data-dir",
)


def safe_media_args(raw: Any) -> list[str]:
    """Legacy filter for extensions that accept freeform media arguments.

    By default DROP dangerous flags (input/filter/template injection that
    bypasses the tool's path confinement -- e.g. ``pandoc --lua-filter=x.lua``
    = arbitrary code, ``ffmpeg -i /etc/passwd`` = arbitrary file read). An
    operator who genuinely needs raw passthrough can opt in with
    ``MAVERICK_ALLOW_RAW_MEDIA_ARGS=1`` (then the list passes verbatim).
    Built-in media tools use their own closed option sets instead.
    """
    items = [str(a) for a in (raw or [])]
    from ..env_setting import env_or_config

    if (env_or_config("MAVERICK_ALLOW_RAW_MEDIA_ARGS", "tools", "raw_media_args")
            or "").strip().lower() in ("1", "true", "yes", "on"):
        return items
    safe: list[str] = []
    skip_next = False
    for a in items:
        if skip_next:
            # This token is the value of a dropped flag (e.g. the path after
            # a bare `-i`); drop it too.
            skip_next = False
            continue
        low = a.lower()
        dangerous = False
        takes_value = False
        for f in _DANGEROUS_MEDIA_FLAGS:
            if f.endswith(":"):
                if low.startswith(f):          # e.g. concat:...
                    dangerous = True
                    break
            elif low == f:                     # bare flag -> value is the next token
                dangerous = True
                takes_value = True
                break
            elif low.startswith(f + "="):      # flag=value -> self-contained
                dangerous = True
                break
        if dangerous:
            skip_next = takes_value
            continue
        safe.append(a)
    return safe


def sandbox_run(
    sandbox: Any,
    argv: list[str],
    *,
    timeout: float = 120.0,
    stdin: str | None = None,
) -> tuple[int, str, str]:
    """Run ``argv`` through the sandbox chokepoint; return (code, stdout, stderr).

    Media tools (ffmpeg/imagemagick/pandoc/tesseract/pa11y...) historically
    shelled out on the host with ``subprocess.run`` even when a sandbox was
    wired in, bypassing the chokepoint that confines model-driven commands and
    lets tests swap the backend (CLAUDE.md rule #4). This routes the command
    through ``sandbox.exec()`` instead.

    Through a sandbox, the argv is shell-quoted with ``shlex.join`` and handed
    to ``exec()`` (which runs ``sh -c``); ``stdin`` is fed via a base64 pipe so
    arbitrary text reaches the process without shell-quoting hazards. Windows
    LocalBackend runs the argv directly with a bounded stdin pipe. When no
    sandbox is wired in, falls back to a scrubbed-env ``subprocess.run`` of the
    raw argv list (no shell interpolation -- the chokepoint guard forbids that
    outside the sandbox backends), passing ``stdin`` directly.
    """
    if sandbox is not None:
        # Resolve the call shape before any effect. Explicitly bounded legacy
        # backends may be adapted; no internal TypeError authorizes replay.
        from ..sandbox.sdk import execution_callable

        execute = execution_callable(sandbox)
        if os.name == "nt":
            from ..sandbox.local import LocalBackend

            if type(sandbox) is LocalBackend:
                # cmd.exe has no printf/base64 -d pipeline and an 8191-char
                # command limit. Direct argv avoids shell interpolation; the
                # bounded stdin pipe keeps notebook contents off the command line.
                res = execute(argv, timeout=timeout, stdin=stdin)
                return res.exit_code, res.stdout, res.stderr
        import shlex
        cmd = shlex.join(argv)
        if stdin is not None:
            import base64
            b64 = base64.b64encode(stdin.encode("utf-8")).decode("ascii")
            cmd = f"printf %s {shlex.quote(b64)} | base64 -d | {cmd}"
        res = execute(cmd, timeout=timeout)
        return res.exit_code, res.stdout, res.stderr

    import subprocess
    try:
        r = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=timeout, env=scrub_child_env(), input=stdin,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"TIMEOUT after {timeout}s"


def host_exec(
    argv: list[str],
    *,
    timeout: float = 60.0,
    text: bool = True,
) -> tuple[int, Any, Any]:
    """Run ``argv`` directly on the HOST, deliberately NOT sandbox-mediated.

    CLAUDE.md rule #4 ("sandbox-mediate all shell") applies to *model-influenced
    commands whose work happens inside the workspace* — those go through
    ``sandbox_run`` / ``sandbox.exec`` so the configured container isolation
    applies and tests can swap the backend.

    A small set of tools are **host-bound by nature**: the resource they act on
    (a USB-attached Android device via ``adb``, an iOS simulator via ``simctl``,
    the desktop clipboard) lives on the *host*, not in the workspace. The
    sandbox runs in a network-isolated container with no access to that
    hardware, so routing these through ``sandbox.exec`` would simply break them.
    They call ``host_exec`` instead — a single, greppable, env-scrubbed entry
    point that makes the "intentionally direct, not sandbox-mediated" choice
    explicit and auditable (rather than a bare ``subprocess.run`` that looks
    like an un-migrated rule-#4 violation).

    Returns ``(exit_code, stdout, stderr)``; a timeout yields ``(124, "", msg)``.
    The child env is scrubbed of secrets (``scrub_child_env``). ``argv`` is a
    list (no shell interpolation).
    """
    import subprocess
    try:
        r = subprocess.run(
            argv, capture_output=True, text=text,
            timeout=timeout, env=scrub_child_env(),
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        empty = "" if text else b""
        return 124, empty, f"TIMEOUT after {timeout}s"


def _forward_progress(listener, name: str, count: int) -> None:
    """Only fixed progress may escape before complete-result screening."""
    if listener is not None:
        try:
            from ..safety.secret_detector import redact

            safe_name, _ = redact(name[:128])
            listener(safe_name, f"[Buffering tool output: {count} bytes; content withheld until screening.]")
        except Exception:  # listener must never break the call
            pass


async def _execute_tool_fn(fn, args: dict[str, Any], stream_chunk) -> str:
    """Collect under a fixed quota; the callback carries byte-count progress only."""
    from ..tool_result_stream import execute_tool

    return await execute_tool(fn, args, stream_chunk)


def _store_bounded_cached(store, tool, args, result, namespace, generation=None):
    # Snapshots and shared caches store plain strings and would discard the
    # explicit state. Do not let a restored value acquire a different meaning.
    from ..tool_results import ToolResultText, classify_tool_result

    if isinstance(result, ToolResultText):
        # A plain-string snapshot is safe only when restoring it preserves the
        # explicit state; otherwise skip the cache rather than changing meaning.
        if classify_tool_result(str(result)) is not result.state:
            return
        result = str(result)
    if len(result) <= 64_000:
        if generation is None:
            store(tool, args, result, namespace=namespace)
        else:
            store(tool, args, result, namespace=namespace, generation=generation)


def _tool_error_result(error, name):
    from ..tool_result_stream import ToolOutputUncertain

    if getattr(error, "tool_execution_unknown", False):
        return ToolOutputUncertain(
            "INDETERMINATE: tool dispatch may have produced effects, but its complete output "
            "could not be retained within the collection/cleanup limits. Partial output was "
            "withheld; reconcile external state and do not retry the action blindly."
        )
    try:
        from ..observability import record_metric
        record_metric("tool_calls", labels={"tool": name, "status": "error"})
    except Exception:
        pass
    return f"ERROR: {type(error).__name__}: {error}"


ToolFn = Callable[[dict[str, Any]], str | ToolOutcome | Awaitable[str | ToolOutcome]]


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    fn: ToolFn
    # When True, the agent loop may run this tool CONCURRENTLY with the
    # other tool calls in the same model turn (asyncio.gather). Only set
    # it on side-effect-free, idempotent reads (read_file, list_dir,
    # repo_map, dep_graph). Anything that writes the workspace, shells
    # out, spawns children, sends a message, or holds a remote rate limit
    # must stay False so it executes serially. The loop only parallelises
    # a turn when EVERY call in it is parallel_safe, so the default of
    # False is always safe — it just forgoes the speedup. Not part of
    # ``to_anthropic()``: it must never alter the tool catalog the model
    # sees (that would bust the prompt cache).
    parallel_safe: bool = False
    # Ask the provider to validate tool inputs against input_schema
    # (Anthropic ``strict: true``; OpenAI function ``strict: true``) so a
    # malformed-arguments retry is never needed. Off by default: strict mode
    # constrains the schema (e.g. additionalProperties: false, every property
    # required on OpenAI), so a tool opts in once its schema is ready. Only
    # emitted when set, so the catalog the model sees -- and the prompt
    # cache key -- is unchanged for every other tool.
    strict: bool = False

    def to_anthropic(self) -> dict[str, Any]:
        spec: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }
        if self.strict:
            spec["strict"] = True
        return spec


class ToolRegistry:
    # Deferred-loading meta-tool name (see enable_deferred / find_tools.py).
    META_TOOL = "find_tools"

    def __init__(self, *, principal: str | None = None):
        self._tools: dict[str, Tool] = {}
        # Authenticated execution identity used by credential-bearing tools.
        # Stored on the registry and rebound with a ContextVar per invocation so
        # sync tools running in worker threads cannot borrow another run's saved
        # SaaS connection.
        self._principal = str(principal or "").strip() or None
        self._acl_allowed: set[str] = set()
        self._acl_denied: set[str] = set()
        self._acl_max_risk: str | None = None
        # Deferred tool loading: when on, only _core (+ find_tools + any
        # _activated) tools are shown to the model; the long tail is
        # discovered on demand. run() can still execute ANY registered tool.
        self._deferred = False
        self._core_names: set[str] = set()
        self._core: set[str] = set()
        self._activated: set[str] = set()
        self._activation_order: list[str] = []
        # The last model-facing catalog ceiling. Overflow is discoverable by
        # find_tools, rather than disappearing when a provider truncates it.
        self._catalog_limit: int | None = None
        # Names never exposed NOR discoverable (a pack's deny_tools, or
        # anything the agent's capability would refuse anyway). run() can
        # still resolve them -- the capability / ACL check at call time is
        # the authority; this only keeps them out of the catalog and out of
        # find_tools' search space.
        self._hidden: set[str] = set()
        # Listeners receive safe progress before screening, never raw chunks.
        # The agent explicitly releases screened/redacted content at delivery.
        self._chunk_listener = None
        # Names base_registry marks as deferred-eligible (the SaaS connector
        # long tail). Consumed by Agent._build_tools when the
        # [capabilities] deferred_tools knob (default on) hides them behind
        # the find_tools meta-tool. Empty == nothing marked.
        self.deferrable_names: set[str] = set()
        # Memoized to_anthropic() payload. The exposed tool set is stable
        # across turns (it only changes on register / set_acl /
        # enable_deferred / activate), but the agent loop re-serialises all
        # 80+ tool schemas every model turn. Cache it and invalidate at those
        # four mutation points. Consumers copy before mutating (the Anthropic
        # provider does ``[dict(t) for t in ...]``), so sharing is safe.
        self._anthropic_cache: list[dict[str, Any]] | None = None
        # MCP refresh is discovery, never authority expansion. These guards
        # retain only exact admitted metadata while the remote catalog is fresh.
        self._mcp_bindings: dict[str, Callable[[], bool]] = {}
        self._mcp_visibility: tuple[str, ...] = ()

    def set_acl(
        self,
        *,
        allowed: set[str] | None = None,
        denied: set[str] | None = None,
        max_risk: str | None = None,
    ) -> None:
        self._acl_allowed = set(allowed or set())
        self._acl_denied = set(denied or set())
        self._acl_max_risk = max_risk
        self._anthropic_cache = None

    def _acl_allows(self, name: str) -> bool:
        if self._acl_allowed and name not in self._acl_allowed:
            return False
        if self._acl_denied and name in self._acl_denied:
            return False
        if self._acl_max_risk:
            from ..safety.tool_risk import risk_rank, tool_risk

            if risk_rank(tool_risk(name)) > risk_rank(self._acl_max_risk):
                return False
        return True

    def set_chunk_listener(self, listener) -> None:
        """Receive safe progress, then explicitly screened chunks at delivery.

        ``run`` returns complete bounded execution data but cannot itself assert
        the caller's Shield policy. The agent calls ``deliver_screened`` only
        after full-output policy checks, redaction and terminal audit. Standalone
        integrations must do the same; raw producer chunks are never forwarded.
        """
        self._chunk_listener = listener

    def deliver_screened(self, name: str, output: str) -> None:
        """Trusted caller asserts policy screening; redaction is checked again."""
        if self._chunk_listener is None:
            return
        from ..safety.secret_detector import redact
        from ..tool_result_stream import COPY_CHARS, result_bytes

        try:
            result_bytes(output)
            safe, _ = redact(output)
            safe_name, _ = redact(name[:128])
        except Exception:
            return  # fail closed for observers without inviting effect replay
        for start in range(0, len(safe), COPY_CHARS):
            try:
                self._chunk_listener(safe_name, safe[start:start + COPY_CHARS])
            except Exception:
                pass  # an observer must not invite replay of a completed effect

    def register(self, tool: Tool) -> None:
        if not self._acl_allows(tool.name):
            return
        self._tools[tool.name] = tool
        if self._deferred and tool.name in self._core_names:
            self._core.add(tool.name)
        self._anthropic_cache = None

    def get(self, name: str) -> Tool:
        if not self._mcp_binding_current(name):
            raise KeyError(name)
        return self._tools[name]

    def all(self) -> list[Tool]:
        return [t for n, t in self._tools.items() if self._mcp_binding_current(n)]

    def catalog_metadata(self) -> list[dict[str, Any]]:
        """Describe registered, discoverable tools without exposing hidden names."""
        return [
            {"name": tool.name, "deferred_eligible": tool.name in self.deferrable_names}
            for tool in self.all()
            if tool.name not in self._hidden and self._acl_allows(tool.name)
        ]

    def _mcp_binding_current(self, name: str) -> bool:
        check = self._mcp_bindings.get(name)
        return check is None or check()

    # --- deferred tool loading -----------------------------------------
    # With 80+ tools (+ MCP servers), sending every schema every turn
    # dominates the context window. When enabled, only a small CORE set +
    # the find_tools meta-tool are exposed to the model; the long tail is
    # discovered and activated on demand. The exposed set is stable across
    # turns (until an activation), so the tool-catalog prompt cache still
    # hits. activation only governs what the model SEES -- run() executes
    # any registered tool regardless.

    def enable_deferred(self, core: set[str], *, hidden: set[str] | None = None) -> None:
        """Expose only ``core`` (∩ registered) + find_tools to the model.

        ``hidden`` names are neither exposed nor discoverable via find_tools
        (they stay registered, so execution semantics are unchanged).
        """
        self._deferred = True
        self._hidden = set(hidden or ())
        self._core_names = set(core) - self._hidden
        self._core = {n for n in self._core_names if n in self._tools}
        self._anthropic_cache = None

    def deferred_enabled(self) -> bool:
        return self._deferred

    def _exposed_names(self) -> set[str]:
        return self._core | self._activated | {self.META_TOOL}

    def activate(self, names: list[str]) -> list[str]:
        """Reveal deferred tools to the model. Returns the names that
        can actually be shown next turn (unknown names are ignored)."""
        resolved = [n for n in names if n in self._tools and n not in self._hidden
                    and self._acl_allows(n) and self._mcp_binding_current(n)]
        if resolved:
            self._activated.update(resolved)
            for name in resolved:
                if name in self._activation_order:
                    self._activation_order.remove(name)
                self._activation_order.append(name)
            self._anthropic_cache = None
        if self._catalog_limit is not None:
            visible = self._limited_names(self._catalog_limit)
            return [n for n in resolved if n in visible]
        return resolved

    def exposed(self) -> list[Tool]:
        """Tools the model sees this turn, in registration order.

        Identity when deferred loading is off, so default behavior and the
        byte-identical tool catalog (for prompt caching) are unchanged.
        """
        if not self._deferred:
            return [t for n, t in self._tools.items() if self._acl_allows(n) and self._mcp_binding_current(n)]
        names = self._exposed_names() - self._hidden
        return [t for n, t in self._tools.items() if n in names and self._acl_allows(n) and self._mcp_binding_current(n)]

    def deferred_tools(self) -> list[Tool]:
        """Registered tools not currently exposed -- find_tools' search space."""
        if self._catalog_limit is not None:
            names = self._limited_names(self._catalog_limit) | self._hidden
        elif self._deferred:
            names = self._exposed_names() | self._hidden
        else:
            names = {t.name for t in self.exposed()} | self._hidden
        return [t for n, t in self._tools.items() if n not in names and self._acl_allows(n) and self._mcp_binding_current(n)]

    def _limited_names(self, limit: int) -> set[str]:
        """Prefer discovery, recently requested tools and the working core."""
        offered = self.exposed()
        if len(offered) <= limit:
            return {t.name for t in offered}
        available = {t.name for t in offered}
        # Registration order puts orchestration after hundreds of base tools.
        # A model with a tool ceiling must retain discovery and coordination;
        # recently discovered tools then displace the ordinary catalog tail.
        priority = (
            [self.META_TOOL]
            + list(reversed(self._activation_order))
            + ["ask_user", "spawn_subagent", "spawn_swarm", "spawn_specialist",
               "list_specialists", "send_to_agent", "recv_from_agent",
               "delegate_to_agent", "knowledge_search"]
            + sorted(CORE_TOOL_NAMES)
            + [t.name for t in offered]
        )
        selected: set[str] = set()
        for name in priority:
            if name in available:
                selected.add(name)
                if len(selected) == limit:
                    break
        return selected

    def to_anthropic(self, *, max_tools: int | None = None) -> list[dict[str, Any]]:
        if max_tools is not None and (type(max_tools) is not int or max_tools < 1):
            raise ValueError("max_tools must be a positive integer")
        self._catalog_limit = max_tools
        visible = tuple(n for n in self._mcp_bindings if self._mcp_binding_current(n))
        if visible != self._mcp_visibility:
            self._mcp_visibility = visible
            self._anthropic_cache = None
        if self._anthropic_cache is None:
            self._anthropic_cache = [t.to_anthropic() for t in self.exposed()]
        if max_tools is not None and len(self._anthropic_cache) > max_tools:
            names = self._limited_names(max_tools)
            return [t for t in self._anthropic_cache if t["name"] in names]
        return self._anthropic_cache

    def cache_namespace(self) -> str:
        """The tool-output cache scope of this registry's calls: the active
        tenant and the principal, so two users never share a read result."""
        from ..paths import current_tenant_id

        return (
            f"tenant={current_tenant_id() or '<shared>'}\0"
            f"principal={self._principal or '<anonymous>'}"
        )

    def speculate_reads(self, predictions, *, budget_guard=None):
        """Pre-run predicted repeat reads so their results wait in the cache.

        Only tools this registry would run right now for this principal (ACL,
        current MCP binding, no refused ambient credentials) are offered to
        :func:`maverick.speculative_tools.speculate`, under the same cache
        scope and principal a real call uses. When the model then asks, the
        call still passes every gate in the agent and in :meth:`run`; only the
        side-effect-free read itself has already happened. Never raises.
        """
        from ..speculative_tools import speculate

        allowed = [
            (name, args) for name, args in predictions
            if self._tool_access_error(name) is None
            and _ambient_credential_denial(name, self._principal) is None
            and not any(isinstance(key, str) and key.startswith("_capability_") for key in args)
        ]
        return speculate(self, allowed, namespace=self.cache_namespace(),
                         principal=self._principal, budget_guard=budget_guard)

    def _tool_access_error(self, name: str) -> str | None:
        """Check current authorization before touching a lazy executor."""
        if name not in self._tools:
            return f"ERROR: unknown tool {name!r}"
        if not self._acl_allows(name):
            return f"ERROR: tool {name!r} is denied by the current tool ACL"
        if not self._mcp_binding_current(name):
            return "ERROR: MCP binding is stale or changed; refresh tools and rebuild the registry"
        return None

    async def _run_tool_attempt(self, name, args, expected_tool):
        from ..connections import bind_principal

        if denial := self._tool_access_error(name):
            return denial
        if self._tools[name] is not expected_tool:
            return "ERROR: tool registration changed during invocation"
        if denial := _ambient_credential_denial(name, self._principal):
            return denial
        with bind_principal(self._principal):
            try:
                return await _execute_tool_fn(
                    self._tools[name].fn, args,
                    lambda count: _forward_progress(self._chunk_listener, name, count),
                )
            finally:
                # Once dispatched, even an exception or cancellation can leave
                # a write committed. Invalidate after each retry attempt.
                try:
                    from ..cache.tool import note_side_effect
                    note_side_effect(expected_tool)
                except Exception:  # pragma: no cover -- cache is best effort
                    pass

    async def run(self, name: str, args: dict[str, Any]) -> str:
        # Flow actions and library callers can reach the registry without the
        # agent. Strip all caller-provided internal capability metadata here.
        args = {key: value for key, value in args.items()
                if not (isinstance(key, str) and key.startswith("_capability_"))}
        hosts = _TOOL_HOST_SCOPE.get()
        if hosts:
            args["_capability_allow_hosts"] = hosts
        access_error = self._tool_access_error(name)
        if access_error:
            return access_error
        try:
            from ..observability import gen_ai_tool_attributes, trace_span
        except ImportError:  # pragma: no cover
            import contextlib

            def trace_span(*_args, **_kwargs):  # type: ignore
                return contextlib.nullcontext()

            def gen_ai_tool_attributes(tool_name, **_kwargs):  # type: ignore
                return {}
        with trace_span(
            "tool.run",
            attributes={"tool.name": name, **gen_ai_tool_attributes(name)},
        ):
            import time as _perf_time
            _t0 = _perf_time.perf_counter()
            try:
                # Opt-in tool-output cache (default OFF): serve a memoized
                # result for side-effect-free (parallel_safe) tools so a
                # repeated read doesn't re-do the work. Never caches writes
                # or error results. See tool_cache.py.
                _tool = self._tools[name]
                if denial := _ambient_credential_denial(name, self._principal):
                    return denial
                # Cache identity is an authorization boundary. Resolve it
                # before lookup (the connector ContextVar is bound only while
                # invoking the function) and include both tenant and principal
                # so two users or clients cannot share a credential-bearing
                # read result merely because the tool arguments match.
                _cache_namespace = self.cache_namespace()
                try:
                    from ..cache.tool import get_cached, store_cached
                except ImportError:  # pragma: no cover
                    get_cached = store_cached = None  # type: ignore[assignment]
                if get_cached is not None:
                    _hit, _cached = get_cached(
                        _tool, args, namespace=_cache_namespace,
                    )
                    if _hit:
                        from ..tool_result_stream import result_bytes
                        result_bytes(_cached)
                        try:
                            from ..observability import record_metric as _rm
                            _rm("tool_calls",
                                labels={"tool": name, "status": "cache"})
                        except Exception:  # pragma: no cover
                            pass
                        return _cached
                from ..cache.tool import generation as _cache_generation
                _read_generation = _cache_generation()
                try:
                    from ..chaos import maybe_fail
                    maybe_fail("tool_dispatch",
                               message=f"chaos: tool_dispatch on {name!r}")
                except ImportError:
                    pass
                async def _invoke() -> str:
                    return await self._run_tool_attempt(name, args, _tool)

                # One shared reliability policy: transient upstream failures
                # on retry-safe (non-high-risk) tools are retried with backoff.
                from ..tool_reliability import run_with_retry
                result = await run_with_retry(name, _invoke)
                # Internal connector status/retry/dispatch metadata is no
                # longer needed beyond this model-visible string boundary.
                from ..connector_attempts import public_result
                result = public_result(result)
                from ..tool_results import ToolResultState, classify_tool_result
                result_state = classify_tool_result(result)
                if store_cached is not None and result_state is ToolResultState.SUCCEEDED:
                    try:
                        _store_bounded_cached(
                            store_cached, _tool, args, result, _cache_namespace,
                            _read_generation,
                        )
                    except Exception:  # pragma: no cover
                        pass
                try:
                    from ..observability import record_metric as _rm
                    _rm("tool_calls", labels={"tool": name, "status": result_state.value})
                except Exception:  # pragma: no cover
                    pass
                return result
            except (BudgetExceeded, UsageAccountingError, killswitch.Halted):
                # Control-flow stop signals are NOT tool errors: a spawned
                # child (spawn_subagent/spawn_swarm/spawn_specialist) shares
                # the parent Budget and killswitch, and re-raises these to
                # halt the whole run immediately. They must propagate to the
                # agent loop's `except (BudgetExceeded, killswitch.Halted)`
                # handler (agent.py) instead of being folded into an "ERROR:"
                # string by the blanket handler below — otherwise the budget
                # cap / killswitch is not enforced and the run keeps going.
                raise
            except Exception as e:
                # Tool errors (incl. an injected tool_dispatch chaos failure)
                # are surfaced as a tool-result string so the agent can react
                # — this mirrors how real tool exceptions behave. The chaos
                # gap worth covering is on the LLM path, fixed by wiring
                # maybe_fail("llm_call") into complete_async (not here).
                return _tool_error_result(e, name)
            finally:
                # Always-on per-tool latency profile (complements OTel spans).
                # Records on both the success and error paths; never raises.
                _elapsed_ms = (_perf_time.perf_counter() - _t0) * 1000.0
                try:
                    from ..tool_latency import record as _rec_latency
                    _rec_latency(name, _elapsed_ms)
                except Exception:  # pragma: no cover -- profiling never breaks a tool
                    pass
                # Opt-in per-tool latency budget (default OFF): record a breach
                # if the call ran longer than [tools] latency_budget_ms. Fail-open.
                try:
                    from ..latency_budget import note_elapsed as _note_budget
                    _note_budget(name, _elapsed_ms)
                except Exception:  # pragma: no cover -- budget never breaks a tool
                    pass


# Tools exposed to the model by default under deferred loading. The long
# tail (SaaS/cloud integrations, MCP, plugins) is discovered via find_tools.
# Listing a name that isn't registered is harmless -- enable_deferred
# intersects with the actual registry.
CORE_TOOL_NAMES = frozenset({
    # filesystem + execution
    "read_file", "write_file", "list_dir", "shell", "read_tool_result",
    # code editing
    "str_replace_editor", "apply_patch", "ast_edit", "preview_diff",
    # repo understanding
    "repo_map", "dep_graph",
    # interaction + attachments
    "ask_user", "list_attachments", "read_attachment",
    # web / docs / media basics
    "http_fetch", "web_search", "read_pdf", "view_image",
    # memory + run introspection
    "recall_past_goals", "kv_memory", "memory", "budget_status", "diagnose",
    "spend_report", "notify", "compute",
    # multi-agent
    "spawn_subagent", "spawn_swarm",
    # kernel tools Agent._build_tools registers on top of base_registry
    # (bus, specialists, governed knowledge, self-learning) -- listed here so
    # they stay visible under [tools] exposure = "core".
    "send_to_agent", "recv_from_agent", "delegate_to_agent",
    "spawn_specialist", "list_specialists", "knowledge_search",
    "learn_capability", "code_exec",
    # the read-only data basics 1,700+ specialist packs allow
    "sql_query_read", "spreadsheet_read",
    # the discovery meta-tool itself
    "find_tools",
})

# Role-specific additions to CORE_TOOL_NAMES under [tools] exposure = "core".
# Kept small: everything else stays discoverable through find_tools. A role
# without an entry (worker, writer, summarizer, verifier, a pack's name...)
# gets exactly CORE_TOOL_NAMES.
ROLE_TOOL_OVERLAYS: dict[str, frozenset[str]] = {
    "orchestrator": frozenset({"task_graph", "spend_report"}),
    "coder": frozenset({
        "git_advanced", "test_impact", "test_gen", "semantic_code_search",
        "lsp_bridge", "cross_repo_deps",
    }),
    "researcher": frozenset({
        "arxiv", "wikipedia", "semantic_scholar", "hackernews",
        "citation_verifier", "web_archive", "spreadsheet",
    }),
    "analyst": frozenset({"pandas_query", "spreadsheet", "sql_query", "format_money", "currency"}),
    "writer": frozenset({"outline_writer", "plain_language", "pandoc", "latex"}),
}
ROLE_TOOL_OVERLAYS["coding"] = ROLE_TOOL_OVERLAYS["coder"]
ROLE_TOOL_OVERLAYS["reviewer"] = ROLE_TOOL_OVERLAYS["coder"]
ROLE_TOOL_OVERLAYS["revisor"] = ROLE_TOOL_OVERLAYS["coder"]
# Not every role needs the code-editing tools; the kernel core keeps
# read_file/write_file/shell for all, and these ride only with code roles.
_CODE_EDIT_TOOLS = frozenset({"apply_patch", "ast_edit", "preview_diff", "repo_map", "dep_graph"})
_NON_CODE_ROLES = frozenset({"worker", "researcher", "writer", "analyst", "summarizer",
                             "verifier", "translator", "vision", "skill_distiller"})


def core_tool_names(role: str, *, extra=()) -> frozenset[str]:
    """The tool names shown up front for ``role`` under exposure = "core".

    ``extra`` is the operator's ``[tools] core_extra`` pin list. Names that
    are not registered are harmless (enable_deferred intersects).
    """
    role = str(role or "").strip().lower()
    names = set(CORE_TOOL_NAMES) | ROLE_TOOL_OVERLAYS.get(role, frozenset())
    if role in _NON_CODE_ROLES:
        names -= _CODE_EDIT_TOOLS
    names.update(str(t).strip() for t in (extra or ()) if str(t).strip())
    return frozenset(names)

# Credentialed SaaS/cloud tools that may use ambient host credentials: they
# only register when the operator opts in via
# MAVERICK_ENABLE_CRED_TOOLS=true (see base_registry below). These names are
# reserved -- the always-on enterprise_connectors catalog must never reuse one
# (see test_no_collision_with_opt_in_ambient_cred_tools).
AMBIENT_CRED_TOOL_NAMES = frozenset({
    "airtable", "asana", "clickup", "lambda", "dynamodb", "vercel", "gdrive",
})

# Hand-written connectors that still read operator-global environment
# credentials directly. They are safe for the anonymous/local operator path,
# but cannot enforce per-principal grants. Authenticated enterprise execution
# therefore refuses them until each is migrated to the sealed connection
# resolver. Generic REST/GraphQL connectors are intentionally absent: their
# resolver enforces principal-scoped saved connections at credential use.
AUTHENTICATED_AMBIENT_CRED_TOOL_NAMES = AMBIENT_CRED_TOOL_NAMES | frozenset({
    "bigquery", "bitbucket", "calendar", "calendly", "cloudflare",
    "confluence", "database", "databricks", "datadog", "discord_bot",
    "discord_slash", "dropbox", "dynamics", "elasticsearch", "email", "erp_read",
    "ga4", "github_actions", "github_issues", "gitlab", "gitlab_issues",
    "geocode", "github_repo_search", "github_search", "gmail", "home_assistant",
    "hubspot", "huggingface", "jira", "linear", "mixpanel",
    "mongodb", "msgraph", "newsapi", "notion", "onetrust", "oracle",
    "pagerduty", "plaid", "plausible", "posthog", "reddit", "redis",
    "replicate", "s3", "salesforce", "sap", "sentry", "servicenow", "ses",
    "semantic_scholar", "shopify", "slack_bot", "slack_workflow", "snowflake",
    "sns", "speak", "spotify", "stripe", "teams", "transcribe_audio", "translate",
    "trello", "truelayer", "twilio", "vertex", "wolfram", "workday", "zoom",
})


def _ambient_credential_denial(name: str, principal: str | None) -> str | None:
    from ..template_connections import SelectionUnavailable, active, selected
    if active() and name in AUTHENTICATED_AMBIENT_CRED_TOOL_NAMES:
        if name == "gdrive":
            try:
                selected("gdrive", principal)
                return None
            except SelectionUnavailable:
                pass
        return "REFUSED: this connector cannot use the task's exact selected account. No ambient account was substituted."
    if not principal or name not in AUTHENTICATED_AMBIENT_CRED_TOOL_NAMES:
        return None
    from ..enterprise import enterprise_enabled

    if not enterprise_enabled():
        return None
    return (
        "REFUSED (credentials): authenticated enterprise execution cannot use "
        f"operator-global environment credentials for connector {name!r}. This "
        "connector must be migrated to a principal-authorized saved connection "
        "before tenant users or agents can run it."
    )


def enterprise_unavailable_tool_names() -> frozenset[str]:
    """Connector tools a signed-in person cannot run while Enterprise mode is on.

    The same rule :func:`_ambient_credential_denial` applies at call time, stated
    ahead of time so the Tools page can tell an administrator before rollout
    rather than the person's task being refused. Empty when Enterprise mode is
    off. Callers intersect it with the tools actually registered.
    """
    from ..enterprise import enterprise_enabled

    return AUTHENTICATED_AMBIENT_CRED_TOOL_NAMES if enterprise_enabled() else frozenset()


def _deferred_loading_enabled() -> bool:
    """Use the same explicit policy as agents, retaining the standalone default."""
    try:
        from ..config import get_deferred_tools
        return get_deferred_tools(default=False)
    except Exception:  # pragma: no cover -- config never blocks the registry
        return True  # a failed policy read must not widen the visible catalog


def _register_local_workspace_tool(reg, sandbox, factory, has_local_workdir):
    """Register a local path tool only for a locally accessible workspace."""
    if has_local_workdir:
        reg.register(factory(sandbox))


def _registry_principal(user_id: str | None) -> str:
    """Capture the user or authenticated caller identity for registry dispatch."""
    principal = str(user_id or "").strip()
    if principal and not principal.startswith("user:"):
        return f"user:{principal}"
    if principal:
        return principal
    # Network adapters bind the authenticated principal in a ContextVar.
    # Capture it so worker threads and nested agents retain the caller's
    # credential and output-cache namespace even after the context exits.
    from ..connections import current_principal

    return str(current_principal() or "").strip()


def base_registry(
    world,
    sandbox,
    mcp_clients: list | None = None,
    goal_id: int | None = None,
    enable_computer_use: bool = False,
    enable_browser: bool = False,
    enable_web_search: bool = False,
    enable_mobile_tools: bool = False,
    enable_ros: bool = False,
    channel: str | None = None,
    user_id: str | None = None,
    budget: Any = None,
    _include_generated_tools: bool = True,
    _skip_tool_acl: bool = False,
    _include_plugins: bool = True,
) -> ToolRegistry:
    """Build the base tool set (no spawn tools).

    If ``mcp_clients`` is given, each one's discovered tools are
    registered as ``mcp_<server>__<tool>``.

    ``goal_id`` scopes ``ask_user`` so questions are filed against the
    running goal — otherwise the orchestrator's ``open_questions(gid)``
    filter returns nothing and "PAUSED: 0 open question(s)" is shown
    even though the agent asked.

    ``enable_computer_use`` / ``enable_browser`` / ``enable_mobile_tools`` /
    ``enable_ros`` register optional high-impact tools. Computer/browser require
    optional extras
    (``maverick-agent[computer-use]`` / ``[browser]``); when missing
    the tool factories raise an actionable ImportError at registration
    time, NOT at tool-call time -- so a user who picks computer-use in
    the wizard discovers the missing dep immediately rather than after
    the first run.

    ``budget`` binds tools that perform their own metered provider calls
    (for example ``view_video``) to the active run budget.

    ``_include_generated_tools`` is an internal recursion guard used only by
    :func:`base_tool_names`: namespace introspection must assemble the built-in
    registry without recursively loading generated tools whose own collision
    check calls ``base_tool_names``.
    """
    from .ask_user import ask_user
    from .attachments import list_attachments_tool, read_attachment_tool
    from .fs import list_dir, read_file, write_file
    from .repo_map import repo_map
    from .shell import shell
    from .str_edit import str_replace_editor

    principal = _registry_principal(user_id)
    reg = ToolRegistry(principal=principal or None)
    from ..sandbox.sdk import workdir_is_local

    # These tools use local pathlib operations rather than sandbox.exec().
    # A remote workspace path would refer to an unrelated host directory.
    has_local_workdir = workdir_is_local(sandbox)
    _register_local_workspace_tool(reg, sandbox, read_file, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, lambda sb: write_file(sb, goal_id=goal_id), has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, list_dir, has_local_workdir)
    reg.register(shell(sandbox))
    reg.register(ask_user(world, goal_id=goal_id))
    reg.register(list_attachments_tool(world, goal_id))
    from ..tool_result_artifacts import read_tool_result

    reg.register(read_tool_result(goal_id=goal_id, principal=principal or None))
    reg.register(read_attachment_tool(world, goal_id))
    _register_local_workspace_tool(reg, sandbox, repo_map, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, str_replace_editor, has_local_workdir)
    # Governed session kernel. Registered ONLY when the operator has turned
    # it on: an unregistered tool costs no catalog tokens and cannot be
    # called, so the default deployment is unchanged.
    try:
        from ..governed_repl import enabled as _repl_enabled
        if _repl_enabled():
            from .repl import repl_exec
            reg.register(repl_exec(goal_id=goal_id, principal=principal))
    except Exception as e:  # pragma: no cover - config read must not break setup
        import logging as _repl_logging
        _repl_logging.getLogger(__name__).warning(
            "repl tool registration skipped: %s", e)
    _apply_commerce_tools(reg, principal)

    from .a11y import a11y
    from .a11y_tree import a11y_tree
    from .adversarial_self_test import adversarial_self_test
    from .agent_simulator import agent_simulator
    from .ai_act_classifier import ai_act_classifier
    from .airtable_tool import airtable_tool
    from .android import android
    from .anki import anki
    from .anomaly_scan import anomaly_scan
    from .apple_shortcuts import apple_shortcuts
    from .apply_patch import apply_patch
    from .arxiv import arxiv
    from .asana_tool import asana_tool
    from .ast_edit import ast_edit
    from .async_compaction import async_compaction
    from .audio_understanding import audio_understanding
    from .audit_mirror import audit_mirror
    from .autogen_adapter import autogen_adapter
    from .bias_eval import bias_eval
    from .bitbucket_tool import bitbucket_tool
    from .breach_notification import breach_notification
    from .budget_status import budget_status
    from .cache_admin import cache_admin
    from .cache_eviction import cache_eviction
    from .calendar_tool import calendar_tool
    from .calendly_tool import calendly_tool
    from .capability_delegation import capability_delegation
    from .capability_delegation_graph import capability_delegation_graph
    from .capability_leak_fuzzer import capability_leak_fuzzer
    from .capability_negotiation import capability_negotiation
    from .capability_revocation import capability_revocation
    from .channel_autoroute import channel_autoroute
    from .chaos_gameday import chaos_gameday
    from .cidr_check import cidr_check
    from .citation_verifier import citation_verifier
    from .clickup_tool import clickup_tool
    from .clipboard import clipboard
    from .cloudflare_tool import cloudflare_tool
    from .collusion_detector import collusion_detector
    from .compaction_classifier import compaction_classifier
    from .comparative_replay import comparative_replay
    from .compute import compute
    from .confluence_tool import confluence_tool
    from .consent_check import consent_check
    from .consent_ergonomics import consent_ergonomics
    from .constrained_output import constrained_output
    from .container_build import container_build
    from .containment_mode import containment_mode
    from .coordinated_disclosure import coordinated_disclosure
    from .cost_attribution import cost_attribution
    from .cost_aware_router import cost_aware_router
    from .cost_guardrail import cost_guardrail
    from .cost_of_quality import cost_of_quality
    from .crewai_adapter import crewai_adapter
    from .cross_repo_deps import cross_repo_deps
    from .crypto_budget_receipt import crypto_budget_receipt
    from .currency import currency
    from .data_minimization import data_minimization
    from .data_residency import data_residency
    from .datadog_tool import datadog_tool
    from .decision_explainer import decision_explainer
    from .dep_graph import dep_graph
    from .diagnose import diagnose
    from .diff_to_expected import diff_to_expected
    from .differential_privacy import differential_privacy
    from .discord_bot import discord_bot
    from .discord_slash import discord_slash
    from .dns_lookup import dns_lookup
    from .dp_stats import dp_stats
    from .dropbox_tool import dropbox_tool
    from .dynamodb_tool import dynamodb_tool
    from .elasticsearch_tool import elasticsearch_tool
    from .email_tool import email_tool
    from .embedded_device import embedded_device
    from .embeddings import embeddings
    from .energy_accounting import energy_accounting
    from .erp_tool import erp_tool
    from .error_patterns import error_patterns
    from .fairness_scheduler import fairness_scheduler
    from .ffmpeg_tool import ffmpeg_tool
    from .file_watcher import file_watcher
    from .format_money import format_money_tool
    from .ga4_tool import ga4_tool
    from .gdrive_tool import gdrive_tool
    from .generic_oauth import generic_oauth
    from .geocode import geocode
    from .geofence import geofence
    from .git_advanced import git_advanced
    from .github_actions import github_actions
    from .github_issues import github_issues
    from .github_repo_search import github_repo_search
    from .gitlab import gitlab
    from .gitlab_issues import gitlab_issues
    from .gmail_tool import gmail_tool
    from .hackernews import hackernews
    from .home_assistant_tool import home_assistant_tool
    from .honeytoken import honeytoken
    from .http_fetch import http_fetch
    from .hubspot_tool import hubspot_tool
    from .huggingface import huggingface
    from .image_edit import image_edit
    from .imagemagick_tool import imagemagick_tool
    from .ios_sim import ios_sim
    from .jira import jira
    from .jwt_inspect import jwt_inspect
    from .k_anonymity import k_anonymity
    from .key_rotation import key_rotation
    from .knowledge_graph import knowledge_graph
    from .kv_cache_offload import kv_cache_offload
    from .kv_memory import kv_memory
    from .lambda_tool import lambda_tool
    from .latency_heatmap import latency_heatmap
    from .latency_slo import latency_slo
    from .linear import linear
    from .local_embeddings_cache import local_embeddings_cache
    from .marketplace_moderation import marketplace_moderation
    from .marketplace_ratings import marketplace_ratings
    from .memleak_quarantine import memleak_quarantine
    from .memory import memory
    from .memory_safe_parse import memory_safe_parse
    from .migration_cost import migration_cost
    from .misuse_removal import misuse_removal
    from .mixpanel_tool import mixpanel_tool
    from .model3d_inspect import model3d_inspect
    from .model_card import model_card
    from .mongodb_tool import mongodb_tool
    from .msgraph_tool import msgraph_tool
    from .multimodal_rag import multimodal_rag
    from .multiregion_failover import multiregion_failover
    from .mutation_test import mutation_test
    from .newsapi_tool import newsapi_tool
    from .notify import notify_tool
    from .notion import notion
    from .observation_channel import observation_channel
    from .obsidian import obsidian
    from .ocr import ocr
    from .office_convert import office_convert
    from .openapi_runner import openapi_runner
    from .openmetrics import openmetrics
    from .otel_semconv import otel_semconv
    from .outline_writer import outline_writer
    from .pagerduty_tool import pagerduty_tool
    from .pandas_query import pandas_query
    from .pandoc_tool import pandoc_tool
    from .payload_compress import payload_compress
    from .pdf_reader import read_pdf
    from .pia_generator import pia_generator
    from .plaid_tool import plaid_tool
    from .plain_language import plain_language
    from .plausible_tool import plausible_tool
    from .plugin_lockfile import plugin_lockfile
    from .polyglot_injection import polyglot_injection
    from .posthog_tool import posthog_tool
    from .preview_diff import preview_diff
    from .privacy_budget import privacy_budget
    from .process_introspect import process_introspect
    from .provenance_chain import provenance_chain
    from .provider_failover_policy import provider_failover_policy
    from .query_plan_regression import query_plan_regression
    from .quorum_approval import quorum_approval
    from .rbac_check import rbac_check
    from .recall import recall
    from .rectification import rectification
    from .redact import redact_tool
    from .reddit_tool import reddit_tool
    from .redis_tool import redis_tool
    from .reflect_loop import reflect_loop
    from .reliability_harness import reliability_harness
    from .replicate_tool import replicate_tool
    from .retention_check import retention_check
    from .right_to_explanation import right_to_explanation
    from .risk_tier import risk_tier
    from .risk_tier_classifier import risk_tier_classifier
    from .ros_tool import ros_tool
    from .run_events_firehose import run_events_firehose
    from .s3_attachments import s3_attachments
    from .s3_tool import s3_tool
    from .saas_trigger import saas_trigger
    from .saas_trigger_registry import saas_trigger_registry
    from .safety_regression_budget import safety_regression_budget
    from .salesforce_tool import salesforce_tool
    from .semantic_code_search import semantic_code_search
    from .semantic_scholar import semantic_scholar
    from .semver_check import semver_check
    from .sentry_tool import sentry_tool
    from .serial_tool import serial_tool
    from .ses_tool import ses_tool
    from .shopify_tool import shopify_tool
    from .skill_distill import skill_distill_v2
    from .sla_breach import sla_breach
    from .slack_bot import slack_bot
    from .slack_workflow import slack_workflow
    from .smart_goal_completion import smart_goal_completion
    from .smart_nl_filter import smart_nl_filter
    from .sns_tool import sns_tool
    from .spend_report import spend_report
    from .spotify_tool import spotify_tool
    from .spreadsheet import spreadsheet, spreadsheet_read
    from .sql_query import sql_query, sql_query_read
    from .streaming_reasoning_trace import streaming_reasoning_trace
    from .stripe_tool import stripe_tool
    from .supply_chain_pin import supply_chain_pin
    from .synthetic_data import synthetic_data
    from .template_generator import template_generator
    from .test_gen import test_gen
    from .test_impact import test_impact
    from .tiered_storage import tiered_storage
    from .tool_call_inspector import tool_call_inspector
    from .translate import translate
    from .trello_tool import trello_tool
    from .truelayer_tool import truelayer_tool
    from .twilio_tool import twilio_tool
    from .two_person_rule import two_person_rule
    from .unified_inbox import unified_inbox
    from .vercel_tool import vercel_tool
    from .view_image import view_image
    from .view_video import view_video
    from .voice_cloning_consent import voice_cloning_consent
    from .wal_contention import wal_contention
    from .wasm_run import wasm_run
    from .watermark_detector import watermark_detector
    from .web_archive import web_archive
    from .web_recorder import web_recorder
    from .whats_changed import whats_changed
    from .wikipedia import wikipedia
    from .wolfram_tool import wolfram_tool
    from .youtube import youtube
    from .zoom_tool import zoom_tool
    reg.register(recall())
    reg.register(http_fetch())
    from .control_tools import find_controls_tool
    reg.register(find_controls_tool())
    _register_local_workspace_tool(reg, sandbox, read_pdf, has_local_workdir)
    if has_local_workdir:
        reg.register(view_image(sandbox, budget=budget))
        reg.register(view_video(sandbox, budget=budget))
    _register_local_workspace_tool(reg, sandbox, dep_graph, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, ast_edit, has_local_workdir)
    reg.register(clipboard())
    _register_local_workspace_tool(reg, sandbox, preview_diff, has_local_workdir)
    reg.register(kv_memory(world, goal_id))
    # Grounded-outcome linking: only offered once the learning loop is on, so the
    # default tool surface (and the plugin matrix) is unchanged (kernel rule 1).
    try:
        from ..consequence import enabled as _consequence_enabled
        if _consequence_enabled():
            from .outcome_link import remember_outcome_key
            reg.register(remember_outcome_key(world, goal_id))
    except Exception:  # pragma: no cover -- a tool never blocks registry build
        pass
    reg.register(memory())
    reg.register(arxiv())
    reg.register(semantic_scholar())
    reg.register(wikipedia())
    _register_local_workspace_tool(reg, sandbox, apply_patch, has_local_workdir)
    reg.register(compute())
    _register_local_workspace_tool(reg, sandbox, sql_query, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, sql_query_read, has_local_workdir)
    reg.register(email_tool())
    _register_local_workspace_tool(reg, sandbox, pandas_query, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, git_advanced, has_local_workdir)
    reg.register(calendar_tool())
    reg.register(capability_delegation())
    reg.register(coordinated_disclosure())
    reg.register(collusion_detector())
    reg.register(risk_tier())
    reg.register(bias_eval())
    reg.register(decision_explainer())
    reg.register(rectification())
    reg.register(redact_tool())
    _register_local_workspace_tool(reg, sandbox, file_watcher, has_local_workdir)
    reg.register(format_money_tool())
    reg.register(linear())
    reg.register(jira())
    reg.register(gitlab())
    reg.register(embeddings())
    reg.register(error_patterns())
    reg.register(huggingface())
    reg.register(notify_tool())
    reg.register(diagnose())
    reg.register(differential_privacy())
    if enable_mobile_tools:
        reg.register(android(sandbox))
        reg.register(ios_sim(sandbox))
    reg.register(spend_report())
    reg.register(budget_status(budget=budget))
    reg.register(test_impact())
    reg.register(youtube())
    reg.register(notion())
    reg.register(obsidian())
    _register_local_workspace_tool(reg, sandbox, spreadsheet, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, spreadsheet_read, has_local_workdir)
    reg.register(translate())
    reg.register(slack_bot())
    reg.register(stripe_tool())
    from .sanctions_screen import sanctions_screen
    reg.register(sanctions_screen())  # finance: OFAC/SDN screening (finance-agent-suite)
    from .finance_anomaly import finance_anomaly
    reg.register(finance_anomaly())
    reg.register(currency())
    _register_local_workspace_tool(reg, sandbox, a11y, has_local_workdir)
    reg.register(discord_bot())
    reg.register(hackernews())
    reg.register(dns_lookup())
    reg.register(geocode())
    reg.register(geofence())
    reg.register(knowledge_graph())
    reg.register(citation_verifier())
    _register_local_workspace_tool(reg, sandbox, cross_repo_deps, has_local_workdir)
    reg.register(test_gen())
    reg.register(two_person_rule())
    reg.register(compaction_classifier())
    reg.register(kv_cache_offload())
    reg.register(otel_semconv())
    reg.register(payload_compress())
    reg.register(capability_revocation())
    reg.register(memory_safe_parse())
    reg.register(misuse_removal())
    reg.register(consent_ergonomics())
    reg.register(skill_distill_v2())
    reg.register(observation_channel())
    reg.register(marketplace_moderation())
    reg.register(channel_autoroute())
    reg.register(capability_delegation_graph())
    reg.register(honeytoken())
    reg.register(dp_stats())
    reg.register(cost_attribution())
    reg.register(model_card())
    reg.register(anomaly_scan())
    reg.register(k_anonymity())
    reg.register(retention_check())
    reg.register(breach_notification())
    reg.register(data_minimization())
    reg.register(consent_check())
    reg.register(jwt_inspect())
    reg.register(rbac_check())
    reg.register(cidr_check())
    reg.register(semver_check())
    reg.register(supply_chain_pin())
    reg.register(quorum_approval())
    reg.register(crypto_budget_receipt())
    reg.register(provenance_chain())
    reg.register(migration_cost())
    reg.register(energy_accounting())
    reg.register(cost_guardrail())
    reg.register(cache_eviction())
    reg.register(latency_slo())
    reg.register(cost_of_quality())
    reg.register(outline_writer())
    reg.register(agent_simulator())
    reg.register(fairness_scheduler())
    reg.register(process_introspect())
    reg.register(adversarial_self_test())
    reg.register(reflect_loop())
    reg.register(github_repo_search())
    reg.register(github_issues())
    reg.register(gitlab_issues())
    reg.register(web_archive())
    reg.register(anki())
    reg.register(s3_attachments())
    reg.register(template_generator())
    reg.register(generic_oauth())
    reg.register(plugin_lockfile())
    reg.register(saas_trigger())
    reg.register(apple_shortcuts())
    reg.register(discord_slash())
    reg.register(slack_workflow())
    reg.register(risk_tier_classifier())
    reg.register(containment_mode())
    reg.register(capability_leak_fuzzer())
    reg.register(right_to_explanation())
    reg.register(audit_mirror())
    reg.register(tiered_storage())
    reg.register(async_compaction())
    reg.register(wal_contention())
    reg.register(memleak_quarantine())
    reg.register(openmetrics())
    reg.register(sla_breach())
    reg.register(whats_changed())
    reg.register(comparative_replay())
    reg.register(tool_call_inspector())
    reg.register(latency_heatmap())
    reg.register(plain_language())
    reg.register(multimodal_rag())
    reg.register(query_plan_regression())
    reg.register(provider_failover_policy())
    reg.register(cost_aware_router())
    reg.register(multiregion_failover())
    reg.register(reliability_harness())
    reg.register(chaos_gameday())
    reg.register(pia_generator())
    reg.register(capability_negotiation())
    reg.register(key_rotation())
    reg.register(data_residency())
    reg.register(polyglot_injection())
    reg.register(safety_regression_budget())
    reg.register(autogen_adapter())
    reg.register(crewai_adapter())
    if enable_ros:
        reg.register(ros_tool())
    reg.register(run_events_firehose())
    reg.register(marketplace_ratings())
    reg.register(local_embeddings_cache())
    reg.register(saas_trigger_registry())
    reg.register(streaming_reasoning_trace())
    reg.register(voice_cloning_consent())
    reg.register(diff_to_expected())
    reg.register(smart_goal_completion())
    reg.register(unified_inbox())
    reg.register(smart_nl_filter())
    _register_local_workspace_tool(reg, sandbox, semantic_code_search, has_local_workdir)
    reg.register(mutation_test())
    reg.register(constrained_output())
    _register_local_workspace_tool(reg, sandbox, model3d_inspect, has_local_workdir)
    reg.register(synthetic_data())
    reg.register(web_recorder())
    reg.register(watermark_detector())
    from .agent_identity import agent_identity
    # capability_delegation_graph / collusion_detector / coordinated_disclosure:
    # registered once above (parallel-built on both branches; unified at merge).
    reg.register(agent_identity())
    from .adversarial_eval import adversarial_eval
    from .gui_element_memory import gui_element_memory
    from .hardware_sensors import hardware_sensors
    from .voice_command_grammar import voice_command_grammar
    from .what_changed_digest import what_changed_digest
    reg.register(voice_command_grammar())
    reg.register(what_changed_digest())
    reg.register(gui_element_memory())
    reg.register(adversarial_eval())
    from .trace_compare import trace_compare
    # latency_heatmap / tool_call_inspector: registered once above (merge dup).
    reg.register(trace_compare())
    from .github_search import github_search
    from .governance_explainer import governance_explainer
    from .image_content_classifier import image_content_classifier
    from .lsp_bridge import lsp_bridge
    from .oauth_helper import oauth_helper
    # template_generator / web_archive / anki: registered once above
    # (parallel-built on both branches; unified at merge).
    _register_local_workspace_tool(reg, sandbox, image_content_classifier, has_local_workdir)
    reg.register(lsp_bridge(sandbox))
    reg.register(oauth_helper())
    reg.register(github_search())
    reg.register(governance_explainer())
    reg.register(a11y_tree())
    reg.register(ai_act_classifier())
    reg.register(cache_admin())
    _register_local_workspace_tool(reg, sandbox, openapi_runner, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, ocr, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, container_build, has_local_workdir)
    from .catalog import ToolDescriptor, register_descriptors

    # Declarations retain registration order and defer factory invocation
    # until this point, preserving credential and optional-dependency behavior.
    register_descriptors(reg, (ToolDescriptor("posthog", posthog_tool, True),))
    reg.register(privacy_budget())
    register_descriptors(reg, (
        ToolDescriptor("shopify", shopify_tool, True),
        ToolDescriptor("mongodb", mongodb_tool, True),
        ToolDescriptor("redis", redis_tool, True),
        ToolDescriptor("sentry", sentry_tool, True),
        ToolDescriptor("pagerduty", pagerduty_tool, True),
        ToolDescriptor("salesforce", salesforce_tool, True),
        ToolDescriptor("cloudflare", cloudflare_tool, True),
        ToolDescriptor("datadog", datadog_tool, True),
        ToolDescriptor("hubspot", hubspot_tool, True),
        ToolDescriptor("twilio", twilio_tool, True),
        ToolDescriptor("s3", s3_tool, True),
    ))
    reg.register(serial_tool())
    register_descriptors(reg, (ToolDescriptor("elasticsearch", elasticsearch_tool, True),))
    reg.register(github_actions())
    # Strategic-fit connectors (ITSM / data / cloud-ML / GRC). Explicit-token
    # auth (no ambient creds), so registered unconditionally like salesforce.
    from .bigquery_tool import bigquery_tool
    from .databricks_tool import databricks_tool
    from .dynamics_tool import dynamics_tool
    from .onetrust_tool import onetrust_tool
    from .oracle_tool import oracle_tool
    from .sap_tool import sap_tool
    from .servicenow_tool import servicenow_tool
    from .snowflake_tool import snowflake_tool
    from .vertex_tool import vertex_tool
    from .workday_tool import workday_tool
    register_descriptors(reg, (
        ToolDescriptor("servicenow", servicenow_tool, True),
        ToolDescriptor("snowflake", snowflake_tool, True),
        ToolDescriptor("databricks", databricks_tool, True),
        ToolDescriptor("onetrust", onetrust_tool, True),
        ToolDescriptor("vertex", vertex_tool, True),
        ToolDescriptor("oracle", oracle_tool, True),
        ToolDescriptor("sap", sap_tool, True),
        ToolDescriptor("workday", workday_tool, True),
        ToolDescriptor("bigquery", bigquery_tool, True),
        ToolDescriptor("dynamics", dynamics_tool, True),
    ))
    # The long tail of token-authed REST connectors (one spec each, built on
    # make_rest_tool). Same house rules: explicit env auth, confirm-gated writes.
    from .enterprise_connectors import enterprise_connectors
    for _conn in enterprise_connectors():
        reg.register(_conn)
        # The long tail is deferred-eligible: with [capabilities]
        # deferred_tools on (the default), these schemas stay out of the
        # model's catalog until find_tools activates them -- 470+ connector
        # schemas on every turn dominated the context window (observed: 601
        # tools offered per call at consumer defaults). run() can still
        # execute them regardless of exposure.
        reg.deferrable_names.add(_conn.name)
    from .database_tool import database_tool
    reg.register(database_tool())
    # Credentialed SaaS/cloud tools are opt-in: they can use
    # ambient host credentials, so they only register when the operator
    # sets MAVERICK_ENABLE_CRED_TOOLS=true. Their names are reserved in
    # AMBIENT_CRED_TOOL_NAMES above -- keep that set in sync with this list.
    from ..env_setting import env_or_config

    if (env_or_config("MAVERICK_ENABLE_CRED_TOOLS", "tools", "credential_connectors")
            or "").strip().lower() in ("1", "true", "yes", "on"):
        reg.register(airtable_tool())
        reg.register(asana_tool())
        reg.register(clickup_tool())
        reg.register(lambda_tool())
        reg.register(dynamodb_tool())
        reg.register(vercel_tool())
        reg.register(gdrive_tool())
    register_descriptors(reg, (
        ToolDescriptor("trello", trello_tool, True),
        ToolDescriptor("confluence", confluence_tool, True),
        ToolDescriptor("replicate", replicate_tool, True),
        ToolDescriptor("newsapi", newsapi_tool, True),
        ToolDescriptor("wolfram", wolfram_tool, True),
        ToolDescriptor("dropbox", dropbox_tool, True),
        ToolDescriptor("msgraph", msgraph_tool, True),
        ToolDescriptor("gmail", gmail_tool, True),
        ToolDescriptor("plausible", plausible_tool, True),
        ToolDescriptor("mixpanel", mixpanel_tool, True),
        ToolDescriptor("calendly", calendly_tool, True),
        ToolDescriptor("zoom", zoom_tool, True),
        ToolDescriptor("spotify", spotify_tool, True),
        ToolDescriptor("home_assistant", home_assistant_tool, True),
        ToolDescriptor("reddit", reddit_tool, True),
        ToolDescriptor("bitbucket", bitbucket_tool, True),
        ToolDescriptor("ses", ses_tool, True),
        ToolDescriptor("sns", sns_tool, True),
    ))
    _register_local_workspace_tool(reg, sandbox, ffmpeg_tool, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, pandoc_tool, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, office_convert, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, wasm_run, has_local_workdir)
    if _hardware_sensors_enabled():
        reg.register(hardware_sensors())
    _register_local_workspace_tool(reg, sandbox, imagemagick_tool, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, audio_understanding, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, image_edit, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, embedded_device, has_local_workdir)
    register_descriptors(reg, (
        ToolDescriptor("ga4", ga4_tool, True),
        ToolDescriptor("plaid", plaid_tool, True),
        ToolDescriptor("truelayer", truelayer_tool, True),
        ToolDescriptor("erp_read", erp_tool, True),
    ))

    # Voice tools (opt-in extra; tool factories raise ImportError only
    # when called without the required API key OR SDK; registering is
    # cheap).
    from .voice import speak, transcribe_audio
    _register_local_workspace_tool(reg, sandbox, transcribe_audio, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, speak, has_local_workdir)

    # Capability tools that live in the parent package (maverick/), not the
    # tools subpackage.
    from ..browser_auth_vault import browser_auth_vault
    from ..browser_device import browser_device
    from ..continuous_benchmark import bench_track
    from ..dom_diff import dom_diff
    from ..html_to_app import html_to_app
    from ..license_scan import license_scan
    from ..task_graph import task_graph
    from ..workspace_snapshot import workspace_snapshot
    reg.register(dom_diff())
    reg.register(license_scan())
    _register_local_workspace_tool(reg, sandbox, workspace_snapshot, has_local_workdir)
    reg.register(task_graph())
    reg.register(browser_device())
    reg.register(bench_track())
    _register_local_workspace_tool(reg, sandbox, html_to_app, has_local_workdir)
    reg.register(browser_auth_vault())

    # Subpackage capability tools. The sandbox-backed ones
    # take the sandbox; the rest are stateless.
    from .diagram_tool import diagram_tool
    from .latex_tool import latex_tool
    from .notebook_exec import notebook_exec
    from .teams_tool import teams_tool
    from .websocket_tool import websocket_tool
    _register_local_workspace_tool(reg, sandbox, notebook_exec, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, latex_tool, has_local_workdir)
    _register_local_workspace_tool(reg, sandbox, diagram_tool, has_local_workdir)
    reg.register(websocket_tool())
    reg.register(teams_tool())

    # Runtime / introspection tools.
    from ..cost.curve_fitter import cost_curve_tool
    from .capability_query import capability_query
    from .oidc_tool import oidc_tool
    reg.register(capability_query(user_id=user_id))
    reg.register(oidc_tool())
    reg.register(cost_curve_tool(world))

    # Zero-config BYO tools registered via the @tool decorator (any that were
    # imported before the registry was built). Never shadow a built-in.
    try:
        from .decorator import registered_tools as _byo_tools
        for _t in _byo_tools():
            if _t.name not in reg._tools:
                reg.register(_t)
    except Exception as e:  # pragma: no cover -- never block the registry
        import logging as _logging
        _logging.getLogger(__name__).warning("byo @tool load: %s", e)

    _register_optional_tools(
        reg, sandbox,
        enable_web_search=enable_web_search,
        enable_computer_use=enable_computer_use,
        enable_browser=enable_browser,
    )

    _apply_mcp_tools(reg, mcp_clients)
    # Per-tool rate limits from ~/.maverick/config.toml [rate_limits].
    # Wrap AFTER MCP + before plugin tools so MCP-exposed tools (which
    # share the most-abused namespace, mcp_*) are covered; plugins
    # register below and pick up their own limits via a second pass.
    _apply_rate_limits(reg)
    if _include_plugins:
        _apply_python_plugins(reg)
        _apply_ts_plugins(reg)
        _apply_grpc_plugins(reg)
    if _include_generated_tools:
        _apply_generated_tools(reg, sandbox)
    # Second rate-limit pass to cover plugin-registered tools. Earlier
    # pass already wrapped core + MCP tools; double-wrapping is avoided
    # because apply_to_registry walks the current dict snapshot.
    _apply_rate_limits(reg, fail_silently=True)
    # ACLs are an execution-boundary policy and therefore run only after every
    # registration source (core, optional, MCP, Python/TS/gRPC plugins, and
    # generated tools).  Applying them earlier lets later providers bypass a
    # user's allow/deny list simply by registering the same capability class.
    # Introspection callers may need the catalog before policy filtering so
    # they can display "present but denied" honestly. Execution callers must
    # never set this private flag; the default remains fail-closed ACL
    # enforcement and the permissions snapshot applies the same resolver to
    # the introspection registry immediately after capturing catalog names.
    from ..governed_tools import apply_governed_connectors
    from ..safety.tool_risk import pinned_overrides

    # Everything below registers tools past the ACL, whose risk check read the
    # config once per tool (thousands of times per agent). Pin the
    # [security.tool_risk] snapshot for the rest of the build.
    with pinned_overrides():
        _apply_tool_acl_unless_skipped(
            reg,
            skip=_skip_tool_acl,
            channel=channel,
            user_id=user_id,
        )
        if not _skip_tool_acl:
            _apply_containment(reg)
            _apply_network_posture(reg)
        _apply_deferred_loading(reg)

        # Route every compatible external connector write through the durable,
        # fresh-human governed transaction boundary. Done last so it wraps the
        # final tool objects; assembly fails closed if the boundary cannot load.
        apply_governed_connectors(reg, goal_id=goal_id)

    # Host pathlib tools cannot safely interpret an SSH workdir: it denotes a
    # path on another machine. Keep remote shell available, and remove known
    # local workspace tools after optional/plugin registration has completed.
    from ..sandbox.ssh import SSHBackend
    if isinstance(sandbox, SSHBackend):
        from ..agent import _FILE_TOOL_POLICIES
        host_path_tools = set(_FILE_TOOL_POLICIES) | {
            "apply_patch", "repo_map", "dep_graph", "preview_diff", "file_watcher",
            "cross_repo_deps", "semantic_code_search", "pandas_query", "lsp_bridge",
            "view_video", "model3d_inspect", "office_convert", "image_edit",
            "container_build", "workspace_snapshot", "html_to_app", "notebook_exec",
            "read_pdf", "audio_understanding", "embedded_device", "a11y",
        }
        for name in host_path_tools:
            reg._tools.pop(name, None)

    return reg


def base_tool_names(*, configured_optional: bool = False, include_plugins: bool = True) -> set[str] | None:
    """Best-effort set of the built-in tool names, for callers that need to
    diff a pack's declared tools against what actually exists (the agent
    factory's capability-provisioning step).

    Builds the base registry against an in-memory world and a local sandbox.
    Legacy add-on assembly may run configured factories or contact add-on hosts;
    this helper does not invoke an action tool. The default omits optional high-impact tools;
    ``configured_optional=True`` includes only those enabled in this
    deployment, so a roster can show honest workflow-action availability.
    Returns the registered names, or ``None`` if assembly fails (a caller
    then skips tool-existence checks rather than guessing). Never raises.
    ``include_plugins=False`` omits Python/TS/gRPC add-on loading and generated
    tool probing; callers can read consented generated names separately.
    """
    world = None
    try:
        from ..sandbox.local import LocalBackend
        from ..world_model import open_world

        world = open_world(None)
        if configured_optional:
            from ..config import get_capabilities

            caps = get_capabilities()
        else:
            caps = {}
        reg = base_registry(
            world,
            LocalBackend(),
            enable_computer_use=bool(caps.get("computer_use", False)),
            enable_browser=bool(caps.get("browser", False)),
            enable_web_search=bool(caps.get("web_search", False)),
            enable_mobile_tools=bool(caps.get("mobile_tools", False)),
            enable_ros=bool(caps.get("ros", False)),
            _include_generated_tools=configured_optional and include_plugins,
            _skip_tool_acl=True,
            _include_plugins=include_plugins,
        )
        return {t.name for t in reg.all()}
    except Exception as e:  # pragma: no cover -- best-effort introspection
        import logging as _logging
        _logging.getLogger(__name__).debug("base_tool_names unavailable: %s", e)
        return None
    finally:
        if world is not None:
            from ..world_model import close_world_if_owned

            try:
                close_world_if_owned(world)
            except Exception:  # pragma: no cover -- introspection never raises
                import logging as _logging

                _logging.getLogger(__name__).debug(
                    "base_tool_names world close failed", exc_info=True,
                )


def _register_optional_tools(
    reg: ToolRegistry,
    sandbox,
    *,
    enable_web_search: bool,
    enable_computer_use: bool,
    enable_browser: bool,
) -> None:
    if enable_web_search:
        from .web_search import web_search
        reg.register(web_search())

    if enable_computer_use:
        from .computer import computer
        reg.register(computer())

    if enable_browser:
        from .aria_navigate import aria_navigate
        from .browser import browser
        # Sync Playwright objects must be created, used, and closed on one
        # worker for this customer goal; generic tool threads can rotate.
        reg.register(browser(managed=True))
        reg.register(aria_navigate(managed=True))


def _apply_tool_acl(reg: ToolRegistry, *, channel: str | None, user_id: str | None) -> None:
    # Apply allow/deny lists from ~/.maverick/config.toml [security].
    # Operational discovery errors remain fail-soft, but an unreadable
    # operator policy must stop registry construction. Swallowing that
    # security error would leave every tool registered after a deny-list
    # became corrupt.
    from ..runtime_overrides import RuntimeOverridesSecurityError

    try:
        from ..safety.tool_acl import apply_to_registry
        apply_to_registry(reg, channel=channel, user_id=user_id)
    except RuntimeOverridesSecurityError:
        raise
    except Exception as e:  # pragma: no cover
        import logging as _logging
        _logging.getLogger(__name__).warning("tool_acl: %s", e)


def _apply_containment(reg: ToolRegistry) -> None:
    """Containment mode: union the exfil tools into the ACL (existing denials
    are kept). An enabled profile that cannot be applied stops registry
    construction rather than running uncontained."""
    from ..containment import active_profile, apply

    profile = active_profile()
    if profile is not None:
        apply(profile, registry=reg, sandbox_env={})


def _apply_network_posture(reg: ToolRegistry) -> None:
    """``[security] network_policy``: remove the web tools the posture blocks,
    unioned into the ACL so existing denials are kept (as containment does)."""
    from ..sandbox.network_policy import denied_tools

    blocked = denied_tools()
    if blocked:
        reg.set_acl(allowed=set(getattr(reg, "_acl_allowed", set()) or set()),
                    denied=set(getattr(reg, "_acl_denied", set()) or set()) | set(blocked),
                    max_risk=getattr(reg, "_acl_max_risk", None))


def _apply_tool_acl_unless_skipped(
    reg: ToolRegistry,
    *,
    skip: bool,
    channel: str | None,
    user_id: str | None,
) -> None:
    """Keep the private catalog-introspection bypass out of registry flow."""
    if not skip:
        _apply_tool_acl(reg, channel=channel, user_id=user_id)


def _apply_mcp_tools(reg: ToolRegistry, mcp_clients: list | None) -> None:
    if not mcp_clients:
        return
    from ..mcp_tools import tools_from_mcp
    for client in mcp_clients:
        guards = {}
        for t in tools_from_mcp(client, authorize=reg._acl_allows, binding_guards=guards):
            # Never let an external MCP server silently SHADOW a built-in
            # (shell, read_file, ...): every registration path (plugins,
            # @tool, this MCP loop) checks this, so a malicious or
            # misconfigured MCP server cannot substitute a core tool.
            # Built-ins are registered above, so a
            # name collision here is the MCP tool losing -- skip it.
            if t.name in reg._tools:
                import logging
                logging.getLogger(__name__).warning(
                    "MCP tool %r from %s conflicts with an existing tool; "
                    "skipping to avoid shadowing a built-in.",
                    t.name, getattr(client, "name", "?"),
                )
                continue
            reg.register(t)
            if t.name in guards:
                reg._mcp_bindings[t.name] = guards[t.name]


def _apply_rate_limits(reg: ToolRegistry, *, fail_silently: bool = False) -> None:
    try:
        from ..safety.rate_limiter import apply_to_registry as _rl_apply
        _rl_apply(reg)
    except Exception as e:  # pragma: no cover
        if fail_silently:
            return
        import logging as _logging
        _logging.getLogger(__name__).warning("rate_limiter: %s", e)


def _apply_python_plugins(reg: ToolRegistry) -> None:
    # Plugin tools registered via the `maverick.tools` entry point. Each
    # factory is called with no args and must return a Tool. A broken
    # plugin logs but never takes the swarm down.
    try:
        from ..plugins import discover_tools
        for name, factory in discover_tools():
            try:
                t = factory()
                # Never let a plugin shadow a built-in (or an MCP) tool: an
                # allowlisted plugin returning Tool(name="shell") would silently
                # replace the real shell and run attacker code under that name.
                if t.name in reg._tools:
                    import logging
                    logging.getLogger(__name__).warning(
                        "plugin tool %r conflicts with an existing tool; skipping",
                        t.name,
                    )
                    continue
                reg.register(t)
            except Exception as e:  # pragma: no cover -- plugin failure
                import logging
                logging.getLogger(__name__).warning(
                    "plugin tool %s factory raised: %s", name, e
                )
    except Exception as exc:  # pragma: no cover -- discovery/policy failure
        import logging
        logging.getLogger(__name__).warning("plugin discovery refused: %s", exc)


def _apply_ts_plugins(reg: ToolRegistry) -> None:
    # TypeScript plugins (the NDJSON stdio SDK): each `[plugins] ts` command
    # contributes its described tools. Same no-shadowing rule as Python
    # plugins; a broken plugin logs but never takes the swarm down.
    try:
        from ..ts_plugin_host import load_configured_ts_plugins
        for t in load_configured_ts_plugins():
            if t.name in reg._tools:
                import logging
                logging.getLogger(__name__).warning(
                    "ts plugin tool %r conflicts with an existing tool; skipping",
                    t.name,
                )
                continue
            reg.register(t)
    except Exception:  # pragma: no cover -- plugin failure never blocks boot
        pass


def _apply_grpc_plugins(reg: ToolRegistry) -> None:
    # gRPC plugins (the multi-language plugin host): each [plugins] grpc entry
    # contributes its described tools, same no-shadowing rule.
    try:
        from ..grpc_plugin_host import load_configured_grpc_plugins
        for t in load_configured_grpc_plugins():
            if t.name in reg._tools:
                import logging
                logging.getLogger(__name__).warning(
                    "grpc plugin tool %r conflicts with an existing tool; skipping",
                    t.name,
                )
                continue
            reg.register(t)
    except Exception:  # pragma: no cover -- plugin failure never blocks boot
        pass


def _apply_commerce_tools(reg: ToolRegistry, principal: str | None) -> None:
    # Commerce suite (shopper + merchant tools over the governed storefront /
    # merchant backends). Registered ONLY when [commerce] enable is on, so the
    # default catalog is unchanged; the caps, provenance gate, staged writes and
    # opaque checkout handoff live in maverick.commerce, not in the prompts.
    try:
        from ..commerce import enabled as _commerce_enabled
        if _commerce_enabled():
            from .commerce_tools import commerce_tools
            for tool in commerce_tools(principal=principal or None):
                reg.register(tool)
    except Exception as e:  # pragma: no cover - config read must not break setup
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "commerce tool registration skipped: %s", e)


def _apply_generated_tools(reg: ToolRegistry, sandbox: Any = None) -> None:
    # Self-learning: tools the agent generated for itself on a prior run
    # live in ~/.maverick/generated_tools/ and load like first-class tools.
    # Only consulted when [self_learning] enable is set. Persisted source is
    # never imported in the kernel; loading returns sandbox-backed proxies.
    try:
        from .. import self_learning
        if self_learning.enabled():
            for t in self_learning.load_generated_tools(sandbox=sandbox):
                # Same no-shadowing rule as the plugin/MCP loaders: a generated
                # tool named e.g. "shell"/"read_file" must never silently replace
                # a built-in.
                if t.name in reg._tools:
                    import logging as _logging
                    _logging.getLogger(__name__).warning(
                        "generated tool %r conflicts with an existing tool; skipping",
                        t.name,
                    )
                    continue
                reg.register(t)
    except Exception as e:  # pragma: no cover -- never block the registry
        import logging as _logging
        _logging.getLogger(__name__).warning("generated tools load: %s", e)


def _apply_deferred_loading(reg: ToolRegistry) -> None:
    # Deferred tool loading (opt-in): expose only CORE + find_tools to the
    # model; everything else (incl. MCP and plugin tools) is discovered on
    # demand. Enabled last, after every tool is registered, so the long tail
    # find_tools searches is complete.
    if _deferred_loading_enabled():
        from .find_tools import find_tools as _find_tools
        reg.register(_find_tools(reg))
        reg.enable_deferred(CORE_TOOL_NAMES)


default_registry = base_registry
