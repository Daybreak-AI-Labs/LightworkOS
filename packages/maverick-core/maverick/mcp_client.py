"""MCP client: let Lightwork consume external MCP servers as tools.

Hardening:
  - Env passed to the child process is an EXPLICIT allowlist, not
    full ``os.environ``, so a compromised npm MCP server cannot exfil
    ANTHROPIC_API_KEY / MAVERICK_DASHBOARD_TOKEN / GITHUB_TOKEN / AWS_*.
  - stderr is drained by a background task so the pipe buffer never fills
    and sustained logging cannot deadlock the server.
  - returncode is checked before sending each request; we fail loudly
    instead of hanging on a dead pipe.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Any

from .mcp_catalog import CatalogLimits, ToolCatalog, check_call_guard
from .runtime_overrides import RuntimeOverridesSecurityError
from .safety.remote_scan import scan_remote_content
from .safety.secret_detector import redact as _redact_secrets

log = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"
DEFAULT_TIMEOUT = 30.0
_CANCEL_NOTICE_TIMEOUT = 1.0
# Bound remote HTTP MCP replies so a malicious server cannot keep an SSE
# response open forever or force the client to buffer unbounded data.
_MAX_HTTP_RESPONSE_BYTES = 1024 * 1024

_MAX_ERROR_DETAIL_CHARS = 512

# Inbound elicitation policy (server -> client elicitation/create). Mirrors the
# env-var idiom of MAVERICK_CONSENT_MODE. Default "decline" is the safe,
# non-stalling outcome: the server continues without the value. "cancel" aborts
# the server's operation; "prompt" collects typed input from an interactive
# operator (off the event loop, gated through require_consent).
ELICITATION_ENV = "MAVERICK_MCP_ELICITATION"


def _resolve_elicitation_policy() -> str:
    return (os.environ.get(ELICITATION_ENV) or "decline").strip().lower()


def _elicitation_field_text(schema: object) -> str:
    """The field labels an elicitation prompt would show the operator."""
    props = schema.get("properties") if isinstance(schema, dict) else None
    parts: list[str] = []
    for key, field_spec in (props or {}).items() if isinstance(props, dict) else ():
        parts.append(str(key))
        if isinstance(field_spec, dict):
            parts.extend(str(field_spec.get(k) or "") for k in ("title", "description"))
    return "\n".join(parts)


def _coerce_scalar(raw: str, declared: object) -> Any:
    """Coerce a typed-in string to the JSON-Schema scalar the server asked for.

    Best-effort: a value that doesn't parse as the declared type is returned as
    the raw string rather than raising -- the server validates its own schema."""
    if declared == "integer":
        try:
            return int(raw)
        except ValueError:
            return raw
    if declared == "number":
        try:
            return float(raw)
        except ValueError:
            return raw
    if declared == "boolean":
        return raw.strip().lower() in {"1", "true", "yes", "y", "on"}
    return raw


def _safe_error_detail(text: str) -> str:
    """Return MCP error text safe enough to place in loggable exceptions.

    MCP tool error content is controlled by the server. Exceptions are often
    logged before the agent's tool-output redaction path runs, so scrub common
    secret shapes here and cap the detail length before embedding it in an
    exception message.
    """
    if not text:
        return ""
    text, _matches = _redact_secrets(text)
    if len(text) <= _MAX_ERROR_DETAIL_CHARS:
        return text
    omitted = len(text) - _MAX_ERROR_DETAIL_CHARS
    return f"{text[:_MAX_ERROR_DETAIL_CHARS]}... [truncated {omitted} chars]"

# Env vars that we'll pass through to MCP server subprocesses by default.
# Everything else (API keys, dashboard tokens, AWS creds, etc.) stays
# in the parent process unless the spec explicitly opts a key in via
# its own [mcp_servers.<name>] env table.
DEFAULT_ENV_ALLOWLIST = (
    "PATH", "HOME", "USER", "LANG", "LC_ALL", "TZ", "TMPDIR", "TEMP", "TMP",
    "NODE_PATH", "NVM_DIR", "NPM_CONFIG_PREFIX",
    "SHELL", "PWD",
)


class MCPClientError(Exception):
    pass


def _finalize_tool_result(spec_name: str, tool_name: str, resp: dict) -> str:
    """Turn a tools/call response into the agent-visible text result.

    A tool error is a real failure -> raise, so it rides the same path as
    transport/protocol errors (the wrapper in mcp_tools.py turns any exception
    into the agent-visible "ERROR: ..." string). The old "ERROR: " text prefix
    was ambiguous: a successful result whose text merely started with "ERROR:"
    was indistinguishable from a failure. A spec-compliant server mirrors
    structuredContent in a text block, but one that returns only structured
    output would come back empty -- fall back to the serialized structured
    result so the data still reaches the model.
    """
    if resp.get("isError"):
        detail = _safe_error_detail(_content_to_str(resp.get("content", [])))
        msg = f"MCP {spec_name!r} tool {tool_name!r} failed"
        if detail:
            msg += f": {detail}"
        raise MCPClientError(msg)
    text = _content_to_str(resp.get("content", []))
    if not text and resp.get("structuredContent") is not None:
        return json.dumps(resp["structuredContent"])
    return text


def _format_rpc_error(err: object) -> str:
    """Render a JSON-RPC ``error`` member for a message.

    The spec says ``error`` is an object with ``code``/``message``, but the
    server is untrusted: a hostile or buggy one can send a string, list, or
    null. Calling ``.get()`` on that raised an ``AttributeError`` that killed
    the read loop and failed every in-flight call. Format defensively instead.
    """
    if isinstance(err, dict):
        return f"{err.get('code')}: {err.get('message')}"
    return repr(err)


@dataclass
class MCPServerSpec:
    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    inherit_env: bool = False  # opt-in to full os.environ inheritance
    # SHA-256 of the resolved executable file (argv[0]) the operator expects.
    # When set, MCPClient.start() refuses to spawn if that file hashes
    # differently. It pins only the launcher: a pin on npx/docker does not pin
    # the package or image they fetch. Defends the
    # supply-chain attack class shipped to STDIO MCP in April 2026
    # (CVE-2026-30615 et al). Default None = no pin (legacy behavior).
    pin_sha256: str | None = None
    # Remote (Streamable HTTP) transport: when ``url`` is set the server is
    # reached over HTTP (StreamableHttpMCPClient) instead of a stdio subprocess,
    # and command/args/env/pin are unused. ``auth_token`` is sent as a bearer
    # (a static token -- full OAuth 2.1 is separate, §B2); ``headers`` are extra
    # request headers. The url is operator config, not model-controlled.
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    auth_token: str | None = None
    # OAuth 2.1 (§B2): a table {token_url, client_id, client_secret?, scope?,
    # grant_type?, authorize_url?, redirect_uri?}. When set, the HTTP client
    # fetches + refreshes a short-lived access token (mcp_oauth) instead of
    # using a static auth_token.
    oauth: dict | None = None

    @property
    def is_http(self) -> bool:
        return bool(self.url)

    def to_dict(self) -> dict:
        """Serialize to a ``[mcp_servers.<name>]`` config dict (inverse of
        ``from_config``). Omits the name (it's the table key) and any empty
        optionals so the emitted config stays minimal. Used by the MCP registry
        to write an installed server into ~/.maverick/config.toml."""
        if self.url:
            d: dict = {"url": self.url}
            if self.headers:
                d["headers"] = dict(self.headers)
            if self.auth_token:
                d["auth_token"] = self.auth_token
            if self.oauth:
                d["oauth"] = dict(self.oauth)
            return d
        d = {"command": self.command}
        if self.args:
            d["args"] = list(self.args)
        if self.env:
            d["env"] = dict(self.env)
        if self.inherit_env:
            d["inherit_env"] = True
        if self.pin_sha256:
            d["pin_sha256"] = self.pin_sha256
        return d

    @classmethod
    def from_config(cls, name: str, cfg: dict) -> MCPServerSpec:
        if cfg.get("url"):
            spec = cls(
                name=name,
                url=str(cfg["url"]),
                headers={str(k): str(v) for k, v in (cfg.get("headers", {}) or {}).items()},
                auth_token=cfg.get("auth_token"),
                oauth=cfg.get("oauth") if isinstance(cfg.get("oauth"), dict) else None,
            )
            return spec  # __post_init__ validated the http spec
        spec = cls(
            name=name,
            command=cfg["command"],
            args=list(cfg.get("args", [])),
            env={k: str(v) for k, v in (cfg.get("env", {}) or {}).items()},
            inherit_env=bool(cfg.get("inherit_env", False)),
            pin_sha256=cfg.get("pin_sha256"),
        )
        return spec  # __post_init__ validated the subprocess inputs

    def __post_init__(self):
        # Allow direct construction (tests / programmatic use) but still apply
        # the right validation: HTTP specs validate the url, stdio specs validate
        # the command/args/env against the CVE-2026-30615 subprocess-injection class.
        if self.url:
            _validate_http_spec(self)
        else:
            _validate_subprocess_inputs(self)


@dataclass
class _ApprovedElicitation:
    """Internal response whose exact permit is spent at transport write."""

    result: dict[str, Any]
    permit: Any


_DENY_CHARS = ("\n", "\r", "\0")
_DENY_SHELL_METAS = (";", "|", "&", "$(", "`", ">", "<")


def _validate_http_spec(spec: MCPServerSpec) -> None:
    """Validate a remote (HTTP) MCP server spec: scheme + no control chars, and
    https:// (or a loopback host) whenever a credential is configured.

    The url is operator config (not model-controlled), so this is a sanity
    guard, not an SSRF defense -- it rejects obvious mistakes (non-http schemes,
    embedded newlines) up front rather than at connect time."""
    from urllib.parse import urlparse
    url = spec.url or ""
    for ch in _DENY_CHARS:
        if ch in url:
            raise ValueError(
                f"MCP server {spec.name!r} url contains illegal char {ch!r}")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            f"MCP server {spec.name!r} url must be http(s)://host/…; got {url!r}")
    if spec.oauth and parsed.scheme != "https":
        raise ValueError(
            f"MCP server {spec.name!r} url must be https:// when oauth is configured; got {url!r}")
    has_credential = bool(spec.auth_token) or any(
        str(k).strip().lower() == "authorization" for k in (spec.headers or {}))
    if has_credential and parsed.scheme != "https" and not _is_loopback_host(parsed.hostname):
        raise ValueError(
            f"MCP server {spec.name!r} sends a token or Authorization header, which "
            f"plain http:// would expose on the network: change the url to https:// "
            f"(or point it at localhost); got {url!r}")


def _is_loopback_host(host: str | None) -> bool:
    import ipaddress
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_subprocess_inputs(spec: MCPServerSpec) -> None:
    """Defend against the CVE-2026-30615 STDIO Trifecta and friends.

    Hostile MCP server listings embedded newlines / shell metas in
    `command` or `args`, causing client launchers to spawn unintended
    processes (200k vulnerable clients across Cursor, VS Code, Windsurf,
    Claude Code, LangChain, LangFlow, LiteLLM, Flowise per April 2026
    OX Security advisory).

    Rules:
      - command must be a simple program name or absolute path; no
        shell metacharacters, no embedded NUL / newline.
      - each arg must not contain NUL / newline / CR.
      - env keys must match [A-Za-z_][A-Za-z0-9_]*; values must not contain
        NUL / newline / CR.
    """
    for ch in _DENY_CHARS:
        if ch in spec.command:
            raise ValueError(
                f"MCP server {spec.name!r} command contains illegal char {ch!r}"
            )
    # The command itself is allowed to include path slashes / dots /
    # dashes; reject only shell metacharacters that would re-enter a
    # shell parse.
    for meta in _DENY_SHELL_METAS:
        if meta in spec.command:
            raise ValueError(
                f"MCP server {spec.name!r} command contains shell metacharacter "
                f"{meta!r}; pass it through args instead"
            )
    for i, arg in enumerate(spec.args):
        if not isinstance(arg, str):
            raise ValueError(
                f"MCP server {spec.name!r} arg #{i} is not a string"
            )
        for ch in _DENY_CHARS:
            if ch in arg:
                raise ValueError(
                    f"MCP server {spec.name!r} arg #{i} contains illegal char {ch!r}"
                )
    import re as _re
    key_re = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    for k, v in (spec.env or {}).items():
        if not key_re.match(k):
            raise ValueError(
                f"MCP server {spec.name!r} env key {k!r} is not a valid identifier"
            )
        if not isinstance(v, str):
            raise ValueError(
                f"MCP server {spec.name!r} env[{k}] is not a string"
            )
        for ch in _DENY_CHARS:
            if ch in v:
                raise ValueError(
                    f"MCP server {spec.name!r} env[{k}] contains illegal char {ch!r}"
                )


def _command_looks_like_path(command: str, on_windows: bool | None = None) -> bool:
    """Heuristic: does `command` look like a filesystem path (so we
    should NOT send it through `shutil.which`)?

    Backslash counts as a separator only on Windows; on POSIX it's a
    legal filename character. Split out so tests can pass `on_windows`
    explicitly without monkeypatching `os.name`, which has process-wide
    side effects (it changes which pathlib class `Path()` instantiates).
    """
    if on_windows is None:
        on_windows = os.name == "nt"
    return "/" in command or (on_windows and "\\" in command)


def _verify_command_pin(spec: MCPServerSpec) -> str | None:
    """If spec.pin_sha256 is set, hash the resolved executable, refuse to spawn
    on mismatch, and return the resolved executable PATH so the caller spawns
    exactly the file that was hashed. Resolution uses shutil.which for argv[0].
    Treat backslash as a path separator only on Windows so verifier resolution
    matches subprocess execution semantics on each platform.

    Returning the path closes a verify-then-re-resolve TOCTOU: spawning the bare
    command name let the OS re-run PATH resolution and could land on a different
    (or newly-planted) binary than the one whose hash we just verified. Returns
    None when no pin is set (legacy: the caller spawns the bare command).
    """
    if not spec.pin_sha256:
        return None
    import hashlib as _hashlib
    import shutil as _shutil
    from pathlib import Path as _Path
    looks_like_path = _command_looks_like_path(spec.command)
    resolved = spec.command if looks_like_path else _shutil.which(spec.command)
    if not resolved or not _Path(resolved).exists():
        raise MCPClientError(
            f"MCP server {spec.name!r}: cannot resolve {spec.command!r} to "
            f"verify pin_sha256"
        )
    h = _hashlib.sha256()
    with open(resolved, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != spec.pin_sha256:
        raise MCPClientError(
            f"MCP server {spec.name!r}: pin_sha256 mismatch. "
            f"Expected {spec.pin_sha256}, got {actual} for {resolved}"
        )
    return resolved


def _build_env(spec: MCPServerSpec) -> dict[str, str]:
    """Build the env dict for a child MCP server.

    Default: minimal allowlist (PATH/HOME/etc.) + spec.env explicit overrides.
    Opt-in via spec.inherit_env=True for the legacy full-inherit behavior.
    """
    if spec.inherit_env:
        base = dict(os.environ)
    else:
        base = {k: os.environ[k] for k in DEFAULT_ENV_ALLOWLIST if k in os.environ}
    base.update(spec.env)
    return base


class MCPClient:
    def __init__(self, spec: MCPServerSpec, timeout: float = DEFAULT_TIMEOUT):
        self.spec = spec
        self.timeout = timeout
        self._proc: asyncio.subprocess.Process | None = None
        self._req_id = 0
        # _lock now guards ONLY id-allocation + the stdin write -- a single
        # StreamWriter isn't safe for interleaved concurrent writes. It is
        # NOT held across the read: the background reader is the sole stdout
        # consumer, so concurrent requests no longer serialize on the read.
        self._lock = asyncio.Lock()
        self._stderr_task: asyncio.Task | None = None
        # Single persistent stdout consumer, started lazily on first request.
        self._reader_task: asyncio.Task | None = None
        # request id -> Future the caller awaits. A reply whose id is not in
        # this map (already timed out / cancelled) is dropped, not crashed on.
        self._pending: dict[int, asyncio.Future] = {}
        # Tasks answering inbound requests the server sends US (e.g.
        # elicitation/create). Tracked so they aren't GC'd mid-flight and can be
        # cancelled on stop().
        self._inbound_tasks: set[asyncio.Task] = set()
        self.catalog = ToolCatalog(
            lambda method, params: self._request(method, params),
            limits=CatalogLimits(seconds=min(timeout, 30.0)),
        )

    @property
    def tools(self) -> list[dict[str, Any]]:
        return self.catalog.tools

    async def refresh_tools(self) -> None:
        await self.catalog.refresh()

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    async def start(self) -> None:
        # Verify pinned hash before doing anything. This catches the
        # CVE-2026-30615 / Postmark / Smithery supply-chain class -- if the
        # binary was replaced under us, refuse to launch. Spawn the exact
        # verified path (not the bare command) so the OS can't re-resolve PATH
        # to a different binary between the hash check and exec.
        pinned_path = _verify_command_pin(self.spec)
        env = _build_env(self.spec)
        log.info("MCP client starting server %r (command=%s, args=%d, env keys=%d)",
                 self.spec.name, self.spec.command, len(self.spec.args), len(env))
        try:
            self._proc = await asyncio.create_subprocess_exec(
                pinned_path or self.spec.command, *self.spec.args,
                env=env,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Raise the StreamReader buffer well above the 64 KB default:
                # MCP tools/call results (file reads, search hits, base64
                # images) and big tools/list responses routinely exceed 64 KB,
                # and readline() raises LimitOverrunError on a longer line --
                # crashing the request (or dropping the whole server at start).
                limit=8 * 1024 * 1024,
            )
        except FileNotFoundError as e:
            raise MCPClientError(
                f"MCP server {self.spec.name!r} command not found: {self.spec.command}. "
                "Is it installed? (e.g., `npm install -g @modelcontextprotocol/server-*`)"
            ) from e

        # Drain stderr in the background so the pipe buffer (~64KB on Linux)
        # never fills and blocks the child on write. Without this, MCP
        # servers that log heavily deadlock mid-tool-call.
        self._stderr_task = asyncio.create_task(self._drain_stderr())

        init_resp = await self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            # Advertise elicitation now that we handle inbound elicitation/create
            # (see _handle_elicitation). Without a handler this would invite a
            # request we'd never answer -- the exact stall the spec warns about.
            "capabilities": {"elicitation": {}},
            "clientInfo": {"name": "maverick", "version": "0.1.0"},
        })
        log.debug("MCP %s initialized: %s", self.spec.name,
                  init_resp.get("serverInfo", {}))
        await self._notify("notifications/initialized", {})

        await self.refresh_tools()
        log.info("MCP %s ready (%d tool(s))", self.spec.name, len(self.tools))

    async def _drain_stderr(self) -> None:
        """Forward stderr lines to log.debug so the pipe never fills."""
        if self._proc is None or self._proc.stderr is None:
            return
        try:
            from .secrets import scrub
        except ImportError:  # pragma: no cover -- secrets is in-tree
            scrub = lambda s: s  # noqa: E731
        try:
            while True:
                line = await self._proc.stderr.readline()
                if not line:
                    return
                try:
                    # A hostile / buggy MCP server can echo bearer tokens or
                    # .env values to stderr; scrub before they hit the log.
                    log.debug("MCP[%s] stderr: %s", self.spec.name,
                              scrub(line.decode("utf-8", errors="replace").rstrip()))
                except Exception:  # noqa: BLE001
                    # Never let a scrub/logging error kill the drain task --
                    # if it dies the ~64KB stderr pipe fills and the child
                    # blocks mid tool-call, the exact deadlock this prevents.
                    pass
        except asyncio.CancelledError:
            return

    def _check_alive(self) -> None:
        if self._proc is None:
            raise MCPClientError("server not started")
        if self._proc.returncode is not None:
            raise MCPClientError(
                f"MCP server {self.spec.name!r} exited with code "
                f"{self._proc.returncode}"
            )

    def _ensure_reader(self) -> None:
        """Start the single persistent stdout reader if it isn't running yet.

        Lazy so tests / callers that never issue a request don't spawn it, and
        so it starts only once the subprocess (and thus stdout) exists."""
        if self._reader_task is None or self._reader_task.done():
            self._reader_task = asyncio.create_task(self._read_loop())

    async def _request(self, method: str, params: dict) -> dict:
        # Register the Future + send under the small lock, but await the reply
        # OUTSIDE it so concurrent requests overlap instead of serializing.
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        async with self._lock:
            if method == "tools/call":
                check_call_guard()
            self._check_alive()
            self._ensure_reader()
            req_id = self._next_id()
            self._pending[req_id] = future
            payload = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params,
            }
            try:
                await self._send(payload)
            except asyncio.CancelledError:
                self._pending.pop(req_id, None)
                future.cancel()
                self._schedule_cancel_notice(req_id)
                raise
            except Exception:
                # The request never made it onto the wire; no reply will ever
                # arrive for it, so don't leave a dangling pending Future.
                self._pending.pop(req_id, None)
                if not future.done():
                    future.cancel()
                raise
        try:
            return await asyncio.wait_for(future, timeout=self.timeout)
        except asyncio.TimeoutError:
            # req_id is already on the wire; without a cancel the server runs
            # the call to completion and emits a late reply. De-register the
            # Future so the reader drops that late reply, then tell the server
            # to stop. Our own timeout, not a caller cancel, so
            # the bounded notice is awaited: it is on the wire when this raises.
            self._pending.pop(req_id, None)
            await self._bounded_send_cancel(req_id)
            raise
        except asyncio.CancelledError:
            # The awaiting caller's task was cancelled (not our timeout). The
            # request is already on the wire, so drop the pending Future
            # synchronously -- otherwise it leaks in self._pending until the
            # connection closes (a slow drain on a long-lived client whose
            # callers are routinely cancelled). The pop is the leak fix; the
            # server-side cancel notification is best-effort, so send it from
            # a bounded background task; awaiting it here would let blocked
            # cleanup I/O delay propagation of the original cancellation.
            self._pending.pop(req_id, None)
            self._schedule_cancel_notice(req_id)
            raise

    async def _notify(self, method: str, params: dict) -> None:
        async with self._lock:
            self._check_alive()
            await self._send({"jsonrpc": "2.0", "method": method, "params": params})

    async def _send_cancel(self, request_id: int) -> None:
        """Best-effort MCP cancellation for a request we've given up on.

        A failure here must not mask the timeout the caller is about to see."""
        try:
            async with self._lock:
                await self._send({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": request_id, "reason": "client timeout"},
                })
        except Exception:  # noqa: BLE001 -- the request is already lost
            pass

    async def _bounded_send_cancel(self, request_id: int) -> None:
        try:
            await asyncio.wait_for(
                self._send_cancel(request_id), timeout=_CANCEL_NOTICE_TIMEOUT,
            )
        except Exception:  # noqa: BLE001 -- request already abandoned
            pass

    def _schedule_cancel_notice(self, request_id: int) -> None:
        """Send a best-effort cancellation notice without blocking callers."""
        # Keep a strong reference: the event loop only holds a WEAK ref to a
        # task, so a bare `create_task` whose handle isn't stored can be GC'd
        # mid-flight, dropping the cancel notice ("Task was destroyed but it is
        # pending"). Track it like _handle_inbound_request does so it stays alive
        # until done and is cancelled on stop().
        task = asyncio.create_task(self._bounded_send_cancel(request_id))
        self._inbound_tasks.add(task)
        task.add_done_callback(self._inbound_tasks.discard)

    async def _send(self, payload: dict) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        line = (json.dumps(payload) + "\n").encode()
        self._proc.stdin.write(line)
        try:
            # A server that stops reading stdin would otherwise hold self._lock,
            # and with it every later request, forever.
            await asyncio.wait_for(self._proc.stdin.drain(), timeout=self.timeout)
        except asyncio.TimeoutError:
            # A partly written message leaves the stream unusable: stop the
            # server so pending callers fail instead of waiting on it.
            with contextlib.suppress(ProcessLookupError):
                self._proc.kill()
            raise MCPClientError(
                f"MCP server {self.spec.name!r} stopped reading its input") from None

    def _fail_all_pending(self, exc: Exception) -> None:
        """Resolve every awaiting caller with `exc` so none hang forever.

        Used on reader EOF / transport close / fatal parse and on stop()."""
        pending = self._pending
        self._pending = {}
        for fut in pending.values():
            if not fut.done():
                fut.set_exception(exc)

    async def _read_loop(self) -> None:
        """Sole consumer of the server's stdout.

        Reads one message at a time, correlates responses to the registered
        Future by JSON-RPC id, and ignores notifications. On EOF / fatal parse
        it fails every pending caller so none hang on a dead stream."""
        assert self._proc is not None and self._proc.stdout is not None
        stdout = self._proc.stdout
        try:
            while True:
                line = await stdout.readline()
                if not line:
                    self._fail_all_pending(
                        MCPClientError(
                            f"MCP server {self.spec.name!r} closed stdout"))
                    return
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    log.debug("MCP %s non-JSON line: %s", self.spec.name, line[:200])
                    continue
                if not isinstance(msg, dict):
                    log.debug("MCP %s non-object message ignored", self.spec.name)
                    continue
                self._dispatch(msg)
        except asyncio.CancelledError:
            return
        except Exception as e:  # noqa: BLE001
            # Reader must never die silently: an unexpected stream error would
            # otherwise leave every caller awaiting forever.
            log.error("MCP %s reader loop crashed: %s", self.spec.name, e)
            self._fail_all_pending(
                MCPClientError(
                    f"MCP server {self.spec.name!r} reader failed: {e}"))

    def _dispatch(self, msg: dict) -> None:
        """Route one parsed message: inbound request, notification, or response."""
        # A message carrying "method" originates FROM the server: an inbound
        # request (has "id" -> we must reply) or a notification (no "id" ->
        # ignored). Responses to OUR requests never carry "method"; keying on it
        # also stops a server-chosen request id from being mistaken for one of
        # our pending response ids.
        if msg.get("method") is not None:
            if msg.get("id") is not None:
                self._handle_inbound_request(msg)
            elif msg.get("method") == "notifications/tools/list_changed":
                self.catalog.changed()
            return  # notification: nothing to route
        # A JSON-RPC error with id:null (parse error / invalid request) can't
        # be correlated to a single request -- the server choked on our input.
        # Surface it to every in-flight caller rather than swallowing it.
        if msg.get("id") is None and "error" in msg:
            self._fail_all_pending(
                MCPClientError(
                    f"MCP {self.spec.name!r} protocol error "
                    f"{_format_rpc_error(msg['error'])}"))
            return
        msg_id = msg.get("id")
        if msg_id is None:
            return  # a notification: nothing to route, ignored as before
        if isinstance(msg_id, bool) or not isinstance(msg_id, (int, str)):
            # Unhashable ids would crash the reader; true == 1 would resolve
            # someone else's request. Neither can be a reply to us.
            return
        future = self._pending.pop(msg_id, None)
        if future is None:
            # Reply for an id we no longer track (already timed out / cancelled
            # / unknown). Drop it -- never crash the reader.
            return
        if future.done():  # cancelled caller; nothing to deliver
            return
        if "error" in msg:
            future.set_exception(
                MCPClientError(
                    f"MCP {self.spec.name!r} error "
                    f"{_format_rpc_error(msg['error'])}"))
        else:
            future.set_result(msg.get("result", {}))

    # ---- inbound requests (server -> client) -------------------------------

    def _handle_inbound_request(self, msg: dict) -> None:
        """Answer a request the server sent US (e.g. elicitation/create).

        A server that issues a request and gets no reply stalls the call, so we
        always respond: a supported method is handled, anything else gets a
        JSON-RPC "method not found". Handling runs in its own task so blocking
        work (consent prompt, human input) never stalls the single stdout
        reader that has to keep correlating other in-flight replies."""
        task = asyncio.create_task(self._respond_to_inbound(msg))
        self._inbound_tasks.add(task)
        task.add_done_callback(self._inbound_tasks.discard)

    async def _respond_to_inbound(self, msg: dict) -> None:
        req_id = msg.get("id")
        method = msg.get("method")
        try:
            if method == "elicitation/create":
                result = await self._handle_elicitation(msg.get("params") or {})
                if isinstance(result, _ApprovedElicitation):
                    await self._send_response(
                        req_id,
                        result=result.result,
                        operation_permit=result.permit,
                    )
                else:
                    await self._send_response(req_id, result=result)
            else:
                # roots/list, sampling/createMessage, etc. -- we don't advertise
                # these, so decline cleanly instead of leaving the server hanging.
                await self._send_response(
                    req_id,
                    error={"code": -32601,
                           "message": f"Method not found: {method}"})
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 -- a handler bug must still reply
            log.error("MCP %s inbound %r handler failed: %s",
                      self.spec.name, method, e)
            await self._send_response(
                req_id, error={"code": -32603, "message": "Internal error"})

    async def _send_response(
        self, req_id: object, *, result: dict | None = None,
        error: dict | None = None,
        operation_permit: Any = None,
    ) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result if result is not None else {}
        try:
            async with self._lock:
                self._check_alive()
                if operation_permit is None:
                    await self._send(payload)
                else:
                    from .approval_cards import ApprovalCardError
                    from .safety import consume_operation_consent

                    try:
                        # Spend the exact permit at the byte-write boundary,
                        # after any time the operator spent filling the form.
                        with consume_operation_consent(operation_permit):
                            await self._send(payload)
                    except ApprovalCardError:
                        await self._send({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {"action": "cancel"},
                        })
        except Exception as e:  # noqa: BLE001 -- server gone/unwritable; drop it
            log.debug("MCP %s could not send response for id %s: %s",
                      self.spec.name, req_id, e)

    async def _handle_elicitation(
        self, params: dict,
    ) -> dict | _ApprovedElicitation:
        """Decide an inbound elicitation/create per policy + shield.

        Returns an MCP elicitation result:
        ``{"action": "accept"|"decline"|"cancel", "content"?: {...}}``.

        Safety invariants:
          - The prompt is untrusted remote content -> floor-scanned; a flagged
            prompt is declined, never shown to a human or acted on.
          - Elicited content is resolved entirely in the transport (operator or
            policy); it never passes through the model context.
          - No URL carried in the request is ever fetched or auto-opened -- this
            handler performs no network/browser I/O on the params at all."""
        message = str(params.get("message") or "")
        scan = scan_remote_content(message)
        # Field names, titles and descriptions are shown to the operator too.
        schema_scan = scan_remote_content(
            _elicitation_field_text(params.get("requestedSchema")))
        if schema_scan.suspicious:
            scan = schema_scan
        if scan.suspicious:
            log.warning(
                "MCP %s elicitation prompt flagged (score=%.2f, patterns=%s); "
                "declining", self.spec.name, scan.score, scan.matched_patterns)
            return {"action": "decline"}

        policy = _resolve_elicitation_policy()
        if policy == "cancel":
            return {"action": "cancel"}
        if policy != "prompt":
            return {"action": "decline"}  # default + any unrecognized value

        schema = params.get("requestedSchema") or {}
        # Blocking consent + input() run off the event loop so the reader keeps
        # servicing other in-flight requests while a human is typing.
        return await asyncio.to_thread(
            self._collect_elicitation_blocking, scan.cleaned, schema)

    def _collect_elicitation_blocking(self, message: str, schema: dict) -> dict:
        """Collect typed input, then bind it to a one-use transport permit."""
        if not sys.stdin.isatty():
            return {"action": "cancel"}

        props = schema.get("properties") if isinstance(schema, dict) else None
        required = set(schema.get("required") or []) if isinstance(schema, dict) else set()
        sys.stderr.write(f"\n[MCP {self.spec.name}] {message}\n")
        sys.stderr.flush()
        content: dict[str, Any] = {}
        for key, field_spec in (props or {}).items():
            field_spec = field_spec if isinstance(field_spec, dict) else {}
            label = field_spec.get("title") or key
            prompt = f"  {label}"
            if field_spec.get("description"):
                prompt += f" ({field_spec['description']})"
            sys.stderr.write(prompt + ": ")
            sys.stderr.flush()
            try:
                raw = input().strip()
            except (EOFError, KeyboardInterrupt):
                return {"action": "cancel"}
            if not raw:
                if key in required:
                    return {"action": "cancel"}
                continue
            content[key] = _coerce_scalar(raw, field_spec.get("type"))

        from .approval_cards import ApprovalCardError, digest
        from .safety import ConsentDenied, require_operation_consent

        def target() -> dict[str, Any]:
            return {
                "server": self.spec.name,
                "transport": "http" if self.spec.is_http else "stdio",
                "endpoint": self.spec.url or self.spec.command,
            }

        def credentials() -> dict[str, str]:
            # ``to_dict`` may contain bearer/OAuth material. Only its aggregate
            # digest enters the card, never the secret-bearing configuration.
            return {
                "server_spec_sha256": digest(self.spec.to_dict()),
            }

        parameters = {
            "message": message,
            "schema": schema,
            "content": content,
        }
        field_summary = ", ".join(
            f"{key} ({len(str(value))} chars)"
            for key, value in sorted(content.items())
        ) or "no response fields"
        try:
            permit = require_operation_consent(
                "mcp-elicitation",
                risk="medium",
                scope=self.spec.name,
                detail=f"Return reviewed form values to MCP server {self.spec.name}.",
                provenance="mcp-elicitation",
                target=target(),
                parameters=parameters,
                parameter_summary=[f"Return {field_summary}."],
                known_effects=[
                    "Sends the exact committed field values to the named MCP server."
                ],
                unresolved_assumptions=[
                    "The remote server controls how it stores and uses the submitted values."
                ],
                before="The MCP server has not received these form values.",
                after="The MCP server has received these form values once.",
                irreversible=True,
                target_provider=target,
                parameters_provider=lambda: {
                    "message": message,
                    "schema": schema,
                    "content": dict(content),
                },
                input_versions_provider=lambda: {
                    "elicitation_sha256": digest({
                        "message": message,
                        "schema": schema,
                    }),
                    "content_sha256": digest(content),
                },
                credential_versions_provider=credentials,
                budget_provider=lambda: {
                    "response_bytes": len(
                        json.dumps(content, sort_keys=True).encode("utf-8")
                    )
                },
                allow_auto_approve=False,
                consult_ledger=False,
            )
        except (ConsentDenied, ApprovalCardError):
            return {"action": "cancel"}
        return _ApprovedElicitation(
            result={"action": "accept", "content": content},
            permit=permit,
        )

    async def call_tool(self, tool_name: str, arguments: dict) -> str:
        resp = await self._request("tools/call", {
            "name": tool_name,
            "arguments": arguments,
        })
        return _finalize_tool_result(self.spec.name, tool_name, resp)

    async def stop(self) -> None:
        await self.catalog.close()
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
            self._reader_task = None
        # Drop any in-flight inbound-request handlers (e.g. an elicitation
        # blocked on operator input) so they don't outlive the transport.
        for task in list(self._inbound_tasks):
            task.cancel()
        self._inbound_tasks.clear()
        # Cancelling the reader stops it before it can fail pending callers, so
        # release any still-waiting requests here so they don't hang on close.
        self._fail_all_pending(
            MCPClientError(f"MCP server {self.spec.name!r} stopped"))
        if self._stderr_task is not None:
            self._stderr_task.cancel()
            try:
                await self._stderr_task
            except (asyncio.CancelledError, Exception):
                pass
            self._stderr_task = None
        if self._proc is None:
            return
        if self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:  # pragma: no cover
                self._proc.kill()
                # Reap the killed child so it isn't left a zombie (the only
                # handle is dropped on the next line).
                try:
                    await self._proc.wait()
                except Exception:
                    pass
        self._proc = None


@dataclass
class _HTTPMCPResponse:
    status_code: int
    headers: Any
    text: str


class StreamableHttpMCPClient:
    """MCP client over Streamable HTTP (spec 2025-11-25) for REMOTE servers.

    Covers the request/response path -- initialize, tools/list, tools/call --
    which is what consuming a remote server's tools needs. POSTs JSON-RPC and
    accepts either a single ``application/json`` response or a Streamable-HTTP
    SSE stream carrying the response event. Server->client SSE streaming (push
    notifications, server-initiated elicitation over HTTP) is not supported;
    this client advertises no such capability.

    Exposes the same surface the registry uses (``spec``, ``tools``,
    ``call_tool``, ``stop``) so it's a drop-in alongside the stdio MCPClient."""

    def __init__(self, spec: MCPServerSpec, timeout: float = DEFAULT_TIMEOUT, *,
                 transport: Any = None):
        self.spec = spec
        self.timeout = timeout
        # An httpx transport to connect through (e.g. an IP-pinned one from
        # ``tools._ssrf.pinned_async_transport``); None uses httpx's own.
        self._transport = transport
        self._client: Any = None  # httpx.AsyncClient
        self._session_id: str | None = None
        self._protocol_version = PROTOCOL_VERSION
        self._initialized = False
        self._oauth_bearer: str | None = None
        self._req_id = 0
        self._oauth_provider: Any = None
        self.catalog = ToolCatalog(
            lambda method, params: self._request(method, params),
            limits=CatalogLimits(seconds=min(timeout, 30.0)),
        )

    @property
    def tools(self) -> list[dict[str, Any]]:
        return self.catalog.tools

    async def refresh_tools(self) -> None:
        await self.catalog.refresh()

    def _oauth_config(self):
        """Parse the OAuth config for this server, if one is configured."""
        if not self.spec.oauth:
            return None
        from .mcp_oauth import OAuthConfig
        return OAuthConfig.from_dict(self.spec.oauth)

    def _ensure_oauth_provider(self):
        """Return the grant-appropriate OAuth provider for this server."""
        cfg = self._oauth_config()
        if cfg is None:
            return None
        if self._oauth_provider is None:
            from .mcp_oauth import AuthorizationCodeProvider, OAuthTokenProvider
            provider_cls = (
                AuthorizationCodeProvider
                if cfg.grant_type == "authorization_code"
                else OAuthTokenProvider
            )
            self._oauth_provider = provider_cls(cfg)
        return self._oauth_provider

    def oauth_authorization_start(self) -> tuple[str, str, str]:
        """Start an OAuth authorization-code flow for this HTTP server.

        Returns ``(authorization_url, state, code_verifier)``. The caller should
        open ``authorization_url``, validate that the redirect's state matches
        ``state``, and pass the returned code plus ``code_verifier`` to
        :meth:`oauth_authorization_complete` before connecting.
        """
        provider = self._ensure_oauth_provider()
        if provider is None or not hasattr(provider, "start"):
            raise ValueError("oauth authorization start requires the authorization_code grant")
        return provider.start()

    def oauth_authorization_complete(
        self, code: str, code_verifier: str, *, now: float | None = None
    ) -> str:
        """Complete an OAuth authorization-code flow and cache the access token."""
        provider = self._ensure_oauth_provider()
        if provider is None or not hasattr(provider, "complete"):
            raise ValueError("oauth authorization complete requires the authorization_code grant")
        return provider.complete(code, code_verifier, now=now)

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _bearer(self) -> str | None:
        """The bearer token for this server: an OAuth access token when an
        ``oauth`` block is configured (fetched + cached + refreshed), else the
        static ``auth_token``. Returns None when neither is set."""
        if self.spec.oauth:
            provider = self._ensure_oauth_provider()
            return provider.token()
        return self.spec.auth_token

    async def start(self) -> None:
        # Enterprise mode: this client POSTs tool args to a remote MCP server.
        # Refuse to connect to a non-local, non-allow-listed host so data stays
        # in the boundary (the egress lock covers MCP-HTTP, not just LLM calls).
        from .enterprise import enterprise_egress_denial
        deny = enterprise_egress_denial(self.spec.url, tool=f"mcp:{self.spec.name}")
        if deny:
            raise MCPClientError(deny)
        import httpx
        headers = {"User-Agent": "maverick-mcp-client/0.1"}
        if self.spec.headers:
            headers.update(self.spec.headers)
        bearer = await asyncio.to_thread(self._bearer)
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        if self.spec.oauth:
            self._oauth_bearer = bearer
        extra = {"transport": self._transport} if self._transport is not None else {}
        self._client = httpx.AsyncClient(
            timeout=self.timeout, headers=headers, follow_redirects=False, **extra,
        )
        log.info("MCP HTTP client connecting %r (%s)", self.spec.name, self.spec.url)
        init = await self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "maverick", "version": "0.1.0"},
        })
        if isinstance(init, dict) and init.get("protocolVersion"):
            self._protocol_version = init["protocolVersion"]
        self._initialized = True  # gates the MCP-Protocol-Version header below
        await self._notify("notifications/initialized", {})
        await self.refresh_tools()
        log.info("MCP %s ready (%d tool(s)) over HTTP", self.spec.name, len(self.tools))

    def _headers(self) -> dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        # Session continuity + protocol pinning per the 2025-11-25 spec: resend
        # the server-assigned session id and the negotiated protocol version.
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        if self._initialized:
            h["MCP-Protocol-Version"] = self._protocol_version
        if self.spec.oauth and self._oauth_bearer:
            # Kept current by _refresh_bearer before each request, so a
            # long-lived client does not keep the token fetched at start().
            h["Authorization"] = f"Bearer {self._oauth_bearer}"
        return h

    async def _refresh_bearer(self) -> None:
        """Use the cached OAuth token until shortly before it expires; the
        refresh is a blocking HTTP call, so it runs off the event loop."""
        if not self.spec.oauth:
            return
        provider = self._ensure_oauth_provider()
        token = provider.cached_token() if hasattr(provider, "cached_token") else None
        if token is None:
            token = await asyncio.to_thread(provider.token)
        self._oauth_bearer = token

    async def _post(self, payload: dict, req_id: int | None = None) -> Any:
        if self._client is None:
            raise MCPClientError(f"MCP server {self.spec.name!r} not started")

        async def _send() -> _HTTPMCPResponse:
            if payload.get("method") == "tools/call":
                check_call_guard()
            await self._refresh_bearer()
            from .governed_http import admit_client_request

            admit_client_request(self._client, self.spec.url)
            async with self._client.stream(
                "POST", self.spec.url, json=payload, headers=self._headers()
            ) as resp:
                sid = resp.headers.get("mcp-session-id")
                if sid:
                    self._session_id = sid
                text = await self._read_response_text(resp, req_id)
                return _HTTPMCPResponse(resp.status_code, resp.headers, text)

        try:
            return await asyncio.wait_for(_send(), timeout=self.timeout)
        except MCPClientError:
            raise
        except asyncio.TimeoutError as e:
            raise MCPClientError(
                f"MCP {self.spec.name!r} HTTP request timed out after "
                f"{self.timeout:.1f}s") from e
        except Exception as e:  # connect/timeout/transport error
            raise MCPClientError(
                f"MCP {self.spec.name!r} HTTP request failed: "
                f"{_safe_error_detail(str(e))}") from e

    async def _read_response_text(self, resp: Any, req_id: int | None) -> str:
        ctype = (resp.headers.get("content-type") or "").lower()
        if "text/event-stream" in ctype:
            return await self._read_sse_response_text(resp, req_id)
        body = bytearray()
        async for chunk in resp.aiter_bytes():
            body.extend(chunk)
            if len(body) > _MAX_HTTP_RESPONSE_BYTES:
                raise MCPClientError(
                    f"MCP {self.spec.name!r} HTTP response exceeded "
                    f"{_MAX_HTTP_RESPONSE_BYTES} bytes")
        return body.decode(resp.encoding or "utf-8", errors="replace")

    async def _read_sse_response_text(self, resp: Any, req_id: int | None) -> str:
        # Read SSE incrementally and stop as soon as the requested JSON-RPC
        # response event arrives. Do not wait for the server to close the stream:
        # Streamable HTTP servers may keep it open for heartbeats/notifications.
        text = ""
        buffer = ""
        total = 0
        async for chunk in resp.aiter_text():
            total += len(chunk.encode("utf-8", errors="replace"))
            if total > _MAX_HTTP_RESPONSE_BYTES:
                raise MCPClientError(
                    f"MCP {self.spec.name!r} SSE response exceeded "
                    f"{_MAX_HTTP_RESPONSE_BYTES} bytes")
            text += chunk
            buffer += chunk
            buffer = buffer.replace("\r\n", "\n").replace("\r", "\n")
            while "\n\n" in buffer:
                block, buffer = buffer.split("\n\n", 1)
                data = "\n".join(
                    line[len("data:"):].lstrip()
                    for line in block.split("\n") if line.startswith("data:")
                )
                if not data:
                    continue
                try:
                    msg = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if isinstance(msg, dict) and msg.get("method") == "notifications/tools/list_changed" and "id" not in msg:
                    self.catalog.changed()
                if req_id is None or (isinstance(msg, dict) and msg.get("id") == req_id):
                    return text
        return text

    async def _request(self, method: str, params: dict) -> dict:
        req_id = self._next_id()
        resp = await self._post(
            {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
            req_id=req_id)
        if resp.status_code >= 400:
            raise MCPClientError(
                f"MCP {self.spec.name!r} {method} -> HTTP {resp.status_code}: "
                f"{_safe_error_detail(resp.text)}")
        msg = self._extract(resp, req_id)
        if msg is None:
            raise MCPClientError(
                f"MCP {self.spec.name!r} {method}: no JSON-RPC response in reply")
        if "error" in msg:
            raise MCPClientError(
                f"MCP {self.spec.name!r} error {_format_rpc_error(msg['error'])}")
        result = msg.get("result", {})
        return result if isinstance(result, dict) else {}

    async def _notify(self, method: str, params: dict) -> None:
        # A notification carries no id; a spec server replies 202 with no body.
        await self._post({"jsonrpc": "2.0", "method": method, "params": params})

    def _extract(self, resp: Any, req_id: int) -> dict | None:
        """Pull the JSON-RPC response for ``req_id`` from a JSON or SSE reply."""
        ctype = (resp.headers.get("content-type") or "").lower()
        text = resp.text or ""
        if "text/event-stream" in ctype:
            # Streamable-HTTP SSE: scan `data:` events for our response, skipping
            # heartbeats (comment lines) and any interleaved notifications.
            for block in text.replace("\r\n", "\n").split("\n\n"):
                data = "\n".join(
                    line[len("data:"):].lstrip()
                    for line in block.split("\n") if line.startswith("data:")
                )
                if not data:
                    continue
                try:
                    m = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if isinstance(m, dict) and m.get("id") == req_id:
                    return m
            return None
        try:
            m = json.loads(text)
        except json.JSONDecodeError:
            return None
        return m if isinstance(m, dict) else None

    async def call_tool(self, tool_name: str, arguments: dict) -> str:
        resp = await self._request("tools/call", {
            "name": tool_name, "arguments": arguments,
        })
        return _finalize_tool_result(self.spec.name, tool_name, resp)

    async def stop(self) -> None:
        await self.catalog.close()
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:  # pragma: no cover -- best-effort close
                pass
            self._client = None


def _content_to_str(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return str(content) if content is not None else ""
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict):
            btype = block.get("type")
            if btype == "text":
                parts.append(block.get("text", ""))
            elif btype == "resource":
                # Embedded resource: surface its text directly (a text file's
                # contents) instead of a JSON dump; fall back to JSON for a
                # binary blob / bare uri so nothing is silently lost.
                res = block.get("resource")
                if isinstance(res, dict) and isinstance(res.get("text"), str):
                    parts.append(res["text"])
                else:
                    parts.append(json.dumps(block))
            else:
                parts.append(json.dumps(block))
        else:
            parts.append(str(block))
    return "\n".join(parts)


async def start_mcp_clients(specs: list[MCPServerSpec]) -> list:
    # Build the transport that matches each spec: remote (Streamable HTTP) when
    # a url is set, else the stdio subprocess client.
    clients = [
        StreamableHttpMCPClient(spec) if spec.is_http else MCPClient(spec)
        for spec in specs
    ]

    async def _try_start(c) -> object | None:
        try:
            await c.start()
            return c
        except Exception as e:
            log.error("MCP server %r failed to start: %s", c.spec.name, e)
            # start() spawns the subprocess + a stderr-drain task BEFORE
            # the initialize/tools-list calls that can fail. A failed
            # client is dropped from the returned list, so nothing else
            # will ever reap it — clean it up here to avoid a zombie
            # process + orphaned task per failed start.
            try:
                await c.stop()
            except Exception:  # pragma: no cover -- best-effort cleanup
                pass
            return None

    results = await asyncio.gather(*(_try_start(c) for c in clients))
    return [c for c in results if c is not None]


async def stop_mcp_clients(clients: list[MCPClient]) -> None:
    await asyncio.gather(*(c.stop() for c in clients), return_exceptions=True)


def load_mcp_specs_from_config() -> list[MCPServerSpec]:
    try:
        from .config import load_config
        cfg = load_config()
    except Exception:
        cfg = {}
    servers = dict(cfg.get("mcp_servers", {}) or {})
    # Dashboard-added servers (runtime overlay, never config.toml). config wins
    # on a name clash so the overlay can't shadow a hand-tuned entry; otherwise a
    # server added from the dashboard runs on the next goal with no config edit.
    try:
        from .runtime_overrides import mcp_overlay
        for name, spec in mcp_overlay().items():
            servers.setdefault(name, spec)
    except RuntimeOverridesSecurityError:
        raise
    except Exception:  # pragma: no cover -- overlay never breaks MCP loading
        pass
    out: list[MCPServerSpec] = []
    for name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue
        enabled = server_cfg.get("enabled", True)
        if type(enabled) is not bool:
            # bool("false") is True: refuse a non-boolean rather than spawn it.
            log.warning("mcp_servers.%s enabled must be true or false; skipping", name)
            continue
        if not enabled:
            continue
        if "command" not in server_cfg and "url" not in server_cfg:
            log.warning("mcp_servers.%s needs 'command' (stdio) or 'url' (http); skipping", name)
            continue
        try:
            out.append(MCPServerSpec.from_config(name, server_cfg))
        except Exception as e:  # pragma: no cover
            log.error("mcp_servers.%s invalid: %s", name, e)
    return out
