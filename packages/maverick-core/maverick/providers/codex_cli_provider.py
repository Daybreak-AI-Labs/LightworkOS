"""Codex CLI provider client (ChatGPT/Codex subscription).

Routes ``complete()`` calls through the locally installed OpenAI Codex
CLI (``codex exec``) instead of a metered API SDK, so a ChatGPT/Codex
subscription can back Lightwork roles and benchmarks. Spec form:
``codex_cli:<model-id>`` (aliases ``codex-cli:`` / ``codex:``), e.g.::

    [models]
    orchestrator = "codex_cli:gpt-5.5"

or, for a one-off benchmark run::

    MAVERICK_MODEL_OVERRIDE='codex_cli:gpt-5.5' \
        python3 benchmarks/eval_tau2.py --limit 1 --max-dollars 2

Use a model id your Codex plan actually serves. With a ChatGPT subscription
that is ``gpt-5.5`` (the codex CLI's own default) or ``gpt-5``; the
Codex-tuned ``*-codex`` ids are rejected for ChatGPT-account auth.

Auth comes from the Codex CLI's own login state (``$CODEX_HOME/auth.json``,
default ``~/.codex/auth.json``) or from ``CODEX_ACCESS_TOKEN`` — the env var
OpenAI documents for trusted automation. When only the env var is present,
the client performs ``codex login --with-access-token`` once, feeding the
token on STDIN so it never appears on argv, in process listings, or in logs.
With neither surface present the client refuses at construction time.

Differences from API-key providers, by design:
  - **Spend is subscription-metered, not per-token dollars.** Model ids
    behind the ``codex_cli:`` prefix price at $0 (see ``budget._lookup_price``);
    ``Budget`` still enforces wall-clock, token counts, and tool-call caps.
  - **No native tool-call wire format.** ``codex exec`` takes a prompt and
    returns text, so tool use is emulated: tool schemas are embedded in the
    prompt and the model is instructed to answer with one fenced ``json``
    block (``{"tool_call": {"name": ..., "input": {...}}}``), which is parsed
    back into a ``ToolCall``. Fine for benchmarks and general agent loops;
    weaker guarantees than a native tools API.
  - The subprocess runs with ``--sandbox read-only`` by default and with
    Codex's own shell and exec tools turned off (``features.shell_tool`` and
    ``features.unified_exec``): Lightwork owns tool execution, Codex is used
    purely as the model backend.

Config knobs (``[providers.codex_cli]``): ``binary`` (default ``codex``),
``sandbox_mode`` (default ``read-only``), ``timeout_seconds`` (default 600),
``cwd`` (default: a private temp dir so Codex never scans the caller's repo).
"""
from __future__ import annotations

import asyncio
import bisect
import json
import math
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..budget import Budget, UsageAccountingError
from ..llm import LLMResponse, ToolCall
from ..owned_process import ProcessOutputLimit, run_owned, run_sync
from ..secrets import scrub

# Pricing qualifier: unknown ids behind this prefix bill $0 (subscription
# usage has no per-token API invoice; see budget._lookup_price).
PRICE_MODEL_PREFIX = "codex_cli:"

DEFAULT_BINARY = "codex"
DEFAULT_SANDBOX_MODE = "read-only"
DEFAULT_TIMEOUT_SECONDS = 600.0
LAST_MESSAGE_BYTES = 4 * 1024 * 1024


class CodexExecutionError(UsageAccountingError):
    """Failed invocation: no final usage receipt, and no automatic replay."""

    usage_status = "unknown"

_ENV_ALLOWLIST = (
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "TERM",
    "TMPDIR",
    "USER",
    "USERNAME",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "CODEX_HOME",
)

_SANDBOX_MODES = ("read-only", "workspace-write", "danger-full-access")

# One fenced json block carrying the emulated tool call: an opener
# (```json, optional whitespace, "{") closed by the first later "}", optional
# whitespace and ``` -- the shortest block, so trailing prose after it is not
# swallowed into the JSON parse. Openers and closers are found by two linear
# scans and paired with a binary search: a single ``\{.*?\}`` pattern rescans
# the rest of the reply for every unclosed opener, which is quadratic on a
# reply full of ```json{ openers.
_TOOL_CALL_OPENER = re.compile(r"```json\s*\{")
_TOOL_CALL_CLOSER = re.compile(r"\}\s*```")


def _tool_call_blocks(text: str) -> list[tuple[int, int, str]]:
    """Return ``(start, end, json_body)`` for each fenced tool-call block."""
    closers = [(m.start(), m.end()) for m in _TOOL_CALL_CLOSER.finditer(text)]
    closer_starts = [start for start, _ in closers]
    blocks: list[tuple[int, int, str]] = []
    pos = 0
    for opener in _TOOL_CALL_OPENER.finditer(text):
        if opener.start() < pos:
            continue
        brace = opener.end() - 1
        i = bisect.bisect_right(closer_starts, brace)
        if i == len(closers):
            break  # no later closer, so none for any later opener either
        close, pos = closers[i]
        blocks.append((opener.start(), pos, text[brace:close + 1]))
    return blocks

_TOOL_PROTOCOL = """\

## Tool calls

You may use the tools listed below (JSON Schemas included). To call one,
end your reply with EXACTLY ONE fenced code block of this form and nothing
after it:

```json
{{"tool_call": {{"name": "<tool name>", "input": {{<arguments matching the schema>}}}}}}
```

Call at most one tool per reply. If no tool is needed, reply with plain text
and no fenced json block. Available tools:

{tools}
"""


def codex_home(env: dict | None = None) -> Path:
    """The Codex CLI state dir: ``$CODEX_HOME`` or ``~/.codex``."""
    e = os.environ if env is None else env
    raw = (e.get("CODEX_HOME") or "").strip()
    home = e.get("USERPROFILE" if os.name == "nt" else "HOME")
    if raw:
        return Path(raw)
    if home and home.strip():
        return Path(home) / ".codex"
    if env is not None:
        raise RuntimeError(
            "Codex provider environment requires CODEX_HOME or a captured "
            "home directory; refusing live authentication-directory discovery"
        )
    return Path.home() / ".codex"


def _snapshot_binary(command: str, environment: dict[str, str]) -> str | None:
    """Resolve only the admitted PATH/PATHEXT without changing process globals.

    Windows ``shutil.which(..., path=...)`` still reads live PATHEXT and may
    prepend the current directory according to ambient Win32 policy. An explicit
    snapshot searches only its PATH entries (or the configured binary path).
    Relative entries are pinned to absolute paths at construction.
    """
    if os.name != "nt":
        resolved = shutil.which(command, path=environment.get("PATH", os.defpath))
        return os.path.abspath(resolved) if resolved is not None else None
    extensions = [
        extension for extension in environment.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";")
        if extension
    ]
    if any(command.lower().endswith(extension.lower()) for extension in extensions):
        candidates = [command]
    else:
        candidates = [command + extension for extension in extensions]
    if os.path.dirname(command):
        directories = [""]
    else:
        # Windows' os.defpath includes '.', which would silently widen a
        # snapshot that omitted PATH to the current working directory.
        path = environment.get("PATH", "")
        if not path:
            return None
        directories = path.split(os.pathsep)
    seen: set[str] = set()
    for directory in directories:
        normalized = os.path.normcase(os.path.abspath(directory or os.curdir))
        if normalized in seen:
            continue
        seen.add(normalized)
        for candidate in candidates:
            filename = os.path.join(directory, candidate)
            if os.path.isfile(filename) and os.access(filename, os.F_OK | os.X_OK):
                return os.path.abspath(filename)
    return None


def _auth_file_present(env: dict | None = None) -> bool:
    try:
        return (codex_home(env) / "auth.json").is_file()
    except OSError:  # pragma: no cover -- unreadable home dir
        return False


class CodexCLIClient:
    """``codex exec`` as a Lightwork provider (structural ``Provider`` type).

    ``api_key`` is the ChatGPT/Codex ACCESS TOKEN (from
    ``[providers.codex_cli] api_key`` or ``CODEX_ACCESS_TOKEN``); it is held
    only to feed ``codex login --with-access-token`` on STDIN and is never
    logged, never placed on argv, and never echoed into error messages.
    """

    # The codex CLI's own default for ChatGPT-account auth. The Codex-tuned
    # `*-codex` ids (e.g. gpt-5.5-codex) 400 with "not supported when using
    # Codex with a ChatGPT account", so they must NOT be the default.
    DEFAULT_MODEL = "gpt-5.5"
    PRICE_MODEL_PREFIX = PRICE_MODEL_PREFIX
    # Subscription usage: nothing to dollar-enforce, so a missing usage
    # event must not abort the turn (mirrors the self-hosted providers).
    USAGE_REQUIRED = False

    def __init__(self, api_key: str | None = None, base_url: str | None = None, *, environment=None, provider_options=None):
        if base_url:
            raise ValueError("providers.codex_cli.base_url is unsupported; the CLI owns its endpoint")
        self._environment = dict(os.environ if environment is None else environment)
        # Admission, login and execution must all use the same authentication
        # directory, including Windows where USERPROFILE is deliberately not
        # forwarded to the subprocess. A direct constructor may discover its
        # default once; an explicit snapshot may never consult a later home.
        self._environment["CODEX_HOME"] = str(
            codex_home(None if environment is None else self._environment).absolute()
        )
        token = (api_key or self._environment.get("CODEX_ACCESS_TOKEN") or "").strip()
        self._access_token = token or None
        self._login_succeeded = False
        self._login_lock = threading.Lock()

        cfg = self._provider_config() if provider_options is None else dict(provider_options)
        from .configuration import adapter_options, validate_fields
        validate_fields("codex_cli", cfg)
        cfg = dict(adapter_options("codex_cli", cfg))
        self.binary = str(cfg.get("binary") or DEFAULT_BINARY)
        sandbox_mode = str(cfg.get("sandbox_mode") or DEFAULT_SANDBOX_MODE)
        if sandbox_mode not in _SANDBOX_MODES:
            raise ValueError(
                f"[providers.codex_cli] sandbox_mode={sandbox_mode!r} invalid; "
                f"one of {_SANDBOX_MODES}"
            )
        self.sandbox_mode = sandbox_mode
        try:
            self.timeout_seconds = float(
                cfg.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
            )
        except (TypeError, ValueError):
            self.timeout_seconds = DEFAULT_TIMEOUT_SECONDS
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("[providers.codex_cli] timeout_seconds must be finite and positive")
        cwd = cfg.get("cwd")
        self.cwd = str(cwd) if isinstance(cwd, str) and cwd.strip() else None

        # Resolve to an ABSOLUTE path once, here, and launch that -- not the
        # bare name. On Windows `npm install -g` puts `codex` on PATH as a
        # `.cmd`/`.bat` shim; a bare-name subprocess (correctly, no shell) then
        # fails with FileNotFoundError mid-run even though `shutil.which` found
        # the shim. Resolving + routing the shim (see `_launch_prefix`) fixes
        # that. shutil.which also accepts an already-absolute path, so an
        # operator-set `binary` pointing straight at codex.exe works too.
        resolved = shutil.which(self.binary) if environment is None else _snapshot_binary(
            self.binary, self._environment,
        )
        if resolved is None:
            raise RuntimeError(
                f"Codex CLI binary {self.binary!r} not found on PATH. Install it "
                "(npm install -g @openai/codex, or brew install codex) or set "
                "[providers.codex_cli] binary in ~/.maverick/config.toml."
            )
        self._binary_path = resolved
        if not self._access_token and not _auth_file_present(self._environment):
            raise RuntimeError(
                "Codex CLI is not authenticated: no CODEX_ACCESS_TOKEN env var, "
                "no [providers.codex_cli] api_key, and no "
                f"{codex_home(self._environment) / 'auth.json'}. Run `codex login`, or export "
                "CODEX_ACCESS_TOKEN (kept out of logs and argv)."
            )

    @staticmethod
    def _provider_config() -> dict:
        try:
            from ..config import get_provider_config
            return get_provider_config("codex_cli") or {}
        except Exception:  # pragma: no cover -- config read fails soft
            return {}

    @staticmethod
    def _cmd_quote(arg: str) -> str:
        """Quote one argv element for cmd.exe's /c command string.

        Windows ``subprocess`` still builds one command line for ``cmd.exe``.
        For ``.cmd``/``.bat`` shims, every shim argument must therefore stay
        inside quotes so cmd metacharacters such as ``&`` and ``|`` remain data
        instead of command separators. Backslashes before quotes are doubled to
        preserve normal Windows argv parsing after cmd removes the outer quotes.
        """
        quoted = ['"']
        backslashes = 0
        for ch in arg:
            if ch == "\\":
                backslashes += 1
                continue
            if ch == '"':
                quoted.append("\\" * (backslashes * 2 + 1))
                quoted.append('"')
            else:
                quoted.append("\\" * backslashes)
                quoted.append(ch)
            backslashes = 0
        quoted.append("\\" * (backslashes * 2))
        quoted.append('"')
        return "".join(quoted)

    def _launch_cmd(self, *args: str) -> list[str]:
        """Complete argv that launches Codex with ``args``.

        A real executable is launched directly by its absolute path. On Windows
        a `.cmd`/`.bat` shim (how npm installs the `codex` bin) cannot be run by
        CreateProcess without an interpreter, so route it through ``%COMSPEC%``
        (cmd.exe) ``/d /s /c``. The command interpreted by cmd is a single
        string whose every argv element is quoted, preserving list-argv
        semantics for untrusted values such as model ids.
        """
        path = self._binary_path
        if os.name == "nt" and path.lower().endswith((".cmd", ".bat")):
            comspec = self._environment.get("COMSPEC") or "cmd.exe"
            # cmd.exe still expands %VAR% (and !VAR!) inside quotes, and an
            # embedded quote toggles its quote state, so no quoting is safe.
            if any(ch in part for part in (path, *args) for ch in '%"^!\r\n'):
                raise RuntimeError(
                    "Codex CLI arguments contain a character that cmd.exe cannot "
                    "pass safely (% \" ^ ! or a line break); point "
                    "[providers.codex_cli] binary at codex.exe instead of the shim."
                )
            command = " ".join(self._cmd_quote(part) for part in (path, *args))
            return [comspec, "/d", "/s", "/c", command]
        return [path, *args]

    def _launch_prefix(self) -> list[str]:
        """Backward-compatible argv head for tests and diagnostics."""
        return self._launch_cmd()

    # ------------------------------------------------------------------ auth

    async def _ensure_login(self, deadline: float, check: Callable[[], None]) -> None:
        """One-shot ``codex login --with-access-token`` when we hold a token
        but the CLI has no stored login. Token travels on STDIN only."""
        if _auth_file_present(self._environment) or not self._access_token:
            return
        while not self._login_lock.acquire(blocking=False):
            check()
            if time.monotonic() >= deadline:
                raise TimeoutError("codex login queue deadline exceeded")
            await asyncio.sleep(0.005)
        try:
            if self._login_succeeded or _auth_file_present(self._environment):
                return
            proc = await run_owned(
                self._launch_cmd("login", "--with-access-token"),
                input=self._access_token,
                deadline=min(deadline, time.monotonic() + 60), check=check,
                env=self._subprocess_env(),
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    "codex login --with-access-token failed "
                    f"(exit {proc.returncode}): {self._scrub(proc.stderr)[-500:]}"
                )
            self._login_succeeded = True
        finally:
            self._login_lock.release()

    def _subprocess_env(self) -> dict[str, str]:
        """Minimal environment for Codex subprocesses.

        ``codex exec`` is an agent runtime, not a passive model API.  Never
        pass Maverick's full process environment through to it: provider keys,
        cloud credentials, and deployment secrets must remain outside the
        provider subprocess even if a prompt injection convinces Codex to run
        read-only commands such as ``env`` or ``printenv``.
        """
        env = {k: v for k, v in self._environment.items() if k in _ENV_ALLOWLIST}
        if "PATH" not in env:
            env["PATH"] = os.defpath
        return env

    def _scrub(self, text: str) -> str:
        """Secret-scrub subprocess output; belt-and-braces drop of the exact
        token value in case the generic patterns miss its shape."""
        out = scrub(text or "")
        if self._access_token:
            out = out.replace(self._access_token, "[REDACTED:codex_access_token]")
        return out

    # -------------------------------------------------------------- prompting

    @staticmethod
    def _flatten_content(content: Any) -> str:
        """One message's Anthropic content (str or block list) as plain text."""
        if isinstance(content, str):
            return content
        if not isinstance(content, list):
            return str(content) if content is not None else ""
        parts: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                parts.append(str(block))
                continue
            bt = block.get("type")
            if bt == "text":
                parts.append(block.get("text", ""))
            elif bt == "tool_use":
                parts.append(
                    "[assistant called tool "
                    f"{block.get('name')!r} (id {block.get('id')}) with input "
                    f"{json.dumps(block.get('input', {}), default=str)}]"
                )
            elif bt == "tool_result":
                inner = block.get("content")
                if isinstance(inner, list):
                    inner = "\n".join(
                        b.get("text", "") if isinstance(b, dict) else str(b)
                        for b in inner
                    )
                parts.append(
                    f"[tool result for {block.get('tool_use_id')}]\n{inner}"
                )
            # thinking blocks are dropped (no Codex equivalent)
        return "\n".join(p for p in parts if p)

    @classmethod
    def _compose_prompt(
        cls, system: str, messages: list[dict], tools: list[dict] | None,
    ) -> str:
        """Flatten system + Anthropic-format history into one exec prompt."""
        lines: list[str] = [
            "You are the model backend for the Lightwork agent runtime. "
            "Continue the conversation below as the assistant. Do not run "
            "commands or edit files yourself; just produce the assistant's "
            "next reply.",
        ]
        if system:
            lines.append(f"\n## System instructions\n\n{system}")
        if tools:
            schemas = "\n".join(
                f"- {t.get('name')}: {t.get('description', '')}\n"
                f"  input schema: "
                f"{json.dumps(t.get('input_schema', {'type': 'object'}), default=str)}"
                for t in tools
            )
            lines.append(_TOOL_PROTOCOL.format(tools=schemas))
        lines.append("\n## Conversation\n")
        from .conversation import ConversationMessage

        for msg in messages or []:
            if isinstance(msg, ConversationMessage):
                msg = msg.to_anthropic()
            role = msg.get("role", "user") if isinstance(msg, dict) else "user"
            content = msg.get("content") if isinstance(msg, dict) else msg
            text = cls._flatten_content(content)
            lines.append(f"[{role}]\n{text}\n")
        lines.append("[assistant]")
        return "\n".join(lines)

    # --------------------------------------------------------------- response

    @staticmethod
    def _parse_events(stdout: str) -> tuple[str | None, dict[str, int]]:
        """(last agent-message text, usage totals) from ``--json`` JSONL.

        Parsed defensively across the event shapes Codex CLI has shipped:
        ``{"type": "item.completed", "item": {"type": "agent_message", ...}}``
        and the older ``{"msg": {"type": "agent_message", ...}}``; usage from
        ``turn.completed`` / ``token_count`` events. Unknown lines are skipped.
        """
        text: str | None = None
        usage = {"input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0}

        def _take_usage(u: Any) -> None:
            if not isinstance(u, dict):
                return
            for ours, theirs in (
                ("input_tokens", ("input_tokens", "prompt_tokens")),
                ("cached_input_tokens", ("cached_input_tokens", "cached_tokens")),
                ("output_tokens", ("output_tokens", "completion_tokens")),
            ):
                for name in theirs:
                    v = u.get(name)
                    if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v >= 0:
                        usage[ours] = int(v)
                        break

        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            item = event.get("item") or event.get("msg") or event
            if isinstance(item, dict) and item.get("type") == "agent_message":
                candidate = item.get("text") or item.get("message")
                if isinstance(candidate, str) and candidate.strip():
                    text = candidate
            for u in (event.get("usage"), (item or {}).get("usage") if isinstance(item, dict) else None):
                _take_usage(u)
            if isinstance(item, dict) and item.get("type") == "token_count":
                _take_usage(item.get("info") or item)
        return text, usage

    @staticmethod
    def _extract_tool_call(text: str) -> tuple[str, ToolCall | None]:
        """Split an emulated tool call out of the reply text, if present."""
        for start, end, body in reversed(_tool_call_blocks(text or "")):
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                continue
            call = payload.get("tool_call") if isinstance(payload, dict) else None
            if not (isinstance(call, dict) and isinstance(call.get("name"), str)):
                continue
            args = call.get("input")
            if not isinstance(args, dict):
                args = {}
            remaining = (text[:start] + text[end:]).strip()
            return remaining, ToolCall(
                id=f"codex_{uuid.uuid4().hex[:16]}",
                name=call["name"],
                input=args,
            )
        return (text or "").strip(), None

    # ------------------------------------------------------------------- exec

    async def _run_exec(
        self, prompt: str, model: str, deadline: float, check: Callable[[], None],
    ) -> tuple[str, str]:
        """Run one ``codex exec`` turn; return (final text, stdout JSONL)."""
        await self._ensure_login(deadline, check)
        with tempfile.TemporaryDirectory(prefix="mav-codex-") as tmp:
            last_msg = Path(tmp) / "last-message.txt"
            cmd = self._launch_cmd(
                "exec",
                "--json",
                "--skip-git-repo-check",
                # Codex is only the model here; Lightwork runs the tools. Its
                # read-only sandbox still lets its own shell READ host files
                # (config, credentials), which an injected tool result could
                # ask it to echo back, so its shell and exec tools are off.
                "-c", "features.shell_tool=false",
                "-c", "features.unified_exec=false",
                "--sandbox", self.sandbox_mode,
                "--output-last-message", str(last_msg),
                "--model", model,
                "-",  # prompt on STDIN: no argv-size limit, not in `ps` output
            )
            try:
                proc = await run_owned(
                    cmd, input=prompt, deadline=deadline, check=check,
                    cwd=self.cwd or tmp,
                    env=self._subprocess_env(),
                )
            except FileNotFoundError as e:
                raise RuntimeError(
                    f"Codex CLI binary {self._binary_path!r} disappeared from PATH"
                ) from e
            except TimeoutError as e:
                raise CodexExecutionError(
                    f"codex exec timed out after {self.timeout_seconds:.0f}s "
                    "(raise [providers.codex_cli] timeout_seconds if the task "
                    "legitimately needs longer); usage is unknown"
                ) from e
            except ProcessOutputLimit as e:
                raise CodexExecutionError("codex exec exceeded output limits; usage is unknown") from e
            if proc.returncode != 0:
                raise CodexExecutionError(
                    f"codex exec failed (exit {proc.returncode}): "
                    f"{self._scrub(proc.stderr)[-800:]}"
                )
            file_text = ""
            try:
                with last_msg.open("rb") as stream:
                    content = stream.read(LAST_MESSAGE_BYTES + 1)
                if len(content) > LAST_MESSAGE_BYTES:
                    raise CodexExecutionError("codex final message exceeded its byte limit; usage is unknown")
                file_text = content.decode("utf-8", errors="replace").strip()
            except OSError:
                pass
            return file_text, proc.stdout or ""

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
    ) -> LLMResponse:
        del on_delta  # This provider has no delta stream.
        return run_sync(lambda: self.complete_async(
            system, messages, tools=tools, budget=budget, max_tokens=max_tokens,
            thinking_budget=thinking_budget, model=model,
        ))

    def _response(self, file_text, stdout, chosen_model, tools, budget) -> LLMResponse:
        # max_tokens / thinking_budget / on_delta accepted for Provider-protocol
        # parity; codex exec exposes no per-call output cap, no thinking knob,
        # and no delta stream. Budget's token caps still enforce at record time.
        event_text, usage = self._parse_events(stdout)
        text = file_text or event_text or ""
        if not text.strip():
            raise RuntimeError(
                "codex exec returned no agent message (empty --output-last-message "
                "and no agent_message event in --json output)"
            )
        if budget is not None:
            # Subscription usage prices $0 via the codex_cli: prefix, but the
            # record still drives token counters and the wall-clock cap.
            # Codex reports input_tokens INCLUSIVE of cached tokens; Budget
            # wants the billable remainder with the cached count split out.
            cached = min(usage["cached_input_tokens"], usage["input_tokens"])
            budget.record_tokens(
                usage["input_tokens"] - cached,
                usage["output_tokens"],
                model=PRICE_MODEL_PREFIX + chosen_model,
                cache_read_tok=cached,
            )
        text, tool_call = self._extract_tool_call(text) if tools else (text, None)
        return LLMResponse(
            text=text,
            thinking=None,
            tool_calls=[tool_call] if tool_call else [],
            stop_reason="tool_use" if tool_call else "end_turn",
            raw=None,  # JSONL events are not retained (nothing to price from)
        )

    async def complete_async(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        budget: Budget | None = None,
        max_tokens: int = 4096,
        thinking_budget: int | None = None,
        model: str | None = None,
    ) -> LLMResponse:
        from .. import killswitch

        def check() -> None:
            killswitch.check()
            if budget is not None:
                budget.check()

        check()
        deadline = time.monotonic() + self.timeout_seconds
        chosen_model = model or self.DEFAULT_MODEL
        prompt = self._compose_prompt(system, messages, tools)
        try:
            file_text, stdout = await self._run_exec(prompt, chosen_model, deadline, check)
        except BaseException as exc:
            # Keep cancellation, halt and Budget exceptions unchanged. An absent
            # final receipt cannot be presented as a zero-token completion.
            exc.usage_status = "unknown"
            raise
        return self._response(file_text, stdout, chosen_model, tools, budget)
