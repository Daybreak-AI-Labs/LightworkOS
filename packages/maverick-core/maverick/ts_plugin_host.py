"""TypeScript plugin host: tools served by an external process over NDJSON stdio.

Lightwork's native plugins are Python entry points (see ``plugins``). The
TypeScript plugin SDK (``sdks/plugin-ts``, npm ``@maverick/plugin-sdk``) lets an
author ship tools as a Node script instead; this module is the Python side of
that seam. The wire protocol is NDJSON, one JSON object per line:

  - ``<command> --describe`` prints a one-line manifest and exits::

        {"protocol": "maverick-plugin/2",
         "tools": [{"name": ..., "description": ..., "inputSchema": {...}}]}

  - otherwise the child reads requests on stdin and answers on stdout::

        {"id": 1, "tool": "echo", "args": {...}}
        -> {"id": 1, "result": "..."}  |  {"id": 1, "error": "..."}

The current SDK emits ``maverick-plugin/2``; ``maverick-plugin/1`` remains an
accepted legacy contract. These stdio versions are separate from the Python
plugin manifest's API major.

``load_ts_plugin(command)`` runs the describe step and returns one
``maverick.tools.Tool`` per manifest entry; calls share a single persistent
child, started lazily on first use. This is host-level plugin loading driven by
operator config -- like the MCP stdio client (``mcp_client``), not model-driven
shell -- so it spawns the child directly rather than through ``sandbox.exec``,
always with a scrubbed env (``scrub_child_env``) so provider keys and connector
tokens never reach plugin code. Failures follow the built-in tool convention:
the model sees an ``"ERROR: ..."`` string for operational failures. Control
exceptions propagate unchanged. A child that dies mid-call is never replayed;
its effects are unknown. A later independent invocation may start a fresh child.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import logging
import math
import os
import queue
import re
import shutil
import threading
import time
import uuid
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .connector_attempts import ConnectorAttempt, ConnectorResult, current_invocation
from .owned_process import (
    OwnedProcess,
    ProcessCleanupError,
    ProcessOutputLimit,
    run_owned,
    run_sync,
)
from .tools import Tool, scrub_child_env

log = logging.getLogger(__name__)

DESCRIBE_TIMEOUT = 10.0
DEFAULT_CALL_TIMEOUT = 60.0
MAX_FRAME_BYTES = 1024 * 1024
MAX_CALL_OUTPUT_BYTES = 2 * 1024 * 1024
PROTOCOL = "maverick-plugin/2"
LEGACY_PROTOCOL = "maverick-plugin/1"

# Same constraint the model-facing tool catalog imposes (Anthropic tool names).
_TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


class TsPluginError(Exception):
    """The plugin command couldn't be run or produced no usable manifest."""


class _ChildDied(Exception):
    """Child exited / closed its pipes mid-call; effects may have happened."""


@dataclass(frozen=True)
class _PinnedFile:
    arg_index: int
    path: Path
    digest: str


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class _PinnedCommand:
    command: list[str]
    files: tuple[_PinnedFile, ...]

    @classmethod
    def from_command(cls, command: list[str]) -> _PinnedCommand:
        if not command:
            raise TsPluginError("ts plugin command is empty")
        pinned = list(command)
        exe = shutil.which(command[0]) if os.sep not in command[0] else None
        if exe is not None:
            pinned[0] = exe
        files: list[_PinnedFile] = []
        for i, arg in enumerate(pinned):
            path = Path(arg).expanduser()
            try:
                resolved = path.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_file():
                continue
            files.append(_PinnedFile(i, resolved, _sha256_file(resolved)))
            pinned[i] = str(resolved)
        return cls(pinned, tuple(files))

    def verify(self) -> None:
        for f in self.files:
            try:
                resolved = Path(self.command[f.arg_index]).resolve(strict=True)
                digest = _sha256_file(resolved)
            except OSError as e:
                raise TsPluginError(
                    f"ts plugin command file {f.path} is no longer readable"
                ) from e
            if resolved != f.path or digest != f.digest:
                raise TsPluginError(
                    f"ts plugin command file {f.path} changed after manifest discovery"
                )


@dataclass
class _ChildLease:
    """Process custody without retaining its tool or invocation owner."""

    process: OwnedProcess | None = None

    def close(self) -> None:
        process, self.process = self.process, None
        if process is not None:
            process.close()


def _release_child(lease: _ChildLease) -> None:
    try:
        lease.close()
    except Exception:
        # No invocation remains to receive this failure. Keep cleanup visible;
        # never restart the process or repeat an earlier tool effect.
        log.error("released ts plugin child cleanup incomplete")


class _PluginChild:
    """One serialized invocation owner; restarting a process never replays work."""

    def __init__(self, command: _PinnedCommand, call_timeout: float, protocol: str):
        if not math.isfinite(call_timeout) or call_timeout <= 0:
            raise TsPluginError("ts plugin call_timeout must be finite and positive")
        self.command = command.command
        self.call_timeout = call_timeout
        self.protocol = protocol
        self._pinned_command = command
        self._lease = _ChildLease()
        # The finalizer must own only the lease. A bound method or this child
        # in its arguments would retain the tools and recreate the leak.
        self._finalizer = weakref.finalize(self, _release_child, self._lease)
        self._lock = threading.Lock()
        self._buffer = bytearray()

    def _ensure_started(self) -> OwnedProcess:
        if self._lease.process is not None and self._lease.process.proc.poll() is not None:
            self.close()
        if self._lease.process is None:
            self._pinned_command.verify()
            self._lease.process = OwnedProcess(self.command, env=scrub_child_env())
        return self._lease.process

    def close(self) -> None:
        self._buffer.clear()
        self._lease.close()

    def _response(self, child: OwnedProcess, rid: str, deadline: float, check) -> dict:
        received = len(self._buffer)
        while True:
            check()
            if time.monotonic() >= deadline:
                raise TimeoutError("ts plugin call timed out")
            for output in (child.stdout, child.stderr):
                for _ in range(16):
                    try:
                        chunk = output.get_nowait()
                    except queue.Empty:
                        break
                    if chunk is None:
                        if output is child.stdout:
                            raise _ChildDied
                        break
                    received += len(chunk)
                    if received > MAX_CALL_OUTPUT_BYTES:
                        raise ProcessOutputLimit("ts plugin output byte limit exceeded")
                    if output is child.stderr:
                        continue  # Never expose raw child diagnostics/secrets.
                    self._buffer.extend(chunk)
                    while b"\n" in self._buffer:
                        line, _, remaining = self._buffer.partition(b"\n")
                        self._buffer = bytearray(remaining)
                        if len(line) > MAX_FRAME_BYTES:
                            raise ProcessOutputLimit("ts plugin response frame too large")
                        try:
                            response = json.loads(line)
                        except (ValueError, UnicodeDecodeError):
                            continue  # Bounded legacy console output is tolerated.
                        if not isinstance(response, dict) or response.get("id") != rid:
                            continue
                        if self.protocol == PROTOCOL and (
                            response.get("attempt") != 1
                            or response.get("effect") not in {"not_started", "completed", "unknown"}
                        ):
                            raise TsPluginError("ts plugin response has invalid execution metadata")
                        if ("result" in response) == ("error" in response):
                            raise TsPluginError("ts plugin response must contain exactly one result or error")
                        return response
                    if len(self._buffer) > MAX_FRAME_BYTES:
                        raise ProcessOutputLimit("ts plugin response frame too large")
            if child.proc.poll() is not None:
                # The reader may still be draining its last bounded chunk.
                child.stop_tree()
            time.sleep(0.005)

    @staticmethod
    def _result(text: str, rid: str, *, dispatched: bool, unknown: bool, failed: bool) -> ConnectorResult:
        return ConnectorResult(text, ConnectorAttempt(
            request_id=rid, attempt=1, operation="plugin",
            dispatch_may_have_happened=dispatched, outcome_unknown=unknown,
            error_class="plugin_failure" if failed else None,
        ))

    def call(self, tool: str, args: dict[str, Any]) -> str:
        deadline = time.monotonic() + self.call_timeout
        invocation = current_invocation()
        rid = uuid.uuid4().hex
        # Include lock wait, executable verification, spawn and blocked writes
        # in the same deadline. Control failures remain original exceptions.
        while not self._lock.acquire(blocking=False):
            invocation.check()
            if time.monotonic() >= deadline:
                return self._result("ERROR: ts plugin queue timed out; not dispatched", rid,
                                    dispatched=False, unknown=False, failed=True)
            time.sleep(0.005)
        write = None
        try:
            invocation.check()
            request = {"id": rid, "tool": tool, "args": args}
            if self.protocol == PROTOCOL:
                request.update(protocol=PROTOCOL, attempt=1, replay="never",
                               deadline_unix_ms=int((time.time() + max(0, deadline - time.monotonic())) * 1000))
            payload = (json.dumps(request, ensure_ascii=True) + "\n").encode("utf-8")
            if len(payload) > MAX_FRAME_BYTES:
                raise TsPluginError("ts plugin request frame too large")
            child = self._ensure_started()
            if time.monotonic() >= deadline:
                raise TimeoutError("ts plugin call timed out before dispatch")
            write = child.write(payload, deadline=deadline)
            response = self._response(child, rid, deadline, invocation.check)
            effect = response.get("effect") if self.protocol == PROTOCOL else None
            failed = "error" in response or str(response.get("result", "")).startswith("ERROR:")
            if "error" in response:
                text = f"ERROR: ts plugin tool {tool!r}: {response['error']}"
            else:
                result = response["result"]
                text = result if isinstance(result, str) else json.dumps(result)
            unknown = effect == "unknown" or (failed and effect != "not_started")
            if unknown:
                if not text.startswith("ERROR:"):
                    text = "ERROR: ts plugin did not confirm completion. " + text
                text += "\nOutcome unknown; reconcile before any new invocation."
            return self._result(text, rid, dispatched=effect != "not_started", unknown=unknown, failed=failed)
        except (TsPluginError, OSError, TimeoutError, ProcessOutputLimit, _ChildDied,
                ProcessCleanupError) as exc:
            try:
                self.close()  # A late reply cannot be accepted for the next request.
            except ProcessCleanupError:
                # A descendant outlived cleanup. Report it as a tool error with
                # its dispatch state, never as an exception out of the tool.
                log.error("ts plugin child cleanup incomplete")
            # Join the writer before deciding "not dispatched": it may have
            # started concurrently with the failure on the reading side.
            dispatched = write is not None and write.started.is_set()
            if isinstance(exc, _ChildDied):
                reason = "child crashed or closed its output"
            elif isinstance(exc, TimeoutError):
                reason = "call timed out"
            elif isinstance(exc, ProcessCleanupError):
                reason = "previous child could not be cleaned up"
            elif isinstance(exc, (TsPluginError, ProcessOutputLimit)):
                reason = str(exc)
            else:
                reason = "child process transport failed"
            state = "outcome unknown; reconcile before any new invocation" if dispatched else "not dispatched"
            return self._result(f"ERROR: ts plugin {reason}; {state}", rid,
                                dispatched=dispatched, unknown=dispatched, failed=True)
        except BaseException:
            try:
                self.close()
            except Exception:
                log.error("ts plugin cleanup failed while propagating the original stop")
            raise
        finally:
            self._lock.release()


# Tool closures and active call frames retain their native child. Once the last
# tool/call is released, its lease reaps the owned process; this index must not
# keep discarded agent registries alive. Live children are also closed at exit.
_CHILDREN: weakref.WeakSet[_PluginChild] = weakref.WeakSet()
_CHILDREN_LOCK = threading.Lock()


def _close_all_children() -> None:
    with _CHILDREN_LOCK:
        children = tuple(_CHILDREN)
    for c in children:
        c.close()


atexit.register(_close_all_children)


def _fetch_manifest(command: _PinnedCommand) -> tuple[str, list[Any]]:
    command.verify()
    try:
        result = run_sync(lambda: run_owned(
            [*command.command, "--describe"], input="",
            deadline=time.monotonic() + DESCRIBE_TIMEOUT, env=scrub_child_env(),
            stdout_limit=MAX_FRAME_BYTES, stderr_limit=MAX_FRAME_BYTES,
        ))
    except (OSError, TimeoutError, ProcessOutputLimit) as exc:
        raise TsPluginError(f"ts plugin --describe failed: {type(exc).__name__}") from exc
    if result.returncode != 0:
        raise TsPluginError(f"ts plugin --describe exited {result.returncode}")
    for line in result.stdout.splitlines():
        try:
            manifest = json.loads(line)
        except ValueError:
            continue
        if isinstance(manifest, dict) and isinstance(manifest.get("tools"), list):
            protocol = manifest.get("protocol", LEGACY_PROTOCOL)
            if protocol not in {PROTOCOL, LEGACY_PROTOCOL}:
                raise TsPluginError("ts plugin manifest protocol is unsupported")
            return protocol, manifest["tools"]
    raise TsPluginError("ts plugin --describe printed no manifest")


def load_ts_plugin(
    command: list[str], *, call_timeout: float = DEFAULT_CALL_TIMEOUT,
    expected_source_sha256: str | None = None,
) -> list[Tool]:
    """Load an NDJSON plugin; one Tool per manifest entry.

    ``command`` is the operator-configured argv, e.g. ``["node", "/abs/plugin.js"]``.
    Raises TsPluginError when the manifest can't be fetched or parsed; entries
    with an invalid name are skipped with a warning.
    """
    pinned_command = _PinnedCommand.from_command(command)
    if expected_source_sha256 is not None and not any(item.arg_index == 1 and item.digest == expected_source_sha256 for item in pinned_command.files):
        raise TsPluginError("Node plugin source changed before manifest discovery")
    protocol, manifest = _fetch_manifest(pinned_command)
    pinned_command.verify()
    child = _PluginChild(pinned_command, call_timeout, protocol)
    tools: list[Tool] = []
    for entry in manifest:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not (isinstance(name, str) and _TOOL_NAME_RE.fullmatch(name)):
            log.warning("ts plugin %s: invalid tool name %r; skipping", command, name)
            continue
        schema = entry.get("inputSchema")
        if not isinstance(schema, dict):
            schema = {"type": "object"}

        def fn(args: dict[str, Any], _name: str = name) -> str:
            return child.call(_name, dict(args or {}))

        tools.append(Tool(
            name=name,
            description=str(entry.get("description") or ""),
            input_schema=schema,
            fn=fn,
        ))
    if tools:
        with _CHILDREN_LOCK:
            _CHILDREN.add(child)
    return tools


def _entry_command(entry: object) -> list[str] | None:
    """One ``[plugins] ts`` entry as an argv list, or None when malformed.

    An entry is an argv list (``["node", "/abs/plugin.js"]``) or the table the
    dashboard writes: ``{program = "/usr/bin/node", file = "/abs/plugin.js",
    args = ["--quiet"]}`` (``file`` and ``args`` optional)."""
    if isinstance(entry, dict):
        program, file, args = entry.get("program"), entry.get("file", ""), entry.get("args", [])
        if not (isinstance(program, str) and program.strip() and isinstance(file, str)
                and isinstance(args, list) and all(isinstance(a, str) for a in args)):
            return None
        return [program.strip(), *([file.strip()] if file.strip() else []), *args]
    if isinstance(entry, list) and entry and all(isinstance(c, str) for c in entry):
        return list(entry)
    return None


def load_configured_ts_plugins() -> list[Tool]:
    """Tools from ``[plugins] ts = [["node", "/abs/plugin.js"], ...]`` in config.

    Listing a command there is the opt-in (see :func:`_entry_command` for the
    table form the dashboard writes). Forgiving like the entry-point
    loaders in ``plugins``: a broken entry logs and is skipped. Returns the
    Tools for the integrator to register -- this module never touches the
    registry itself.
    """
    try:
        from .config import load_config
        configured = load_config().get("plugins", {}).get("ts", [])
    except Exception as e:
        log.warning(
            "ts plugin config read failed (%s: %s); none loaded",
            type(e).__name__, e,
        )
        return []
    if not isinstance(configured, list):
        log.warning("[plugins] ts must be a list of argv lists; none loaded")
        return []
    out: list[Tool] = []
    for entry in configured:
        cmd = _entry_command(entry)
        if cmd is None:
            log.warning("[plugins] ts entry %r is not a list of strings; skipping", entry)
            continue
        try:
            from .config import load_config
            governed = (load_config().get("plugins") or {}).get("workbench", False) is True
            if governed:
                from .plugin_workbench_ts import admit, pin_tools
                source_sha256 = admit(cmd)
                tools = load_ts_plugin(cmd, expected_source_sha256=source_sha256)
                tools = pin_tools(cmd, tools)
            else:
                tools = load_ts_plugin(cmd)
            out.extend(tools)
        except (TsPluginError, ValueError, PermissionError, OSError) as e:
            log.warning("ts plugin %s failed to load: %s", cmd, e)
    return out
