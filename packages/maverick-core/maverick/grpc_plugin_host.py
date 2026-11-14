"""gRPC plugin host: tools served by an external process over gRPC.

``ts_plugin_host`` hosts NDJSON-over-stdio plugins (the TypeScript SDK); this
module is the same seam for every other language â€” anything that can serve two
gRPC methods can ship Lightwork tools. The contract lives in
``grpc_api/plugin_host.proto``::

    service MaverickPlugin {
      rpc Describe(DescribeRequest) returns (Manifest);  // the tool manifest
      rpc Call(ToolCall) returns (ToolResult);           // one invocation
    }

``load_grpc_plugin(target)`` dials the plugin server (``localhost:50051`` or
``unix:///path.sock``), runs ``Describe`` and returns one
``maverick.tools.Tool`` per manifest entry; pass ``command`` to have the host
spawn the server process first. This is host-level plugin loading driven by
operator config â€” like the MCP stdio client (``mcp_client``), not model-driven
shell â€” so it spawns the child directly rather than through ``sandbox.exec``,
always with a scrubbed env (``scrub_child_env``) so provider keys and connector
tokens never reach plugin code, and kills it at interpreter exit. Failures
follow the built-in tool convention: the model sees an ``"ERROR: ..."`` string,
never an exception. Every ``Call`` carries a deadline (a gRPC deadline,
mirrored in ``deadline_ms``). A call is never retried: on a transport error
the channel is closed and the model gets an ERROR result (marked outcome
unknown when the request may have been dispatched); the next call rebuilds the
channel, respawning a spawned server that died. grpcio is imported lazily behind the
``[grpc]`` extra; importing this module never requires it.
"""
from __future__ import annotations

import atexit
import ipaddress
import json
import logging
import math
import queue
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .connector_attempts import ConnectorAttempt, ConnectorResult, current_invocation
from .mcp_tools import _collect_schema_strings, _try_shield
from .owned_process import OwnedProcess, ProcessCleanupError, ProcessOutputLimit
from .tools import Tool, scrub_child_env
from .ts_plugin_host import TsPluginError, _PinnedCommand

log = logging.getLogger(__name__)

DESCRIBE_TIMEOUT = 10.0
DEFAULT_CALL_TIMEOUT = 60.0

# Same constraint the model-facing tool catalog imposes (Anthropic tool names).
_TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_MAX_MANIFEST_FIELD_BYTES = 64_000

def _is_local_grpc_target(target: str) -> bool:
    """Return whether an insecure gRPC target is constrained to local IPC/loopback."""
    t = target.strip()
    if t.startswith("unix:"):
        return True
    # gRPC accepts URI-style targets such as ipv4:127.0.0.1:5000,
    # dns:///localhost:5000, and plain host:port strings.  This loader only
    # creates insecure channels, so keep it to loopback names/addresses.
    parsed = urlparse(t)
    host = parsed.hostname
    if host is None:
        if t.startswith(("ipv4:", "ipv6:")):
            host = t.split(":", 1)[1].rsplit(":", 1)[0].strip("[]")
        else:
            host = t.rsplit(":", 1)[0].strip("[]")
    if host == "localhost":
        return True
    # Match real loopback addresses (127.0.0.0/8, ::1), not string prefixes:
    # "127.0.0.1.attacker.com" startswith "127." but is NOT loopback and would
    # be dialed over an insecure channel.
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _spec_passes_shield(name: str, description: str, schema: dict[str, Any], shield) -> bool:
    if len(description.encode("utf-8")) > _MAX_MANIFEST_FIELD_BYTES:
        log.warning("grpc plugin tool %r rejected: description too large", name)
        return False
    schema_json = json.dumps(schema, sort_keys=True)
    if len(schema_json.encode("utf-8")) > _MAX_MANIFEST_FIELD_BYTES:
        log.warning("grpc plugin tool %r rejected: input schema too large", name)
        return False
    leaves: list[str] = []
    if not _collect_schema_strings(schema, leaves):
        log.warning("grpc plugin tool %r rejected: input schema exceeds scan depth", name)
        return False
    if shield is None:
        return True
    payload = "\n".join(
        [f"tool: {name}", f"description: {description}"]
        + [f"schema_text: {leaf}" for leaf in leaves]
    )
    try:
        verdict = shield.scan_input(payload)
        return bool(verdict.allowed)
    except Exception as e:
        # The plugin manifest is untrusted model-facing metadata. Once Shield
        # is present, an unavailable scanner cannot establish that the
        # description/schema is safe to register.
        log.warning(
            "grpc plugin tool %r shield scan errored; rejecting manifest: %s",
            name,
            e,
        )
        return False


_PROTO = Path(__file__).with_name("grpc_api") / "plugin_host.proto"


class GrpcPluginError(Exception):
    """The plugin server couldn't be spawned/reached or gave no manifest."""


def _require_grpc():
    try:
        import grpc
    except ImportError as e:
        raise ImportError(
            "grpc not installed (needed for gRPC plugins). "
            "Run: python -m pip install -e './packages/maverick-core[grpc]'"
        ) from e
    return grpc


def _load_stubs():
    """Import the generated pb2 modules, generating them first if absent.

    Same scheme as ``grpc_api.server._load_stubs``: stubs compile on demand
    from the bundled ``plugin_host.proto`` so no generated code is checked in.
    """
    try:
        from .grpc_api import plugin_host_pb2, plugin_host_pb2_grpc  # type: ignore
        return plugin_host_pb2, plugin_host_pb2_grpc
    except ImportError:
        from .grpc_stubs import guard_runtime_generation
        guard_runtime_generation("plugin_host.proto")
        _generate_stubs()
        from .grpc_api import plugin_host_pb2, plugin_host_pb2_grpc  # type: ignore
        return plugin_host_pb2, plugin_host_pb2_grpc


def _generate_stubs() -> None:
    """Compile plugin_host.proto into the grpc_api package via grpc_tools.

    Rooted at the directory *containing* ``maverick/`` (site-packages in an
    installed wheel) so protoc emits package-qualified imports
    (``from maverick.grpc_api import plugin_host_pb2 ...``) and the generated
    pair is importable from anywhere.
    """
    try:
        from grpc_tools import protoc
    except ImportError as e:
        raise ImportError(
            "grpcio-tools not installed (needed to generate stubs). "
            "Run: python -m pip install -e './packages/maverick-core[grpc]'"
        ) from e
    root = _PROTO.parents[2]
    rc = protoc.main([
        "protoc",
        f"-I{root}",
        f"--python_out={root}",
        f"--grpc_python_out={root}",
        str(_PROTO),
    ])
    if rc != 0:  # pragma: no cover -- only on a broken protoc toolchain
        raise RuntimeError(f"protoc failed to generate gRPC plugin stubs (rc={rc})")


class _PluginChannel:
    """One plugin-server connection shared by every tool of a plugin.

    Calls are serialized under a lock (reconnecting mutates the channel). The
    optional server process and the channel are built on first use. A call that
    fails closes the channel without retrying; the next call rebuilds it,
    respawning a spawned server that died.
    """

    def __init__(self, target: str, command: list[str] | None, call_timeout: float):
        self.target = target
        self.command = list(command) if command else None
        if not math.isfinite(call_timeout) or call_timeout <= 0:
            raise ValueError("gRPC call timeout must be finite and positive")
        self.call_timeout = call_timeout
        self._owner = None
        self._cleanup_failed = False
        self._pinned = _PinnedCommand.from_command(self.command) if self.command else None
        self._proc: subprocess.Popen | None = None
        self._channel: Any = None
        self._stub: Any = None
        self._lock = threading.Lock()

    def _connect(self):
        """(stub, pb2), spawning the server / dialing the channel as needed."""
        if self._cleanup_failed:
            self.close()
        grpc = _require_grpc()
        pb2, pb2_grpc = _load_stubs()
        if self.command and (self._proc is None or self._proc.poll() is not None):
            if self._owner is not None:
                self.close()
            self._pinned.verify()
            self._owner = OwnedProcess(self._pinned.command, env=scrub_child_env())
            self._proc = self._owner.proc
        if self._stub is None:
            self._channel = grpc.insecure_channel(self.target, options=(("grpc.max_receive_message_length", 1024 * 1024), ("grpc.max_send_message_length", 1024 * 1024)))
            self._stub = pb2_grpc.MaverickPluginStub(self._channel)
        return self._stub, pb2

    def _drop_channel(self) -> None:
        channel, self._channel, self._stub = self._channel, None, None
        if channel is not None:
            try:
                channel.close()
            except Exception:  # pragma: no cover -- close is best-effort
                pass

    def close(self) -> None:
        self._drop_channel()
        if self._owner is not None:
            try:
                self._owner.close()
            except ProcessCleanupError:
                self._cleanup_failed = True
                raise
            self._owner = None
            self._cleanup_failed = False
        self._proc = None

    def _drain(self, count):
        if self._owner is None:
            return count
        for output in (self._owner.stdout, self._owner.stderr):
            for _ in range(32):
                try:
                    chunk = output.get_nowait()
                except queue.Empty:
                    break
                count += len(chunk) if chunk else 0
                if count > 2 * 1024 * 1024:
                    raise ProcessOutputLimit("gRPC plugin process output exceeded 2 MiB")
        return count

    def _rpc(self, method, request, timeout, *, wait_for_ready):
        invocation = current_invocation()
        invocation.check()
        deadline = time.monotonic() + timeout
        future = method.future(request, timeout=timeout, wait_for_ready=wait_for_ready)
        count = 0
        try:
            while not future.done():
                invocation.check()
                count = self._drain(count)
                if time.monotonic() >= deadline:
                    raise TimeoutError("gRPC plugin call timed out")
                time.sleep(0.005)
            self._drain(count)
            return future.result()
        except BaseException:
            future.cancel()
            raise

    def describe(self) -> list[Any]:
        """The manifest's ToolSpecs. Raises GrpcPluginError (or ImportError)."""
        try:
            stub, pb2 = self._connect()
        except OSError as e:
            raise GrpcPluginError(f"grpc plugin {self.command} failed to run: {e}") from e
        try:
            # wait_for_ready: a just-spawned server needs a moment to bind.
            manifest = self._rpc(stub.Describe, pb2.DescribeRequest(), DESCRIBE_TIMEOUT, wait_for_ready=True)
        except Exception as e:
            raise GrpcPluginError(
                f"grpc plugin at {self.target}: Describe failed: {e}"
            ) from e
        return list(manifest.tools)

    def call(self, tool: str, args: dict[str, Any]) -> str:
        grpc = _require_grpc()
        invocation = current_invocation()
        rid = uuid.uuid4().hex
        deadline = time.monotonic() + self.call_timeout
        def result(text, *, dispatched, unknown, failed):
            return ConnectorResult(text, ConnectorAttempt(request_id=rid, attempt=1, operation="plugin",
                dispatch_may_have_happened=dispatched, outcome_unknown=unknown,
                error_class="plugin_failure" if failed else None))
        while not self._lock.acquire(blocking=False):
            invocation.check()
            if time.monotonic() >= deadline:
                return result("ERROR: gRPC plugin queue timed out; not dispatched", dispatched=False, unknown=False, failed=True)
            time.sleep(0.005)
        dispatched = False
        try:
            invocation.check()
            encoded = json.dumps(args, allow_nan=False)
            if len(encoded.encode()) > 1024 * 1024:
                raise ValueError("gRPC input exceeds 1 MiB")
            stub, pb2 = self._connect()
            if self._pinned is not None:
                self._pinned.verify()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("gRPC deadline expired before dispatch")
            request = pb2.ToolCall(tool=tool, args_json=encoded, deadline_ms=int(remaining * 1000))
            dispatched = True
            response = self._rpc(stub.Call, request, remaining, wait_for_ready=False)
            outcome = response.WhichOneof("outcome")
            if outcome not in {"result", "error"}:
                raise ValueError("gRPC plugin returned no terminal outcome")
            if outcome == "error":
                return result(f"ERROR: grpc plugin tool {tool!r}: {response.error}. Outcome unknown; reconcile before a new invocation.", dispatched=True, unknown=True, failed=True)
            return result(str(response.result), dispatched=True, unknown=False, failed=False)
        except (grpc.RpcError, OSError, TimeoutError, TypeError, ValueError, TsPluginError, ProcessCleanupError, ProcessOutputLimit) as exc:
            try:
                self.close()
            except ProcessCleanupError:
                log.error("gRPC plugin owned-process cleanup incomplete")
            code = getattr(exc, "code", None)
            timeout = isinstance(exc, TimeoutError) or (callable(code) and code() == grpc.StatusCode.DEADLINE_EXCEEDED)
            reason = "timed out" if timeout else "failed"
            state = "outcome unknown; reconcile before a new invocation" if dispatched else "not dispatched"
            return result(f"ERROR: grpc plugin tool {tool!r} {reason}; {state}", dispatched=dispatched, unknown=dispatched, failed=True)
        except BaseException:
            try:
                self.close()
            except Exception:
                log.error("gRPC plugin cleanup failed while propagating the original stop")
            raise
        finally:
            self._lock.release()


# Channels (and any spawned servers) live as long as the process (tools have
# no lifecycle hooks); close them at interpreter exit so none outlive the host.
_CHANNELS: list[_PluginChannel] = []


def _close_all_channels() -> None:
    for c in _CHANNELS:
        try:
            c.close()
        except ProcessCleanupError:
            log.error("gRPC plugin child cleanup incomplete")


atexit.register(_close_all_channels)


def load_grpc_plugin(
    target: str,
    *,
    command: list[str] | None = None,
    call_timeout: float = DEFAULT_CALL_TIMEOUT,
    strict_schema: bool = False,
    expected_source_sha256: str | None = None,
) -> list[Tool]:
    """Load a gRPC plugin; one Tool per manifest entry.

    ``target`` is the gRPC target to dial, e.g. ``localhost:50051`` or
    ``unix:///run/plugin.sock``. ``command`` is an optional operator-configured
    argv the host spawns first (the server side of ``target``), e.g.
    ``["/usr/local/bin/my-plugin", "--port", "50051"]``. Raises ImportError
    without the [grpc] extra and GrpcPluginError when the manifest can't be
    fetched; entries with an invalid name are skipped with a warning.
    """
    if not _is_local_grpc_target(target):
        raise GrpcPluginError(
            f"grpc plugin target {target!r} is not local; insecure gRPC plugins "
            "must use localhost/127.0.0.1/::1 or unix:// targets"
        )
    chan = _PluginChannel(target, command, call_timeout)
    if expected_source_sha256 is not None and (chan._pinned is None or not any(item.arg_index == 1 and item.digest == expected_source_sha256 for item in chan._pinned.files)):
        raise GrpcPluginError("gRPC server source changed before manifest discovery")
    try:
        specs = chan.describe()
        if strict_schema:
            from .sandbox.plugin_contracts import validator
            names = set()
            for spec in specs:
                if spec.name in names or not _TOOL_NAME_RE.fullmatch(spec.name):
                    raise GrpcPluginError("gRPC manifest has invalid or duplicate tool names")
                names.add(spec.name)
                validator(json.loads(spec.input_schema_json))
    except Exception:
        chan.close()  # never leak a spawned server on a failed load
        raise
    tools: list[Tool] = []
    shield = _try_shield()
    for spec in specs:
        name = str(spec.name or "")
        if not _TOOL_NAME_RE.fullmatch(name):
            log.warning("grpc plugin at %s: invalid tool name %r; skipping", target, name)
            continue
        try:
            schema = json.loads(spec.input_schema_json or "")
        except ValueError:
            schema = None
        if not isinstance(schema, dict):
            schema = {"type": "object"}

        description = str(spec.description or "")
        if not _spec_passes_shield(name, description, schema, shield):
            log.warning("grpc plugin tool %s from %s rejected by Shield", name, target)
            continue

        def fn(args: dict[str, Any], _name: str = name) -> str:
            return chan.call(_name, dict(args or {}))

        tools.append(Tool(
            name=name,
            description=description,
            input_schema=schema,
            fn=fn,
        ))
    if tools:
        _CHANNELS.append(chan)
    else:
        chan.close()
    return tools


def load_configured_grpc_plugins() -> list[Tool]:
    """Tools from ``[plugins] grpc = [{ target = "...", command = ["..."] }]``
    (or ``program = "/abs/server"`` with ``args = [...]``, as the dashboard
    writes it).

    Listing an entry there is the opt-in; ``command`` is optional (the host
    then spawns the server too). Forgiving like the entry-point loaders in
    ``plugins``: a broken entry â€” including a missing [grpc] extra â€” logs and
    is skipped. Returns the Tools for the integrator to register â€” this module
    never touches the registry itself.
    """
    try:
        from .config import load_config
        configured = load_config().get("plugins", {}).get("grpc", [])
    except Exception as e:
        log.warning(
            "grpc plugin config read failed (%s: %s); none loaded",
            type(e).__name__, e,
        )
        return []
    if not isinstance(configured, list):
        log.warning("[plugins] grpc must be a list of {target, command} tables; none loaded")
        return []
    out: list[Tool] = []
    for entry in configured:
        target = entry.get("target") if isinstance(entry, dict) else None
        command = entry.get("command") if isinstance(entry, dict) else None
        if isinstance(entry, dict) and command is None and entry.get("program"):
            # The dashboard's form: a program on the server plus its words.
            program, args = entry.get("program"), entry.get("args", [])
            command = [program, *args] if isinstance(program, str) \
                and isinstance(args, list) else [None]
        if not (isinstance(target, str) and target.strip()):
            log.warning("[plugins] grpc entry %r has no target; skipping", entry)
            continue
        if command is not None and not (
            isinstance(command, list) and command and all(isinstance(c, str) for c in command)
        ):
            log.warning(
                "[plugins] grpc entry %r command is not a list of strings; skipping", entry,
            )
            continue
        try:
            governed = (load_config().get("plugins") or {}).get("workbench", False) is True
            if governed:
                from .plugin_workbench_grpc import admit, pin_tools
                value = {"target": target.strip(), "command": command}
                fingerprint = admit(value)
                tools = load_grpc_plugin(target.strip(), command=command, expected_source_sha256=fingerprint)
                out.extend(pin_tools(value, tools))
            else:
                out.extend(load_grpc_plugin(target.strip(), command=command))
        except (GrpcPluginError, ImportError, ValueError, PermissionError, OSError, TsPluginError) as e:
            log.warning("grpc plugin %s failed to load: %s", target, e)
    return out
