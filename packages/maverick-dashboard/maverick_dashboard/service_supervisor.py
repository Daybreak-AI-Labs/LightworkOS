"""Every child program this dashboard runs: one registry, one rule, one shutdown.

Two sets of programs run as children the dashboard owns:

* Lightwork's services, started and stopped from Settings > Maintenance: the
  background worker (``maverick worker``), the chat channel server
  (``maverick serve``) and the tool server for outside apps (``maverick mcp``,
  over local HTTP). They are ordinarily started by the desktop app or the
  server's own service manager, and neither exposes a start/stop protocol to
  the dashboard.
* Background programs that follow a setting on Settings > All settings
  (:mod:`maverick_dashboard.background_programs` decides which settings start
  which): performance profiling, the kernel activity monitor and the model
  proxy. They start with the dashboard when their setting is on, and the
  Maintenance buttons can also start, stop or restart them while it is.

For all of them:

* :data:`KINDS` is the single registry of what may run;
* a program starts from a fixed argument list (never a shell) through
  :class:`maverick.owned_process.OwnedProcess`, which contains its whole
  process tree; a frozen release build, which has no separate Python to run a
  program module with, refuses those plainly;
* one instance per kind;
* while the model proxy is on, only the proxy is given the key of the AI
  service it forwards to;
* output is drained into a small bounded log (secrets masked) so a stopped
  program can say why;
* it is stopped politely, then forcibly, on request and when the dashboard
  shuts down (one shutdown-supervisor component, plus an exit hook).

A program started some other way is not visible here and is never touched.
"""
from __future__ import annotations

import atexit
import collections
import os
import queue
import secrets
import signal
import sys
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

MCP_PORT = 8771
KINDS: dict[str, dict[str, Any]] = {
    "worker": {"label": "Background worker", "args": ("worker",),
               "about": "Runs scheduled and queued tasks."},
    "channels": {"label": "Chat channel server", "args": ("serve",),
                 "about": "Receives and answers messages from your connected chat apps."},
    "tools": {"label": "Tool server for outside apps",
              "args": ("mcp", "--http", "--host", "127.0.0.1", "--port", str(MCP_PORT)),
              "about": "Lets outside apps on this computer use Lightwork's tools."},
    # Programs a setting turns on (see background_programs): a program module
    # run with this interpreter; ``{pid}`` is this dashboard's process id.
    "profiling": {"label": "Performance profiling", "module": "maverick.profiling_daemon",
                  "args": ("--pid", "{pid}"), "setting": "perf.profiling.enabled",
                  "about": "Records where this app spends its time, to find slow spots."},
    "ebpf_monitor": {"label": "Kernel activity monitor", "module": "maverick.ebpf_monitor",
                     "args": ("run", "--pid", "{pid}"), "setting": "ebpf_monitor.enable",
                     "about": "Follows every program Lightwork starts and warns about risky system requests."},
    "model_proxy": {"label": "Model proxy", "module": "maverick.model_proxy", "args": (),
                    "setting": "model_proxy.enable",
                    "about": "Holds the AI service key in a separate program, so agents never see it."},
}
# Tags the chat service's held chat replies statuses (see _drain); the same
# name as maverick_channels.hold_status.OWNER_ENV.
HOLDS_OWNER_ENV = "MAVERICK_CHANNEL_HOLDS_OWNER"
LOG_LINES = 200
LOG_LINE_CHARS = 400
STOP_GRACE_SECONDS = 10.0
FROZEN_REFUSAL = ("This installation can't start it: it has no separate Python to run the program with.")

_LOCK = threading.Lock()
_threads: list[threading.Thread] = []


@dataclass
class Service:
    kind: str
    process: Any = None
    started_at: float | None = None
    stopped_at: float | None = None
    exit_code: int | None = None
    last_error: str = ""
    stopping: bool = False
    log: collections.deque = field(default_factory=lambda: collections.deque(maxlen=LOG_LINES))


_SERVICES: dict[str, Service] = {kind: Service(kind) for kind in KINDS}


class ServiceError(RuntimeError):
    """A plain sentence the page shows."""


def setting_driven(kind: str) -> bool:
    return bool(KINDS[kind].get("setting"))


def wanted(kind: str) -> bool | None:
    """Whether a setting-driven program's setting is on (None for services)."""
    if not setting_driven(kind):
        return None
    from .background_programs import wanted as setting_on
    return setting_on(kind)


def command(kind: str) -> list[str]:
    """The fixed argument list for ``kind``.

    Services run the ``maverick`` command with the same interpreter (or the
    frozen release binary) as this dashboard; setting-driven programs run
    their module with this interpreter, which a frozen build does not have.
    """
    spec = KINDS[kind]
    if spec.get("module"):
        if getattr(sys, "frozen", False):
            raise ServiceError(FROZEN_REFUSAL)
        args = [str(a).format(pid=os.getpid()) for a in spec["args"]]
        return [sys.executable, "-m", spec["module"], *args]
    base = [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, "-m", "maverick.cli"]
    return [*base, *spec["args"]]


def _scrub(text: str) -> str:
    try:
        from maverick.safety.secret_detector import redact
        text, _ = redact(text)
    except Exception:  # noqa: BLE001 -- masking is best effort; lines stay bounded
        pass
    return text[:LOG_LINE_CHARS]


def _proxied_credentials() -> tuple[str, ...]:
    """The environment credentials of the AI service the model proxy forwards to.

    The upstream is read exactly as the proxy reads it
    (:func:`maverick.model_proxy.config_from_env`) and matched to a provider by
    its public API host. Fail safe: when the upstream is missing, unreadable or
    not a known provider host (a self-hosted or private endpoint), every
    provider credential is treated as proxied and removed."""
    from urllib.parse import urlparse

    from maverick.config import PROVIDER_CREDENTIAL_ENV_MAP, PROVIDER_CREDENTIAL_ENV_VARS
    try:
        from maverick.model_discovery import LIST_ENDPOINTS
        from maverick.model_proxy import config_from_env
        cfg = config_from_env()
        host = (urlparse(cfg.upstream).hostname or "").lower() if cfg else ""
        providers = [name for name, (url, _style) in LIST_ENDPOINTS.items()
                     if host and urlparse(url).hostname == host]
    except Exception:  # noqa: BLE001 -- an unreadable upstream removes every key (fail safe)
        providers = []
    if not providers:
        return PROVIDER_CREDENTIAL_ENV_VARS
    return tuple(name for provider in providers for name in PROVIDER_CREDENTIAL_ENV_MAP.get(provider, ()))


def _child_env(kind: str) -> dict[str, str]:
    """This dashboard's environment for ``kind``. While the model proxy is on,
    only the proxy keeps the key of the AI service it forwards to; every other
    program reaches that service through it. Keys for other AI services stay."""
    env = dict(os.environ)
    if kind != "model_proxy" and wanted("model_proxy"):
        for name in (*_proxied_credentials(), "MAVERICK_PROXY_KEY"):
            env.pop(name, None)
    return env


def _spawn(kind: str, extra_env: dict[str, str] | None = None):
    from maverick.owned_process import OwnedProcess
    return OwnedProcess(command(kind), env={**_child_env(kind), **(extra_env or {})})


def _take_lines(service: Service, pending: bytes, chunk: bytes) -> bytes:
    *lines, pending = (pending + chunk).split(b"\n")
    if len(pending) > LOG_LINE_CHARS * 4:  # a very long line without an end
        lines.append(pending)
        pending = b""
    with _LOCK:
        for line in lines:
            line = line.removesuffix(b"\r")
            if line.strip():
                service.log.append(_scrub(line.decode("utf-8", errors="replace")))
    return pending


def _drain(service: Service, process: Any, holds_owner: str = "") -> None:
    """Keep the child's bounded pipes flowing into the bounded log, and notice
    when it exits."""
    pending = {"stdout": b"", "stderr": b""}
    open_streams = {"stdout", "stderr"}
    while open_streams or process.proc.poll() is None:
        idle = True
        for name in tuple(open_streams):
            try:
                chunk = getattr(process, name).get(timeout=0.05)
            except queue.Empty:
                continue
            idle = False
            if chunk is None:
                open_streams.discard(name)
                chunk = b"\n"
            pending[name] = _take_lines(service, pending[name], chunk)
        if idle and not open_streams:
            time.sleep(0.05)
    code = process.proc.returncode
    ended, released = time.time(), False
    with _LOCK:
        if service.process is process:
            released = True  # not replaced by one started meanwhile
            service.exit_code = code
            service.stopped_at = time.time()
            if not service.stopping and code not in (0, None):
                tail = [line for line in list(service.log)[-3:] if line]
                service.last_error = (f"Stopped unexpectedly (exit code {code})."
                                      + (" Last message: " + tail[-1] if tail else ""))
            service.process = None
            service.stopping = False
    try:
        process.close()
    except Exception:  # noqa: BLE001 -- the tree is already gone; cleanup is best effort
        pass
    if released and holds_owner:
        _clear_held_reply_statuses(ended, holds_owner)


def _clear_held_reply_statuses(ended: float, owner: str) -> None:
    """The chat service started with ``owner`` has ended: remove the held
    chat replies statuses it saved, which it cannot remove itself when it is
    stopped without a signal it can handle (every stop on Windows)."""
    try:
        from maverick_channels import hold_status
    except ImportError:
        return
    hold_status.clear_saved_before(ended, owner=owner)


def _running(service: Service) -> bool:
    return service.process is not None and service.process.proc.poll() is None


def _settings_href(kind: str) -> str:
    setting = KINDS[kind].get("setting")
    if not setting:
        return ""
    try:
        from . import settings_catalog
        from .settings_all_page import _slug
        return "/settings/all#group-" + _slug(settings_catalog.BY_ID[setting].group)
    except Exception:  # noqa: BLE001 -- the page falls back to All settings
        return "/settings/all"


def _row(kind: str) -> dict[str, Any]:
    meta, service = KINDS[kind], _SERVICES[kind]
    running = _running(service)
    return {
        "kind": kind, "label": meta["label"], "about": meta["about"], "running": running,
        "since": service.started_at if running else service.stopped_at,
        "started_at": service.started_at, "stopped_at": service.stopped_at, "exit_code": service.exit_code,
        "last_error": service.last_error, "log": list(service.log)[-40:],
        "setting_driven": setting_driven(kind), "settings_href": _settings_href(kind),
    }


def status(kinds: Iterable[str] | None = None) -> list[dict[str, Any]]:
    selected = list(KINDS) if kinds is None else list(kinds)
    with _LOCK:
        rows = [_row(kind) for kind in selected]
    for row in rows:  # the setting read happens outside the lock
        row["wanted"] = wanted(row["kind"])
    return rows


def _one(kind: str) -> dict[str, Any]:
    return status([kind])[0]


def start(kind: str, *, quiet: bool = False) -> dict[str, Any]:
    """Start ``kind``; one instance per kind.

    From the Maintenance page (``quiet=False``) a running program, a program
    whose setting is off, or a frozen build's refusal is a :class:`ServiceError`.
    The settings-driven start (``quiet=True``) leaves a running program alone
    and records a refusal in its status instead of raising."""
    if kind not in KINDS:
        raise ServiceError("Choose a service from the list.")
    label = KINDS[kind]["label"]
    if not quiet and setting_driven(kind) and not wanted(kind):
        raise ServiceError(f"{label} is turned off in All settings. Turn it on there first.")
    refusal: ServiceError | None = None
    with _LOCK:
        service = _SERVICES[kind]
        if _running(service):
            if not quiet:
                raise ServiceError(f"{label} is already running.")
            thread = None
        else:
            thread, refusal = _launch(kind, service, label)
    if refusal is not None and not quiet:
        raise refusal
    if thread is not None:
        thread.start()
    return _one(kind)


def _launch(kind: str, service: Service, label: str) -> tuple[threading.Thread | None, ServiceError | None]:
    """Spawn ``kind`` (caller holds the lock); a refusal is recorded in its status."""
    holds_owner = secrets.token_hex(8) if kind == "channels" else ""
    try:
        process = _spawn(kind, {HOLDS_OWNER_ENV: holds_owner} if holds_owner else None)
    except ServiceError as exc:
        service.last_error = str(exc)
        return None, exc
    except OSError:
        service.last_error = "Could not start: the program could not be launched."
        return None, ServiceError(f"{label} could not be started on this computer.")
    service.process = process
    service.started_at = time.time()
    service.stopped_at = None
    service.exit_code = None
    service.last_error = ""
    service.stopping = False
    service.log.clear()
    thread = threading.Thread(target=_drain, args=(service, process, holds_owner), name=f"lightwork-service-{kind}",
                              daemon=True)
    _threads[:] = [t for t in _threads if t.is_alive()]
    _threads.append(thread)
    return thread, None


def _signal_stop(service: Service) -> Any:
    process = service.process
    if process is None or process.proc.poll() is not None:
        return None
    service.stopping = True
    try:
        if os.name == "nt":
            process.proc.terminate()
        else:
            os.killpg(process.proc.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass
    return process


def _finish_stop(process: Any, timeout: float) -> None:
    deadline = time.monotonic() + max(0.0, timeout)
    while process.proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if process.proc.poll() is None:
        process.stop_tree()


def _wait_released(kind: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _LOCK:
            if _SERVICES[kind].process is None:
                return
        time.sleep(0.02)


def stop(kind: str, *, timeout: float = STOP_GRACE_SECONDS, quiet: bool = False) -> dict[str, Any]:
    if kind not in KINDS:
        raise ServiceError("Choose a service from the list.")
    with _LOCK:
        process = _signal_stop(_SERVICES[kind])
    if process is None:
        if quiet:
            return _one(kind)
        raise ServiceError(f"{KINDS[kind]['label']} is not running from this app.")
    _finish_stop(process, timeout)
    _wait_released(kind)
    return _one(kind)


def restart(kind: str) -> dict[str, Any]:
    if kind not in KINDS:
        raise ServiceError("Choose a service from the list.")
    if setting_driven(kind) and not wanted(kind):
        raise ServiceError(f"{KINDS[kind]['label']} is turned off in All settings. Turn it on there first.")
    with _LOCK:
        process = _signal_stop(_SERVICES[kind])
    if process is not None:
        _finish_stop(process, STOP_GRACE_SECONDS)
        _wait_released(kind)
    return start(kind)


def alive(kinds: Iterable[str] | None = None) -> bool:
    selected = list(KINDS) if kinds is None else list(kinds)
    with _LOCK:
        return any(_running(_SERVICES[kind]) for kind in selected)


def stop_all(*, timeout: float = STOP_GRACE_SECONDS, wait: bool = True,
             kinds: Iterable[str] | None = None) -> None:
    """Dashboard shutdown: signal every owned program; with ``wait`` also end them."""
    selected = list(KINDS) if kinds is None else list(kinds)
    with _LOCK:
        processes = [p for p in (_signal_stop(_SERVICES[k]) for k in selected) if p is not None]
        if not processes and wait:
            processes = [_SERVICES[k].process for k in selected if _SERVICES[k].process is not None]
    if wait:
        deadline = time.monotonic() + max(0.0, timeout)
        for process in processes:
            _finish_stop(process, max(0.0, deadline - time.monotonic()))


atexit.register(lambda: stop_all(timeout=2.0))

__all__ = ["KINDS", "MCP_PORT", "FROZEN_REFUSAL", "ServiceError", "command", "setting_driven", "wanted",
           "status", "start", "stop", "restart", "alive", "stop_all"]
