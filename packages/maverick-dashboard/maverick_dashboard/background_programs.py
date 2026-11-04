"""Background programs the dashboard runs while their setting is on.

Three helpers used to exist only as ``python -m`` commands an operator had to
start by hand, so their settings changed nothing:

* performance profiling (``[perf.profiling] enabled``, ``MAVERICK_PROFILING``):
  ``maverick.profiling_daemon`` samples this dashboard's process with py-spy;
* the kernel activity monitor (``[ebpf_monitor] enable``): ``maverick.ebpf_monitor
  run`` follows this dashboard's process tree with bpftrace (it needs root and
  bpftrace, and otherwise stops straight away and says why);
* the model proxy (``[model_proxy] enable``): ``maverick.model_proxy`` holds the
  AI service key outside the agent process. The key itself stays in the
  server's environment (``MAVERICK_PROXY_KEY``) by design: a key kept in the
  settings would be loaded into the very process the proxy protects it from.

This module decides which settings start which program. Running them belongs
to :mod:`maverick_dashboard.service_supervisor`, the dashboard's single
registry of child programs: fixed argument lists (never a shell), one instance
per kind, a bounded masked log, and one shutdown path. When the dashboard
starts, :func:`start_enabled` starts each program whose setting is on; the
Settings > Maintenance buttons can also start, stop or restart it while its
setting stays on.

The settings take effect at the next start of the dashboard, which is why
their rows on Settings > All settings are marked "after a restart".
"""
from __future__ import annotations

import os
from typing import Any

from . import service_supervisor

# kind -> (environment override, config table path, key). The environment wins.
_SETTINGS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "profiling": ("MAVERICK_PROFILING", ("perf", "profiling"), "enabled"),
    "ebpf_monitor": ("", ("ebpf_monitor",), "enable"),
    "model_proxy": ("", ("model_proxy",), "enable"),
}
KINDS: tuple[str, ...] = tuple(_SETTINGS)
_TRUE = {"1", "true", "yes", "on"}


def _setting(env: str, section: tuple[str, ...], key: str) -> bool:
    raw = os.environ.get(env, "").strip().lower() if env else ""
    if raw:
        return raw in _TRUE
    try:
        from maverick.config import load_config

        node: Any = load_config() or {}
        for part in section:
            node = node.get(part) if isinstance(node, dict) else None
        return isinstance(node, dict) and node.get(key) is True
    except Exception:  # an unreadable configuration never starts a program
        return False


def wanted(kind: str) -> bool:
    """Whether ``kind``'s setting asks for it to run (the environment wins)."""
    return _setting(*_SETTINGS[kind])


def command(kind: str) -> list[str]:
    """The fixed argument list for ``kind``: this interpreter running its module."""
    return service_supervisor.command(kind)


def start(kind: str) -> dict[str, Any]:
    """Start ``kind`` unless it is already running; returns its status."""
    return service_supervisor.start(kind, quiet=True)


def stop(kind: str, *, timeout: float = service_supervisor.STOP_GRACE_SECONDS) -> dict[str, Any]:
    """Stop ``kind`` politely, then forcibly after ``timeout`` seconds."""
    return service_supervisor.stop(kind, timeout=timeout, quiet=True)


def start_enabled() -> list[str]:
    """Start every program whose setting is on (dashboard start-up)."""
    started = []
    for kind in KINDS:
        if wanted(kind):
            start(kind)
            started.append(kind)
    return started


def stop_all(*, timeout: float = service_supervisor.STOP_GRACE_SECONDS, wait: bool = True) -> None:
    """Stop these programs only (the dashboard's shutdown stops every child)."""
    service_supervisor.stop_all(timeout=timeout, wait=wait, kinds=KINDS)


def alive() -> bool:
    return service_supervisor.alive(KINDS)


def status() -> list[dict[str, Any]]:
    """Every program's state, for the dashboard."""
    return service_supervisor.status(KINDS)


__all__ = ["KINDS", "alive", "command", "start", "start_enabled", "status", "stop",
           "stop_all", "wanted"]
