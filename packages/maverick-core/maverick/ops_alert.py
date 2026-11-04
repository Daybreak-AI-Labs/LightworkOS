"""Operational alerts — page an operator on INFRASTRUCTURE events (killswitch
trip, budget exhaustion, audit-chain break, ...), distinct from the agent-task
deliverable notifications.

Every existing notification/webhook seam is wired to agent-task lifecycle
events; nothing paged an SRE when the killswitch tripped or a budget cap blew.
This is that seam: a single :func:`alert` entry point that, when enabled, routes
an operational event through the operator's existing notification transport
(:func:`maverick.notifications.notify`) at high priority.

**Off by default** (outward-facing). Enable with ``[alerts] enabled = true`` /
``MAVERICK_ALERTS=1``. When disabled — or if delivery fails — :func:`alert` is a
strict, non-raising no-op so it can be called from anywhere (including the
killswitch and the budget guard) without ever blocking the path it observes.
"""
from __future__ import annotations

import logging
import os

from ._envparse import coerce_bool, is_truthy

log = logging.getLogger(__name__)

# Map a severity to the notification priority understood by notifications.notify.
_PRIORITY = {"critical": "max", "high": "high", "warning": "default", "info": "low"}


def alerts_enabled() -> bool:
    """Operational alerting is opt-in. ``MAVERICK_ALERTS`` env wins over
    ``[alerts] enabled``; off by default."""
    env = os.environ.get("MAVERICK_ALERTS")
    if env is not None and env.strip() != "":
        return is_truthy(env)
    try:
        from .config import load_config
        return coerce_bool(((load_config() or {}).get("alerts") or {}).get("enabled"))
    except Exception:  # pragma: no cover - config never blocks an alert path
        return False


def alert(event: str, detail: str = "", *, severity: str = "high") -> bool:
    """Page the operator about an operational ``event``. Returns True if an
    alert was dispatched. No-op (False) when alerting is disabled; never raises
    — the caller is always on a hot/critical path it must not break."""
    if not alerts_enabled():
        return False
    try:
        from .notifications import notify
        notify(
            detail or event,
            title=f"Lightwork ALERT: {event}",
            priority=_PRIORITY.get(severity, "high"),
            category="ops_alert",
        )
        return True
    except Exception as e:  # pragma: no cover - alerting must never crash a path
        log.warning("ops alert delivery failed for %r: %s", event, e)
        return False


__all__ = ["alert", "alerts_enabled"]
