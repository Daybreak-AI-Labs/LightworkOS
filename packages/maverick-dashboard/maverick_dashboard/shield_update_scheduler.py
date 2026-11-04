"""Scheduled check for signed shared threat rules ([shield] federated_updates).

Every ``[shield] update_interval_hours`` (default 24, 1 to 168) the dashboard
fetches the bundle at ``[shield] update_url`` and stages it through
:func:`maverick.shield_updates.check_and_apply`, which refuses anything
unsigned, signed by another key, older than what is staged, or too large.
The shield adds the staged rules to its own checks on the next task
(:func:`maverick.shield_updates.load_verified_rules`).

Every check that changes or refuses something is written to the audit log
(``shield_rules_update``); a check that finds nothing new is not, so the log
stays readable. Nothing is fetched unless the switch, an address and a key
are all set. The thread reads the settings once a minute, so turning the
updates on, or changing the address, key or interval, applies without a
restart; it is stopped by the dashboard's shutdown supervisor.
"""
from __future__ import annotations

import logging
import math
import threading
import time

log = logging.getLogger(__name__)

_scheduler_lock = threading.Lock()
_scheduler_stop: threading.Event | None = None
_scheduler_thread: threading.Thread | None = None

DEFAULT_INTERVAL_HOURS = 24.0
MIN_INTERVAL_HOURS = 1.0
MAX_INTERVAL_HOURS = 168.0
ACTOR = "system:shield-updates"
POLL_SECONDS = 60.0


def interval_seconds() -> float:
    """``[shield] update_interval_hours`` in seconds, kept inside 1 to 168 hours."""
    try:
        from maverick.config import load_config

        raw = ((load_config() or {}).get("shield") or {}).get(
            "update_interval_hours", DEFAULT_INTERVAL_HOURS)
    except Exception:  # noqa: BLE001 -- an unreadable config keeps the default
        raw = DEFAULT_INTERVAL_HOURS
    try:
        hours = DEFAULT_INTERVAL_HOURS if isinstance(raw, bool) else float(raw)
    except (TypeError, ValueError):
        hours = DEFAULT_INTERVAL_HOURS
    if not math.isfinite(hours):
        hours = DEFAULT_INTERVAL_HOURS
    return min(max(hours, MIN_INTERVAL_HOURS), MAX_INTERVAL_HOURS) * 3600.0


def _configured() -> bool:
    from maverick.shield_updates import get_update_config

    cfg = get_update_config()
    return bool(cfg["federated_updates"] and cfg["update_url"] and cfg["update_pubkey"])


def check_once(*, fetcher=None) -> str:
    """One check: returns ``"applied"``, ``"unchanged"``, ``"refused"`` or
    ``"off"``. Changes and refusals are audited."""
    from maverick.audit import EventKind, audit_event
    from maverick.shield_updates import UpdateRefused, check_and_apply

    if not _configured():
        return "off"
    try:
        result = check_and_apply(fetcher=fetcher)
    except UpdateRefused as exc:
        audit_event(EventKind.SHIELD_RULES_UPDATE, agent="dashboard", _global=True,
                    actor=ACTOR, outcome="refused", reason=str(exc)[:300])
        log.warning("shared threat rules update refused: %s", exc)
        return "refused"
    if not result.applied:
        return "unchanged"
    audit_event(EventKind.SHIELD_RULES_UPDATE, agent="dashboard", _global=True,
                actor=ACTOR, outcome="applied", version=result.version,
                previous_version=result.previous_version,
                added=result.added[:100], removed=result.removed[:100])
    return "applied"


def _cycle() -> None:
    """Check in the shared workspace and every active one: staged rules live
    in each workspace's own data folder."""
    from .automation_queue import _run_for_active_tenants

    _run_for_active_tenants("shared threat rules check", check_once)


def _signature() -> tuple:
    from maverick.shield_updates import get_update_config

    cfg = get_update_config()
    return (cfg["federated_updates"], cfg["update_url"], cfg["update_pubkey"],
            interval_seconds())


def _loop(stop: threading.Event, clock=time.monotonic) -> None:
    last_run: float | None = None
    last_signature: tuple | None = None
    while not stop.is_set():
        try:
            signature = _signature()
            now = clock()
            # Nothing is fetched anywhere unless the shared settings turn it on.
            due = signature[0] and (last_run is None or signature != last_signature
                                    or now - last_run >= signature[-1])
            if due:
                last_run, last_signature = now, signature
                _cycle()
        except Exception as exc:  # failure-policy: visible_degradation
            log.warning("shared threat rules check failed safely: %s", type(exc).__name__)
        stop.wait(POLL_SECONDS)


def start_shield_update_scheduler() -> bool:
    """Start the settings watcher. False when it is already running."""
    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return False
        stop = threading.Event()
        worker = threading.Thread(target=_loop, args=(stop,),
                                  name="shield-rules-updates", daemon=True)
        _scheduler_stop = stop
        _scheduler_thread = worker
        worker.start()
        return True


def stop_shield_update_scheduler(*, timeout: float = 5.0, wait: bool = True) -> bool:
    """Signal first; keep a stopping worker until its exit is seen."""
    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        stop = _scheduler_stop
        worker = _scheduler_thread
        if stop is not None:
            stop.set()
    if stop is None or worker is None:
        return False
    if not wait:
        return not worker.is_alive()
    worker.join(max(0.0, min(float(timeout), 30.0)))
    if worker.is_alive():
        return False
    with _scheduler_lock:
        if _scheduler_thread is worker:
            _scheduler_stop = None
            _scheduler_thread = None
    return True


__all__ = [
    "check_once",
    "interval_seconds",
    "start_shield_update_scheduler",
    "stop_shield_update_scheduler",
]
