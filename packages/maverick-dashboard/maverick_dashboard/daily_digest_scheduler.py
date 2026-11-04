"""Daemon thread that sends each person's daily summary at their own hour.

Off by default (``[my_work] digest_enable``). Every ``digest_poll_seconds``
it takes a short file lease (so two dashboard workers on one host never
send the same summary twice) and renews it before each recipient, asks
``maverick.daily_digest`` to send whatever is due, and backs off (doubling,
capped) after a failed cycle.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_scheduler_lock = threading.Lock()
_scheduler_stop: threading.Event | None = None
_scheduler_thread: threading.Thread | None = None
_LEASE_SECONDS = 120.0
_MAX_BACKOFF_SECONDS = 3600.0


def lease_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "daily-digest.lease"


def acquire_lease(holder: str, *, now: float | None = None,
                  ttl_seconds: float = _LEASE_SECONDS) -> bool:
    """Take (or renew) the send lease. False when another live holder has it."""
    from maverick.file_lock import (
        atomic_read_text,
        atomic_write_text,
        cross_process_lock,
        ensure_private_directory,
    )

    current = time.time() if now is None else float(now)
    path = lease_path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path):
        record: dict[str, Any] = {}
        if path.exists():
            try:
                loaded = json.loads(atomic_read_text(path))
                record = loaded if isinstance(loaded, dict) else {}
            except (OSError, ValueError):
                record = {}
        other = str(record.get("holder") or "")
        expires = float(record.get("expires_at") or 0)
        if other and other != holder and expires > current:
            return False
        atomic_write_text(path, json.dumps(
            {"holder": holder, "expires_at": current + ttl_seconds}))
        return True


def release_lease(holder: str) -> None:
    from maverick.file_lock import atomic_read_text, cross_process_lock

    path = lease_path()
    try:
        with cross_process_lock(path):
            if not path.exists():
                return
            record = json.loads(atomic_read_text(path))
            if isinstance(record, dict) and record.get("holder") == holder:
                path.unlink()
    except (OSError, ValueError):  # a stale lease simply expires
        log.debug("daily digest lease release skipped", exc_info=True)


def _recipients() -> list[str]:
    """Everyone with a role, a chat account or saved choices (deduplicated)."""
    from maverick import channel_identities, user_preferences

    from . import rbac

    names: set[str] = set()
    try:
        names.update(rbac.list_users().keys())
    except rbac.RbacStoreError:
        log.warning("daily digest: the user roster is unreadable; using linked accounts only")
    try:
        names.update(channel_identities.all_links().keys())
    except channel_identities.ChannelIdentityError:
        log.warning("daily digest: the chat account store is unreadable")
    names.update(user_preferences.principals_with_preferences())
    return sorted(n for n in names if n)


def _can_decide(principal: str) -> bool:
    from . import rbac
    from .auth import role_for_principal

    try:
        return "operate" in rbac.permissions_for(role_for_principal(principal))
    except Exception:  # noqa: BLE001 -- a broken roster shows the person only their own requests
        return False


def _suites(principal: str) -> frozenset[str] | None:
    """The departments whose approvals the person may decide; None is all."""
    from . import suite_grants
    from .auth import is_dashboard_admin

    try:
        return None if is_dashboard_admin(principal) else suite_grants.granted_suites(principal)
    except Exception:  # noqa: BLE001 -- an unreadable grant store shows no departmental approvals
        return frozenset()


def status_scope(principal: str) -> tuple[bool, frozenset[str] | None]:
    """``/lightwork status``: the same role and department rule as the summary."""
    return _can_decide(principal), _suites(principal)


def scheduler_cycle(holder: str, *, now: float | None = None,
                    clock=time.time) -> dict[str, Any] | None:
    """One pass: send every due summary. ``None`` when disabled or not leased.

    The lease is renewed before each recipient, so a slow cycle (channel
    timeouts) never outlives it while another worker's loop wakes; if a renewal
    finds another live holder, the rest of the cycle is left to that worker."""
    from maverick.config import config_source_errors, get_my_work
    from maverick.daily_digest import run_digest_cycle

    from ._shared import _world

    if config_source_errors(include_tenant=False):
        log.warning("daily digest scheduler skipped: config is unreadable")
        return None
    if not get_my_work().get("digest_enable"):
        return None
    if not acquire_lease(holder, now=clock() if now is None else now):
        return None
    world = _world()
    # Every named account, administrators included, gets only its own work:
    # the summary leaves Lightwork by chat or email, and /me lists the same.
    options = {"can_decide": _can_decide, "suites_for": _suites, "now": now}
    summary: dict[str, Any] | None = None
    for principal in _recipients():
        if summary is not None and not acquire_lease(holder, now=clock() if now is None else now):
            log.warning("daily digest: the send lease was lost mid-cycle; "
                        "the rest is left to its new holder")
            break
        part = run_digest_cycle(world, principals=[principal], **options)
        summary = part if summary is None else {
            key: summary.get(key, 0) + value if isinstance(value, int) else value
            for key, value in part.items()}
    return summary if summary is not None else run_digest_cycle(world, principals=[], **options)


def _scheduler_loop(stop: threading.Event, holder: str, poll_seconds: float) -> None:
    failures = 0
    while not stop.is_set():
        try:
            summary = scheduler_cycle(holder)
            failures = 0
            if summary and summary.get("sent"):
                log.info("daily digest: sent %s, skipped %s empty, %s unlinked, %s failed",
                         summary["sent"], summary["skipped_empty"],
                         summary["skipped_unlinked"], summary["failed"])
        except Exception as exc:  # failure-policy: visible_degradation
            failures += 1
            log.warning("daily digest scheduler failed safely: %s", type(exc).__name__)
        wait = min(_MAX_BACKOFF_SECONDS, poll_seconds * (2 ** min(failures, 6)))
        stop.wait(wait)
    release_lease(holder)


def start_daily_digest_scheduler() -> bool:
    """Start the off-by-default daily summary sender."""
    from maverick.config import config_source_errors, get_my_work

    if config_source_errors(include_tenant=False):
        return False
    section = get_my_work()
    if not section.get("digest_enable"):
        return False
    poll_seconds = float(section["digest_poll_seconds"])
    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return False
        stop = threading.Event()
        holder = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        worker = threading.Thread(
            target=_scheduler_loop, args=(stop, holder, poll_seconds),
            name="daily-digest-scheduler", daemon=True,
        )
        _scheduler_stop = stop
        _scheduler_thread = worker
        worker.start()
        return True


def stop_daily_digest_scheduler(*, timeout: float = 5.0, wait: bool = True) -> bool:
    """Signal first; retain a stopping worker until its exit is observed."""
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
    "acquire_lease",
    "release_lease",
    "scheduler_cycle",
    "start_daily_digest_scheduler",
    "stop_daily_digest_scheduler",
]
