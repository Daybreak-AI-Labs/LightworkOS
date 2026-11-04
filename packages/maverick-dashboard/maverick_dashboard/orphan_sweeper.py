"""Revisit recent goals missed by startup crash recovery.

The process-bound world, or a bounded rotating set of registered tenants on
shared PostgreSQL, is swept. A running goal heartbeats its ``updated_at``; a
dead process stops doing so. Pending goals are left to their dispatcher, and
unsafe zero/tiny reclaim windows disable periodic reclaim.
"""
from __future__ import annotations

import contextvars
import logging
import math
import threading
from bisect import bisect_right
from collections.abc import Callable

log = logging.getLogger(__name__)

_sweeper_lock = threading.Lock()
_sweeper_stop: threading.Event | None = None
_sweeper_thread: threading.Thread | None = None
_sweeper_window: float | None = None
_window_change_warned = False
_tenant_cursor_lock = threading.Lock()
_last_periodic_tenant: str | None = None
# A tenant whose reclaim failed first in a pass, before anything showed the
# backend was up; if it fails first again, the fault is that tenant's own.
_stalled_tenant: str | None = None

# Running goals may already be waiting up to 15 seconds for their next beat.
# Keep at least twice that margin even after a dashboard process restart.
MIN_WINDOW_SECONDS = 30.0
MAX_TENANTS_PER_SWEEP = 64
# Tenants one pass may skip as individually broken before it stops, so a pool
# that breaks mid-pass costs a few timeouts, not one per remaining tenant.
MAX_SKIPPED_PER_SWEEP = 3


def _registered_tenant_ids() -> tuple[str, ...]:
    """Use only the complete, validated non-retired control-plane roster.

    A corrupt/unreadable registry must never turn maintenance into an unbound
    shared-PostgreSQL write. Validate the whole snapshot before any tenant is
    visited, so a bad final record cannot leave a partial cross-tenant pass.
    """
    from maverick.paths import canonical_tenant_id
    from maverick.tenant.registry import list_tenants

    ids = tuple(sorted(record.id for record in list_tenants()))
    if any(not isinstance(tid, str) or canonical_tenant_id(tid) != tid for tid in ids):
        raise ValueError("tenant registry contains a noncanonical id")
    if len(ids) != len(set(ids)):
        raise ValueError("tenant registry contains duplicate ids")
    return ids


def _periodic_batch(ids: tuple[str, ...]) -> tuple[str, ...]:
    """Rotate a bounded batch through even a changing, large tenant roster."""
    if not ids:
        return ()
    with _tenant_cursor_lock:
        start = bisect_right(ids, _last_periodic_tenant) if _last_periodic_tenant else 0
        count = min(len(ids), MAX_TENANTS_PER_SWEEP)
        return tuple(ids[(start + offset) % len(ids)] for offset in range(count))


def _mark_tenant_scanned(tenant_id: str) -> None:
    global _last_periodic_tenant
    with _tenant_cursor_lock:
        _last_periodic_tenant = tenant_id


def _tenant_worked(tenant_id: str) -> None:
    global _stalled_tenant
    _mark_tenant_scanned(tenant_id)
    with _tenant_cursor_lock:
        _stalled_tenant = None


def _tenant_fault(tenant_id: str, backend_up: bool) -> bool:
    """Whether a failed tenant is skipped (its own fault) or stops the pass.

    A failure after another tenant worked in the same pass, or from the tenant
    that already failed first in the previous pass, is that tenant's own: it is
    marked scanned so later tenants are reached, and is retried when the
    rotation returns to it. A failure with no such evidence may be a broken
    database or pool, so the pass stops with the cursor unchanged and this
    tenant is retried first."""
    global _stalled_tenant
    with _tenant_cursor_lock:
        own = backend_up or tenant_id == _stalled_tenant
        _stalled_tenant = None if own else tenant_id
    if own:
        _mark_tenant_scanned(tenant_id)
    return own


def reclaim_registered_postgres(
    world_factory: Callable,
    *,
    resolved_window_seconds: float | None = None,
) -> int:
    """Reclaim only exact registered PostgreSQL tenants, never legacy NULL rows.

    Shared startup and repeated periodic passes use the same bounded rotating
    cursor, so a large roster does not delay readiness and all tenants are
    eventually visited. Both inspect active goals only.
    """
    from maverick.paths import tenant_scope
    from maverick.world_model import reclaim_window_seconds

    window = (reclaim_window_seconds() if resolved_window_seconds is None
              else float(resolved_window_seconds))
    if not math.isfinite(window) or window < MIN_WINDOW_SECONDS:
        log.warning("stopped-task reclaim skipped: unsafe PostgreSQL stale window")
        return 0

    try:
        ids = _registered_tenant_ids()
    except Exception:
        log.exception("stopped-task reclaim skipped: tenant registry unavailable")
        return 0
    selected = _periodic_batch(ids)
    if not selected:
        return 0
    # _world() opens/migrates the shared backend and can wait for a failed
    # connection. Open it once under the first exact tenant scope; do not make
    # one slow connection attempt for every registered customer.
    try:
        with tenant_scope(tenant=selected[0]):
            world = world_factory()
    except Exception:
        log.exception("stopped-task reclaim paused: shared PostgreSQL unavailable")
        return 0
    reclaimed = 0
    backend_up = False
    skipped = 0
    for tenant_id in selected:
        try:
            with tenant_scope(tenant=tenant_id):
                reclaimed += world.reclaim_orphan_goals(
                    statuses=("active",), exact_tenant=True,
                    resolved_window_seconds=window,
                )
        except Exception:
            # A failed transaction can be a broken database or pool, or one
            # tenant's own unreadable data. Stop instead of repeating a long
            # timeout for every tenant, unless the failure is provably this
            # tenant's (see _tenant_fault); either way it is retried next cycle.
            log.exception("stopped-task reclaim paused at tenant %r", tenant_id)
            skipped += 1
            if not _tenant_fault(tenant_id, backend_up) or skipped >= MAX_SKIPPED_PER_SWEEP:
                return reclaimed
            continue
        backend_up = True
        _tenant_worked(tenant_id)
    return reclaimed


def reclaim_registered_sqlite(
    world_factory: Callable,
    *,
    resolved_window_seconds: float | None = None,
) -> int:
    """Visit existing world files for registered UI workspaces in bounded batches.

    An unbound dashboard's background thread has no request tenant. Its default
    world is only one of the worlds used by chat, so sweeping that file alone
    leaves crashed workspace chats active forever. Do not create a missing
    tenant database merely to inspect it.
    """
    from maverick.paths import tenant_scope
    from maverick.workspace import Workspace
    from maverick.world_model import reclaim_window_seconds

    window = (reclaim_window_seconds() if resolved_window_seconds is None
              else float(resolved_window_seconds))
    if not math.isfinite(window) or window < MIN_WINDOW_SECONDS:
        return 0
    try:
        selected = _periodic_batch(_registered_tenant_ids())
    except Exception:
        log.exception("stopped-task reclaim skipped: tenant registry unavailable")
        return 0
    reclaimed = 0
    for tenant_id in selected:
        try:
            with tenant_scope(tenant=tenant_id):
                if Workspace(tenant_id).db_path.is_file():
                    reclaimed += world_factory().reclaim_orphan_goals(
                        statuses=("active",), resolved_window_seconds=window,
                    )
        except Exception:
            # A tenant-local SQLite failure must not starve every later tenant.
            log.exception("stopped-task reclaim failed for workspace %r", tenant_id)
        _mark_tenant_scanned(tenant_id)
    return reclaimed


def sweep_interval() -> float:
    """Wait half the configured stale window, bounded to 5–30 seconds."""
    from maverick.world_model import reclaim_window_seconds

    window = reclaim_window_seconds()
    if not math.isfinite(window) or window <= 0:
        return 30.0
    return min(30.0, max(5.0, window / 2.0))


def sweep_once() -> int:
    """Mark only stale active goals in the configured world or registered tenants."""
    global _window_change_warned
    from maverick.paths import current_tenant_id_strict
    from maverick.world_model import reclaim_window_seconds
    from maverick.world_model_backends import is_postgres_configured

    window = reclaim_window_seconds()
    if not math.isfinite(window) or window < MIN_WINDOW_SECONDS:
        return 0
    # Heartbeat intervals were chosen when each run started. A live setting
    # reduction cannot shorten an already sleeping heartbeat thread, so pause
    # recurring reclaim until a restart establishes one consistent window.
    if _sweeper_window is not None and window != _sweeper_window:
        if not _window_change_warned:
            log.warning("stopped-task sweep paused after reclaim window changed; restart required")
            _window_change_warned = True
        return 0
    postgres = is_postgres_configured()
    from ._shared import _world

    if postgres:
        if current_tenant_id_strict() is not None:
            reclaimed = _world().reclaim_orphan_goals(
                statuses=("active",), resolved_window_seconds=window,
                exact_tenant=True,
            )
        else:
            reclaimed = reclaim_registered_postgres(
                _world, resolved_window_seconds=window,
            )
    else:
        reclaimed = _world().reclaim_orphan_goals(
            statuses=("active",), resolved_window_seconds=window,
        )
        if current_tenant_id_strict() is None:
            reclaimed += reclaim_registered_sqlite(
                _world, resolved_window_seconds=window,
            )
    if reclaimed:
        log.warning("marked %d stopped task(s) as stuck", reclaimed)
    return reclaimed


def _loop(stop: threading.Event) -> None:
    while True:
        try:
            interval = sweep_interval()
        except Exception:
            log.warning("stopped-task sweep interval unavailable", exc_info=True)
            interval = 30.0
        if stop.wait(interval):
            return
        try:
            sweep_once()
        except Exception:
            log.warning("stopped-task sweep failed safely", exc_info=True)


def start_orphan_sweeper() -> bool:
    """Start one daemon thread; the lifespan supervisor owns its shutdown."""
    global _sweeper_stop, _sweeper_thread, _sweeper_window, _window_change_warned
    from maverick.world_model import reclaim_window_seconds

    with _sweeper_lock:
        if _sweeper_thread is not None and _sweeper_thread.is_alive():
            return False
        window = reclaim_window_seconds()
        stop = threading.Event()
        worker = threading.Thread(
            target=contextvars.copy_context().run, args=(_loop, stop),
            name="orphan-sweeper", daemon=True,
        )
        _sweeper_stop, _sweeper_thread = stop, worker
        _sweeper_window = window
        _window_change_warned = False
        try:
            worker.start()
        except RuntimeError:
            _sweeper_stop = _sweeper_thread = _sweeper_window = None
            raise
        return True


def stop_orphan_sweeper(*, timeout: float = 5.0, wait: bool = True) -> bool:
    """Signal first, then join within the supervisor's remaining deadline."""
    global _sweeper_stop, _sweeper_thread, _sweeper_window, _window_change_warned
    global _last_periodic_tenant, _stalled_tenant
    with _sweeper_lock:
        stop, worker = _sweeper_stop, _sweeper_thread
        if stop is not None:
            stop.set()
    if stop is None or worker is None:
        return True
    if not wait:
        return not worker.is_alive()
    worker.join(max(0.0, min(float(timeout), 30.0)))
    if worker.is_alive():
        return False
    with _sweeper_lock:
        if _sweeper_thread is worker:
            _sweeper_stop = None
            _sweeper_thread = None
            _sweeper_window = None
            _window_change_warned = False
            _last_periodic_tenant = None
            _stalled_tenant = None
    return True
