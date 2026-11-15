"""Per-tenant "tasks at once" plan limit, shared by every process.

The global runner semaphore (:data:`maverick.runner.MAX_CONCURRENT_GOALS`)
bounds *total* in-flight goals in one process, but it is tenant-blind. This
module bounds how many goals one tenant runs at once, from the tenant's plan
(:func:`maverick.billing.entitlements_for` ``.max_concurrent_goals``).

A plan of N tasks at once is N numbered slots. A run holds one slot from
admission (:func:`maverick.runner.run_goal_in_thread`) until it finishes. A
slot is the same lease the task execution guard uses: an operating-system
file lock on a SQLite install, a PostgreSQL session advisory lock on a shared
database. So every process on the host, or every replica on the database,
counts against the same slots, and a process that dies gives its slot back
without anyone doing anything.

Fail-open (kernel rule 1): with no active tenant, or a plan whose
``max_concurrent_goals`` is 0 (unlimited), nothing is enforced. A tenant with
no roster entry, or an unknown plan name, resolves to the ``free`` plan, whose
default ceiling applies. An error resolving the limit admits the run; a slot
store that cannot be reached refuses it, so the limit is never skipped.
"""
from __future__ import annotations

import hashlib
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace

# A world without a shared database counts slots with host file locks.
_LOCAL = SimpleNamespace(path="local")
_BUSY = "This workspace is at its limit of tasks at once."


class TenantAtCapacity(Exception):
    """Every one of the tenant's plan slots is held by a running task."""


def _limit_for(tenant: str) -> int:
    """The tenant's concurrent-goal ceiling (0 = unlimited). Fail-open to 0."""
    try:
        from ..billing import _effective_plan, entitlements_for
        from .registry import get_tenant
        rec = get_tenant(tenant)
        # The served plan, so a lapsed payment drops to the base plan's ceiling.
        plan = _effective_plan(rec) if rec else "free"
        return max(0, int(entitlements_for(plan).max_concurrent_goals))
    except Exception:  # pragma: no cover -- never block a run on a lookup error
        return 0


def _identity(tenant: str, index: int) -> bytes:
    return hashlib.sha256(f"tenant-slot\0{tenant}\0{index}".encode()).digest()


@contextmanager
def slot(tenant: str | None, world=None):
    """Hold one of ``tenant``'s plan slots for the duration of the block.

    Raises :class:`TenantAtCapacity` when every slot is taken. ``world`` picks
    the slot store: a PostgreSQL world shares slots across replicas.
    """
    limit = _limit_for(tenant) if tenant is not None else 0
    if limit <= 0:
        yield
        return
    from ..task_execution_guard import TaskBusy, held

    store = world if getattr(world, "_dsn", None) else _LOCAL
    with ExitStack() as stack:
        for index in range(limit):
            try:
                stack.enter_context(held(store, _identity(tenant, index), "tenant-slot-", _BUSY, _BUSY))
                break
            except TaskBusy:
                continue
        else:
            raise TenantAtCapacity(_BUSY)
        yield


def has_room(tenant: str | None, world=None) -> bool:
    """Whether a run for ``tenant`` would be admitted now. Advisory only: the
    runner takes the slot itself, so a race here can only change the reply."""
    try:
        with slot(tenant, world):
            return True
    except TenantAtCapacity:
        return False
