"""Per-tenant concurrency ceiling -- noisy-neighbor protection.

The global runner semaphore (:data:`maverick.runner.MAX_CONCURRENT_GOALS`)
bounds *total* in-flight goals, but it is tenant-blind: one tenant can fill
every slot and starve all the others for the duration of their runs. This
module adds a per-tenant ceiling derived from the tenant's provisioned plan
(:func:`maverick.billing.entitlements_for` ``.max_concurrent_goals``), so a
single noisy tenant cannot monopolise a shared instance.

Fail-open (kernel rule 1): with no active tenant, or a plan whose
``max_concurrent_goals`` is 0 (unlimited), nothing is enforced. A tenant with
no roster entry, or an unknown plan name, resolves to the ``free`` plan, whose
default ceiling applies.
Any error resolving the limit leaves the slot granted -- this gate can only
refuse a *tenant already at its own ceiling*, never become a new way to down
the channel server.
"""
from __future__ import annotations

import threading

_lock = threading.Lock()
# tenant id -> number of goals currently in flight for that tenant.
_inflight: dict[str, int] = {}
# tenant id -> slots granted without counting (unlimited plan or lookup error
# at acquire time). Their release must not decrement ``_inflight``, or a plan
# change mid-run would free a counted slot early and admit one goal too many.
_uncounted: dict[str, int] = {}


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


def acquire(tenant: str | None) -> bool:
    """Atomically reserve a concurrency slot for ``tenant``.

    Returns True when the slot is granted (always so for ``tenant is None`` or
    an unlimited plan) and False when the tenant is already at its ceiling. On
    a grant the caller MUST pair this with :func:`release` in a ``finally``.
    """
    if tenant is None:
        return True
    limit = _limit_for(tenant)
    if limit <= 0:
        with _lock:
            _uncounted[tenant] = _uncounted.get(tenant, 0) + 1
        return True
    with _lock:
        current = _inflight.get(tenant, 0)
        if current >= limit:
            return False
        _inflight[tenant] = current + 1
    return True


def release(tenant: str | None) -> None:
    """Release a slot previously granted by :func:`acquire`. Idempotent-safe."""
    if tenant is None:
        return
    with _lock:
        # Release uncounted grants first: keeping a counted slot occupied a
        # little longer can only refuse, never over-admit.
        uncounted = _uncounted.get(tenant, 0)
        if uncounted > 0:
            if uncounted == 1:
                _uncounted.pop(tenant, None)
            else:
                _uncounted[tenant] = uncounted - 1
            return
        current = _inflight.get(tenant, 0) - 1
        if current <= 0:
            _inflight.pop(tenant, None)
        else:
            _inflight[tenant] = current


def in_flight(tenant: str) -> int:
    """Goals currently in flight for ``tenant`` (for tests/observability)."""
    with _lock:
        return _inflight.get(tenant, 0)
