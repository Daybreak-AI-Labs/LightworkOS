"""Per-tenant concurrency ceiling -- noisy-neighbor protection.

The global runner semaphore (:data:`maverick.runner.MAX_CONCURRENT_GOALS`)
bounds *total* in-flight goals, but it is tenant-blind: one tenant can fill
every slot and starve all the others for the duration of their runs. This
module adds a per-tenant ceiling derived from the tenant's provisioned plan
(:func:`maverick.billing.entitlements_for` ``.max_concurrent_goals``), so a
single noisy tenant cannot monopolise a shared instance.

OFF by default and fail-open (kernel rule 1): with no active tenant, an
unknown plan, or a plan whose ``max_concurrent_goals`` is 0 (unlimited),
nothing is enforced and single-tenant behaviour is byte-for-byte unchanged.
Any error resolving the limit leaves the slot granted -- this gate can only
refuse a *tenant already at its own ceiling*, never become a new way to down
the channel server.
"""
from __future__ import annotations

import threading

_lock = threading.Lock()
# tenant id -> number of goals currently in flight for that tenant.
_inflight: dict[str, int] = {}


def _limit_for(tenant: str) -> int:
    """The tenant's concurrent-goal ceiling (0 = unlimited). Fail-open to 0."""
    try:
        from ..billing import entitlements_for
        from .registry import get_tenant
        rec = get_tenant(tenant)
        plan = rec.plan if rec else "free"
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
        current = _inflight.get(tenant, 0) - 1
        if current <= 0:
            _inflight.pop(tenant, None)
        else:
            _inflight[tenant] = current


def in_flight(tenant: str) -> int:
    """Goals currently in flight for ``tenant`` (for tests/observability)."""
    with _lock:
        return _inflight.get(tenant, 0)
