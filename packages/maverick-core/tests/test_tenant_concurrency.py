"""Per-tenant concurrency ceiling: noisy-neighbor protection.

A tenant's plan ``max_concurrent_goals`` bounds how many of its goals run at
once, so one tenant cannot fill every global runner slot and starve the rest.
Fail-open: no tenant, or an unlimited plan, enforces nothing.
"""
from __future__ import annotations

import pytest
from maverick.tenant import concurrency as tc


@pytest.fixture(autouse=True)
def _clear():
    tc._inflight.clear()
    yield
    tc._inflight.clear()


def test_none_tenant_is_never_limited():
    # Single-tenant path: acquire always granted, release is a no-op.
    assert tc.acquire(None) is True
    tc.release(None)
    assert tc._inflight == {}


def test_unlimited_plan_grants_every_slot(monkeypatch):
    monkeypatch.setattr(tc, "_limit_for", lambda t: 0)  # 0 == unlimited
    for _ in range(50):
        assert tc.acquire("acme") is True
    # Unlimited plans don't even track in-flight (nothing to bound).
    assert tc.in_flight("acme") == 0


def test_ceiling_refuses_when_full_and_frees_on_release(monkeypatch):
    monkeypatch.setattr(tc, "_limit_for", lambda t: 2)
    assert tc.acquire("acme") is True
    assert tc.acquire("acme") is True
    assert tc.in_flight("acme") == 2
    # Third concurrent goal is refused.
    assert tc.acquire("acme") is False
    # Finishing one frees exactly one slot.
    tc.release("acme")
    assert tc.in_flight("acme") == 1
    assert tc.acquire("acme") is True
    assert tc.acquire("acme") is False


def test_tenants_have_independent_ceilings(monkeypatch):
    monkeypatch.setattr(tc, "_limit_for", lambda t: 1)
    assert tc.acquire("acme") is True
    # A different tenant is unaffected by acme being full.
    assert tc.acquire("globex") is True
    assert tc.acquire("acme") is False
    assert tc.acquire("globex") is False


def test_limit_derives_from_plan_entitlement(monkeypatch):
    # free plan default is 1 concurrent goal; unknown tenant -> free.
    monkeypatch.setattr(
        "maverick.tenant.registry.get_tenant", lambda t: None
    )
    assert tc._limit_for("whoever") == 1


def test_lookup_error_fails_open(monkeypatch):
    def boom(_t):
        raise RuntimeError("registry down")
    monkeypatch.setattr("maverick.tenant.registry.get_tenant", boom)
    # A resolution error must never block a run -> treated as unlimited.
    assert tc._limit_for("acme") == 0
    assert tc.acquire("acme") is True
