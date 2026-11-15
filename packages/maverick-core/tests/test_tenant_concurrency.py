"""Per-tenant "tasks at once" plan limit, shared by every process.

A tenant's plan ``max_concurrent_goals`` bounds how many of its goals run at
once. Each run holds one numbered slot lease, so other processes count it
and a process that dies gives its slot back. Fail-open: no tenant, or an
unlimited plan, enforces nothing.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from maverick.tenant import concurrency as tc


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))


def test_none_tenant_and_unlimited_plan_are_never_limited(monkeypatch):
    with tc.slot(None):
        pass
    monkeypatch.setattr(tc, "_limit_for", lambda t: 0)  # 0 == unlimited
    with tc.slot("acme"), tc.slot("acme"), tc.slot("acme"):
        assert tc.has_room("acme")


def test_ceiling_refuses_when_full_and_frees_on_exit(monkeypatch):
    monkeypatch.setattr(tc, "_limit_for", lambda t: 2)
    with tc.slot("acme"):
        with tc.slot("acme"):
            assert not tc.has_room("acme")
            with pytest.raises(tc.TenantAtCapacity):
                with tc.slot("acme"):
                    pass
        assert tc.has_room("acme")
        # A different tenant is unaffected by acme being full.
        with tc.slot("acme"), tc.slot("globex"):
            assert not tc.has_room("acme")


_HOLDER = """
import sys, time
from types import SimpleNamespace
from maverick.tenant import concurrency as tc
tc._limit_for = lambda t: 1
world = SimpleNamespace(_dsn=sys.argv[1], path=None) if sys.argv[1] else None
with tc.slot("acme", world):
    print("held", flush=True)
    time.sleep(120)
"""


@pytest.mark.parametrize("backend", ["files", "postgres"])
def test_a_slot_held_by_another_process_counts_and_comes_back_when_it_dies(monkeypatch, backend):
    dsn = os.environ.get("MAVERICK_PG_DSN", "") if backend == "postgres" else ""
    if backend == "postgres" and not dsn:
        pytest.skip("MAVERICK_PG_DSN not set (no Postgres service)")
    world = SimpleNamespace(_dsn=dsn, path=None) if dsn else None
    monkeypatch.setattr(tc, "_limit_for", lambda t: 1)
    child = subprocess.Popen([sys.executable, "-c", _HOLDER, dsn], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "held"
        assert not tc.has_room("acme", world)
    finally:
        child.kill()
        child.wait(timeout=30)
    deadline = time.monotonic() + 30
    while not tc.has_room("acme", world) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert tc.has_room("acme", world)


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
    assert tc.has_room("acme") is True


def test_limit_uses_the_served_plan_when_payment_lapsed(monkeypatch):
    # A past-due tenant is served the base plan; its paid concurrency must
    # not survive the downgrade.
    from types import SimpleNamespace

    from maverick.billing import entitlements_for

    rec = SimpleNamespace(plan="enterprise", billing_status="past_due")
    monkeypatch.setattr("maverick.tenant.registry.get_tenant", lambda t: rec)
    assert tc._limit_for("acme") == entitlements_for("free").max_concurrent_goals
