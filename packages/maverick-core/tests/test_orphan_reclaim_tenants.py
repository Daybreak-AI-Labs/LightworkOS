"""Startup orphan-goal reclaim across per-tenant ``world.db`` files.

``Server.run()`` reclaims goals stranded in ``active``/``pending`` by a crash.
Before this change it only swept the DEFAULT ``~/.maverick/world.db``; with
per-user tenancy on, each tenant's own ``~/.maverick/tenants/<t>/world.db``
kept its ghosts forever. ``server._reclaim_tenant_orphans()`` closes that gap.

HOME is isolated per test by the autouse ``_isolate_maverick_home`` conftest
fixture, so these are hermetic (no real ``~/.maverick`` touched, no network).
``MAVERICK_ORPHAN_RECLAIM_SECONDS=0`` makes a freshly-created stuck goal
qualify immediately (the production default only reclaims goals >=60s stale).
"""
from __future__ import annotations

import pytest
from maverick import server as server_mod
from maverick.paths import maverick_home
from maverick.world_model import world_for_tenant


@pytest.fixture(autouse=True)
def _clear_world_cache():
    """Drop the process-wide per-tenant WorldModel cache around each test.

    The cache is keyed by resolved DB path; HOME is per-test so paths already
    differ, but clearing (and closing) keeps SQLite FDs from leaking across the
    suite and makes the reclaim re-open the on-disk DBs fresh.
    """
    import maverick.world_model as wm

    def _drain():
        for w in list(wm._tenant_worlds.values()):
            try:
                w.close()
            except Exception:
                pass
        wm._tenant_worlds.clear()

    _drain()
    yield
    _drain()


def _stranded_tenant(tenant: str) -> tuple[int, int]:
    """Create a tenant world with one 'pending' and one 'active' stuck goal.

    Returns the two goal ids. Both are orphans (the process "crashed" before
    set_goal_status('done'/'blocked')).
    """
    w = world_for_tenant(tenant)
    pending = w.create_goal(f"{tenant}-pending", "stuck pending")  # status 'pending'
    active = w.create_goal(f"{tenant}-active", "stuck active")
    w.set_goal_status(active, "active")
    return pending, active


def _assert_reclaimed(tenant: str, goal_ids: tuple[int, ...]) -> None:
    w = world_for_tenant(tenant)
    for gid in goal_ids:
        assert w.get_goal(gid).status == "blocked"


# --- tenancy ON: every tenant's world.db is swept -------------------------

def test_reclaims_orphans_across_all_tenant_worlds(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setenv("MAVERICK_ORPHAN_RECLAIM_SECONDS", "0")

    a_goals = _stranded_tenant("a")
    b_goals = _stranded_tenant("b")

    # Drop the cache so the reclaim re-discovers the tenants from disk and
    # opens their world.db files itself (mirrors a fresh `maverick serve`).
    import maverick.world_model as wm
    for w in list(wm._tenant_worlds.values()):
        w.close()
    wm._tenant_worlds.clear()

    reclaimed = server_mod._reclaim_tenant_orphans()

    assert reclaimed == 4  # 2 tenants x (1 pending + 1 active)
    _assert_reclaimed("a", a_goals)
    _assert_reclaimed("b", b_goals)


def test_reclaim_does_not_populate_tenant_world_cache(monkeypatch):
    """Startup maintenance must not consume live tenant cache slots."""
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setenv("MAVERICK_ORPHAN_RECLAIM_SECONDS", "0")

    tenants = [f"tenant-{idx}" for idx in range(3)]
    goals = {tenant: _stranded_tenant(tenant) for tenant in tenants}

    import maverick.world_model as wm
    for w in list(wm._tenant_worlds.values()):
        w.close()
    wm._tenant_worlds.clear()

    reclaimed = server_mod._reclaim_tenant_orphans()

    assert reclaimed == 6
    assert wm._tenant_worlds == {}

    for tenant, goal_ids in goals.items():
        _assert_reclaimed(tenant, goal_ids)


def test_reclaim_skips_unreadable_tenant_dir_fail_soft(monkeypatch):
    """A bad tenant entry is skipped; the good tenant is still reclaimed."""
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setenv("MAVERICK_ORPHAN_RECLAIM_SECONDS", "0")

    good = _stranded_tenant("good")

    # A plain file (not a dir) sitting in the tenants root must not crash the
    # sweep -- entry.is_dir() is False so it's skipped.
    (maverick_home() / "tenants" / "stray.txt").write_text("not a tenant")

    import maverick.world_model as wm
    for w in list(wm._tenant_worlds.values()):
        w.close()
    wm._tenant_worlds.clear()

    reclaimed = server_mod._reclaim_tenant_orphans()

    assert reclaimed == 2  # only the 'good' tenant's two goals
    _assert_reclaimed("good", good)


def test_reclaim_no_tenants_dir_returns_zero(monkeypatch):
    """No tenant has ever run -> no tenants dir -> no-op, no crash."""
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    assert not (maverick_home() / "tenants").exists()
    assert server_mod._reclaim_tenant_orphans() == 0


# --- tenancy OFF: tenant worlds are NOT touched ---------------------------

def test_disabled_does_not_sweep_tenant_worlds(monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setenv("MAVERICK_ORPHAN_RECLAIM_SECONDS", "0")
    # Tenancy resolution also consults config; force it off there too.
    monkeypatch.setattr("maverick.config.load_config", dict)

    a_goals = _stranded_tenant("a")

    import maverick.world_model as wm
    for w in list(wm._tenant_worlds.values()):
        w.close()
    wm._tenant_worlds.clear()

    # Helper is a no-op when tenancy is off: returns 0 and leaves the tenant's
    # orphans untouched (only the default world is swept by Server.run()).
    assert server_mod._reclaim_tenant_orphans() == 0

    w = world_for_tenant("a")
    for gid in a_goals:
        assert w.get_goal(gid).status in ("pending", "active")
