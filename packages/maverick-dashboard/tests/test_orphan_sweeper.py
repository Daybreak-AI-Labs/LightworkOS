"""A quick dashboard restart must eventually recover dead, but not live, goals."""
from __future__ import annotations

import asyncio
import importlib
import time

import pytest
from maverick.goal_heartbeat import start_goal_heartbeat
from maverick.world_model import WorldModel
from maverick_dashboard import orphan_sweeper


@pytest.fixture
def world(tmp_path, monkeypatch):
    from maverick import world_model_backends
    from maverick_dashboard import _shared

    monkeypatch.setenv("MAVERICK_ORPHAN_RECLAIM_SECONDS", "60")
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: False)
    handle = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(_shared, "_world", lambda: handle)
    yield handle
    orphan_sweeper.stop_orphan_sweeper(timeout=2.0)
    handle.close()


def _active(world, *, age: float) -> int:
    goal_id = world.create_goal("Run", "")
    world.set_goal_status(goal_id, "active", result="partial")
    _age(world, goal_id, age)
    return goal_id


def _age(world, goal_id: int, seconds: float) -> None:
    with world._writing() as conn:
        conn.execute(
            "UPDATE goals SET updated_at = ? WHERE id = ?",
            (time.time() - seconds, goal_id),
        )


def test_quick_restart_recovers_after_window_without_another_restart(world):
    goal_id = _active(world, age=14)
    assert world.reclaim_orphan_goals() == 0  # startup: a sibling may still run it
    assert world.get_goal(goal_id).status == "active"

    _age(world, goal_id, 61)  # no heartbeat from the killed process
    assert orphan_sweeper.sweep_once() == 1
    goal = world.get_goal(goal_id)
    assert goal.status == "blocked"
    assert goal.result == "partial [process restarted mid-run]"


def test_unbound_sqlite_dashboard_recovers_registered_workspace_chats(
    tmp_path, monkeypatch,
):
    from maverick import client, paths, world_model_backends
    from maverick.tenant import registry
    from maverick_dashboard import _shared

    app_module = importlib.import_module("maverick_dashboard.app")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ORPHAN_RECLAIM_SECONDS", "60")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: False)
    monkeypatch.setattr(registry, "list_tenants", lambda: [
        registry.TenantRecord(id="client-a"),
        registry.TenantRecord(id="client-b"),
        registry.TenantRecord(id="client-c"),
    ])
    worlds = {
        None: WorldModel(tmp_path / "world.db"),
        "client-a": WorldModel(tmp_path / "tenants" / "client-a" / "world.db"),
        "client-b": WorldModel(tmp_path / "tenants" / "client-b" / "world.db"),
    }
    def factory():
        return worlds[paths.current_tenant_id_strict()]

    monkeypatch.setattr(_shared, "_world", factory)
    monkeypatch.setattr(app_module, "_world", factory)
    monkeypatch.setattr(orphan_sweeper, "start_orphan_sweeper", lambda: True)
    monkeypatch.setattr(orphan_sweeper, "_last_periodic_tenant", None)
    try:
        shared = _active(worlds[None], age=61)
        stale = _active(worlds["client-a"], age=61)
        recent = _active(worlds["client-b"], age=5)

        asyncio.run(app_module._reclaim_orphans())
        assert worlds[None].get_goal(shared).status == "blocked"
        assert worlds["client-a"].get_goal(stale).status == "blocked"
        assert worlds["client-b"].get_goal(recent).status == "active"

        _age(worlds["client-b"], recent, 61)
        assert orphan_sweeper.sweep_once() == 1
        assert worlds["client-b"].get_goal(recent).status == "blocked"
        assert not (tmp_path / "tenants" / "client-c" / "world.db").exists()
    finally:
        for handle in worlds.values():
            handle.close()


def test_live_heartbeat_prevents_reclaim_then_stopping_allows_it(world):
    goal_id = _active(world, age=61)
    # Separate connections stand in for the dashboard and a surviving worker.
    worker_world = WorldModel(world.path)
    stop = start_goal_heartbeat(worker_world, goal_id, interval=0.02)
    try:
        deadline = time.monotonic() + 2.0
        while world.get_goal(goal_id).updated_at < time.time() - 5:
            assert time.monotonic() < deadline, "live run did not heartbeat"
            time.sleep(0.01)
        assert world.reclaim_orphan_goals() == 0  # restarted dashboard startup
        assert orphan_sweeper.sweep_once() == 0
        assert world.get_goal(goal_id).status == "active"
    finally:
        stop()
        worker_world.close()

    _age(world, goal_id, 61)
    assert orphan_sweeper.sweep_once() == 1


def test_periodic_reclaim_never_blocks_queued_goal(world):
    goal_id = world.create_goal("Waiting for worker", "")
    _age(world, goal_id, 600)
    assert orphan_sweeper.sweep_once() == 0
    assert world.get_goal(goal_id).status == "pending"


@pytest.mark.parametrize("window", ["0", "5"])
def test_zero_or_tiny_window_disables_periodic_reclaim(world, monkeypatch, window):
    monkeypatch.setenv("MAVERICK_ORPHAN_RECLAIM_SECONDS", window)
    goal_id = _active(world, age=600)
    assert orphan_sweeper.sweep_once() == 0
    assert world.get_goal(goal_id).status == "active"


def test_configured_longer_window_is_honored(world, monkeypatch):
    monkeypatch.setenv("MAVERICK_ORPHAN_RECLAIM_SECONDS", "600")
    goal_id = _active(world, age=300)
    assert orphan_sweeper.sweep_once() == 0
    assert world.get_goal(goal_id).status == "active"


def test_unregistered_shared_postgres_is_not_swept(world, monkeypatch):
    from maverick import client, world_model_backends
    from maverick.tenant import registry

    goal_id = _active(world, age=61)
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    monkeypatch.setattr(registry, "list_tenants", list)
    assert orphan_sweeper.sweep_once() == 0
    assert world.get_goal(goal_id).status == "active"


@pytest.mark.parametrize("process_tenant", ["client-a", None])
def test_startup_postgres_reclaims_each_registered_tenant_even_when_unbound(
    world, monkeypatch, process_tenant,
):
    from maverick import client, paths, world_model_backends
    from maverick.tenant import registry

    app_module = importlib.import_module("maverick_dashboard.app")
    calls = []
    goals = {
        "client-a": {"active": "stale", "pending": "queued"},
        "client-b": {"active": "stale", "pending": "queued"},
    }

    class FakeWorld:
        def reclaim_orphan_goals(self, **kwargs):
            tenant = paths.current_tenant_id_strict()
            calls.append((tenant, kwargs))
            assert kwargs["statuses"] == ("active",)
            goals[tenant]["active"] = "blocked"
            return 1

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    if process_tenant is None:
        monkeypatch.setattr(registry, "list_tenants", lambda: [
            registry.TenantRecord(id="client-a"),
            registry.TenantRecord(id="client-b", status=registry.SUSPENDED),
        ])
    else:
        monkeypatch.setattr(registry, "list_tenants", lambda: pytest.fail(
            "a process-bound tenant must not require a local registry",
        ))
    monkeypatch.setattr(app_module, "_world", FakeWorld)
    monkeypatch.setattr(orphan_sweeper, "start_orphan_sweeper", lambda: True)
    monkeypatch.setattr(orphan_sweeper, "_last_periodic_tenant", None)

    with paths.tenant_scope(tenant=process_tenant):
        asyncio.run(app_module._reclaim_orphans())
    expected = ["client-a", "client-b"] if process_tenant is None else ["client-a"]
    assert calls == [
        (tenant, {
            "statuses": ("active",), "resolved_window_seconds": 60.0,
            "exact_tenant": True,
        })
        for tenant in expected
    ]
    assert all(goals[tenant]["pending"] == "queued" for tenant in goals)
    assert paths.current_tenant_id_strict() is None


def test_unavailable_postgres_roster_refuses_startup_and_periodic_writes(world, monkeypatch):
    from maverick import client, world_model_backends
    from maverick.tenant import registry
    from maverick_dashboard import _shared

    app_module = importlib.import_module("maverick_dashboard.app")

    def unavailable():
        raise registry.TenantRegistryError("roster unreadable")

    def unexpected_world():
        pytest.fail("world opened without an authoritative tenant roster")

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    monkeypatch.setattr(registry, "list_tenants", unavailable)
    monkeypatch.setattr(_shared, "_world", unexpected_world)
    monkeypatch.setattr(app_module, "_world", unexpected_world)
    monkeypatch.setattr(orphan_sweeper, "start_orphan_sweeper", lambda: True)

    asyncio.run(app_module._reclaim_orphans())
    assert orphan_sweeper.sweep_once() == 0


def test_shared_postgres_startup_batch_and_periodic_sweep_resume_cursor(world, monkeypatch):
    from maverick import client, paths, world_model_backends
    from maverick.tenant import registry
    from maverick_dashboard import _shared

    app_module = importlib.import_module("maverick_dashboard.app")
    seen = []
    opens = []

    class FakeWorld:
        def reclaim_orphan_goals(self, **kwargs):
            assert kwargs["statuses"] == ("active",)
            assert kwargs["exact_tenant"] is True
            seen.append(paths.current_tenant_id_strict())
            return 1

    def factory():
        opens.append(paths.current_tenant_id_strict())
        return FakeWorld()

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    monkeypatch.setattr(registry, "list_tenants", lambda: [
        registry.TenantRecord(id=f"client-{index}") for index in range(5)
    ])
    monkeypatch.setattr(app_module, "_world", factory)
    monkeypatch.setattr(_shared, "_world", factory)
    monkeypatch.setattr(orphan_sweeper, "start_orphan_sweeper", lambda: True)
    monkeypatch.setattr(orphan_sweeper, "MAX_TENANTS_PER_SWEEP", 2)
    monkeypatch.setattr(orphan_sweeper, "_last_periodic_tenant", None)

    asyncio.run(app_module._reclaim_orphans())
    assert seen == ["client-0", "client-1"]
    assert opens == ["client-0"]
    assert orphan_sweeper.sweep_once() == 2
    assert seen == ["client-0", "client-1", "client-2", "client-3"]
    assert opens == ["client-0", "client-2"]
    assert orphan_sweeper.sweep_once() == 2
    assert seen[-2:] == ["client-4", "client-0"]
    assert opens == ["client-0", "client-2", "client-4"]


@pytest.mark.parametrize("failure", ["open", "transaction"])
def test_shared_postgres_startup_aborts_after_one_backend_failure(
    world, monkeypatch, failure,
):
    from maverick import client, paths, world_model_backends
    from maverick.tenant import registry

    app_module = importlib.import_module("maverick_dashboard.app")
    opens = []
    transactions = []

    class FailingWorld:
        def reclaim_orphan_goals(self, **kwargs):
            transactions.append(paths.current_tenant_id_strict())
            raise RuntimeError("shared database unavailable")

    def factory():
        opens.append(paths.current_tenant_id_strict())
        if failure == "open":
            raise RuntimeError("shared database unavailable")
        return FailingWorld()

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    monkeypatch.setattr(registry, "list_tenants", lambda: [
        registry.TenantRecord(id=f"client-{index:03}") for index in range(100)
    ])
    monkeypatch.setattr(app_module, "_world", factory)
    monkeypatch.setattr(orphan_sweeper, "start_orphan_sweeper", lambda: True)
    monkeypatch.setattr(orphan_sweeper, "_last_periodic_tenant", None)

    asyncio.run(app_module._reclaim_orphans())
    assert opens == ["client-000"]
    assert transactions == ([] if failure == "open" else ["client-000"])
    assert orphan_sweeper._last_periodic_tenant is None  # retry first on next pass


@pytest.mark.parametrize("window", ["0", "5"])
@pytest.mark.parametrize("process_tenant", [None, "client-a"])
def test_unsafe_postgres_startup_window_never_reclaims_active(
    world, monkeypatch, window, process_tenant,
):
    from maverick import client, paths, world_model_backends

    app_module = importlib.import_module("maverick_dashboard.app")
    goal_id = _active(world, age=60)

    monkeypatch.setenv("MAVERICK_ORPHAN_RECLAIM_SECONDS", window)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.setattr(app_module, "_world", lambda: pytest.fail(
        "unsafe window must be refused before opening PostgreSQL",
    ))
    monkeypatch.setattr(orphan_sweeper, "start_orphan_sweeper", lambda: True)

    with paths.tenant_scope(tenant=process_tenant):
        asyncio.run(app_module._reclaim_orphans())
    assert world.get_goal(goal_id).status == "active"


def test_process_bound_postgres_sweep_does_not_depend_on_roster(world, monkeypatch):
    from maverick import paths, world_model_backends
    from maverick.tenant import registry
    from maverick_dashboard import _shared

    calls = []

    class FakeWorld:
        def reclaim_orphan_goals(self, **kwargs):
            calls.append((paths.current_tenant_id_strict(), kwargs))
            return 1

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.setattr(registry, "list_tenants", lambda: pytest.fail(
        "a process-bound tenant must not require a local registry",
    ))
    monkeypatch.setattr(_shared, "_world", FakeWorld)
    with paths.tenant_scope(tenant="single-customer"):
        assert orphan_sweeper.sweep_once() == 1
    assert calls == [("single-customer", {
        "statuses": ("active",), "exact_tenant": True,
        "resolved_window_seconds": 60.0,
    })]


def test_periodic_postgres_sweep_visits_registered_tenants_and_preserves_pending(
    world, monkeypatch,
):
    from maverick import client, paths, world_model_backends
    from maverick.tenant import registry
    from maverick_dashboard import _shared

    goals = {
        "client-a": {"active": "stale", "pending": "queued"},
        "client-b": {"active": "stale", "pending": "queued"},
        "legacy-null": {"active": "stale", "pending": "queued"},
    }
    calls = []

    class FakeWorld:
        def reclaim_orphan_goals(self, **kwargs):
            tenant = paths.current_tenant_id_strict()
            calls.append((tenant, kwargs))
            assert kwargs["exact_tenant"] is True
            assert kwargs["statuses"] == ("active",)
            assert tenant in ("client-a", "client-b")
            goals[tenant]["active"] = "blocked"
            return 1

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    monkeypatch.setattr(registry, "list_tenants", lambda: [
        registry.TenantRecord(id="client-a"),
        registry.TenantRecord(id="client-b", status=registry.SUSPENDED),
    ])
    monkeypatch.setattr(_shared, "_world", FakeWorld)
    monkeypatch.setattr(orphan_sweeper, "_last_periodic_tenant", None)

    assert orphan_sweeper.sweep_once() == 2
    assert [tenant for tenant, _ in calls] == ["client-a", "client-b"]
    assert all(goals[t]["pending"] == "queued" for t in goals)
    assert goals["legacy-null"]["active"] == "stale"


def test_periodic_postgres_batches_rotate_fairly_when_roster_is_large(world, monkeypatch):
    from maverick import client, paths, world_model_backends
    from maverick.tenant import registry
    from maverick_dashboard import _shared

    seen = []

    class FakeWorld:
        def reclaim_orphan_goals(self, **kwargs):
            assert kwargs["statuses"] == ("active",)
            assert kwargs["exact_tenant"] is True
            seen.append(paths.current_tenant_id_strict())
            return 1

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    monkeypatch.setattr(registry, "list_tenants", lambda: [
        registry.TenantRecord(id=f"client-{index}") for index in range(5)
    ])
    monkeypatch.setattr(_shared, "_world", FakeWorld)
    monkeypatch.setattr(orphan_sweeper, "MAX_TENANTS_PER_SWEEP", 2)
    monkeypatch.setattr(orphan_sweeper, "_last_periodic_tenant", None)

    assert [orphan_sweeper.sweep_once() for _ in range(3)] == [2, 2, 2]
    assert seen == [
        "client-0", "client-1", "client-2", "client-3", "client-4", "client-0",
    ]


def _postgres_roster(monkeypatch, failing, *, tenants=5, batch=64):
    """Shared PostgreSQL with ``tenants`` registered tenants; those in ``failing``
    always raise (for example an at-rest decrypt failure with per-tenant keys)."""
    from maverick import client, paths, world_model_backends
    from maverick.tenant import registry
    from maverick_dashboard import _shared

    seen = []

    class FakeWorld:
        def reclaim_orphan_goals(self, **kwargs):
            tenant = paths.current_tenant_id_strict()
            seen.append(tenant)
            if tenant in failing:
                raise RuntimeError("tenant data cannot be read")
            return 1

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    monkeypatch.setattr(registry, "list_tenants", lambda: [
        registry.TenantRecord(id=f"client-{index}") for index in range(tenants)
    ])
    monkeypatch.setattr(_shared, "_world", FakeWorld)
    monkeypatch.setattr(orphan_sweeper, "MAX_TENANTS_PER_SWEEP", batch)
    monkeypatch.setattr(orphan_sweeper, "_last_periodic_tenant", None)
    monkeypatch.setattr(orphan_sweeper, "_stalled_tenant", None)
    return seen


def test_one_persistently_failing_tenant_does_not_starve_later_tenants(world, monkeypatch):
    seen = _postgres_roster(monkeypatch, {"client-2"})
    assert orphan_sweeper.sweep_once() == 4
    assert seen == [f"client-{index}" for index in range(5)]
    # The failing tenant is tried again on the next rotation, and the others
    # are still swept every time.
    assert orphan_sweeper.sweep_once() == 4
    assert seen[5:] == [f"client-{index}" for index in range(5)]


def test_a_failing_tenant_at_the_start_of_a_batch_is_skipped_on_its_second_failure(world, monkeypatch):
    seen = _postgres_roster(monkeypatch, {"client-2"}, batch=2)
    assert orphan_sweeper.sweep_once() == 2          # client-0, client-1
    assert orphan_sweeper.sweep_once() == 0          # client-2 fails first: nothing shows the backend is up
    assert seen[-1:] == ["client-2"]
    assert orphan_sweeper._last_periodic_tenant == "client-1"
    assert orphan_sweeper.sweep_once() == 1          # failed first again: skipped, client-3 swept
    assert seen[-2:] == ["client-2", "client-3"]
    assert orphan_sweeper.sweep_once() == 2          # the rotation moves on to client-4, client-0
    assert seen[-2:] == ["client-4", "client-0"]


def test_a_broken_backend_still_costs_few_attempts_per_pass(world, monkeypatch):
    seen = _postgres_roster(monkeypatch, {f"client-{index}" for index in range(100)}, tenants=100)
    assert orphan_sweeper.sweep_once() == 0
    assert seen == ["client-0"]                      # no evidence yet: stop at the first failure
    assert orphan_sweeper.sweep_once() == 0
    assert len(seen) <= 1 + 2                        # the repeat is skipped, the next one stops the pass


def test_invalid_roster_is_rejected_before_any_postgres_write(world, monkeypatch):
    from maverick import client, world_model_backends
    from maverick.tenant import registry
    from maverick_dashboard import _shared

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    monkeypatch.setattr(registry, "list_tenants", lambda: [
        registry.TenantRecord(id="client-a"),
        registry.TenantRecord(id="client-a"),
    ])
    monkeypatch.setattr(_shared, "_world", lambda: pytest.fail("partial roster write"))
    assert orphan_sweeper.sweep_once() == 0


def test_postgres_sweep_uses_exact_configured_tenant(world, monkeypatch):
    from contextlib import contextmanager

    from maverick import client, crypto_at_rest, world_model_backends
    from maverick.tenant import registry
    from maverick.world_model_backends import postgres
    from maverick_dashboard import _shared

    class Cursor:
        rowcount = 1
        query = None

        def execute(self, sql, params):
            self.query = sql, tuple(params)

    cursor = Cursor()

    @contextmanager
    def transaction(_self):
        yield cursor

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(client, "strict_client_id", lambda: None)
    monkeypatch.setattr(registry, "list_tenants", lambda: [
        registry.TenantRecord(id="client-a"),
    ])
    monkeypatch.setattr(postgres, "_tenant_scope", lambda: (
        "(tenant_id = %s OR tenant_id IS NULL)", ["client-a"],
    ))
    monkeypatch.setattr(postgres.PostgresWorldModel, "_tx", transaction)
    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", lambda: False)
    monkeypatch.setattr(_shared, "_world", lambda: postgres.PostgresWorldModel.__new__(
        postgres.PostgresWorldModel,
    ))

    assert orphan_sweeper.sweep_once() == 1
    sql, params = cursor.query
    assert "tenant_id = %s" in sql
    assert "OR tenant_id IS NULL" not in sql
    assert params[-1] == "client-a"


def test_supervised_thread_inherits_startup_tenant_scope(world, monkeypatch):
    from maverick.paths import current_tenant_id_strict, reset_tenant, set_tenant

    seen = []

    def loop(_stop):
        seen.append(current_tenant_id_strict())

    monkeypatch.setattr(orphan_sweeper, "_loop", loop)
    token = set_tenant("client-a")
    try:
        assert orphan_sweeper.start_orphan_sweeper()
        assert orphan_sweeper.stop_orphan_sweeper(timeout=2.0)
    finally:
        reset_tenant(token)
    assert seen == ["client-a"]


def test_supervised_sweeper_runs_and_stops(world, monkeypatch):
    monkeypatch.setattr(orphan_sweeper, "sweep_interval", lambda: 0.02)
    goal_id = _active(world, age=61)
    assert orphan_sweeper.start_orphan_sweeper()
    assert not orphan_sweeper.start_orphan_sweeper()
    deadline = time.monotonic() + 2.0
    while world.get_goal(goal_id).status == "active":
        assert time.monotonic() < deadline, "sweeper did not revisit the goal"
        time.sleep(0.01)
    assert orphan_sweeper.stop_orphan_sweeper(timeout=2.0)
    assert orphan_sweeper._sweeper_thread is None


def test_lowered_reclaim_window_waits_for_restart(world, monkeypatch):
    goal_id = _active(world, age=61)
    assert orphan_sweeper.start_orphan_sweeper()  # heartbeat cadence was set for 60 s
    stop = start_goal_heartbeat(world, goal_id, interval=15.0)
    try:
        monkeypatch.setenv("MAVERICK_ORPHAN_RECLAIM_SECONDS", "30")
        assert orphan_sweeper.sweep_once() == 0  # old heartbeat may still be asleep
        assert world.get_goal(goal_id).status == "active"
    finally:
        stop()

    assert orphan_sweeper.stop_orphan_sweeper(timeout=2.0)
    assert orphan_sweeper.start_orphan_sweeper()  # new process/window boundary
    live_goal = _active(world, age=14)  # old 15 s cadence is safe at 30 s
    assert orphan_sweeper.sweep_once() == 1
    assert world.get_goal(live_goal).status == "active"
