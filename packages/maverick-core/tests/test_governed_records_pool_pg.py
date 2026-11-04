"""Actual pooled tenant/RLS/crypto authority and database failure boundaries."""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import postgres_transactions as pt
from maverick.governed_records import GovernedRecordBackendError
from maverick.paths import tenant_scope

from test_support.postgres_authority import authority as authority

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"), reason="dedicated Postgres service unavailable")


def save(backend, tenant, value):
    with tenant_scope(tenant=tenant):
        now = time.time()
        return backend.save({"id": "PRB-item", "value": value,
                             "created_at": now, "updated_at": now, "revision": 1})


def test_reused_socket_retains_forced_rls_and_has_no_tenant_between_transactions(authority):
    factory, _, _ = authority
    backend = factory()
    save(backend, "alpha", "alpha-only")
    save(backend, "beta", "beta-only")
    pids = set()
    for tenant in ("alpha", "beta", "alpha", "beta"):
        with tenant_scope(tenant=tenant):
            assert backend.load("PRB-item")["value"] == tenant + "-only"
            with backend._transaction(tenant) as cursor:
                # No application WHERE predicate: database RLS must scope this.
                cursor.execute("SELECT tenant_id, pg_backend_pid() FROM governed_records")
                rows = cursor.fetchall()
                assert len(rows) == 1 and rows[0][0] == tenant
                pids.add(rows[0][1])
        with backend._raw_transaction() as cursor:
            cursor.execute("SELECT COUNT(*) FROM governed_records")
            assert cursor.fetchone()[0] == 0
            cursor.execute("SELECT nullif(current_setting('maverick.tenant', true), '')")
            assert cursor.fetchone()[0] is None
    assert len(pids) == 1
    assert len(pt._POOLS) == 1


def test_four_threads_and_namespaces_share_one_pool_without_cross_tenant_state(authority):
    factory, _, _ = authority
    backends = [factory("records_" + str(i)) for i in range(4)]
    for i, backend in enumerate(backends):
        save(backend, "tenant-" + str(i), "value-" + str(i))
    start = threading.Barrier(4)
    def read(i):
        start.wait(timeout=5)
        with tenant_scope(tenant="tenant-" + str(i)):
            return [backends[i].load("PRB-item")["value"] for _ in range(8)]
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(read, range(4)))
    assert results == [["value-" + str(i)] * 8 for i in range(4)]
    assert len(pt._POOLS) == 1
    stats = next(iter(pt._POOLS.values())).pool.get_stats()
    assert stats["connections_num"] == 1


def test_baseexception_rolls_back_before_reuse(authority):
    factory, _, _ = authority
    backend = factory()
    save(backend, "alpha", "kept")
    class Interrupted(BaseException):
        pass
    with tenant_scope(tenant="alpha"):
        with pytest.raises(Interrupted), backend._transaction("alpha") as cursor:
            cursor.execute("DELETE FROM governed_records")
            raise Interrupted
        assert backend.load("PRB-item")["value"] == "kept"
    with backend._raw_transaction() as cursor:
        cursor.execute("SELECT COUNT(*) FROM governed_records")
        assert cursor.fetchone()[0] == 0


def test_shutdown_stays_pending_until_real_pool_reset_worker_exits(authority, monkeypatch):
    factory, _, _ = authority
    started, release = threading.Event(), threading.Event()
    armed = [False]
    original = pt._reset_connection
    def held_reset(connection):
        if armed[0]:
            started.set()
            assert release.wait(timeout=5)
        original(connection)
    monkeypatch.setattr(pt, "_reset_connection", held_reset)
    backend = factory()
    save(backend, "alpha", "kept")
    pool = next(iter(pt._POOLS.values())).pool
    deadline = time.monotonic() + 2
    while pool.get_stats().get("pool_available", 0) != 1 and time.monotonic() < deadline:
        time.sleep(.005)
    assert pool.get_stats()["pool_available"] == 1
    armed[0] = True
    try:
        with backend._raw_transaction() as cursor:
            cursor.execute("SELECT 1")
        assert started.wait(timeout=2)
        before = time.monotonic()
        pt.close_postgres_pools(timeout=.03)
        assert time.monotonic() - before < .5
        assert pt.postgres_pools_pending()
        with pytest.raises(RuntimeError, match="pending"):
            pt.open_postgres_pools()
    finally:
        release.set()
        pt.close_postgres_pools(timeout=3)
    assert not pt.postgres_pools_pending()


def test_pool_wait_is_bounded_without_retrying_the_operation(authority):
    factory, _, _ = authority
    backend = factory(timeout=.1)
    # This checks an exhausted warm pool, not Windows process/socket startup.
    # Establish the same real pool before measuring its unchanged 100ms lease.
    transactions = backend._transactions
    options = transactions._connection_options()
    pool = pt._shared_pool(transactions._dsn, options, transactions._size,
                           transactions._timeout, transactions._io_timeout).pool
    with pool.connection(timeout=5) as connection:
        connection.execute("SELECT 1")
    deadline = time.monotonic() + 5
    while pool.get_stats().get("pool_available", 0) != 1 and time.monotonic() < deadline:
        time.sleep(.005)
    assert pool.get_stats().get("pool_available", 0) == 1
    save(backend, "alpha", "kept")
    with tenant_scope(tenant="alpha"), backend._raw_transaction():
        started = time.monotonic()
        with pytest.raises(GovernedRecordBackendError, match="load failed"):
            backend.load("PRB-item")
        elapsed = time.monotonic() - started
        assert .08 <= elapsed < 2
    with tenant_scope(tenant="alpha"):
        assert backend.load("PRB-item")["value"] == "kept"


def test_dead_socket_fails_current_operation_then_next_call_reconnects(authority):
    import psycopg
    factory, admin_dsn, _ = authority
    backend = factory()
    save(backend, "alpha", "kept")
    with backend._raw_transaction() as cursor:
        cursor.execute("SELECT pg_backend_pid()")
        pid = cursor.fetchone()[0]
    # Wait until the reset worker has published that same idle connection.
    pool = next(iter(pt._POOLS.values())).pool
    deadline = time.monotonic() + 2
    while pool.get_stats().get("pool_available", 0) != 1 and time.monotonic() < deadline:
        time.sleep(.005)
    assert pool.get_stats()["pool_available"] == 1
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        assert admin.execute("SELECT pg_terminate_backend(%s)", (pid,)).fetchone()[0]
    with tenant_scope(tenant="alpha"):
        with pytest.raises(GovernedRecordBackendError):
            backend.load("PRB-item")
        assert backend.load("PRB-item")["value"] == "kept"
    assert pool.get_stats()["connections_num"] == 2


@pytest.mark.parametrize("drift", ["extra_policy", "disable_rls", "key_loss", "bypass_role"])
def test_warm_connection_rechecks_current_authority(authority, monkeypatch, drift):
    import psycopg
    from psycopg import sql
    factory, admin_dsn, role = authority
    backend = factory()
    save(backend, "alpha", "private")
    with tenant_scope(tenant="alpha"):
        assert backend.load("PRB-item")["value"] == "private"
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        table = sql.Identifier(role, "governed_records")
        if drift == "extra_policy":
            admin.execute(sql.SQL("CREATE POLICY accidental_public ON {} USING (true)").format(table))
        elif drift == "disable_rls":
            admin.execute(sql.SQL("ALTER TABLE {} DISABLE ROW LEVEL SECURITY").format(table))
        elif drift == "bypass_role":
            admin.execute(sql.SQL("ALTER ROLE {} BYPASSRLS").format(sql.Identifier(role)))
        else:
            monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY")
    with tenant_scope(tenant="alpha"), pytest.raises(GovernedRecordBackendError):
        backend.load("PRB-item")
