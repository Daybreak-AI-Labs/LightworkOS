"""Connection ownership, bounded acquisition and unknown-commit boundaries."""
from __future__ import annotations

import sys
import threading
from types import ModuleType, SimpleNamespace

import pytest
from maverick import postgres_transactions as pt


@pytest.fixture(autouse=True)
def isolated_pools(monkeypatch):
    monkeypatch.setattr(pt, "_POOLS", {})
    monkeypatch.setattr(pt, "_CLOSED", False)
    monkeypatch.setattr(pt, "_CLOSER", None)
    monkeypatch.setattr(pt, "_CLOSE_FAILED", False)
    yield
    pt.close_postgres_pools(timeout=2)


class StopWork(BaseException):
    pass


class Connection:
    def __init__(self):
        self.commits = self.rollbacks = self.closes = self.cursor_closes = 0
        self.commit_error = self.rollback_error = None
        self.statements = []

    def cursor(self):
        connection = self
        class Cursor:
            def execute(self, query, parameters=None):
                connection.statements.append((query, parameters))

            def close(self):
                connection.cursor_closes += 1

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.close()
        return Cursor()

    def commit(self):
        self.commits += 1
        if self.commit_error:
            raise self.commit_error

    def rollback(self):
        self.rollbacks += 1
        if self.rollback_error:
            raise self.rollback_error

    def close(self):
        self.closes += 1


def test_owned_transaction_rolls_back_baseexception_and_closes():
    connection = Connection()
    calls = []
    def connect(dsn, *, autocommit):
        calls.append((dsn, autocommit))
        return connection
    facility = pt.PostgresTransactions("private-test-adapter", connect=connect)
    stop = StopWork("cancel")
    with pytest.raises(StopWork) as caught, facility.transaction():
        raise stop
    assert caught.value is stop
    assert calls == [("private-test-adapter", False)]
    assert (connection.commits, connection.rollbacks, connection.closes) == (0, 1, 1)
    assert connection.cursor_closes == 1


def test_unknown_commit_never_reconnects_or_replays_and_preserves_first_failure():
    connection = Connection()
    original = OSError("commit result unknown")
    connection.commit_error = original
    connection.rollback_error = StopWork("rollback also stopped")
    attempts = 0
    def connect(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        return connection
    facility = pt.PostgresTransactions("private-test-adapter", connect=connect)
    with pytest.raises(OSError) as caught, facility.transaction() as cursor:
        cursor.execute("one write")
    assert caught.value is original
    assert attempts == 1 and connection.statements == [("one write", None)]
    assert connection.rollbacks == 1 and connection.closes >= 1


@pytest.mark.parametrize("size,timeout", [(True, 5), (-1, 5), (33, 5), (1.5, 5),
                                         (1, True), (1, 0), (1, 61), (1, float("nan")),
                                         (1, float("inf"))])
def test_invalid_pool_limits_refuse(size, timeout):
    with pytest.raises(ValueError):
        pt.PostgresTransactions("unused", pool_size=size, pool_timeout_seconds=timeout)


def test_caller_owned_connector_cannot_silently_enter_product_pool():
    with pytest.raises(ValueError, match="injected"):
        pt.PostgresTransactions("unused", pool_size=1, connect=lambda: None)


@pytest.mark.parametrize("requested,expected", [(None, 7), (0, 7), (30, 7), (3, 3)])
def test_real_libpq_options_preserve_tls_search_path_and_caps(monkeypatch, requested, expected):
    pytest.importorskip("psycopg")
    from maverick.db_timeouts import postgres_connection_kwargs
    from psycopg.conninfo import make_conninfo
    monkeypatch.setenv("MAVERICK_PG_CONNECT_TIMEOUT_SECONDS", "7")
    monkeypatch.delenv("PGCONNECT_TIMEOUT", raising=False)
    parameters = {"host": "db.example.invalid", "sslmode": "verify-full",
                  "sslrootcert": "custom-ca.pem", "options": "-c search_path=private -c statement_timeout=900"}
    if requested is not None:
        parameters["connect_timeout"] = requested
    dsn = make_conninfo(**parameters)
    result = postgres_connection_kwargs(dsn)
    assert result["connect_timeout"] == expected
    assert result["options"].startswith(parameters["options"])
    assert result["options"].count("statement_timeout") == 1
    assert "idle_in_transaction_session_timeout=60000" in result["options"]
    calls = []
    monkeypatch.setattr("maverick.postgres_io.BoundedConnection.connect", lambda connection_dsn, **kwargs: calls.append((connection_dsn, kwargs)))
    facility = pt.PostgresTransactions(dsn)
    facility.connect()
    monkeypatch.setenv("MAVERICK_PG_CONNECT_TIMEOUT_SECONDS", "200")
    facility.connect()
    expected_options = {**result, "io_timeout_seconds": 35.0}
    assert calls == [(dsn, expected_options), (dsn, expected_options)]


class Pool:
    instances = []
    def __init__(self, dsn, **kwargs):
        self.dsn, self.kwargs = dsn, kwargs
        self.connection = Connection()
        self.timeouts, self.returned, self.closed = [], [], []
        self.acquire_error = None
        self.close_release = None
        self.instances.append(self)

    def getconn(self, *, timeout):
        self.timeouts.append(timeout)
        if self.acquire_error:
            raise self.acquire_error
        return self.connection

    def putconn(self, connection):
        self.returned.append(connection)
        self.kwargs["reset"](connection)

    def close(self, *, timeout):
        self.closed.append(timeout)
        if self.close_release:
            self.close_release.wait(timeout=2)


@pytest.fixture
def fake_pool(monkeypatch):
    Pool.instances = []
    monkeypatch.setitem(sys.modules, "psycopg_pool", SimpleNamespace(ConnectionPool=Pool))
    # These tests exercise pool ownership without opening a libpq socket. Keep
    # the optional driver out of this fixture instead of relying on another
    # test having imported (or faked) psycopg first.
    fake_io = ModuleType("maverick.postgres_io")
    fake_io.BoundedConnection = type("BoundedConnection", (), {})
    fake_io.postgres_io_timeout_seconds = lambda: 35.0
    monkeypatch.setitem(sys.modules, "maverick.postgres_io", fake_io)
    monkeypatch.setattr(pt, "postgres_connection_kwargs", lambda _: {
        "autocommit": False, "connect_timeout": 3, "options": "-c statement_timeout=50",
    })
    return Pool


def test_pool_shared_across_namespaces_but_not_credentials_or_options(fake_pool):
    first = pt.PostgresTransactions("dsn-one", pool_size=1, pool_timeout_seconds=.2)
    same = pt.PostgresTransactions("dsn-one", pool_size=1, pool_timeout_seconds=.2)
    other = pt.PostgresTransactions("dsn-two", pool_size=1, pool_timeout_seconds=.2)
    for facility in (first, same, other):
        with facility.transaction():
            pass
    assert len(fake_pool.instances) == 2
    pool = fake_pool.instances[0]
    assert pool.timeouts == [.2, .2]
    assert pool.kwargs["kwargs"]["connect_timeout"] == 3
    assert pool.kwargs["max_waiting"] == 64 and pool.kwargs["min_size"] == 1
    assert "dsn-one" not in repr(pt._POOLS.keys())
    assert pool.connection.statements[-1][0] == "SELECT set_config('maverick.tenant', '', false)"


def test_pool_acquisition_timeout_does_not_start_or_retry_transaction(fake_pool):
    facility = pt.PostgresTransactions("dsn", pool_size=1, pool_timeout_seconds=.1)
    with facility.transaction():
        pass
    pool = fake_pool.instances[0]
    pool.acquire_error = TimeoutError("pool exhausted")
    committed = pool.connection.commits
    with pytest.raises(TimeoutError), facility.transaction():
        pytest.fail("transaction must not start")
    assert pool.timeouts == [.1, .1]
    assert pool.connection.commits == committed
    assert not pt.postgres_pools_pending()


def test_failed_return_cannot_replace_original_stop(fake_pool, monkeypatch):
    facility = pt.PostgresTransactions("dsn", pool_size=1)
    with facility.transaction():
        pass
    pool = fake_pool.instances[0]
    def fail_return(connection):
        raise OSError("pool bookkeeping failed")
    monkeypatch.setattr(pool, "putconn", fail_return)
    original = StopWork("stop remains authoritative")
    with pytest.raises(StopWork) as caught, facility.transaction():
        raise original
    assert caught.value is original
    assert pool.connection.closes == 1


def test_shutdown_retains_live_lease_and_closer_ownership(fake_pool):
    facility = pt.PostgresTransactions("dsn", pool_size=1)
    with facility.transaction():
        pool = fake_pool.instances[0]
        pool.close_release = threading.Event()
        pt.close_postgres_pools(timeout=0, wait=False)
        assert pt.postgres_pools_pending()
        with pytest.raises(RuntimeError, match="pending"):
            pt.open_postgres_pools()
        with pytest.raises(RuntimeError, match="admission"), facility.transaction():
            pytest.fail("closed admission must refuse")
    assert pt.postgres_pools_pending()
    pool.close_release.set()
    pt.close_postgres_pools(timeout=2)
    assert not pt.postgres_pools_pending()
    assert len(pool.closed) == 1
    pt.open_postgres_pools()
    with facility.transaction():
        pass
    assert len(fake_pool.instances) == 2


def test_failed_cleanup_or_thread_start_stays_visible(fake_pool, monkeypatch):
    facility = pt.PostgresTransactions("dsn", pool_size=1)
    with facility.transaction():
        pass
    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, "start", lambda self: (_ for _ in ()).throw(RuntimeError("start failed")))
        with pytest.raises(RuntimeError, match="start failed"):
            pt.close_postgres_pools(timeout=0, wait=False)
    assert pt.postgres_pools_pending()
    # Test owns cleanup after deliberately failing the thread-start boundary.
    fake_pool.instances[0].close(timeout=1)


def test_pool_identity_capacity_fails_closed(fake_pool):
    for index in range(pt._MAX_POOLS):
        with pt.PostgresTransactions(f"dsn-{index}", pool_size=1).transaction():
            pass
    with pytest.raises(RuntimeError, match="capacity"):
        with pt.PostgresTransactions("one-too-many", pool_size=1).transaction():
            pass


@pytest.mark.parametrize("size,timeout,valid", [(0, 5, True), (1, .1, True), (32, 60, True),
                                             ("1", 5, False), (True, 5, False), (1, -1, False)])
def test_governed_configuration_reaches_validated_pool_policy(monkeypatch, size, timeout, valid):
    from maverick import config
    from maverick import governed_records as gr
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", "postgresql://db.invalid/test")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setattr(config, "load_governed_records_config", lambda: {
        "governed_records": {"pool_size": size, "pool_timeout_seconds": timeout},
    })
    monkeypatch.setattr(config, "governed_records_config_source_errors", dict)
    if not valid:
        with pytest.raises(gr.GovernedRecordBackendError):
            gr._selection()
    else:
        selection = gr._selection()
        assert (selection.pool_size, selection.pool_timeout_seconds) == (size, timeout)


def test_changed_pool_policy_requires_process_restart():
    from maverick import governed_records as gr
    first = gr._BackendSelection("postgres", "not-a-secret-dsn", False, 1, 5)
    changed = gr._BackendSelection("postgres", "not-a-secret-dsn", False, 2, 5)
    assert not gr._backend_authority_matches(gr._backend_authority_token(first),
                                             gr._backend_authority_token(changed))


def test_a_block_that_swallowed_a_database_error_is_not_reported_as_committed():
    connection = Connection()
    connection.info = SimpleNamespace(transaction_status=SimpleNamespace(name="IDLE"))

    def connect(*args, **kwargs):
        return connection
    facility = pt.PostgresTransactions("private-test-adapter", connect=connect)
    with pytest.raises(pt.TransactionAborted), facility.transaction() as cursor:
        cursor.execute("write that failed")
        # the caller caught the database error and carried on; the server now
        # holds an aborted transaction that COMMIT would silently roll back
        connection.info.transaction_status = SimpleNamespace(name="INERROR")
    assert connection.commits == 0 and connection.rollbacks == 1


def test_pool_keeps_one_idle_connection_by_default_and_the_floor_is_configurable(fake_pool):
    default = pt.PostgresTransactions("dsn-min", pool_size=4, pool_timeout_seconds=.2)
    with default.transaction():
        pass
    assert fake_pool.instances[-1].kwargs["min_size"] == 1
    cold = pt.PostgresTransactions("dsn-min", pool_size=4, pool_timeout_seconds=.2, pool_min_size=0)
    with cold.transaction():
        pass
    assert fake_pool.instances[-1].kwargs["min_size"] == 0  # a different pool identity
    capped = pt.PostgresTransactions("dsn-min", pool_size=2, pool_timeout_seconds=.2, pool_min_size=9)
    with capped.transaction():
        pass
    assert fake_pool.instances[-1].kwargs["min_size"] == 2  # never above max_size


@pytest.mark.parametrize("min_size", [True, -1, 1.5, "1"])
def test_invalid_pool_min_size_refuses(min_size):
    with pytest.raises(ValueError, match="pool_min_size"):
        pt.PostgresTransactions("unused", pool_size=2, pool_min_size=min_size)
