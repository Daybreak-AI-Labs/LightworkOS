"""Relational `database` tool (SQLAlchemy). Driver/network-free paths."""
from __future__ import annotations


def test_database_registers(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    names = {t.name for t in base_registry(_W(), LocalBackend(workdir=tmp_path)).all()}
    assert "database" in names


def test_requires_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from maverick.tools.database_tool import database_tool
    out = database_tool().fn({"op": "query", "sql": "select 1"})
    assert "ERROR" in out and "DATABASE_URL" in out


def test_write_needs_confirm(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost/db")
    from maverick.tools.database_tool import database_tool
    out = database_tool().fn({"op": "query", "sql": "DELETE FROM t WHERE 1=1"})
    assert "DRY RUN" in out


def test_read_returns_error_gracefully_without_server(monkeypatch):
    # No reachable DB / maybe no driver: must return an ERROR string, not raise.
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@127.0.0.1:1/db")
    from maverick.tools.database_tool import database_tool
    out = database_tool().fn({"op": "query", "sql": "SELECT 1"})
    assert out.startswith("ERROR")


def test_cte_prefixed_write_needs_confirm(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost/db")
    from maverick.tools.database_tool import database_tool

    out = database_tool().fn({
        "op": "query",
        "sql": "WITH victims AS (SELECT id FROM users) DELETE FROM users USING victims",
    })

    assert "DRY RUN" in out


def test_explain_prefixed_sql_needs_confirm(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost/db")
    from maverick.tools.database_tool import database_tool

    out = database_tool().fn({"op": "query", "sql": "EXPLAIN ANALYZE DELETE FROM users"})

    assert "DRY RUN" in out


def test_pragma_is_always_governed_as_potentially_mutating(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    from maverick.tools.database_tool import database_tool

    for sql in (
        "PRAGMA user_version",
        "PRAGMA user_version = 7",
        "PRAGMA writable_schema=ON",
        "PRAGMA journal_mode=WAL",
    ):
        assert "DRY RUN" in database_tool().fn({"op": "query", "sql": sql}), sql


def test_select_forms_with_known_side_effects_need_confirm(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://u:p@localhost/db")
    from maverick.tools.database_tool import database_tool

    for sql in (
        "SELECT 'owned' INTO OUTFILE '/tmp/pwn'",
        "SELECT * INTO copied_accounts FROM accounts",
        "SELECT * FROM accounts FOR UPDATE",
        "SELECT GET_LOCK('nightly', 30)",
        "SELECT nextval('invoice_seq')",
        # Effects behind VALUES, DESC-as-EXPLAIN and underscore-prefixed names.
        "VALUES (setval('orders_id_seq', 1))",
        "select pg_sleep(100000)",
        "DESC ANALYZE DELETE t1 FROM t1 JOIN t2 ON t1.id = t2.id",
        "SELECT pg_terminate_backend(123)",
        "SELECT load_file('/etc/passwd')",
    ):
        assert "DRY RUN" in database_tool().fn({"op": "query", "sql": sql}), sql


def test_identifiers_resembling_effect_functions_stay_reads():
    from maverick.tools.database_tool import _is_read_sql
    for sql in ("SELECT lo_price FROM items", "SELECT * FROM user_sleep",
                "SELECT 'asleep'", "SHOW CREATE TABLE lo_items"):
        assert _is_read_sql(sql), sql
    for sql in ("SELECT SLEEP(5)", "select lo_unlink(3)", "select pg_sleep_for('1s')"):
        assert not _is_read_sql(sql), sql


def test_comment_prefixed_write_needs_confirm(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost/db")
    from maverick.tools.database_tool import database_tool

    for sql in (
        "/* select */ DELETE FROM users",
        "-- SELECT\nDROP TABLE users",
        "  (/* select */ UPDATE users SET admin = true)",
    ):
        out = database_tool().fn({"op": "query", "sql": sql})
        assert "DRY RUN" in out


def test_returning_write_is_committed(monkeypatch, tmp_path):
    # A confirmed write with a RETURNING clause reports returns_rows, so it took
    # the row path -- SQLAlchemy 2.0 is commit-as-you-go, so without an explicit
    # commit the connection rolls the write back on block exit and the mutation
    # is silently lost. Use a file-backed sqlite URL (no driver/network needed).
    import pytest
    pytest.importorskip("sqlalchemy")
    db = tmp_path / "d.db"
    url = f"sqlite:///{db}"
    monkeypatch.setenv("DATABASE_URL", url)
    from maverick.tools.database_tool import database_tool
    t = database_tool()
    assert "ok" in t.fn({"op": "query",
                         "sql": "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)",
                         "confirm": True}).lower()
    out = t.fn({"op": "query",
                "sql": "INSERT INTO t(id, v) VALUES(1, 'x') RETURNING id",
                "confirm": True})
    assert "1" in out
    # A fresh read (new engine/connection) must see the committed row.
    check = t.fn({"op": "query", "sql": "SELECT v FROM t WHERE id = 1"})
    assert "x" in check


def test_row_returning_read_classified_sql_is_not_committed(monkeypatch):
    import sys
    import types

    committed = {"called": False}

    class _Result:
        returns_rows = True

        def keys(self):
            return ["n"]

        def fetchmany(self, _size):
            return [(1,)]

        def close(self):
            pass

    class _Conn:
        def execute(self, _stmt):
            return _Result()

        def commit(self):
            committed["called"] = True

        def rollback(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Engine:
        def connect(self):
            return _Conn()

        def dispose(self):
            pass

    fake_sa = types.ModuleType("sqlalchemy")
    fake_sa.create_engine = lambda url, **kwargs: _Engine()
    fake_sa.text = lambda s: s
    monkeypatch.setitem(sys.modules, "sqlalchemy", fake_sa)

    # DATABASE_URL (operator-set), not a model-supplied url arg -- this test
    # is about commit behavior for read-classified SQL with side effects,
    # unrelated to the url-arg capability gate.
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost/db")
    from maverick.tools.database_tool import database_tool

    out = database_tool().fn({
        "op": "query",
        "sql": "SELECT perform_side_effect()",
    })

    assert "columns: ['n']" in out
    assert committed["called"] is False


def test_mysql_executable_comment_needs_confirm(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://u:p@localhost/db")
    from maverick.tools.database_tool import database_tool

    for sql in (
        "/*! INSERT INTO audit_log */ SELECT * FROM users",
        "/*!80000 INSERT INTO audit_log */ SELECT * FROM users",
        "/*M! INSERT INTO audit_log */ SELECT * FROM users",
        "/*M!100100 INSERT INTO audit_log */ SELECT * FROM users",
    ):
        out = database_tool().fn({"op": "query", "sql": sql})
        assert "DRY RUN" in out


def test_comment_prefixed_read_is_allowed(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from maverick.tools.database_tool import database_tool

    out = database_tool().fn({"op": "query", "sql": "/* allowed */ -- still allowed\nSELECT 1"})

    assert "DATABASE_URL" in out


def test_stacked_write_behind_select_needs_confirm(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost/db")
    from maverick.tools.database_tool import database_tool

    for sql in (
        "SELECT 1; DELETE FROM users",
        "SELECT * FROM t WHERE x=1; DROP TABLE t",
        # Dollar quotes and `#` comments must not hide a separator.
        "select $a$ -- $a$; drop table t",
        "select $$ ' $$; drop table t; select $$ ' $$",
        "select 1 # '\n; delete from t where true; select 2 # '",
    ):
        out = database_tool().fn({"op": "query", "sql": sql})
        assert "DRY RUN" in out, sql


def test_host_param_in_query_string_is_denied(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from maverick.tools.database_tool import database_tool

    # libpq honors ?host=; the netloc host is empty, so a netloc-only check
    # would fail open.
    for url in (
        "postgresql:///db?host=evil.com",
        "postgresql+psycopg://u@/db?host=evil.com",
    ):
        out = database_tool().fn({
            "op": "query",
            "sql": "SELECT 1",
            "url": url,
            "_capability_allow_hosts": ("*.corp.internal",),
        })
        assert "DENIED by capability" in out, url


def test_hostless_url_fails_closed_under_allowlist(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from maverick.tools.database_tool import database_tool

    out = database_tool().fn({
        "op": "query",
        "sql": "SELECT 1",
        "url": "postgresql:///db",
        "_capability_allow_hosts": ("*.corp.internal",),
    })
    assert "DENIED by capability" in out


def test_row_limit_is_clamped(monkeypatch):
    monkeypatch.delenv("MAVERICK_DATABASE_MAX_ROWS", raising=False)
    import types

    captured = {}

    class _Result:
        returns_rows = True

        def keys(self):
            return ["n"]

        def fetchmany(self, size):
            captured["size"] = size
            return []

        def close(self):
            pass

    class _Conn:
        def execute(self, _stmt):
            return _Result()

        def commit(self):
            pass

        def rollback(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    disposed = {"called": False}

    class _Engine:
        def connect(self):
            return _Conn()

        def dispose(self):
            disposed["called"] = True

    fake_sa = types.ModuleType("sqlalchemy")
    fake_sa.create_engine = lambda url, **kwargs: _Engine()
    fake_sa.text = lambda s: s
    monkeypatch.setitem(__import__("sys").modules, "sqlalchemy", fake_sa)

    # DATABASE_URL (operator-set), not a model-supplied url arg -- this test
    # is about row-limit clamping, unrelated to the url-arg capability gate.
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost/db")
    from maverick.tools.database_tool import database_tool

    database_tool().fn({
        "op": "query",
        "sql": "SELECT 1",
        "limit": 100_000_000,
    })
    assert captured["size"] == 1001  # bounded row allowance plus one completeness sentinel
    assert disposed["called"] is True  # engine pool released


def test_database_url_host_scope_applies_to_env_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@evil.com/db")
    from maverick.tools.database_tool import database_tool

    out = database_tool().fn({
        "op": "query",
        "sql": "SELECT 1",
        "_capability_allow_hosts": ("*.example.com",),
    })

    assert "DENIED by capability" in out
    assert "evil.com" in out


def test_model_supplied_url_denied_without_allow_hosts_or_knob(monkeypatch):
    # With no allow_hosts grant and the opt-in knob off (default), a
    # model-supplied url must be refused outright -- not merely capability
    # scoped -- so an agent cannot pick an arbitrary reachable DB server.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("MAVERICK_DATABASE_ALLOW_URL_ARG", raising=False)
    from maverick.tools.database_tool import database_tool

    out = database_tool().fn({
        "op": "query",
        "sql": "SELECT 1",
        "url": "postgresql+psycopg://u:p@attacker.example/db",
    })

    assert "DENIED" in out
    assert "database_allow_url_arg" in out


def test_model_supplied_sqlite_url_denied_even_with_allow_hosts(monkeypatch):
    # Sqlite: has no host for allow_hosts to scope, so it is refused
    # unconditionally -- granting allow_hosts must not open this back up,
    # since it would let an agent read/write this deployment's own world.db.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from maverick.tools.database_tool import database_tool

    out = database_tool().fn({
        "op": "query",
        "sql": "SELECT 1",
        "url": "sqlite:///./world.db",
        "_capability_allow_hosts": ("*",),
    })

    assert "DENIED" in out
    assert "sqlite" in out


def test_model_supplied_url_allowed_when_opt_in_knob_set(monkeypatch):
    # The MAVERICK_DATABASE_ALLOW_URL_ARG knob is the deliberate operator
    # opt-in that lets a model-supplied non-sqlite url proceed with no
    # allow_hosts grant -- confirm it actually reaches host-scope, not the
    # url-arg gate, by pairing it with a real reproduction below.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("MAVERICK_DATABASE_ALLOW_URL_ARG", "1")
    from maverick.tools.database_tool import database_tool

    out = database_tool().fn({
        "op": "query",
        "sql": "SELECT 1",
        "url": "postgresql+psycopg://u:p@127.0.0.1:1/db",
    })

    # Past the url-arg gate: fails at connection time (nothing listening),
    # not at the capability/knob gate.
    assert "DENIED" not in out
    assert out.startswith("ERROR")


def test_model_supplied_sqlite_reproduction_now_denied(monkeypatch, tmp_path):
    # Direct reproduction of the original vulnerability: a
    # model-supplied sqlite: url pointing at a file containing secret data,
    # with no allow_hosts grant and the opt-in knob off (default). Before the
    # fix this read the row straight back to the model; now it must deny.
    import pytest
    pytest.importorskip("sqlalchemy")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("MAVERICK_DATABASE_ALLOW_URL_ARG", raising=False)

    db = tmp_path / "secrets.db"
    url = f"sqlite:///{db}"

    from sqlalchemy import create_engine, text
    engine = create_engine(url)
    with engine.connect() as conn:
        conn.execute(text("CREATE TABLE secrets(id INTEGER PRIMARY KEY, v TEXT)"))
        conn.execute(text("INSERT INTO secrets(id, v) VALUES(1, 'top-secret')"))
        conn.commit()
    engine.dispose()

    from maverick.tools.database_tool import database_tool

    out = database_tool().fn({
        "op": "query",
        "sql": "SELECT v FROM secrets",
        "url": url,
    })

    assert "DENIED" in out
    assert "top-secret" not in out


def test_world_database_is_refused_unless_the_organisation_allows_it(monkeypatch, tmp_path):
    # The world database's row policies trust a session setting any SQL on the
    # connection can change, so the tool must not open it: neither through
    # DATABASE_URL nor through a model-supplied url, whatever the driver,
    # spelling of localhost or form of the world DSN. A workspace's own
    # settings file cannot allow it; only the organisation's can.
    from maverick.tools.database_tool import database_tool

    monkeypatch.setenv("MAVERICK_PG_DSN", "host=localhost port=5433 dbname=lightwork user=app")
    monkeypatch.delenv("MAVERICK_DATABASE_ALLOW_WORLD_DATABASE", raising=False)
    monkeypatch.setenv("MAVERICK_DATABASE_ALLOW_URL_ARG", "1")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://reader:pw@127.0.0.1:5433/lightwork")

    def run(url=""):
        return database_tool().fn({"op": "query", "sql": "SELECT 1", "url": url})

    assert "DENIED" in run() and "records database" in run()
    assert "DENIED" in run("postgres://other@localhost:5433/lightwork?sslmode=disable")
    # Another database on the same server, or another server, is not refused.
    for elsewhere in ("postgresql+psycopg://u:p@127.0.0.1:5433/reports",
                      "postgresql+psycopg://u:p@127.0.0.1:1/lightwork"):
        assert "DENIED" not in run(elsewhere)
    # A workspace overlay cannot allow it; the organisation's switch can.
    from maverick.paths import maverick_home

    tenant_dir = maverick_home() / "tenants" / "acme"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "config.toml").write_text("[tools]\ndatabase_allow_world_database = true\n")
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    assert "DENIED" in run()
    monkeypatch.setenv("MAVERICK_DATABASE_ALLOW_WORLD_DATABASE", "1")
    assert "DENIED" not in run()  # it now tries to connect


def _local_forms():
    import socket

    return [
        "postgresql+psycopg://u:p@127.0.0.2:5433/lightwork",
        "postgresql+psycopg://u:p@0.0.0.0:5433/lightwork",
        "postgresql+psycopg://u:p@[0:0:0:0:0:0:0:1]:5433/lightwork",
        "postgresql+psycopg://u:p@[::ffff:127.0.0.1]:5433/lightwork",
        "postgresql+psycopg://u:p@LOCALHOST.:5433/lightwork",
        f"postgresql+psycopg://u:p@{socket.gethostname()}:5433/lightwork",
        "postgresql+psycopg://u:p@/lightwork?host=/var/run/postgresql&port=5433",
    ]


def test_world_database_guard_knows_every_spelling_of_this_computer(monkeypatch):
    # The world DSN reaches this computer; every other way of naming it, and
    # libpq's PG* defaults that complete a partial address, are the same server.
    from maverick.tools.database_tool import database_tool

    monkeypatch.setenv("MAVERICK_PG_DSN", "host=localhost port=5433 dbname=lightwork user=app")
    monkeypatch.delenv("MAVERICK_DATABASE_ALLOW_WORLD_DATABASE", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("MAVERICK_DATABASE_ALLOW_URL_ARG", "1")
    for name in ("PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGSERVICE"):
        monkeypatch.delenv(name, raising=False)

    def run(url):
        return database_tool().fn({"op": "query", "sql": "SELECT 1", "url": url})

    for url in _local_forms():
        assert "records database" in run(url), url
    monkeypatch.setenv("PGHOST", "localhost")
    monkeypatch.setenv("PGPORT", "5433")
    monkeypatch.setenv("PGDATABASE", "lightwork")
    assert "records database" in run("postgresql+psycopg://u:p@/")
    assert "records database" not in run("postgresql+psycopg://u:p@/reports")
    # A service definition this check cannot read: refused, and said so.
    monkeypatch.setenv("PGSERVICE", "lightwork")
    assert "cannot tell whether" in run("postgresql+psycopg://u:p@/")
    assert "records database" in run("postgresql+psycopg://u:p@localhost/lightwork?service=other")
    assert "records database" not in run("postgresql+psycopg://u:p@db.invalid/x?service=other")


def test_world_database_guard_reads_service_files_and_more_local_spellings(monkeypatch, tmp_path):
    import socket

    from maverick.tools.database_tool import database_tool

    for name in ("PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGSERVICE", "PGSYSCONFDIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("MAVERICK_DATABASE_ALLOW_WORLD_DATABASE", raising=False)
    monkeypatch.setenv("MAVERICK_DATABASE_ALLOW_URL_ARG", "1")
    services = tmp_path / "pg_service.conf"
    services.write_text("[lw]\nhost=localhost\nport=5433\ndbname=lightwork\n\n"
                        "[reports]\nhost=localhost\nport=5433\ndbname=reports\n")
    monkeypatch.setenv("PGSERVICEFILE", str(services))

    def run(url):
        return database_tool().fn({"op": "query", "sql": "SELECT 1", "url": url})

    # The world DSN itself names a service: it is read from the service file.
    monkeypatch.setenv("MAVERICK_PG_DSN", "service=lw user=app")
    assert "records database" in run("postgresql+psycopg://u:p@localhost:5433/lightwork")
    assert "records database" in run("postgresql+psycopg://u:p@/?service=lw")
    assert "DENIED" not in run("postgresql+psycopg://u:p@/?service=reports")
    assert "DENIED" not in run("postgresql+psycopg://u:p@localhost:5433/reports")
    # A service that cannot be read is refused honestly, not called Lightwork's.
    monkeypatch.setenv("MAVERICK_PG_DSN", "service=missing user=app")
    out = run("postgresql+psycopg://u:p@localhost:5433/reports")
    assert "cannot tell whether" in out and "is Lightwork's own" not in out

    # More spellings of this computer.
    monkeypatch.setenv("MAVERICK_PG_DSN", "host=localhost port=5433 dbname=lightwork user=app")
    for host in ("127.1", "127.0.1", "2130706433", "%2Fvar%2Frun%2Fpostgresql"):
        assert "records database" in run(f"postgresql+psycopg://u:p@{host}:5433/lightwork"), host
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))  # no packet is sent; picks this computer's address
        own = probe.getsockname()[0]
    except OSError:
        own = ""
    finally:
        probe.close()
    if own and not own.startswith("127."):
        assert "records database" in run(f"postgresql+psycopg://u:p@{own}:5433/lightwork"), own


def test_own_addresses_are_looked_up_once_per_process(monkeypatch):
    # A slow or missing resolver must not delay every query: the host-name
    # lookup runs once, with a short limit, and its answer is kept.
    import socket

    from maverick.tools import database_tool as tool

    calls = []
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: calls.append(a) or [(0, 0, 0, "", ("192.0.2.77", 0))])
    tool._own_addresses.cache_clear()
    try:
        assert tool._endpoint_host("192.0.2.77") == "local"
        assert tool._endpoint_host("198.51.100.9") == "198.51.100.9"
        assert len(calls) == 1
    finally:
        tool._own_addresses.cache_clear()
