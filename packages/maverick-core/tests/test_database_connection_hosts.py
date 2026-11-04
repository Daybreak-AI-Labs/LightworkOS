"""A permitted URL label must not authorize a different database destination."""
from __future__ import annotations

import sys
import types

import pytest
from maverick.tools.database_tool import database_tool


@pytest.fixture
def intercepted_engine(monkeypatch):
    calls = []

    def create_engine(url, **kwargs):
        calls.append((url, kwargs))
        raise RuntimeError("test connection intercepted")

    module = types.ModuleType("sqlalchemy")
    module.create_engine = create_engine
    module.text = lambda value: value
    monkeypatch.setitem(sys.modules, "sqlalchemy", module)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    return calls


@pytest.mark.parametrize("url", [
    "postgresql+psycopg://fixture@db.corp.internal/db?hostaddr=127.0.0.1",
    "postgresql+psycopg://fixture@db.corp.internal/db?host=outside.example,db.corp.internal",
    "postgresql+psycopg://fixture@outside.example,db.corp.internal/db",
    "postgresql+psycopg://fixture@db.corp.internal/db?host=outside.example%2Cdb.corp.internal",
    "postgresql+psycopg://fixture@db.corp.internal/db?host=",
    "postgresql+psycopg://fixture@db.corp.internal/db?host=db.corp.internal,",
    "postgresql+psycopg://fixture@db.corp.internal/db?service=alternate",
    "mssql+pyodbc://fixture@db.corp.internal/db?odbc_connect=DSN%3Dalternate",
    "mssql+pyodbc://fixture@db.corp.internal/db?Address=outside.example",
    "mssql+pyodbc://fixture@db.corp.internal/db?Addr=outside.example",
    "mssql+pyodbc://fixture@db.corp.internal/db?Server=outside.example",
    "mssql+pyodbc://fixture@db.corp.internal/db?Failover_Partner=outside.example",
    "mssql+pyodbc://fixture@db.corp.internal/db?FileDSN=/tmp/alternate.dsn",
    "mssql+pyodbc://fixture@db.corp.internal",
    "mssql://fixture@db.corp.internal",
    "mssql+pyodbc:///?host=db.corp.internal",
    "oracle+oracledb://fixture@db.corp.internal",
    "oracle+oracledb://fixture@db.corp.internal/db?dsn=outside.example",
    "mysql+pymysql://fixture@db.corp.internal/db?unix_socket=/tmp/mysql.sock",
    "mysql+pymysql://fixture@db.corp.internal/db?read_default_file=/tmp/alternate.cnf",
])
@pytest.mark.parametrize("source", ["model", "operator"])
def test_scoped_query_refuses_alternate_or_implicit_destination(
    monkeypatch, intercepted_engine, url, source,
):
    args = {"op": "query", "sql": "SELECT 1",
            "_capability_allow_hosts": ("*.corp.internal",)}
    if source == "model":
        args["url"] = url
    else:
        monkeypatch.setenv("DATABASE_URL", url)
    result = database_tool().fn(args)
    assert "DENIED by capability" in result
    assert intercepted_engine == []


@pytest.mark.parametrize("url,hosts", [
    ("postgresql+psycopg://fixture@DB.CORP.INTERNAL:5432/db", ("*.corp.internal",)),
    ("oracle+oracledb://fixture@db.corp.internal/instance", ("*.corp.internal",)),
    ("oracle+oracledb://fixture@db.corp.internal/?service_name=application", ("*.corp.internal",)),
    ("postgresql+psycopg://fixture@/db?host=db.corp.internal:5432&host=standby.corp.internal:5433",
     ("*.corp.internal",)),
    ("postgresql+psycopg://fixture@/db?host=db.corp.internal,standby.corp.internal",
     ("*.corp.internal",)),
    ("postgresql+psycopg://fixture@db.corp.internal/db?hostaddr=127.0.0.1",
     ("*.corp.internal", "127.0.0.1")),
    ("postgresql+psycopg://fixture@db.corp.internal/db?hostaddr=::1",
     ("*.corp.internal", "::1")),
])
def test_every_explicitly_granted_destination_can_reach_driver(intercepted_engine, url, hosts):
    result = database_tool().fn({
        "op": "query", "sql": "SELECT 1", "url": url,
        "_capability_allow_hosts": hosts,
    })
    assert result.startswith("ERROR: database query failed (RuntimeError)")
    assert intercepted_engine and intercepted_engine[0][0] == url


def test_unscoped_operator_connection_keeps_service_options(monkeypatch, intercepted_engine):
    url = "postgresql+psycopg://fixture@db.corp.internal/db?service=customer"
    monkeypatch.setenv("DATABASE_URL", url)
    result = database_tool().fn({"op": "query", "sql": "SELECT 1"})
    assert result.startswith("ERROR: database query failed (RuntimeError)")
    assert intercepted_engine[0][0] == url


@pytest.mark.parametrize("query,expected", [
    ("hostaddr=127.0.0.1", {"host": "db.corp.internal", "hostaddr": "127.0.0.1"}),
    ("host=outside.example,db.corp.internal", {"host": "outside.example,db.corp.internal"}),
])
def test_real_driver_receives_only_explicitly_granted_targets(monkeypatch, query, expected):
    pytest.importorskip("sqlalchemy")
    psycopg = pytest.importorskip("psycopg")
    calls = []

    def connect(*args, **kwargs):
        calls.append(kwargs)
        raise psycopg.OperationalError("test driver intercepted")

    monkeypatch.setattr(psycopg, "connect", connect)
    result = database_tool().fn({
        "op": "query", "sql": "SELECT 1",
        "url": "postgresql+psycopg://fixture@db.corp.internal/db?" + query,
        "_capability_allow_hosts": ("*.corp.internal",),
    })
    assert "DENIED by capability" in result and calls == []

    result = database_tool().fn({
        "op": "query", "sql": "SELECT 1",
        "url": "postgresql+psycopg://fixture@db.corp.internal/db?" + query,
        "_capability_allow_hosts": ("*.corp.internal", "outside.example", "127.0.0.1"),
    })
    assert result.startswith("ERROR: database query failed (OperationalError)") and len(calls) == 1
    assert all(calls[0][key] == value for key, value in expected.items())


@pytest.mark.parametrize("key", ["Address", "Addr", "Server", "Failover_Partner"])
def test_real_odbc_configuration_cannot_redirect_outside_grant(key):
    pytest.importorskip("sqlalchemy")
    from maverick.tools.database_tool import _host_denial
    from sqlalchemy.dialects.mssql.pyodbc import MSDialect_pyodbc
    from sqlalchemy.engine import make_url

    url = ("mssql+pyodbc://fixture@db.corp.internal/db"
           "?driver=ODBC+Driver+18+for+SQL+Server&" + key + "=outside.example")
    # Actual SQLAlchemy translation, without loading an ODBC driver or opening
    # a connection: these options reach the native connection string unchanged.
    connection_args, _ = MSDialect_pyodbc().create_connect_args(make_url(url))
    assert key + "=outside.example" in connection_args[0]
    assert "DENIED by capability" in _host_denial(url, ("*.corp.internal",))
    assert _host_denial(url, ("*.corp.internal", "outside.example")) is None


@pytest.mark.parametrize("url", [
    "mssql+pyodbc://fixture@db.corp.internal",
    "mssql://fixture@db.corp.internal",
    "mssql+pyodbc:///?host=db.corp.internal",
])
def test_real_odbc_hostname_without_database_is_an_indirect_dsn(url):
    pytest.importorskip("sqlalchemy")
    from maverick.tools.database_tool import _host_denial
    from sqlalchemy.dialects.mssql.pyodbc import MSDialect_pyodbc
    from sqlalchemy.engine import make_url

    connection_args, _ = MSDialect_pyodbc().create_connect_args(make_url(url))
    assert "dsn=db.corp.internal" in connection_args[0]
    assert "DENIED by capability" in _host_denial(url, ("*.corp.internal",))
    assert _host_denial(url, ()) is None


def test_real_oracle_authority_without_service_is_an_indirect_tns_alias():
    pytest.importorskip("sqlalchemy")
    from maverick.tools.database_tool import _host_denial
    from sqlalchemy.dialects.oracle.oracledb import OracleDialect_oracledb
    from sqlalchemy.engine import make_url

    url = "oracle+oracledb://fixture@db.corp.internal"
    _, connection_kwargs = OracleDialect_oracledb().create_connect_args(make_url(url))
    assert connection_kwargs["dsn"] == "db.corp.internal"
    assert "DENIED by capability" in _host_denial(url, ("*.corp.internal",))
    assert _host_denial(url, ()) is None
