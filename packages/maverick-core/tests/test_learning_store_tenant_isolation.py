"""Multi-tenant isolation for the shared world learning store.

A single Postgres DSN backs every tenant, so the fleet-learning tables
(``harness_addenda`` and friends) must carry a ``tenant_id`` and scope every
read/write to the active tenant -- otherwise one customer's learned guidance
would surface in another's Cortex recall. The SQLite store needs none: its
``data_dir``-scoped ``world.db`` is already a different file per tenant.

The faithful-double test runs everywhere (no Postgres); the round-trip test
runs only on the dedicated CI ``postgres`` job (``MAVERICK_PG_DSN`` set).
"""
from __future__ import annotations

import contextlib
import os

import pytest
from maverick import learning_store as ls
from maverick.paths import reset_tenant, set_tenant

# --- backend-agnostic faithful double (runs everywhere) ---------------------

class _FakeCursor:
    """A tiny in-memory stand-in for a psycopg cursor over ``harness_addenda``
    that honours the tenant_id predicate, so isolation is proven by behaviour
    (A writes, B cannot read it) rather than by SQL-string matching alone."""

    def __init__(self, db: _FakeDB) -> None:
        self.db = db
        self._result: list[tuple] = []

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def execute(self, sql: str, params: tuple = ()) -> None:
        s = " ".join(sql.split())
        params = tuple(params)
        self.db.log.append((s, params))
        if s.startswith(("CREATE TABLE", "ALTER TABLE")):
            return
        if s.startswith("DELETE FROM harness_addenda"):
            self.db.rows = [r for r in self.db.rows if not self._match(s, params, r)]
        elif s.startswith("INSERT INTO harness_addenda"):
            tenant = params[3] if "tenant_id" in s else None
            self.db.rows.append((params[0], params[1], params[2], tenant))
        elif s.startswith("SELECT key, block FROM harness_addenda"):
            self._result = [
                (r[0], r[1]) for r in self.db.rows if self._match(s, params, r)
            ]
        else:  # pragma: no cover - defensive
            self._result = []

    @staticmethod
    def _match(sql: str, params: tuple, row: tuple) -> bool:
        row_tenant = row[3]
        if "tenant_id = %s" in sql:
            return row_tenant == params[-1]
        if "tenant_id IS NULL" in sql:
            return row_tenant is None
        return True  # unscoped (SQLite shape) -- would match everything

    def fetchall(self) -> list[tuple]:
        return self._result


class _FakeDB:
    def __init__(self) -> None:
        self.rows: list[tuple] = []
        self.log: list[tuple] = []


class _FakeConn:
    def __init__(self, db: _FakeDB) -> None:
        self.db = db

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self.db)


@pytest.fixture
def pg_double(monkeypatch):
    db = _FakeDB()
    monkeypatch.setattr(ls, "_postgres", lambda: True)

    @contextlib.contextmanager
    def _conn():
        yield _FakeConn(db)

    monkeypatch.setattr(ls, "_conn", _conn)
    return db


def _under(tenant, fn, *a):
    tok = set_tenant(tenant)
    try:
        return fn(*a)
    finally:
        reset_tenant(tok)


def test_addenda_are_scoped_to_the_active_tenant_on_postgres(pg_double):
    _under("acme", ls.write_addenda_db, {"M": "acme guidance"})
    # A second tenant sees NONE of acme's rows...
    assert _under("globex", ls.load_addenda_db) == {}
    # ...and its own write does not clobber acme's (scoped DELETE).
    _under("globex", ls.write_addenda_db, {"M": "globex guidance"})
    assert _under("acme", ls.load_addenda_db) == {"M": "acme guidance"}
    assert _under("globex", ls.load_addenda_db) == {"M": "globex guidance"}


def test_unbound_store_only_sees_null_tenant_rows(pg_double):
    # The legacy single-tenant deployment (no active tenant) writes/reads the
    # NULL-tenant partition and never sees a named tenant's rows.
    _under("acme", ls.write_addenda_db, {"M": "acme guidance"})
    tok = set_tenant(None)
    try:
        assert ls.load_addenda_db() == {}
        ls.write_addenda_db({"M": "shared guidance"})
        assert ls.load_addenda_db() == {"M": "shared guidance"}
    finally:
        reset_tenant(tok)
    assert _under("acme", ls.load_addenda_db) == {"M": "acme guidance"}


def test_write_stamps_tenant_and_delete_is_scoped(pg_double):
    _under("acme", ls.write_addenda_db, {"M": "x"})
    inserts = [s for s, _p in pg_double.log if s.startswith("INSERT INTO harness_addenda")]
    deletes = [(s, p) for s, p in pg_double.log if s.startswith("DELETE FROM harness_addenda")]
    assert inserts and all("tenant_id" in s for s in inserts)
    assert deletes and deletes[0][0].endswith("WHERE tenant_id = %s")
    assert deletes[0][1] == ("acme",)


def test_invalid_client_binding_raises_instead_of_using_unbound_partition(
        pg_double, monkeypatch):
    from maverick.client import ClientBindingError

    monkeypatch.setenv("MAVERICK_CLIENT_ID", "bad id!!")
    tok = set_tenant(None)
    try:
        with pytest.raises(ClientBindingError):
            ls.write_addenda_db({"M": "x"})
    finally:
        reset_tenant(tok)
    assert pg_double.rows == []


# --- live Postgres round-trip (CI postgres job only) ------------------------

_DSN = os.environ.get("MAVERICK_PG_DSN")


@pytest.mark.skipif(not _DSN, reason="MAVERICK_PG_DSN not set (no Postgres service)")
def test_world_learning_store_isolates_tenants_on_live_postgres(monkeypatch, postgres_test_dsn):
    pytest.importorskip("psycopg")
    monkeypatch.setattr(ls, "_postgres", lambda: True)
    monkeypatch.setenv("MAVERICK_PG_DSN", postgres_test_dsn)

    marker = f"iso-{os.getpid()}"
    try:
        _under("iso_alpha", ls.write_addenda_db, {"M": f"alpha {marker}"})
        _under("iso_beta", ls.write_addenda_db, {"M": f"beta {marker}"})

        alpha = _under("iso_alpha", ls.load_addenda_db)
        beta = _under("iso_beta", ls.load_addenda_db)
        assert alpha == {"M": f"alpha {marker}"}
        assert beta == {"M": f"beta {marker}"}
        # No cross-tenant leak in either direction.
        assert marker not in "".join(v for v in alpha.values() if "beta" in v)
        assert all("beta" not in v for v in alpha.values())
        assert all("alpha" not in v for v in beta.values())
    finally:
        import psycopg
        with psycopg.connect(postgres_test_dsn, autocommit=True) as c, c.cursor() as cur:
            cur.execute(
                "DELETE FROM harness_addenda WHERE tenant_id IN "
                "('iso_alpha', 'iso_beta')"
            )
