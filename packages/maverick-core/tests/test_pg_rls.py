"""Guided opt-in for Postgres RLS: ownership/legacy-row preflight + NULL backfill.

These exercise the pure SQL-orchestration logic against a fake connection (no
live Postgres), the way test_postgres_rls_unit.py tests policy SQL -- so they run
everywhere, including CI without a DSN.
"""
from __future__ import annotations

import pytest
from maverick.world_model_backends import pg_rls
from maverick.world_model_backends.pg_rls import _PREFLIGHT_TABLES


class _FakeCursor:
    def __init__(self, conn: _FakeConn) -> None:
        self.conn = conn
        self._result: tuple | None = None
        self.rowcount = 0

    def execute(self, sql: str, params: tuple | None = None) -> None:
        self.conn.calls.append((sql, params))
        s = sql.strip().lower()
        if "current_user" in s:
            self._result = (self.conn.role,)
        elif "to_regclass" in s:
            tbl = params[0]
            self._result = (tbl if self.conn.tables.get(tbl, {}).get("exists") else None,)
        elif "pg_get_userbyid" in s:
            self._result = (self.conn.tables[params[0]]["owner"],)
        elif s.startswith("select count(*)"):
            tbl = sql.split("FROM ")[1].split()[0]
            empty = self.conn.tables[tbl].get("empty", 0)
            count = self.conn.tables[tbl]["nulls"] if "is null" in s else 0
            self._result = (count + (empty if "tenant_id = ''" in s else 0),)
        elif s.startswith("update"):
            tbl = sql.split("UPDATE ")[1].split()[0]
            self.rowcount = self.conn.tables[tbl]["nulls"]
            if "tenant_id = ''" in s:
                self.rowcount += self.conn.tables[tbl].get("empty", 0)
            self.conn.updated[tbl] = params[0]
        else:  # pragma: no cover - defensive
            self._result = None

    def fetchone(self) -> tuple | None:
        return self._result


class _FakeConn:
    def __init__(self, role: str, tables: dict[str, dict]) -> None:
        self.role = role
        self.tables = tables
        self.calls: list = []
        self.updated: dict[str, str] = {}
        self.committed = False

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)

    def commit(self) -> None:
        self.committed = True

    def close(self) -> None:
        pass


def _tables(role="app", *, nulls=0, exists=True, owner=None):
    owner = owner if owner is not None else role
    return {t: {"exists": exists, "owner": owner, "nulls": nulls}
            for t in _PREFLIGHT_TABLES}


# --- resolve_dsn precedence -------------------------------------------------

def test_resolve_dsn_prefers_arg_then_env_then_config(monkeypatch):
    monkeypatch.setenv("MAVERICK_PG_DSN", "env-dsn")
    assert pg_rls.resolve_dsn("arg-dsn") == "arg-dsn"
    assert pg_rls.resolve_dsn() == "env-dsn"
    monkeypatch.delenv("MAVERICK_PG_DSN", raising=False)
    monkeypatch.setattr("maverick.config.load_config",
                        lambda *a, **k: {"world_model": {"dsn": "cfg-dsn"}})
    assert pg_rls.resolve_dsn() == "cfg-dsn"


def test_resolve_dsn_empty_when_unconfigured(monkeypatch):
    monkeypatch.delenv("MAVERICK_PG_DSN", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    assert pg_rls.resolve_dsn() == ""


# --- preflight --------------------------------------------------------------

def test_preflight_ready_when_owned_and_no_legacy_rows():
    conn = _FakeConn("app", _tables("app", nulls=0))
    rep = pg_rls.preflight(conn)
    assert rep["role"] == "app"
    assert rep["ready"] is True
    assert all(i["owned_by_current_role"] and i["null_tenant_rows"] == 0
               for i in rep["tables"].values())


def test_preflight_not_ready_with_legacy_null_rows():
    conn = _FakeConn("app", _tables("app", nulls=7))
    rep = pg_rls.preflight(conn)
    assert rep["ready"] is False
    assert all(i["null_tenant_rows"] == 7 for i in rep["tables"].values())


def test_preflight_not_ready_when_role_does_not_own_table():
    conn = _FakeConn("app", _tables("app", nulls=0, owner="postgres"))
    rep = pg_rls.preflight(conn)
    assert rep["ready"] is False
    assert all(i["owned_by_current_role"] is False for i in rep["tables"].values())


def test_preflight_flags_missing_table_without_raising():
    conn = _FakeConn("app", _tables("app", exists=False))
    rep = pg_rls.preflight(conn)
    assert rep["ready"] is False
    assert all(i.get("missing") for i in rep["tables"].values())


# --- backfill ---------------------------------------------------------------

def test_backfill_assigns_null_rows_and_commits():
    conn = _FakeConn("app", _tables("app", nulls=3))
    report = pg_rls.backfill(conn, "acme")
    assert report == dict.fromkeys(_PREFLIGHT_TABLES, 3)
    assert conn.committed is True
    assert conn.updated == dict.fromkeys(_PREFLIGHT_TABLES, "acme")


def test_backfill_dry_run_counts_without_writing():
    conn = _FakeConn("app", _tables("app", nulls=4))
    report = pg_rls.backfill(conn, "acme", dry_run=True)
    assert report == dict.fromkeys(_PREFLIGHT_TABLES, 4)
    assert conn.committed is False
    assert conn.updated == {}


def test_backfill_skips_missing_table():
    conn = _FakeConn("app", _tables("app", nulls=2, exists=False))
    report = pg_rls.backfill(conn, "acme")
    assert report == dict.fromkeys(_PREFLIGHT_TABLES, 0)
    assert conn.updated == {}


def test_backfill_rejects_empty_tenant():
    conn = _FakeConn("app", _tables("app", nulls=1))
    with pytest.raises(ValueError, match="non-empty tenant"):
        pg_rls.backfill(conn, "   ")
    assert conn.committed is False


@pytest.mark.parametrize("table", pg_rls._EMPTY_TENANT_TABLES)
def test_preflight_reports_empty_event_scope_and_requires_ownership(table):
    tables = _tables()
    tables[table]["empty"] = 2
    conn = _FakeConn("app", tables)
    report = pg_rls.preflight(conn)
    assert not report["ready"]
    assert report["tables"][table]["null_tenant_rows"] == 0
    assert report["tables"][table]["empty_tenant_rows"] == 2
    tables[table]["empty"] = 0
    tables[table]["owner"] = "other"
    assert not pg_rls.preflight(conn)["ready"]


def test_backfill_refuses_autocommit_before_any_update():
    conn = _FakeConn("app", _tables(nulls=1))
    conn.autocommit = True
    with pytest.raises(ValueError, match="autocommit disabled"):
        pg_rls.backfill(conn, "alpha")
    assert not conn.calls and not conn.committed


def _event_state(world):
    from maverick import event_admission

    goal, _ = event_admission.admit(
        world, "same-event", "one", "private order", owner="user:synthetic",
        origin="orders", trigger_key="same-trigger")
    batch = event_admission.poll_batch(world, "same-trigger", {
        "events": [{"id": "one", "private": "observed customer payload"}],
        "event_ids": ["one"], "cursor": "next", "cursor_format": 1,
        "before_cursor": "old", "before_format": 0,
    })
    return goal, batch


def test_native_backfill_moves_empty_event_scope_and_preserves_other_tenants(
    postgres_test_dsn, monkeypatch,
):
    import secrets

    import psycopg
    from maverick import event_admission
    from maverick.crypto_at_rest import is_sealed_str
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", secrets.token_hex(32))
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY_DIGEST", raising=False)
    with PostgresWorldModel(postgres_test_dsn) as world:
        with tenant_scope(tenant=None):
            legacy_goal, legacy_batch = _event_state(world)
        with tenant_scope(tenant="beta"):
            beta_goal, beta_batch = _event_state(world)
    with psycopg.connect(postgres_test_dsn) as conn:
        sealed_batch = conn.execute(
            "SELECT sealed_batch FROM event_trigger_batches WHERE tenant_id=''"
        ).fetchone()[0]
        assert is_sealed_str(sealed_batch)
        assert "observed customer payload" not in sealed_batch
        before = pg_rls.preflight(conn)
        assert not before["ready"]
        for table in pg_rls._EMPTY_TENANT_TABLES:
            assert before["tables"][table]["empty_tenant_rows"] == 1
        preview = pg_rls.backfill(conn, "alpha", dry_run=True)
        assert all(preview[table] == 1 for table in pg_rls._EMPTY_TENANT_TABLES)
        assert conn.execute("SELECT tenant_id FROM goals WHERE id=%s", (legacy_goal,)).fetchone() == (None,)
        migrated = pg_rls.backfill(conn, "alpha")
        assert migrated == preview
        assert conn.execute(
            "SELECT sealed_batch FROM event_trigger_batches WHERE tenant_id='alpha'"
        ).fetchone() == (sealed_batch,)
        assert pg_rls.preflight(conn)["ready"]
        assert all(count == 0 for count in pg_rls.backfill(conn, "alpha").values())
    with PostgresWorldModel(postgres_test_dsn) as world:
        with tenant_scope(tenant="alpha"):
            assert event_admission.pending(world, "same-trigger") == [("same-event", legacy_goal, "pending")]
            assert event_admission.poll_batch(world, "same-trigger") == legacy_batch
            assert _event_state(world)[0] == legacy_goal
            assert world.get_goal(legacy_goal).description == "private order"
        with tenant_scope(tenant="beta"):
            assert event_admission.pending(world, "same-trigger") == [("same-event", beta_goal, "pending")]
            assert event_admission.poll_batch(world, "same-trigger") == beta_batch
        with tenant_scope(tenant=None):
            assert event_admission.pending(world, "same-trigger") == []
            assert event_admission.poll_batch(world, "same-trigger") is None


@pytest.mark.parametrize("conflict_table", pg_rls._EMPTY_TENANT_TABLES)
def test_native_event_scope_conflict_rolls_back_every_backfill_table(
    postgres_test_dsn, monkeypatch, conflict_table,
):
    import psycopg
    from maverick import event_admission
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    with PostgresWorldModel(postgres_test_dsn) as world:
        with tenant_scope(tenant=None):
            legacy_goal, legacy_batch = _event_state(world)
        with tenant_scope(tenant="alpha"):
            if conflict_table == "event_goal_admissions":
                event_admission.admit(world, "same-event", "alpha", "existing alpha", owner="user:alpha",
                                      origin="orders", trigger_key="same-trigger")
            else:
                event_admission.poll_batch(world, "same-trigger", {"events": [{"id": "alpha"}]})
    with psycopg.connect(postgres_test_dsn) as conn:
        with pytest.raises(ValueError, match="no rows were reassigned"):
            pg_rls.backfill(conn, "alpha")
        # The failed migration is rolled back, and the connection is usable.
        assert conn.execute("SELECT tenant_id FROM goals WHERE id=%s", (legacy_goal,)).fetchone() == (None,)
        assert conn.execute("SELECT tenant_id FROM event_goal_admissions WHERE goal_id=%s", (legacy_goal,)).fetchone() == ("",)
        assert conn.execute("SELECT COUNT(*) FROM event_trigger_batches WHERE tenant_id='' ").fetchone() == (1,)
    with tenant_scope(tenant=None), PostgresWorldModel(postgres_test_dsn) as world:
        assert event_admission.poll_batch(world, "same-trigger") == legacy_batch
