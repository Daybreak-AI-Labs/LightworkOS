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
            self._result = (count + (empty if "= ''" in s else 0),)
        elif s.startswith("update"):
            tbl = sql.split("UPDATE ")[1].split()[0]
            self.rowcount = self.conn.tables[tbl]["nulls"]
            if "= ''" in s:
                self.rowcount += self.conn.tables[tbl].get("empty", 0)
            self.conn.updated[tbl] = params[0]
        else:  # pragma: no cover - defensive
            self._result = None

    def fetchone(self) -> tuple | None:
        return self._result

    def fetchmany(self, size: int = 0) -> list:
        return []  # the fake store holds no encrypted values to re-seal

    def close(self) -> None:
        pass


class _FakeConn:
    def __init__(self, role: str, tables: dict[str, dict]) -> None:
        self.role = role
        self.tables = tables
        self.calls: list = []
        self.updated: dict[str, str] = {}
        self.committed = False

    def cursor(self, name: str | None = None, **_kwargs) -> _FakeCursor:
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


def test_backfill_covers_every_rls_table_with_the_stored_tenant_value():
    # Every table RLS is forced on must be backfilled (projects, fact history
    # and the approval outbox were left NULL, then hidden), and tenant_id
    # columns hold the path-encoded id the backend writes, not the raw id.
    from maverick.world_model_backends.postgres import _RLS_TABLES

    assert {"projects", "fact_history", "approval_audit_outbox",
            "webhook_subscriptions"} <= set(_PREFLIGHT_TABLES)
    assert set(_PREFLIGHT_TABLES) == set(_RLS_TABLES) - {"encryption_migrations"}
    conn = _FakeConn("app", _tables("app", nulls=1))
    pg_rls.backfill(conn, "acme:eu")
    assert conn.updated["projects"] == "acme%3Aeu"
    assert conn.updated["webhook_subscriptions"] == "acme:eu"


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


# --- records without a workspace that every workspace reads -----------------

class _CountWorld:
    """A world whose one deployment-wide read answers the legacy-row count."""

    def __init__(self, *, legacy=0, named=False):
        self.row = (legacy, *([0] * (len(pg_rls._SHARED_LEGACY_TABLES) - 1)), named)
        self.calls: list = []

    def query(self, sql, params=(), *, system=False):
        self.calls.append((sql, tuple(params), system))
        return [self.row]


def _doctor_rows(monkeypatch, world):
    from maverick import health

    rows: list[tuple] = []
    monkeypatch.setattr(health, "_row", lambda marker, label, detail="", fix="": rows.append(
        (marker, label, detail, fix)))
    health._check_workspace_records(world)
    return rows


def test_doctor_warns_when_every_workspace_reads_records_without_a_workspace(monkeypatch):
    """Postgres in compatibility mode shows records saved before workspaces
    were used to every workspace. The doctor says so, with the count and the
    way out, only when a named workspace exists and such records are there."""
    from maverick import health
    from maverick.paths import tenant_scope

    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    world = _CountWorld(legacy=3, named=True)
    (marker, label, detail, fix), = _doctor_rows(monkeypatch, world)
    assert marker == health.YELLOW and label == "workspace-records"
    assert detail.startswith("3 records saved before workspaces were used")
    assert "every workspace can read them" in detail
    assert "maverick tenant backfill --tenant <id>" in fix and "--dry-run" in fix
    assert "Writes wait while it runs, so pick a quiet period." in fix
    assert "MAVERICK_STRICT_TENANT_ISOLATION=1" in fix
    assert "tenant" not in detail.lower()
    # One statement, marked deployment-wide, with the predicate `maverick
    # tenant backfill` uses; it counts and selects no record content. It
    # counts only the tables whose rows with no workspace a workspace's reads
    # include: message markers, receipts, the approval outbox, event and
    # webhook rows are read by exact workspace, so "every workspace can read
    # them" would be untrue for those.
    (sql, params, system), = world.calls
    assert system is True and params == ()
    assert set(pg_rls._SHARED_LEGACY_TABLES) == {
        "goals", "facts", "fact_history", "conversations", "approvals", "projects"}
    for table in _PREFLIGHT_TABLES:
        counted = f"FROM {table} WHERE {pg_rls._legacy_scope(table)} LIMIT" in sql
        assert counted is (table in pg_rls._SHARED_LEGACY_TABLES), table

    capped = _CountWorld(legacy=pg_rls._LEGACY_COUNT_CAP, named=True)
    assert _doctor_rows(monkeypatch, capped)[0][2].startswith(
        f"{pg_rls._LEGACY_COUNT_CAP} or more records")
    # A workspace that is active counts as a named workspace.
    with tenant_scope(tenant="acme"):
        assert len(_doctor_rows(monkeypatch, _CountWorld(legacy=1))) == 1

    # Nothing warns without such records, without a named workspace, or under
    # strict isolation (which never reads the store for this).
    assert _doctor_rows(monkeypatch, _CountWorld(legacy=0, named=True)) == []
    assert _doctor_rows(monkeypatch, _CountWorld(legacy=3, named=False)) == []
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
    strict = _CountWorld(legacy=3, named=True)
    assert _doctor_rows(monkeypatch, strict) == [] and strict.calls == []


def test_doctor_counts_records_without_a_workspace_on_live_postgres(postgres_test_dsn, monkeypatch):
    """The same warning from the real store: nothing while only the unbound
    install has written, the count once a named workspace exists, and nothing
    again after `maverick tenant backfill` assigned the records."""
    import psycopg
    from maverick import health
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    rows: list[tuple] = []
    monkeypatch.setattr(health, "_row", lambda marker, label, detail="", fix="": rows.append(
        (marker, label, detail, fix)))

    def warnings():
        rows.clear()
        health._check_world_db()
        assert [r[1] for r in rows if r[0] == health.GREEN] == ["world-db"]
        return [r[2] for r in rows if r[1] == "workspace-records"]

    with PostgresWorldModel(postgres_test_dsn) as world:
        with tenant_scope(tenant=None):
            world.create_goal("saved before workspaces")
            world.create_project("an early project")
            # Rows the backfill assigns but no other workspace reads.
            _event_state(world)
            world.mark_message_processed("web", "early-message")
        assert warnings() == []
        with tenant_scope(tenant="acme"):
            world.create_goal("acme's own goal")
    # Counted: the two goals (one came with the event) and the project.
    found = warnings()
    assert len(found) == 1 and found[0].startswith("3 records saved before workspaces were used")
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
    assert warnings() == []
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    with psycopg.connect(postgres_test_dsn) as conn:
        assert sum(pg_rls.backfill(conn, "acme", dry_run=True).values()) == 6
        pg_rls.backfill(conn, "acme")
    assert warnings() == []


def test_backfill_reseals_encrypted_records_for_the_workspace_they_go_to(
    postgres_test_dsn, monkeypatch,
):
    """A record saved with no workspace was sealed with the empty binding.
    Assigning it to a workspace re-seals its values for that workspace in the
    same transaction, so the workspace still reads it under strict isolation.
    A value this computer cannot open stops the backfill before any change."""
    import psycopg
    from maverick.paths import tenant_scope
    from maverick.world_model import _UNSEALED_WITHHELD
    from maverick.world_model_backends import postgres
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    def read(world, goal, conversation):
        found = world.get_goal(goal)
        return None if found is None else (
            found.title, found.description,
            [e.content for e in world.goal_events(goal)],
            [a["content"] for a in world.artifacts_for_goal(goal)],
            [q.question for q in world.open_questions(goal)],
            [t.content for t in world.recent_turns(conversation)],
            world.get_fact("contact"))

    with PostgresWorldModel(postgres_test_dsn) as world:
        goal = world.create_goal("early title", "early description")
        world.append_event(goal, "agent", "note", "early event")
        world.add_artifact(goal, "text", "report", "early artifact")
        world.ask("early question", goal)
        conversation = world.get_or_create_conversation("web", "early-user").id
        world.append_turn(conversation, "user", "early turn")
        world.upsert_fact("contact", "early@example.test")
        expected = read(world, goal, conversation)
        assert _UNSEALED_WITHHELD not in str(expected)
        with tenant_scope(tenant="beta"):
            foreign = postgres._seal("sealed for beta", "goals.title")
    with psycopg.connect(postgres_test_dsn) as conn:
        stuck = conn.execute(
            "INSERT INTO goals(title, status, created_at, updated_at) "
            "VALUES (%s, 'pending', 0, 0) RETURNING id", (foreign,)).fetchone()[0]
        conn.commit()
        for dry_run in (True, False):
            with pytest.raises(ValueError, match="No rows were reassigned") as refused:
                pg_rls.backfill(conn, "acme", dry_run=dry_run)
            # The key here is fine; the value was saved for another workspace.
            # The refusal names both causes and the row to look at.
            assert f"goals.title, id {stuck}" in str(refused.value)
            assert "or the value was saved for another workspace" in str(refused.value)
        assert conn.execute("SELECT count(*) FROM goals WHERE tenant_id IS NULL").fetchone() == (2,)
        conn.execute("DELETE FROM goals WHERE id=%s", (stuck,))
        conn.commit()
        pg_rls.backfill(conn, "acme")
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
    with PostgresWorldModel(postgres_test_dsn) as world:
        with tenant_scope(tenant="acme"):
            assert read(world, goal, conversation) == expected
        with tenant_scope(tenant="beta"):
            assert world.get_goal(goal) is None and world.get_fact("contact") is None


def test_backfill_reseals_in_batches_and_opens_each_value_once(postgres_test_dsn, monkeypatch):
    """The values of a large store are read through a server-side cursor and
    written a batch at a time, never loaded whole. A row with no workspace was
    sealed with the empty binding, so that binding is tried first: one open
    per value, not a failed attempt with the workspace's binding before it."""
    import psycopg
    from maverick import crypto_at_rest
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(pg_rls, "_RESEAL_BATCH", 2)
    with PostgresWorldModel(postgres_test_dsn) as world:
        goal = world.create_goal("early title", "early description")
        for number in range(5):
            world.append_event(goal, "agent", "note", f"early event {number}")
    opened = []
    real_open = crypto_at_rest.unseal_bound_from_str
    with monkeypatch.context() as spy, psycopg.connect(postgres_test_dsn) as conn:
        spy.setattr(crypto_at_rest, "unseal_bound_from_str",
                    lambda *a, **k: opened.append(a[1]) or real_open(*a, **k))
        spy.setattr(psycopg.Cursor, "fetchall", lambda self: pytest.fail("loaded a whole result"))
        # Five events, and the goal's title, description and connection choice.
        preview = pg_rls.backfill(conn, "acme", dry_run=True)
        assert preview.encrypted_values == 8 and len(opened) == 8
        opened.clear()
        done = pg_rls.backfill(conn, "acme")
        assert done.encrypted_values == 8 and done == preview
        assert sorted(opened) == ["goal_events.content"] * 5 + [
            "goals.connection_selection", "goals.description", "goals.title"]
        assert pg_rls.backfill(conn, "acme").encrypted_values == 0
    with PostgresWorldModel(postgres_test_dsn) as world, tenant_scope(tenant="acme"):
        assert world.get_goal(goal).description == "early description"
        assert sorted(e.content for e in world.goal_events(goal)) == [
            f"early event {number}" for number in range(5)]


def test_backfill_does_not_queue_behind_a_transaction_that_is_writing(postgres_test_dsn, monkeypatch):
    """The backfill needs every writer of these tables to be finished. It
    waits a bounded time for that and then stops with nothing changed, rather
    than queue (and hold up every later write) behind a long transaction."""
    import time

    import psycopg
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(pg_rls, "_LOCK_TIMEOUT_SECONDS", 1)
    with PostgresWorldModel(postgres_test_dsn) as world:
        goal = world.create_goal("early title")
        world.append_event(goal, "agent", "note", "early event")
    with psycopg.connect(postgres_test_dsn) as writer, psycopg.connect(postgres_test_dsn) as conn:
        writer.execute("UPDATE goal_events SET ts = ts WHERE goal_id = %s", (goal,))
        started = time.monotonic()
        with pytest.raises(psycopg.errors.LockNotAvailable) as stopped:
            pg_rls.backfill(conn, "acme")
        assert time.monotonic() - started < 10
        message = pg_rls.database_error_message(stopped.value)
        assert "busy writing" in message and "Nothing was changed" in message
        assert "did not start" not in message  # it may have re-sealed values first
        assert conn.execute("SELECT tenant_id FROM goals WHERE id = %s", (goal,)).fetchone() == (None,)
        conn.rollback()
        writer.commit()
        assert pg_rls.backfill(conn, "acme")["goals"] == 1


def test_a_connection_lost_while_committing_does_not_claim_nothing_changed():
    """A commit that fails may already have taken effect: the message must not
    say nothing was changed, and running again is the way to find out."""

    class _Lost(Exception):
        sqlstate = "08006"

    class _Conn:
        autocommit = False

        def cursor(self, *args, **kwargs):
            raise AssertionError("not reached")

        def commit(self):
            raise _Lost("server closed the connection unexpectedly")

        def rollback(self):
            raise _Lost("no connection")

    conn = _Conn()
    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(pg_rls, "_policies_hide_legacy_rows", lambda cur: False)
        monkey.setattr(pg_rls, "_reseal_legacy_values", lambda *a, **k: 0)
        monkey.setattr(pg_rls, "_PREFLIGHT_TABLES", ())
        monkey.setattr(conn, "cursor", lambda *a, **k: object())
        with pytest.raises(pg_rls.BackfillCommitUncertain) as lost:
            pg_rls.backfill(conn, "acme")
    finally:
        monkey.undo()
    message = pg_rls.database_error_message(lost.value)
    assert "may have finished" in message and "Nothing was changed" not in message
