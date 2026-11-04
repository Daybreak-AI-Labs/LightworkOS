"""Where consent records are kept: files (default) or shared Postgres.

The translation and settings tests always run. The live tests run where a
Postgres service is available (``MAVERICK_PG_DSN``, the CI postgres job):
they run the real consent preference store on Postgres, check SQLite's
guarantees hold there, and copy a workspace's records across.
"""
from __future__ import annotations

import os
import sqlite3
import uuid

import pytest
from maverick import consent_storage as storage

_DSN = os.environ.get("MAVERICK_PG_DSN", "")
live = pytest.mark.skipif(not _DSN, reason="MAVERICK_PG_DSN not set (no Postgres service)")


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("HOME", str(tmp_path))
    for name in (storage.BACKEND_ENV, storage.DEFAULT_DSN_ENV, "MAVERICK_CONFIG",
                 "MAVERICK_CONFIG_OVERLAY", "ACME_CONSENT_DSN"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    storage._reset_for_testing()
    yield
    storage._reset_for_testing()
    config.reset_config_cache()


def _config(backend="postgres", **extra):
    return {"consent_preferences": {"storage": {"backend": backend, **extra}}}


# ------------------------------------------------------------------ settings
def test_files_on_this_server_are_the_default():
    assert storage.storage_settings({}) == storage.StorageSelection("sqlite")
    assert storage.shared() is False
    with pytest.raises(storage.ConsentStorageError):
        storage.connect("/tmp/x.sqlite3")


def test_postgres_needs_a_connection_and_the_environment_wins(monkeypatch):
    with pytest.raises(storage.ConsentStorageError, match="needs a database connection"):
        storage.storage_settings(_config())
    saved = storage.storage_settings(_config(dsn="postgresql://saved@db/one"))
    assert saved.dsn == "postgresql://saved@db/one" and "saved" not in repr(saved)
    monkeypatch.setenv(storage.DEFAULT_DSN_ENV, "postgresql://env@db/two")
    assert storage.storage_settings(_config(dsn="postgresql://saved@db/one")).dsn.startswith(
        "postgresql://env@")
    monkeypatch.setenv("ACME_CONSENT_DSN", "postgresql://named@db/three")
    named = storage.storage_settings(_config(dsn_secret_ref="$ACME_CONSENT_DSN"))
    assert named.dsn.startswith("postgresql://named@") and named.dsn_env == "ACME_CONSENT_DSN"
    monkeypatch.setenv(storage.BACKEND_ENV, "sqlite")
    assert storage.storage_settings(_config(dsn="x")).backend == "sqlite"


@pytest.mark.parametrize("ref", ["$PATH", "lower_case", "$GITHUB_TOKEN"])
def test_the_connection_name_must_be_a_consent_setting(ref):
    with pytest.raises(storage.ConsentStorageError):
        storage.storage_settings(_config(dsn_secret_ref=ref, dsn="postgresql://x@db/y"))


def test_the_choice_is_read_once_per_process(monkeypatch):
    assert storage.shared() is False
    monkeypatch.setenv(storage.BACKEND_ENV, "postgres")
    monkeypatch.setenv(storage.DEFAULT_DSN_ENV, "postgresql://x@db/y")
    assert storage.shared() is False  # takes effect at restart
    storage._reset_for_testing()
    assert storage.shared() is True


def test_sqlite_stores_are_unchanged_when_nothing_is_set(tmp_path):
    from maverick.consent_preferences import ConsentPreferenceStore

    store = ConsentPreferenceStore(tmp_path / "consent.sqlite3")
    assert store.path.is_file()
    with sqlite3.connect(store.path) as connection:
        tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master")}
    assert "consent_receipts" in tables and "lw_sqlite_pragma" not in tables


def test_restoration_schema_does_not_commit_an_outer_move_transaction():
    from maverick.consent_preferences import ConsentPreferenceStore

    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("CREATE TABLE copied_record(value TEXT NOT NULL)")
        connection.execute("INSERT INTO copied_record(value) VALUES ('customer-data')")
        ConsentPreferenceStore._ensure_restoration_floor_schema(connection)
        assert connection.in_transaction
        connection.execute("ROLLBACK")
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'copied_record'"
        ).fetchone() is None
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'consent_profile_restoration_floors'"
        ).fetchone() is None
    finally:
        connection.close()


# --------------------------------------------------------------- translation
def test_statements_are_translated_to_postgres():
    t = storage.translate
    assert " ".join(t("INSERT OR IGNORE INTO m(key, value) VALUES (?, ?)", ("a", "b")).sql.split()) \
        == "INSERT INTO m(key, value) VALUES (%s, %s) ON CONFLICT DO NOTHING"
    assert "strpos(lower(a), lower(%s))" in t("SELECT 1 FROM x WHERE instr(lower(a), lower(?))",
                                              ("q",)).sql
    assert "GREATEST(a, %s)" in t("SELECT max(a, ?) FROM x", (1,)).sql
    assert "max(a)" in t("SELECT max(a) FROM x").sql
    numeric = t("SELECT 1 FROM x WHERE json_extract(p,'$.until')>?", (1.5,)).sql
    assert "((p)::jsonb #> '{until}'))::numeric" in numeric and numeric.endswith(">ROW(0, %s)")
    text = t("SELECT 1 FROM x WHERE json_extract(p,'$.id')=?", ("a",)).sql
    assert "::numeric" not in text and text.endswith("=ROW(1, %s)")
    ordered = t("SELECT a FROM x ORDER BY a, b DESC LIMIT ?", (5,)).sql
    assert "a NULLS FIRST, b DESC NULLS LAST LIMIT %s" in ordered
    assert "%%" in t("SELECT a % ? FROM x", (2,)).sql
    assert t("UPDATE x SET a=:a WHERE b=:b", {"a": 1, "b": 2}).sql == \
        "UPDATE x SET a=%(a)s WHERE b=%(b)s"
    assert t("BEGIN IMMEDIATE").kind == "begin" and t("COMMIT").kind == "commit"
    assert t("PRAGMA table_info(t)").pragma == "table_info"


def test_tables_and_triggers_keep_sqlite_types_and_rules():
    table = storage.translate(
        "CREATE TABLE IF NOT EXISTS t (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
        "key TEXT NOT NULL, at REAL, n INTEGER, blob BLOB, "
        "FOREIGN KEY (key) REFERENCES p(key) ON DELETE CASCADE)").sql
    assert "sequence BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY" in table
    assert 'key TEXT COLLATE "C" NOT NULL' in table and "at DOUBLE PRECISION" in table
    assert "n BIGINT" in table and "blob BYTEA" in table
    assert "ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE" in table
    function, trigger = storage.translate(
        "CREATE TRIGGER IF NOT EXISTS t_no_update BEFORE UPDATE OF a, b ON t "
        "BEGIN SELECT RAISE(ABORT, 'rows are immutable'); END").statements
    assert "RAISE EXCEPTION USING ERRCODE = '23000', MESSAGE = 'rows are immutable'" in function
    assert 'BEFORE UPDATE OF a, b ON t FOR EACH ROW EXECUTE FUNCTION "lw_trg_t_no_update"()' \
        in trigger
    assert storage.split_statements(
        "CREATE TABLE a(x TEXT); CREATE TRIGGER g AFTER INSERT ON a BEGIN "
        "INSERT INTO b VALUES (NEW.x); SELECT 1; END; CREATE TABLE c(y TEXT);")[1].endswith("END")


def test_refused_statements_come_back_as_sqlite_errors():
    class Diag:
        message_primary = "consent receipts are immutable"
        constraint_name = None

    class Raised(Exception):
        sqlstate = "23000"
        diag = Diag()

    class Duplicate(Exception):
        sqlstate = "23505"
        diag = type("D", (), {"constraint_name": "t_pkey", "message_primary": "Key (x)=(secret)"})

    assert str(storage._mapped_error(Raised())) == "consent receipts are immutable"
    mapped = storage._mapped_error(Duplicate())
    assert isinstance(mapped, sqlite3.IntegrityError) and "secret" not in str(mapped)
    locked = type("L", (Exception,), {"sqlstate": "55P03"})()
    assert str(storage._mapped_error(locked)) == "database is locked"
    assert issubclass(storage.ConsentStorageError, sqlite3.Error)


# ------------------------------------------------------------------ live Postgres
@pytest.fixture()
def shared(monkeypatch, tmp_path):
    monkeypatch.setenv(storage.BACKEND_ENV, "postgres")
    monkeypatch.setenv(storage.DEFAULT_DSN_ENV, _DSN)
    storage._reset_for_testing()
    schemas: list[str] = []
    yield schemas
    import psycopg

    with psycopg.connect(_DSN, autocommit=True) as connection:
        for schema in schemas:
            connection.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def _policy(store, tenant="tenant-a"):
    return store.publish_policy(tenant, "privacy-notice", 1,
                                {"analytics": "consent", "marketing": "consent"}, "a" * 64,
                                1_700_000_000.0, expected_current_version=0)


@live
def test_the_preference_store_runs_on_postgres_with_sqlite_guarantees(shared, tmp_path):
    from maverick.consent_preferences import ConsentPreferenceStore

    path = tmp_path / f"{uuid.uuid4().hex}.sqlite3"
    shared.append(storage.schema_name(path))
    store = ConsentPreferenceStore(path, clock=lambda: 1_700_000_100.0)
    assert not path.exists()  # nothing is written on this server
    created = _policy(store)
    assert created["version"] == 1
    connection = storage.connect(path)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("UPDATE consent_policies SET notice_sha256 = ?", ("b" * 64,))
        # The refused statement did not spoil the transaction, as in SQLite.
        row = connection.execute("SELECT version FROM consent_policies").fetchone()
        assert row["VERSION"] == 1 and dict(row) == {"version": 1}
        connection.execute("ROLLBACK")
    finally:
        connection.close()
    other = tmp_path / "other" / f"{uuid.uuid4().hex}.sqlite3"
    shared.append(storage.schema_name(other))
    other_store = ConsentPreferenceStore(other)
    connection = storage.connect(other)
    try:
        assert connection.execute("SELECT count(*) FROM consent_policies").fetchone()[0] == 0
    finally:
        connection.close()
    assert other_store.path == other


@live
def test_local_records_are_copied_verified_and_never_doubled(shared, monkeypatch, tmp_path):
    from maverick.consent_preferences import ConsentPreferenceStore
    from maverick.paths import data_dir

    workspace = "copy-" + uuid.uuid4().hex[:10]
    path = data_dir("consent_preferences", "consent-preferences.sqlite3", tenant=workspace)
    monkeypatch.setenv(storage.BACKEND_ENV, "sqlite")
    storage._reset_for_testing()
    local = ConsentPreferenceStore(path, clock=lambda: 1_700_000_100.0)
    _policy(local)
    with sqlite3.connect(path) as connection:
        expected = connection.execute("SELECT count(*) FROM consent_policies").fetchone()[0]
    monkeypatch.setenv(storage.BACKEND_ENV, "postgres")
    storage._reset_for_testing()
    shared.append(storage.schema_name(path))
    preview = storage.preview_move()
    mine = [s for s in preview["stores"] if s["workspace"] and workspace in s["workspace"]]
    assert mine and mine[0]["state"] == "ready" and mine[0]["records"] >= expected
    result = storage.move_local_records()
    assert not [r for r in result["refused"] if workspace in r["workspace"]]
    connection = storage.connect(path)
    try:
        assert connection.execute("SELECT count(*) FROM consent_policies").fetchone()[0] == expected
    finally:
        connection.close()
    assert [s for s in storage.preview_move()["stores"]
            if s["workspace"] and workspace in s["workspace"]][0]["state"] == "moved"
    again = storage.move_local_records()  # nothing new is copied
    assert sum(m["copied"] for m in again["moved"] if workspace in m["workspace"]) == 0
    assert path.is_file()  # the original file is kept
    # Different records already in the shared database: that store is refused.
    connection = storage.connect(path)
    try:
        connection.execute("INSERT INTO consent_meta(key, value) VALUES ('extra', 'x')")
    finally:
        connection.close()
    refused = storage.move_local_records()["refused"]
    assert any(workspace in r["workspace"] for r in refused)


@live
def test_pre_upgrade_restored_profile_moves_with_atomic_consent_reset(
    shared, monkeypatch, tmp_path,
):
    from maverick.consent_preferences import (
        ConsentContext,
        ConsentPreferenceStore,
        PreferenceChoice,
    )

    now = 1_700_000_100.0
    path = tmp_path / f"legacy-{uuid.uuid4().hex}.sqlite3"
    monkeypatch.setenv(storage.BACKEND_ENV, "sqlite")
    storage._reset_for_testing()
    local = ConsentPreferenceStore(path, clock=lambda: now)
    _policy(local)
    local.create_profile("tenant-a", "profile-001", "known", "b" * 64, "create")
    receipt = local.record_preferences(
        "tenant-a", "profile-001", "privacy-notice", 1,
        ConsentContext(
            jurisdiction="us-state-ca", country_code="US", region_code="US-CA",
            collection_point="privacy-center", asserted_source="client",
        ),
        [PreferenceChoice(purpose_id="analytics", action="grant")],
        expected_revision=0, idempotency_key="grant", actor_sha256="c" * 64,
    )
    local.delete_subject(
        "tenant-a", "profile-001", expected_revision=1,
        reason_code="subject-request", idempotency_key="erase",
        actor_sha256="d" * 64,
    )
    local.change_identifier_type(
        "tenant-a", "profile-001", "known", "a" * 64,
        expected_revision=2, idempotency_key="restore", actor_sha256="d" * 64,
    )
    # Simulate a pre-upgrade file: the erasure event and old grant exist, but
    # neither the restoration floor table nor its migration marker does.
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE consent_profile_restoration_floors")
        connection.execute(
            "DELETE FROM consent_meta WHERE key = 'restoration_floor_backfill_v1'"
        )

    monkeypatch.setenv(storage.BACKEND_ENV, "postgres")
    storage._reset_for_testing()
    shared.append(storage.schema_name(path))
    target_store = ConsentPreferenceStore(path, clock=lambda: now)
    connection = storage.connect(path)
    try:
        assert connection.execute(
            "SELECT 1 FROM consent_meta WHERE key = 'restoration_floor_backfill_v1'"
        ).fetchone() is None
        # Recreate the destination-only row written by the earlier build.
        connection.execute(
            "INSERT INTO consent_meta(key, value) "
            "VALUES ('restoration_floor_backfill_v1', '1')"
        )
    finally:
        connection.close()
    storage.move_store(path)
    decision = target_store.decide(
        "tenant-a", "profile-001", "analytics", policy_id="privacy-notice"
    )
    assert decision.allowed is False
    assert decision.reason == "no_current_explicit_grant"
    assert target_store.get_receipt("tenant-a", receipt["receipt_id"])
    connection = storage.connect(path)
    try:
        assert connection.execute(
            "SELECT source FROM consent_profile_restoration_floors"
        ).fetchone()[0] == "legacy_backfill"
    finally:
        connection.close()
    assert storage.move_store(path)["copied"] == 0


# ------------------------------------------------- literals and json_extract parity
def test_percent_signs_are_never_read_as_placeholders_when_values_are_bound():
    t = storage.translate
    # psycopg reads every % in the text: one inside a string literal, quoted
    # name or comment must be doubled, or the statement fails ('50%') or a
    # value lands inside the literal ('%s').
    assert t("SELECT '50%' FROM x WHERE a = ?", (1,)).sql == "SELECT '50%%' FROM x WHERE a = %s"
    assert t("SELECT '%s' FROM x WHERE a = ?", (1,)).sql == "SELECT '%%s' FROM x WHERE a = %s"
    assert t('SELECT "p%" FROM x /* 5% */ WHERE a = ?', (1,)).sql == \
        'SELECT "p%%" FROM x /* 5%% */ WHERE a = %s'
    assert t("SELECT '50%' FROM x").sql == "SELECT '50%' FROM x"  # nothing bound: unchanged


def test_json_extract_shapes_without_sqlite_parity_are_refused():
    for sql, params in (
        ("SELECT 1 FROM x WHERE ? = json_extract(p,'$.a')", ("a",)),
        ("SELECT 1 FROM x WHERE json_extract(p,'$.a') = other", ()),
        ("SELECT 1 FROM x WHERE json_extract(?,'$.a') = ?", ("{}", "a")),
    ):
        with pytest.raises(storage._Unsupported):
            storage.translate(sql, params)


_CONTAINERS = ['{"v": {"k": 1}}', '{"v": [1, 2]}']
_PAYLOADS = ['{"v": 5}', '{"v": 5.5}', '{"v": "5"}', '{"v": "abc"}', '{"v": ""}',
             '{"v": true}', '{"v": false}', '{"v": null}', '{}', '{"v": 9007199254740993}', '{"v": -1}', '{"v": "B"}',
             '{"v": "a"}', '{"v": "é"}']


@live
def test_json_extract_comparisons_match_sqlite(shared, tmp_path):
    path = tmp_path / f"{uuid.uuid4().hex}.sqlite3"
    shared.append(storage.schema_name(path))
    pg = storage.connect(path)
    lite = sqlite3.connect(":memory:")
    try:
        for connection in (pg, lite):
            for table, payloads in (("r", _PAYLOADS), ("c", _PAYLOADS + _CONTAINERS)):
                connection.execute(
                    f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, payload_json TEXT NOT NULL)")
                for i, payload in enumerate(payloads):
                    connection.execute(f"INSERT INTO {table} (id, payload_json) VALUES (?, ?)",
                                       (i, payload))
        values = [5, 5.5, 4, 6, 0, 1, -2, 9007199254740992, float("inf"), "5", "abc", "", "a",
                  "B", "zzz", True, False, None]
        mismatches = []
        for op in ("=", "<>", "!=", "==", ">", ">=", "<", "<="):
            for value in values:
                for form in ("json_extract(payload_json,'$.v'){op}?",
                             "NOT (json_extract(payload_json,'$.v'){op}?)"):
                    sql = f"SELECT id FROM r WHERE {form.format(op=op)} ORDER BY id"
                    want = [r[0] for r in lite.execute(sql, (value,))]
                    got = [r[0] for r in pg.execute(sql, (value,))]
                    if want != got:
                        mismatches.append((sql, value, want, got))
                    if not isinstance(value, str):  # objects/arrays against a number
                        sql = sql.replace("FROM r", "FROM c")
                        want = [r[0] for r in lite.execute(sql, (value,))]
                        got = [r[0] for r in pg.execute(sql, (value,))]
                        if want != got:
                            mismatches.append((sql, value, want, got))
        for sql in ("SELECT id FROM r WHERE json_extract(payload_json,'$.v') IN ('abc','a') ORDER BY id",
                    "SELECT id FROM r WHERE json_extract(payload_json,'$.v') > 5 ORDER BY id",
                    "SELECT id FROM r WHERE json_extract(payload_json,'$.v') = 'abc' ORDER BY id",
                    "SELECT id FROM r WHERE json_extract(payload_json,'$.v') = '5' ORDER BY id"):
            want = [r[0] for r in lite.execute(sql)]
            got = [r[0] for r in pg.execute(sql)]
            if want != got:
                mismatches.append((sql, None, want, got))
        assert mismatches == []
        # SQLite compares an object or array as its compact JSON text, which
        # Postgres cannot reproduce: that comparison fails instead of differing.
        with pytest.raises(sqlite3.OperationalError):
            pg.execute("SELECT id FROM c WHERE json_extract(payload_json,'$.v') = ?", ("x",))
        # Bound values and literals with % keep their meaning.
        assert tuple(pg.execute("SELECT '50%', '%s', ?", ("x",)).fetchone()) == ("50%", "%s", "x")
    finally:
        pg.close()
        lite.close()
