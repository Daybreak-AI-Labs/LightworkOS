"""Native legacy-preserving learning-key upgrade, transaction and crash checks."""
from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from maverick import learning_store as ls
from maverick.learning_store_pg_schema import PG_BOOTSTRAP, LearningSchemaError, ensure_schema
from maverick.paths import tenant_scope

psycopg = pytest.importorskip("psycopg")

TABLES = ("harness_addenda", "harness_line_meta", "harness_transfer_tried", "harness_corpus")


def seed_legacy(dsn):
    with psycopg.connect(dsn) as connection, connection.cursor() as cursor:
        for ddl in PG_BOOTSTRAP:
            cursor.execute(ddl)
        for table in TABLES:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN tenant_id TEXT")
        for key, tenant in (("legacy-null", None), ("legacy-named", "existing")):
            cursor.execute("INSERT INTO harness_addenda VALUES (%s, 'retained', 1, %s)", (key, tenant))
            cursor.execute("INSERT INTO harness_line_meta VALUES (%s, '{}', 2, %s)", (key, tenant))
            cursor.execute("INSERT INTO harness_transfer_tried VALUES (%s, 3, %s)", (key, tenant))
            cursor.execute("INSERT INTO harness_corpus VALUES ('live', %s, 0, '{}', %s)", (key, tenant))


def snapshot(dsn):
    with psycopg.connect(dsn) as connection:
        return {table: connection.execute(f"SELECT * FROM {table} ORDER BY 1, 2").fetchall() for table in TABLES}


def primary_keys(connection):
    return connection.execute(
        "SELECT conrelid::regclass::text FROM pg_constraint WHERE contype='p' AND conrelid=ANY(%s::regclass[]) ORDER BY 1",
        (list(TABLES),),
    ).fetchall()


def test_native_upgrade_preserves_rows_and_all_four_tenant_namespaces(postgres_test_dsn, monkeypatch):
    seed_legacy(postgres_test_dsn)
    before = snapshot(postgres_test_dsn)
    with psycopg.connect(postgres_test_dsn) as connection, connection.cursor() as cursor:
        ensure_schema(cursor)
        ensure_schema(cursor)
        assert primary_keys(connection) == []
    assert snapshot(postgres_test_dsn) == before
    monkeypatch.setattr(ls, "_postgres", lambda: True)
    for tenant in (None, "alpha", "beta"):
        value = tenant or "unbound"
        with tenant_scope(tenant=tenant):
            ls.write_addenda_db({"shared": value})
            ls.write_line_meta_db({"shared": {"value": value}})
            ls.write_transfer_tried_db({"shared": len(value)})
            ls.write_corpus_db("live", {"shared": [{"value": value}], "annotation": value})
    for tenant in (None, "alpha", "beta"):
        value = tenant or "unbound"
        with tenant_scope(tenant=tenant):
            assert ls.load_addenda_db() == {"shared": value}
            assert ls.load_line_meta_db() == {"shared": {"value": value}}
            assert ls.load_transfer_tried_db() == {"shared": len(value)}
            assert ls.load_corpus_db("live") == {"shared": [{"value": value}], "annotation": value}
    # Replacing three scopes does not erase the pre-existing named scope.
    with tenant_scope(tenant="existing"):
        assert ls.load_addenda_db() == {"legacy-named": "retained"}


@pytest.mark.parametrize("tampering", ["foreign_key", "wrong_primary", "wrong_index", "missing_key"])
def test_native_unsafe_last_table_refuses_and_rolls_back_every_change(postgres_test_dsn, tampering):
    seed_legacy(postgres_test_dsn)
    with psycopg.connect(postgres_test_dsn) as connection:
        if tampering == "foreign_key":
            connection.execute("CREATE TABLE dependent (kind TEXT, key TEXT, seq INTEGER, FOREIGN KEY(kind,key,seq) REFERENCES harness_corpus)")
        elif tampering == "wrong_primary":
            connection.execute("ALTER TABLE harness_corpus DROP CONSTRAINT harness_corpus_pkey")
            connection.execute("ALTER TABLE harness_corpus ADD PRIMARY KEY(key)")
        elif tampering == "wrong_index":
            connection.execute("CREATE UNIQUE INDEX uq_harness_corpus_tenant ON harness_corpus(key)")
        else:
            connection.execute("ALTER TABLE harness_corpus DROP CONSTRAINT harness_corpus_pkey")
        before_keys = primary_keys(connection)
    before = snapshot(postgres_test_dsn)
    with pytest.raises(LearningSchemaError, match="learning-key upgrade refused"):
        with psycopg.connect(postgres_test_dsn) as connection, connection.cursor() as cursor:
            ensure_schema(cursor)
    assert snapshot(postgres_test_dsn) == before
    with psycopg.connect(postgres_test_dsn) as connection:
        assert primary_keys(connection) == before_keys
        assert connection.execute("SELECT to_regclass('uq_harness_addenda_tenant')").fetchone() == (None,)


@pytest.mark.parametrize("entry", ["addenda", "line_meta", "tried", "corpus", "write"])
def test_unsafe_lazy_upgrade_never_becomes_an_empty_store(postgres_test_dsn, monkeypatch, entry):
    seed_legacy(postgres_test_dsn)
    monkeypatch.setattr(ls, "_postgres", lambda: True)
    with psycopg.connect(postgres_test_dsn) as connection:
        connection.execute("CREATE UNIQUE INDEX uq_harness_corpus_tenant ON harness_corpus(key)")
    calls = {"addenda": ls.load_addenda_db, "line_meta": ls.load_line_meta_db,
             "tried": ls.load_transfer_tried_db, "corpus": lambda: ls.load_corpus_db("live"),
             "write": lambda: ls.write_addenda_db({"new": "must not replace existing rows"})}
    before = snapshot(postgres_test_dsn)
    with pytest.raises(LearningSchemaError, match="learning-key upgrade refused") as error:
        calls[entry]()
    assert "legacy" not in str(error.value) and "retained" not in str(error.value)
    assert snapshot(postgres_test_dsn) == before


def test_native_concurrent_initializers_commit_one_compatible_shape(postgres_test_dsn):
    seed_legacy(postgres_test_dsn)
    before = snapshot(postgres_test_dsn)
    barrier = Barrier(2)

    def initialize():
        with psycopg.connect(postgres_test_dsn) as connection, connection.cursor() as cursor:
            barrier.wait(timeout=3)
            ensure_schema(cursor)

    with ThreadPoolExecutor(max_workers=2) as workers:
        first, second = workers.submit(initialize), workers.submit(initialize)
        first.result(timeout=5)
        second.result(timeout=5)
    assert snapshot(postgres_test_dsn) == before


def test_native_process_exit_before_commit_leaves_legacy_rows_and_keys(postgres_test_dsn):
    seed_legacy(postgres_test_dsn)
    before = snapshot(postgres_test_dsn)
    code = """
import os, psycopg
from maverick.learning_store_pg_schema import ensure_schema
connection = psycopg.connect(os.environ['MAVERICK_PG_DSN'])
ensure_schema(connection.cursor())
os._exit(24)
"""
    child = subprocess.run([sys.executable, "-I", "-c", code], env=os.environ.copy(), capture_output=True, timeout=8)
    assert child.returncode == 24, "fixture child did not reach the pre-commit exit boundary"
    assert snapshot(postgres_test_dsn) == before
    with psycopg.connect(postgres_test_dsn) as connection:
        assert len(primary_keys(connection)) == 4
        ensure_schema(connection.cursor())
    assert snapshot(postgres_test_dsn) == before


def test_native_rls_policy_and_flags_survive_key_upgrade(postgres_test_dsn):
    seed_legacy(postgres_test_dsn)
    with psycopg.connect(postgres_test_dsn) as connection:
        connection.execute("ALTER TABLE harness_addenda ENABLE ROW LEVEL SECURITY")
        connection.execute("ALTER TABLE harness_addenda FORCE ROW LEVEL SECURITY")
        connection.execute("CREATE POLICY existing_tenant_policy ON harness_addenda USING (tenant_id=current_setting('maverick.tenant', true)) WITH CHECK (tenant_id=current_setting('maverick.tenant', true))")
        query = "SELECT polname, pg_get_expr(polqual,polrelid), pg_get_expr(polwithcheck,polrelid) FROM pg_policy WHERE polrelid='harness_addenda'::regclass"
        before = connection.execute(query).fetchall()
        ensure_schema(connection.cursor())
        assert connection.execute(query).fetchall() == before
        assert connection.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='harness_addenda'::regclass").fetchone() == (True, True)


def test_world_and_standalone_learning_startup_share_migration(postgres_test_dsn, monkeypatch):
    from maverick.world_model_backends.postgres import MIGRATIONS, PostgresWorldModel

    monkeypatch.setattr(ls, "_postgres", lambda: True)
    with tenant_scope(tenant="alpha"):
        ls.write_addenda_db({"shared": "before world startup"})
        with PostgresWorldModel(postgres_test_dsn) as world:
            assert world.schema_version == MIGRATIONS[-1][0]
            with world._tx() as cursor:
                cursor.execute("SELECT version FROM schema_migrations ORDER BY version")
                assert [row[0] for row in cursor.fetchall()] == [version for version, _ in MIGRATIONS]
        assert ls.load_addenda_db() == {"shared": "before world startup"}
    with tenant_scope(tenant="beta"):
        ls.write_addenda_db({"shared": "after world startup"})
        assert ls.load_addenda_db() == {"shared": "after world startup"}
