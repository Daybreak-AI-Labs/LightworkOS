"""sql_query tool: read-only-by-default SQLite querying.

Covers write rejection (keyword guard + engine mode=ro + authorizer), opt-in
writes, params and row caps, tested against a real stdlib sqlite3 db (no
mocks).
"""
from __future__ import annotations

import sqlite3
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from maverick.tools.sql_query import sql_query


@pytest.fixture(autouse=True)
def _approved_sql_writes(monkeypatch):
    import importlib

    module = importlib.import_module("maverick.tools.sql_query")
    monkeypatch.setattr(module, "request_execution_consent", lambda *a, **kw: object())
    monkeypatch.setattr(module, "consume_operation_consent", lambda permit: nullcontext())


def _mkdb(tmp_path):
    db = tmp_path / "t.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT)")
    c.executemany("INSERT INTO users VALUES(?, ?)", [(1, "alice"), (2, "bob"), (3, "carol")])
    c.commit()
    c.close()
    return db


def test_sql_query_rejects_internal_data_inside_workspace(tmp_path, monkeypatch):
    private = tmp_path / ".maverick"
    private.mkdir()
    db = _mkdb(private)
    monkeypatch.setenv("MAVERICK_HOME", str(private))
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({
        "database": str(db), "query": "SELECT name FROM users",
    })
    assert "internal data directory" in out


def test_sql_query_requires_workspace(tmp_path):
    db = _mkdb(tmp_path)
    assert "sandbox workspace is required" in sql_query().fn({
        "database": str(db), "query": "SELECT name FROM users",
    })


def test_sql_query_allows_the_default_workspace_under_state(tmp_path, monkeypatch):
    state = tmp_path / "state"
    workspace = state / "workspace"
    workspace.mkdir(parents=True)
    monkeypatch.setenv("MAVERICK_HOME", str(state))
    db = _mkdb(workspace)
    out = sql_query(SimpleNamespace(workdir=workspace)).fn({
        "database": str(db), "query": "SELECT name FROM users",
    })
    assert "alice" in out


def test_select_returns_rows(tmp_path):
    db = _mkdb(tmp_path)
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({"database": str(db), "query": "SELECT name FROM users ORDER BY id"})
    assert "alice" in out and "bob" in out and "carol" in out
    assert "(3 row(s))" in out


def test_readonly_rejects_write_by_keyword(tmp_path):
    db = _mkdb(tmp_path)
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({"database": str(db), "query": "DELETE FROM users"})
    assert out.startswith("ERROR") and "read-only" in out.lower()
    # data untouched
    c = sqlite3.connect(db)
    assert c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3
    c.close()


def test_readonly_rejects_commented_write_by_keyword(tmp_path):
    db = _mkdb(tmp_path)
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({
        "database": str(db),
        "query": "/* sneaky */ UPDATE users SET name='x'",
    })
    assert out.startswith("ERROR") and "read-only" in out.lower()
    c = sqlite3.connect(db)
    assert c.execute("SELECT COUNT(*) FROM users WHERE name='x'").fetchone()[0] == 0
    c.close()


def test_readonly_blocks_commented_attach_outside_workspace(tmp_path):
    db = _mkdb(tmp_path)
    outside = tmp_path.parent / "outside-attach.db"
    outside.unlink(missing_ok=True)
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({
        "database": str(db),
        "query": f"/* sneaky */ ATTACH DATABASE '{outside}' AS escaped",
    })
    assert out.startswith("ERROR") and "read-only" in out.lower()
    assert not outside.exists()


def test_readonly_authorizer_blocks_commented_vacuum_into(tmp_path):
    db = _mkdb(tmp_path)
    outside = tmp_path.parent / "outside-vacuum.db"
    outside.unlink(missing_ok=True)
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({
        "database": str(db),
        "query": f"/* sneaky */ VACUUM INTO '{outside}'",
    })
    assert out.startswith("ERROR")
    assert not outside.exists()


def test_write_allowed_when_read_only_false(tmp_path):
    db = _mkdb(tmp_path)
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({
        "database": str(db),
        "query": "DELETE FROM users WHERE id = 1",
        "read_only": False,
    })
    assert "affected" in out.lower()
    c = sqlite3.connect(db)
    assert c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
    c.close()


def test_denied_write_leaves_rows_unchanged(tmp_path, monkeypatch):
    import importlib

    from maverick.safety import ConsentDenied

    def deny(*args, **kwargs):
        raise ConsentDenied("sql_query.write")

    module = importlib.import_module("maverick.tools.sql_query")
    monkeypatch.setattr(module, "request_execution_consent", deny)
    db = _mkdb(tmp_path)
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({"database": str(db), "query": "DELETE FROM users",
                          "read_only": False})
    assert "not approved" in out
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3


def test_write_mode_authorizer_blocks_attach_outside_workspace(tmp_path):
    db = _mkdb(tmp_path)
    outside = tmp_path.parent / "outside-write-attach.db"
    outside.unlink(missing_ok=True)

    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({
        "database": str(db),
        "query": f"ATTACH DATABASE '{outside}' AS escaped",
        "read_only": False,
    })

    assert out.startswith("ERROR")
    assert not outside.exists()


def test_write_mode_authorizer_blocks_vacuum_into_outside_workspace(tmp_path):
    db = _mkdb(tmp_path)
    outside = tmp_path.parent / "outside-write-vacuum.db"
    outside.unlink(missing_ok=True)

    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({
        "database": str(db),
        "query": f"VACUUM INTO '{outside}'",
        "read_only": False,
    })

    assert out.startswith("ERROR")
    assert not outside.exists()


def test_write_with_returning_is_committed(tmp_path):
    # A write with a RETURNING clause produces a cursor description, so it takes
    # the row-formatting path -- it must still be committed, or sqlite rolls the
    # mutation back on connection close and the "success" is silently lost.
    db = _mkdb(tmp_path)
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({
        "database": str(db),
        "query": "INSERT INTO users(id, name) VALUES(4, 'dave') RETURNING id",
        "read_only": False,
    })
    assert "4" in out  # the RETURNING row is echoed
    c = sqlite3.connect(db)
    assert c.execute("SELECT name FROM users WHERE id = 4").fetchone() == ("dave",)
    c.close()


def test_delete_with_returning_is_committed(tmp_path):
    db = _mkdb(tmp_path)
    sql_query(SimpleNamespace(workdir=tmp_path)).fn({
        "database": str(db),
        "query": "DELETE FROM users WHERE id = 1 RETURNING name",
        "read_only": False,
    })
    c = sqlite3.connect(db)
    assert c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
    c.close()


def test_params_binding(tmp_path):
    db = _mkdb(tmp_path)
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({
        "database": str(db),
        "query": "SELECT name FROM users WHERE name = ?",
        "params": ["bob"],
    })
    assert "bob" in out and "alice" not in out and "(1 row(s))" in out


def test_max_rows_truncation(tmp_path):
    db = _mkdb(tmp_path)
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({"database": str(db), "query": "SELECT * FROM users", "max_rows": 1})
    assert "truncated at 1" in out


def test_missing_database(tmp_path):
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({"database": str(tmp_path / "nope.db"), "query": "SELECT 1"})
    assert "not found" in out.lower()


def test_bad_sql_returns_error(tmp_path):
    db = _mkdb(tmp_path)
    out = sql_query(SimpleNamespace(workdir=tmp_path)).fn({"database": str(db), "query": "SELECT * FROM does_not_exist"})
    assert out.startswith("ERROR")


def test_multi_statement_does_not_execute_injected_write(tmp_path):
    db = _mkdb(tmp_path)
    # A piggy-backed write must never run -- regardless of how the running
    # Python version handles a multi-statement execute() (<=3.10 raises
    # sqlite3.Warning, 3.11+ raises ProgrammingError, and a hypothetical
    # future could run only the first statement). Asserting the data
    # invariant instead of a version-specific error message is what keeps
    # this test from breaking across the interpreter matrix.
    sql_query(SimpleNamespace(workdir=tmp_path)).fn({
        "database": str(db),
        "query": "SELECT 1; DROP TABLE users",
        "read_only": False,
    })
    c = sqlite3.connect(db)
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    c.close()
    assert "users" in tables  # the injected DROP never executed


def test_requires_database_and_query(tmp_path):
    assert "database is required" in sql_query(SimpleNamespace(workdir=tmp_path)).fn({"query": "SELECT 1"}).lower()
    assert "query is required" in sql_query(SimpleNamespace(workdir=tmp_path)).fn({"database": "x.db"}).lower()


def test_registered_by_default():
    from maverick.tools import base_registry

    class _FakeSandbox:
        pass

    class _FakeWorld:
        pass

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    assert "sql_query" in {t.name for t in reg.all()}


def test_schema_requires_database_and_query():
    schema = sql_query().input_schema
    assert schema["required"] == ["database", "query"]
