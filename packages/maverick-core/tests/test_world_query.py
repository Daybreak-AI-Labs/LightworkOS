"""WorldModel.query / sql_day_from_epoch: the backend-portable raw-read contract.

The dashboard's boards and exports write SQL once, in SQLite paramstyle, and
run it on either backend. The SQLite half runs here; the Postgres half's
paramstyle rewrite and row wrapper are pure functions tested without a server
(the live round-trip lives in test_postgres_world.py).
"""
from __future__ import annotations

import pytest
from maverick.world_model import WorldModel
from maverick.world_model_backends.postgres import _PgRow, _to_pg_paramstyle


@pytest.fixture
def world(tmp_path):
    w = WorldModel(tmp_path / "world.db")
    try:
        yield w
    finally:
        w.close()


def test_query_rows_answer_index_key_and_unpacking(world):
    a = world.create_goal("first", "")
    world.create_goal("second", "")
    world.set_goal_status(a, "done")

    rows = world.query(
        "SELECT status, COUNT(*) AS n FROM goals WHERE status = ? GROUP BY status",
        ("done",),
    )
    assert len(rows) == 1
    assert rows[0][0] == "done" and rows[0]["status"] == "done"
    assert rows[0]["n"] == 1
    (status, n), = rows
    assert (status, n) == ("done", 1)


def test_query_without_params_and_day_bucket(world):
    gid = world.create_goal("today", "")
    (row,) = world.query(
        f"SELECT {world.sql_day_from_epoch('created_at')} AS day FROM goals WHERE id = {gid}"
    )
    # ISO date, UTC: matches the key set the boards build with datetime.now(timezone.utc).
    assert len(row["day"]) == 10 and row["day"][4] == "-" and row["day"][7] == "-"


def test_pg_paramstyle_rewrite_handles_placeholders_and_literal_percent():
    assert _to_pg_paramstyle("SELECT 1 WHERE a = ? AND b < ?") == "SELECT 1 WHERE a = %s AND b < %s"
    # A literal % must be doubled or psycopg reads it as a placeholder marker.
    assert _to_pg_paramstyle("WHERE owner LIKE 'agent:%' AND id = ?") == (
        "WHERE owner LIKE 'agent:%%' AND id = %s"
    )
    # A question mark inside a string literal is data, not a placeholder.
    assert _to_pg_paramstyle("WHERE title = 'why?' AND id = ?") == "WHERE title = 'why?' AND id = %s"


def test_pg_row_supports_index_key_and_unpacking():
    row = _PgRow.wrap(("done", 3), {"status": 0, "n": 1})
    assert row[0] == "done" and row["status"] == "done" and row["n"] == 3
    status, n = row
    assert (status, n) == ("done", 3)
    assert row.keys() == ["status", "n"]
    with pytest.raises(KeyError):
        row["missing"]


def test_tenant_markers_expand_in_parameter_order(world):
    from maverick.tenant_sql import expand

    def resolve(kind, column):
        return f"{kind}:{column} = ?", (kind,)

    sql, values = expand("SELECT 1 FROM goals g WHERE g.id = ? AND {tenant:g.tenant_id} "
                         "AND note = '{tenant:x} ?' AND {tenant_goal:g.id} AND {tenant_exact:t} AND x < ?",
                         (1, 2), resolve)
    assert sql == ("SELECT 1 FROM goals g WHERE g.id = ? AND (read:g.tenant_id = ?) "
                   "AND note = '{tenant:x} ?' AND (goal:g.id = ?) AND (exact:t = ?) AND x < ?")
    assert values == (1, "read", "goal", "exact", 2)
    with pytest.raises(ValueError):
        expand("SELECT 1 FROM goals", (), resolve)
    # The SQLite file is the tenant boundary: markers read as true.
    gid = world.create_goal("scoped", "")
    assert world.tenant_query("SELECT id FROM goals WHERE {tenant:tenant_id} AND id = ?", (gid,))[0][0] == gid
    assert world.query("SELECT id FROM goals WHERE id = ?", (gid,), system=True)[0][0] == gid
