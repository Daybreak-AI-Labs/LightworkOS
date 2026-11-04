"""SQL result completeness across real SQLite and SQLAlchemy tool adapters."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing, nullcontext
from types import SimpleNamespace

import pytest
from maverick.query_results import MAX_OUTPUT, QueryResult, render_effect
from maverick.tools.database_tool import database_tool
from maverick.tools.sql_query import sql_query


@pytest.fixture(autouse=True)
def _approved_sql_writes(monkeypatch):
    import importlib

    module = importlib.import_module("maverick.tools.sql_query")
    monkeypatch.setattr(module, "request_execution_consent", lambda *a, **kw: object())
    monkeypatch.setattr(module, "consume_operation_consent", lambda permit: nullcontext())


@pytest.fixture(params=["sqlite", "sqlalchemy"])
def query(request, monkeypatch, tmp_path):
    path = tmp_path / "rows.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT, payload BLOB, optional TEXT)")
        connection.executemany("INSERT INTO items VALUES(?, ?, ?, ?)",
                               [(1, "first", b"abc", None), (2, "second", b"def", None)])
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(path))

    def run(statement, *, limit=50, write=False, response_format="json"):
        if request.param == "sqlite":
            return sql_query(SimpleNamespace(workdir=tmp_path)).fn({"database": str(path), "query": statement, "max_rows": limit,
                                   "read_only": not write, "response_format": response_format})
        pytest.importorskip("sqlalchemy")
        return database_tool().fn({"op": "query", "sql": statement, "limit": limit,
                                   "confirm": write, "response_format": response_format})

    return run


def test_limit_one_distinguishes_one_row_from_two(query):
    partial = json.loads(query("SELECT id FROM items ORDER BY id", limit=1))
    complete = json.loads(query("SELECT id FROM items WHERE id = 1", limit=1))
    assert partial["rows"] == [[1]] and partial["has_more"] and not partial["complete"]
    assert partial["fetched_rows"] == 2
    assert complete["rows"] == [[1]] and not complete["has_more"] and complete["complete"]
    assert partial["continuation"]["available"] is False
    assert "snapshot closed" in partial["continuation"]["reason"]


def test_nullable_and_binary_cells_preserve_valid_structure(query):
    result = json.loads(query("SELECT value, payload, optional FROM items WHERE id = 1"))
    assert result["rows"][0] == ["first", {"value": "YWJj", "type": "binary_base64", "truncated": False, "source_size": 3}, None]
    assert result["complete"]


def test_confirmed_returning_commits_every_effect_once_after_limited_cursor_close(query):
    result = json.loads(query("UPDATE items SET value = value || '!' RETURNING id, value", limit=1, write=True))
    assert result["transaction_status"] == "committed"
    assert result["has_more"] and not result["complete"]
    observed = json.loads(query("SELECT value FROM items ORDER BY id"))
    assert observed["rows"] == [["first!"], ["second!"]]


def test_effect_result_honors_json_contract(query):
    result = json.loads(query("UPDATE items SET value = 'changed' WHERE id = 1", write=True))
    assert result["complete"] and result["affected_rows"] == 1
    assert result["transaction_status"] == "committed"


def test_long_unicode_and_binary_preview_have_explicit_cell_truncation():
    original = "☃🙂" * 10_000
    result = QueryResult.from_rows(["text", "binary", "null"], [(original, b"a" * 10_000, None)], row_limit=1)
    decoded = json.loads(result.render(response_format="json"))
    assert decoded["rows"][0][0]["truncated"]
    assert decoded["rows"][0][0]["source_size"] == len(original)
    assert decoded["rows"][0][1]["truncated"] and decoded["rows"][0][2] is None
    assert not decoded["complete"] and decoded["cells_truncated"] == 2
    assert "\ufffd" not in decoded["rows"][0][0]["value"]


def test_output_budget_keeps_complete_json_and_metadata_instead_of_slicing():
    result = QueryResult.from_rows(["text"], [("x" * 1000,)] * 1000, row_limit=1000)
    output = result.render(response_format="json")
    assert len(output) <= MAX_OUTPUT
    data = json.loads(output)
    assert data["output_rows_omitted"] and not data["complete"]
    assert data["rows_returned"] < data["fetched_rows"] == 1000
    # Completeness precedes row data, so a later outer tool preview cap cannot
    # remove the only indication that this is partial evidence.
    assert result.render(style="sqlite").splitlines()[0].startswith("result_metadata: ")


def test_nested_driver_values_are_explicitly_omitted_without_full_stringification():
    class NeverRender(dict):
        def __str__(self):
            pytest.fail("do not stringify a whole custom driver object")

    result = QueryResult.from_rows(["payload"], [(NeverRender(large="x" * 100_000),)], row_limit=1)
    data = json.loads(result.render(response_format="json"))
    assert not data["complete"] and data["rows"][0][0]["truncated"]


def test_column_omission_is_explicit_and_bounded():
    result = QueryResult.from_rows(["long" * 100] * 1000, [tuple(range(1000))], row_limit=1)
    data = json.loads(result.render(response_format="json"))
    assert data["columns_omitted"] and data["column_names_truncated"] and not data["complete"]
    assert len(data["columns"]) == len(data["rows"][0]) == 64


def test_driver_unknown_affected_count_is_not_reported_as_negative_rows():
    data = json.loads(render_effect(-1, "committed", "fixture", response_format="json"))
    assert data["affected_rows"] is None and not data["affected_rows_known"]


def test_noncontiguous_binary_is_explicitly_omitted_without_unbounded_copy():
    view = memoryview(b"x" * 100_000)[::2]
    result = QueryResult.from_rows(["binary"], [(view,)], row_limit=1)
    data = json.loads(result.render(response_format="json"))
    assert not data["complete"] and data["rows"][0][0]["source_size"] == view.nbytes
