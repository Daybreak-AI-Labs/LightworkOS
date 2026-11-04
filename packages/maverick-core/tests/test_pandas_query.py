"""Tests for the pandas_query tool: input validation, sandbox confinement,
filtering, and memory-bounded loading.

Parquet and non-lines JSON must not materialize an arbitrarily large file in
full before the row cap is applied. The validation tests need neither pandas
nor pyarrow, so only the tests that read data skip without them.
"""
from __future__ import annotations

import importlib.util
from types import SimpleNamespace

import pytest
from maverick.tools import pandas_query as pqmod


@pytest.fixture
def pd():
    return pytest.importorskip("pandas")


@pytest.fixture
def pq():
    return pytest.importorskip("pyarrow.parquet")


def test_parquet_load_is_row_capped(tmp_path, monkeypatch, pd, pq):
    """Parquet reads must stop at the cap instead of loading the whole file."""
    monkeypatch.setattr(pqmod, "_MAX_LOAD_ROWS", 50)
    path = tmp_path / "big.parquet"
    pd.DataFrame({"a": range(10_000)}).to_parquet(path)

    # Count how many rows pyarrow actually streams in; with a full read this
    # would be all 10_000 rows, defeating the cap.
    real_iter_batches = pq.ParquetFile.iter_batches
    streamed = {"rows": 0}

    def counting_iter_batches(self, *a, **k):
        for b in real_iter_batches(self, *a, **k):
            streamed["rows"] += b.num_rows
            yield b

    monkeypatch.setattr(pq.ParquetFile, "iter_batches", counting_iter_batches)

    df = pqmod._load(path)

    cap = pqmod._MAX_LOAD_ROWS + 1
    assert len(df) == cap
    # The load must route through the streaming batch reader (a full
    # ``read_parquet().head()`` would never touch iter_batches, leaving this 0)
    # and stop early — nowhere near the full 10_000 rows.
    assert 0 < streamed["rows"] < 10_000


def test_json_byte_guard_rejects_oversized_file(tmp_path, monkeypatch, pd):
    """Non-lines .json over the byte limit is refused before any pandas read."""
    monkeypatch.setenv("MAVERICK_PANDAS_MAX_JSON_BYTES", "100")
    path = tmp_path / "big.json"
    pd.DataFrame({"a": range(1000)}).to_json(path)
    assert path.stat().st_size > 100

    with pytest.raises(ValueError, match="read limit"):
        pqmod._load(path)


def test_json_under_limit_still_loads(tmp_path, monkeypatch, pd):
    """A small .json under the byte limit loads normally."""
    monkeypatch.setenv("MAVERICK_PANDAS_MAX_JSON_BYTES", str(10 * 1024 * 1024))
    path = tmp_path / "small.json"
    pd.DataFrame({"a": [1, 2, 3]}).to_json(path)
    df = pqmod._load(path)
    assert len(df) == 3


# ---------- pandas_query ----------

_HAS_PANDAS = importlib.util.find_spec("pandas") is not None


def test_pandas_query_requires_source(tmp_path):
    from maverick.tools.pandas_query import pandas_query
    assert "source is required" in pandas_query(SimpleNamespace(workdir=tmp_path)).fn({"op": "head"})


def test_pandas_query_requires_workspace(tmp_path):
    from maverick.tools.pandas_query import pandas_query
    assert "sandbox workspace is required" in pandas_query().fn({
        "op": "head", "source": str(tmp_path / "input.csv"),
    })


def test_pandas_query_missing_file(tmp_path):
    from maverick.tools.pandas_query import pandas_query
    out = pandas_query(SimpleNamespace(workdir=tmp_path)).fn({
        "op": "head",
        "source": str(tmp_path / "missing.csv"),
    })
    assert "file not found" in out


@pytest.mark.skipif(not _HAS_PANDAS, reason="pandas not installed")
def test_pandas_query_head_csv(tmp_path):
    csv_path = tmp_path / "people.csv"
    csv_path.write_text("name,age\nAlice,30\nBob,25\nCarol,40\n")
    from maverick.tools.pandas_query import pandas_query
    out = pandas_query(SimpleNamespace(workdir=tmp_path)).fn({"op": "head", "source": str(csv_path), "n": 2})
    assert "Alice" in out
    assert "Bob" in out
    assert "Carol" not in out


@pytest.mark.skipif(not _HAS_PANDAS, reason="pandas not installed")
def test_pandas_query_where_filter(tmp_path):
    csv_path = tmp_path / "people.csv"
    csv_path.write_text("name,age\nAlice,30\nBob,25\nCarol,40\n")
    from maverick.tools.pandas_query import pandas_query
    out = pandas_query(SimpleNamespace(workdir=tmp_path)).fn({
        "op": "head", "source": str(csv_path),
        "where": "age > 28",
    })
    assert "Alice" in out
    assert "Carol" in out
    assert "Bob" not in out


def test_pandas_query_rejects_bad_where(tmp_path):
    if not _HAS_PANDAS:
        pytest.skip("pandas not installed")
    csv_path = tmp_path / "p.csv"
    csv_path.write_text("a,b\n1,2\n")
    from maverick.tools.pandas_query import pandas_query
    out = pandas_query(SimpleNamespace(workdir=tmp_path)).fn({
        "op": "head", "source": str(csv_path),
        "where": "df.eval('a + b')",
    })
    assert "bad where clause" in out


def test_pandas_query_confines_path_to_sandbox_workspace(tmp_path):
    """With a sandbox wired in, an absolute path outside workdir is refused
    before any file is read (no arbitrary host-file read). Needs no pandas:
    the path check happens before load."""
    class _SB:
        workdir = tmp_path / "ws"

    (tmp_path / "ws").mkdir()
    secret = tmp_path / "secret.csv"
    secret.write_text("col\nvalue\n")

    from maverick.tools.pandas_query import pandas_query
    tool = pandas_query(_SB())
    out = tool.fn({"op": "head", "source": str(secret)})
    assert "escapes the workspace" in out
    # A traversal attempt is likewise refused.
    assert "escapes the workspace" in tool.fn({"op": "head", "source": "../secret.csv"})


@pytest.mark.skipif(not _HAS_PANDAS, reason="pandas not installed")
def test_pandas_query_caps_oversized_input(tmp_path, monkeypatch):
    """A file larger than the load cap is truncated, not read in full."""
    import maverick.tools.pandas_query as pq
    monkeypatch.setattr(pq, "_MAX_LOAD_ROWS", 5)
    csv_path = tmp_path / "big.csv"
    rows = "\n".join(f"r{i},{i}" for i in range(50))
    csv_path.write_text("name,val\n" + rows + "\n")

    out = pq.pandas_query(SimpleNamespace(workdir=tmp_path)).fn({"op": "head", "source": str(csv_path), "n": 100})
    assert "truncated to the first 5 rows" in out
