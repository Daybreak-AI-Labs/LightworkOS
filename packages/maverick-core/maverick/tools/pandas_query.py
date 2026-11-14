"""Data analysis tool: pandas-backed CSV / Parquet / JSON queries.

Runs simple read + describe + filter + groupby operations on a
file the agent points it at. Result is rendered as a compact text
table so it fits in tool-result token budgets.

The tool is intentionally LIMITED: it doesn't accept arbitrary
``df.eval()`` strings (that's a code-execution vector). Instead,
each op is a typed verb the tool function understands.

Optional [pandas] extra installs pandas + pyarrow (for parquet).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from . import Tool

log = logging.getLogger(__name__)

# Hard cap on rows pulled into memory, regardless of the requested `n`. The
# tool only ever renders the top `n` (<=200) rows or whole-frame summaries, so
# reading a multi-GB file in full would OOM the process for no benefit. Loading
# this many rows + 1 also lets us tell the caller the data was truncated.
_MAX_LOAD_ROWS = 100_000


def _max_json_bytes() -> int:
    """Byte cap for whole-file JSON reads (non-lines .json has no row cap).

    Default 256 MiB; override with MAVERICK_PANDAS_MAX_JSON_BYTES. pandas must
    materialize the entire .json document before we can trim rows, so a size
    guard is the only pre-read bound available for that format.
    """
    try:
        return int(os.environ.get("MAVERICK_PANDAS_MAX_JSON_BYTES", 256 * 1024 * 1024))
    except ValueError:
        return 256 * 1024 * 1024


def _safe_path(sandbox, user_path: str) -> Path:
    """Resolve ``user_path`` confined to the sandbox workspace.

    A local sandbox is required. Resolve under its workspace and reject
    Lightwork's internal data directory even when the workspace contains it.
    """
    from ..paths import maverick_home
    if sandbox is None:
        raise ValueError("a sandbox workspace is required to query a file")
    from ..sandbox.ssh import SSHBackend
    if isinstance(sandbox, SSHBackend):
        raise ValueError("host dataframe tools cannot access an SSH workspace")
    workdir = Path(sandbox.workdir).resolve()
    candidate = Path(user_path)
    candidate = (workdir / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    try:
        candidate.relative_to(workdir)
    except ValueError as exc:
        raise ValueError("path escapes the workspace") from exc
    state = maverick_home().resolve()
    if candidate.is_relative_to(state) and not candidate.is_relative_to(state / "workspace"):
        raise ValueError("Lightwork's internal data directory cannot be queried")
    return candidate


_PANDAS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["head", "describe", "value_counts", "filter", "groupby"],
            "description": "Operation.",
        },
        "source": {
            "type": "string",
            "description": "Path to the file (csv / parquet / json / jsonl).",
        },
        "column": {"type": "string", "description": "Target column (value_counts, groupby)."},
        "agg": {
            "type": "string",
            "enum": ["count", "sum", "mean", "median", "min", "max", "std"],
            "description": "Aggregation function (groupby).",
        },
        "agg_column": {"type": "string", "description": "Column to aggregate (groupby)."},
        "where": {
            "type": "string",
            "description": "Filter expression: 'column op value' (e.g. 'age > 25').",
        },
        "n": {"type": "integer", "description": "Row limit (default 20)."},
    },
    "required": ["op", "source"],
}


def _load(path: Path):
    try:
        import pandas as pd
    except ImportError as e:
        raise ImportError(
            "pandas not installed. Run: python -m pip install -e './packages/maverick-core[pandas]'"
        ) from e
    ext = path.suffix.lower()
    # Read at most _MAX_LOAD_ROWS+1 so a huge file can't exhaust memory; the
    # extra row lets callers detect truncation. csv/jsonl support streaming row
    # caps natively; parquet streams via pyarrow row-group batches and stops at
    # the cap. Non-lines .json has no streaming row cap, so it is byte-bounded
    # before read instead.
    cap = _MAX_LOAD_ROWS + 1
    if ext == ".csv":
        return pd.read_csv(path, nrows=cap)
    if ext == ".jsonl":
        return pd.read_json(path, lines=True, nrows=cap)
    if ext == ".parquet":
        return _load_parquet_capped(path, cap, pd)
    if ext == ".json":
        max_bytes = _max_json_bytes()
        size = path.stat().st_size
        if size > max_bytes:
            raise ValueError(
                f".json is {size:,} bytes, over the {max_bytes:,}-byte read "
                "limit (set MAVERICK_PANDAS_MAX_JSON_BYTES to raise it); "
                "convert to .jsonl for streaming row-capped reads"
            )
        return pd.read_json(path).head(cap)
    raise ValueError(f"unsupported file extension: {ext}")


def _load_parquet_capped(path: Path, cap: int, pd):
    """Read at most ``cap`` rows from a parquet file without loading it whole.

    Streams row-group batches via pyarrow and stops once ``cap`` rows are
    collected, so a multi-GB parquet does not materialize fully in memory.
    Falls back to a full read + head if pyarrow's batch API is unavailable.
    """
    try:
        import pyarrow.parquet as pq
    except ImportError:
        return pd.read_parquet(path).head(cap)
    pf = pq.ParquetFile(path)
    batches = []
    collected = 0
    for batch in pf.iter_batches(batch_size=min(cap, 65_536)):
        batches.append(batch)
        collected += batch.num_rows
        if collected >= cap:
            break
    if not batches:
        return pf.schema_arrow.empty_table().to_pandas()
    import pyarrow as pa
    table = pa.Table.from_batches(batches)
    return table.slice(0, cap).to_pandas()


def _apply_where(df, where: str):
    """Parse a single 'col op value' clause. Safer than df.query()."""
    import re
    # Strip first: a lazy ``(.+?)\s*$`` retries the trailing-space match at
    # every position of a long whitespace run, which is quadratic.
    m = re.fullmatch(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*(==|!=|<=|>=|<|>)\s*(.+)",
        where.strip(),
    )
    if not m:
        raise ValueError(
            f"where clause must be `column op value`; got {where!r}"
        )
    col, op_, raw = m.group(1), m.group(2), m.group(3).strip()
    # Coerce the value: int, float, or string literal.
    if raw.startswith(("'", '"')) and raw.endswith(("'", '"')):
        val = raw[1:-1]
    else:
        try:
            val = int(raw)
        except ValueError:
            try:
                val = float(raw)
            except ValueError:
                val = raw
    series = df[col]
    if op_ == "==":
        return df[series == val]
    if op_ == "!=":
        return df[series != val]
    if op_ == "<":
        return df[series < val]
    if op_ == "<=":
        return df[series <= val]
    if op_ == ">":
        return df[series > val]
    if op_ == ">=":
        return df[series >= val]
    raise ValueError(f"unsupported op: {op_}")


def _fmt(df, *, max_rows: int = 20) -> str:
    """Compact text table; truncate to keep token cost bounded."""
    try:
        return df.head(max_rows).to_string(index=True, max_cols=20)
    except Exception:
        # Fallback for non-DataFrame results (Series, scalars).
        return str(df)


def _run(args: dict[str, Any], sandbox) -> str:
    op = args.get("op")
    src = (args.get("source") or "").strip()
    if not op:
        return "ERROR: op is required"
    if not src:
        return "ERROR: source is required"
    try:
        path = _safe_path(sandbox, src)
    except ValueError as exc:
        return f"ERROR: {exc}"
    if not path.exists() or not path.is_file():
        return f"ERROR: file not found: {src!r}"

    try:
        df = _load(path)
    except ImportError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: cannot load {src!r}: {type(e).__name__}: {e}"

    truncated = ""
    try:
        if len(df) > _MAX_LOAD_ROWS:
            df = df.head(_MAX_LOAD_ROWS)
            truncated = (
                f"\n[note: input truncated to the first {_MAX_LOAD_ROWS:,} rows]"
            )
    except TypeError:  # df without len() — leave as-is
        pass

    n = max(1, min(int(args.get("n") or 20), 200))
    where = args.get("where")
    if where:
        try:
            df = _apply_where(df, where)
        except Exception as e:
            return f"ERROR: bad where clause: {e}"

    try:
        if op == "head":
            out = _fmt(df, max_rows=n)
        elif op == "describe":
            out = df.describe(include="all").to_string()
        elif op == "value_counts":
            col = (args.get("column") or "").strip()
            if not col:
                return "ERROR: value_counts requires column"
            out = df[col].value_counts().head(n).to_string()
        elif op == "filter":
            out = _fmt(df, max_rows=n)
        elif op == "groupby":
            col = (args.get("column") or "").strip()
            agg_col = (args.get("agg_column") or "").strip()
            agg_fn = (args.get("agg") or "count").strip()
            if not col:
                return "ERROR: groupby requires column"
            grouped = df.groupby(col)
            if not agg_col or agg_fn == "count":
                result = grouped.size().sort_values(ascending=False)
            else:
                result = grouped[agg_col].agg(agg_fn).sort_values(ascending=False)
            out = result.head(n).to_string()
        else:
            return f"ERROR: unknown op {op!r}"
    except Exception as e:
        return f"ERROR: {op} failed: {type(e).__name__}: {e}"
    return out + truncated


def pandas_query(sandbox=None) -> Tool:
    return Tool(
        name="pandas_query",
        description=(
            "Tabular data analysis over csv / parquet / json / jsonl "
            "files. ops: head (top n rows), describe (summary stats), "
            "value_counts (frequency table for one column), filter "
            "(with where clause like 'age > 25'), groupby (with agg: "
            "count / sum / mean / median / min / max / std). Loaded "
            "via pandas; install with: pip install "
            "'maverick-agent[pandas]'."
        ),
        input_schema=_PANDAS_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )
