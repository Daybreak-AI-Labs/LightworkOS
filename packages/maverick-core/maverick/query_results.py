"""Bounded SQL result data with explicit row, cell and presentation completeness."""
from __future__ import annotations

import base64
import datetime
import decimal
import json
import math
import uuid
from dataclasses import dataclass, replace

MAX_OUTPUT = 50_000
MAX_COLUMNS = 64


def render_effect(affected_rows, transaction_status, cancellation_support, *, response_format="text", style="database"):
    known = isinstance(affected_rows, int) and affected_rows >= 0
    metadata = {"execution_status": "succeeded", "transaction_status": transaction_status,
                "cancellation_support": cancellation_support, "complete": True,
                "affected_rows": affected_rows if known else None, "affected_rows_known": known}
    if response_format == "json":
        return json.dumps(metadata)
    prefix = "OK" if style == "sqlite" else "ok"
    count = str(affected_rows) if known else "unknown number of"
    return f"{prefix}: {count} row(s) affected\nresult_metadata: " + json.dumps(metadata)


def _text_prefix(value: str, limit: int) -> str:
    # Encode at most `limit` characters, never a whole unbounded text cell.
    return value[:limit].encode("utf-8", errors="replace")[:limit].decode("utf-8", errors="ignore")


@dataclass(frozen=True)
class QueryCell:
    value: str | int | float | bool | None
    kind: str | None = None
    truncated: bool = False
    source_size: int | None = None

    def document(self):
        if self.kind is None and not self.truncated:
            return self.value
        return {"value": self.value, "type": self.kind or "text", "truncated": self.truncated,
                "source_size": self.source_size}


def _cell(value, limit: int) -> QueryCell:
    if value is None or isinstance(value, (bool, int)):
        return QueryCell(value)
    if isinstance(value, float):
        return QueryCell(value) if math.isfinite(value) else QueryCell(str(value), "nonfinite_number")
    if isinstance(value, str):
        prefix = _text_prefix(value, limit)
        return QueryCell(prefix, truncated=prefix != value, source_size=len(value))
    if isinstance(value, (bytes, bytearray, memoryview)):
        view = memoryview(value)
        if not view.c_contiguous:
            return QueryCell(None, "binary_base64", True, view.nbytes)
        view = view.cast("B")
        prefix = bytes(view[:limit * 3 // 4])
        return QueryCell(base64.b64encode(prefix).decode("ascii"), "binary_base64",
                         len(prefix) != view.nbytes, view.nbytes)
    if isinstance(value, (datetime.date, datetime.time, decimal.Decimal, uuid.UUID)):
        text = str(value)
        prefix = _text_prefix(text, limit)
        return QueryCell(prefix, type(value).__name__, len(prefix) != len(text), len(text))
    # Driver-decoded JSON/arrays/custom values can be arbitrarily large. Do not
    # serialize the entire object to manufacture a preview; require projection.
    return QueryCell(None, type(value).__name__[:80], True)


@dataclass(frozen=True)
class QueryResult:
    columns: tuple[str, ...]
    rows: tuple[tuple[QueryCell, ...], ...]
    source_has_more: bool
    row_limit: int
    fetched_rows: int
    omitted_columns: bool = False
    column_names_truncated: bool = False
    output_rows_omitted: bool = False
    execution_status: str = "succeeded"
    transaction_status: str = "read_only"
    cancellation_support: str = "not_reported"

    @classmethod
    def from_rows(cls, columns, rows, *, row_limit: int, transaction_status="read_only",
                  cancellation_support="not_reported"):
        raw_columns = tuple(columns)
        names = tuple(_text_prefix(str(name), 128) for name in raw_columns[:MAX_COLUMNS])
        source_has_more = len(rows) > row_limit
        admitted = []
        used = len(json.dumps(names))
        omitted = False
        cell_limit = min(1024, MAX_OUTPUT // max(1, len(names)) // 4)
        for row in rows[:row_limit]:
            cells = tuple(_cell(value, cell_limit) for value in row[:len(names)])
            size = len(json.dumps([cell.document() for cell in cells], ensure_ascii=True))
            if used + size > MAX_OUTPUT - 4096:
                omitted = True
                break
            admitted.append(cells)
            used += size
        return cls(names, tuple(admitted), source_has_more, row_limit, len(rows),
                   len(raw_columns) > len(names), any(str(raw_columns[i]) != name for i, name in enumerate(names)),
                   omitted, transaction_status=transaction_status, cancellation_support=cancellation_support)

    @property
    def complete(self):
        return not (self.source_has_more or self.omitted_columns or self.column_names_truncated
                    or self.output_rows_omitted or any(cell.truncated for row in self.rows for cell in row))

    def metadata(self):
        return {
            "execution_status": self.execution_status, "transaction_status": self.transaction_status,
            "cancellation_support": self.cancellation_support,
            "complete": self.complete, "has_more": self.source_has_more,
            "rows_returned": len(self.rows), "row_limit": self.row_limit,
            "fetched_rows": self.fetched_rows, "columns_omitted": self.omitted_columns,
            "column_names_truncated": self.column_names_truncated,
            "output_rows_omitted": self.output_rows_omitted,
            "cells_truncated": sum(cell.truncated for row in self.rows for cell in row),
            "continuation": {"available": False, "reason": "per-call snapshot closed; use an explicitly ordered narrower query"},
        }

    def render(self, *, style="database", response_format="text") -> str:
        """Bound the final preview by dropping whole rows, never slicing JSON."""
        current = self
        while True:
            data = [[cell.document() for cell in row] for row in current.rows]
            metadata = current.metadata()
            if response_format == "json":
                output = json.dumps({**metadata, "columns": current.columns, "rows": data})
            elif style == "sqlite":
                lines = [" | ".join(current.columns), "-+-".join("-" * len(name) for name in current.columns)]
                lines += [" | ".join("NULL" if cell is None else json.dumps(cell) for cell in row) for row in data]
                summary = f"({len(data)} row(s)" + (f", truncated at {current.row_limit}" if current.source_has_more else "") + ")"
                output = "\n".join(["result_metadata: " + json.dumps(metadata), *lines, summary])
            else:
                lines = [f"columns: {list(current.columns)}", f"{len(data)} row(s):"]
                lines += ["  " + json.dumps(row) for row in data]
                output = "\n".join(["result_metadata: " + json.dumps(metadata), *lines])
            if len(output) <= MAX_OUTPUT:
                return output
            if not current.rows:
                # Bounded column headers plus fixed metadata fit MAX_OUTPUT;
                # refuse rather than ever emit an incomplete serialized object.
                return "ERROR: SQL result metadata exceeded the output budget"
            current = replace(current, rows=current.rows[:-1], output_rows_omitted=True)
