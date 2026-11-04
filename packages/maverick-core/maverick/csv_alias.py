"""One tolerant alias-headed CSV reader for every governed importer.

Four importers (OneTrust RoPA, OneTrust vendors, OneTrust consents, the
warehouse ``information_schema`` export) share the same loop — lowercase
the headers, resolve per-field aliases, bound the rows — and the same two
failure modes: overflow cells land under ``csv.DictReader``'s ``None`` key
as a LIST (so ``.strip()`` would raise), and ``csv.Error`` (NUL bytes,
oversized fields) would escape as a 500. This module is the one home for that loop, with both failure modes
handled: malformed cells are ignored, and unparseable CSV raises a clean
``ValueError`` the API layer maps to 422.
"""
from __future__ import annotations

import csv
import io
from collections.abc import Mapping

MAX_FIELD_CHARS = 10_000


def alias_rows(
    csv_text: str,
    header_aliases: Mapping[str, tuple[str, ...]],
    *,
    limit: int,
) -> list[dict[str, str]]:
    """Rows of ``csv_text`` mapped through ``header_aliases``, bounded.

    Each returned dict maps an alias-group field name to the row's first
    non-empty matching cell (stripped, bounded). Rows beyond ``limit``
    are dropped; ragged rows contribute what they validly carry; a CSV
    the parser cannot read at all raises ``ValueError``.
    """

    reader = csv.DictReader(io.StringIO(str(csv_text or "")))
    try:
        rows = list(reader)[: max(0, int(limit))]
    except csv.Error as exc:
        raise ValueError(f"csv_text is not parseable CSV: {exc}") from exc
    out: list[dict[str, str]] = []
    for row in rows:
        low: dict[str, str] = {}
        for key, value in row.items():
            # Overflow cells land under the None key as a list; restval
            # fills missing cells with None. Neither is a usable value.
            if key is None or not isinstance(value, str):
                continue
            low[key.strip().lower()] = value.strip()[:MAX_FIELD_CHARS]
        entry: dict[str, str] = {}
        for field, aliases in header_aliases.items():
            for alias in aliases:
                if low.get(alias):
                    entry[field] = low[alias]
                    break
        out.append(entry)
    return out


__all__ = ["MAX_FIELD_CHARS", "alias_rows"]
