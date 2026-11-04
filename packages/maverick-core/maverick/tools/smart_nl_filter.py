"""Smart natural-language filters.

Translate a small natural-language filter query into a structured predicate and
apply it to rows. Pure parsing — no LLM. A query is one or more comparison
clauses joined by ``and`` / ``or``:

    cost > 5 and tool = shell
    status != ok or cost >= 100

Supported operators: ``>`` ``<`` ``>=`` ``<=`` ``=`` ``!=`` and the word
``contains`` (substring match). A handful of natural-language shorthands are
also recognised and expanded to clauses:

    failed runs           -> status = failed
    last 7 days           -> age_days <= 7   (also "last N day(s)")

ops:
  - parse(query)            — query -> {clauses:[{field, op, value}], connector}
  - apply(rows, predicate)  — filter rows (list of dicts) by a predicate dict.

Deterministic and offline. A single connector (all AND or all OR) is supported;
a mix returns an error from parse.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

# Order matters: match two-char operators before one-char ones.
_OP_RE = re.compile(r"\s*(contains|>=|<=|!=|>|<|=)\s*", re.IGNORECASE)


def _coerce(value: str) -> Any:
    """Turn a token into a number when it looks like one, else strip quotes."""
    v = value.strip()
    if len(v) >= 2 and v[0] in "'\"" and v[-1] == v[0]:
        return v[1:-1]
    try:
        if re.fullmatch(r"-?\d+", v):
            return int(v)
        return float(v)
    except ValueError:
        return v


def _expand_shorthands(query: str) -> str:
    """Rewrite recognised NL phrases into canonical ``field op value`` clauses."""
    q = query
    q = re.sub(r"\bfailed\s+runs?\b", "status = failed", q, flags=re.IGNORECASE)
    q = re.sub(
        r"\blast\s+(\d+)\s+days?\b",
        lambda m: f"age_days <= {m.group(1)}",
        q,
        flags=re.IGNORECASE,
    )
    return q


def _parse_clause(text: str) -> dict | None:
    m = _OP_RE.search(text)
    if not m:
        return None
    op = m.group(1).lower()
    field = text[: m.start()].strip()
    value = text[m.end():].strip()
    if not field or value == "":
        return None
    return {"field": field, "op": op, "value": _coerce(value)}


def _split_on(query: str, word: str) -> list[str]:
    """Split ``query`` on ``\\bword\\b``, but only where the connector actually
    separates two clauses — i.e. the fragment that FOLLOWS the connector begins
    a new ``field op value`` clause. This prevents splitting on the word 'and'/
    'or' that merely appears inside a value (``city = New York or LA``).

    Fragments that don't start a new clause are re-joined to the preceding one.
    """
    raw = re.split(rf"\b{word}\b", query, flags=re.IGNORECASE)
    if len(raw) == 1:
        return raw
    merged: list[str] = [raw[0]]
    for frag in raw[1:]:
        # A real connector is followed by a new clause (has an operator). If not,
        # the split fell inside a value — stitch the word back in.
        if _OP_RE.search(frag):
            merged.append(frag)
        else:
            merged[-1] = f"{merged[-1]}{word}{frag}"
    return merged


def _split_connector(query: str) -> tuple[list[str], str | None, str | None]:
    """Split on the connector. Returns (parts, connector, error)."""
    and_parts = _split_on(query, "and")
    or_parts = _split_on(query, "or")
    has_and = len(and_parts) > 1
    has_or = len(or_parts) > 1
    if has_and and has_or:
        return [], None, "mixed AND/OR is not supported"
    if has_and:
        return and_parts, "AND", None
    if has_or:
        return or_parts, "OR", None
    return [query], "AND", None


def _parse(query: str) -> dict | str:
    if not isinstance(query, str) or not query.strip():
        return "ERROR: query is required"
    expanded = _expand_shorthands(query)
    parts, connector, err = _split_connector(expanded)
    if err:
        return f"ERROR: {err}"
    clauses = []
    for part in parts:
        clause = _parse_clause(part)
        if clause is None:
            return f"ERROR: could not parse clause {part.strip()!r}"
        clauses.append(clause)
    if not clauses:
        return "ERROR: no clauses parsed"
    return {"clauses": clauses, "connector": connector}


def _cmp(left: Any, op: str, right: Any) -> bool:
    if op == "contains":
        return str(right).lower() in str(left).lower()
    if op == "=":
        # Coerce numeric strings first (mirrors the ordering operators below) so
        # that e.g. "5.00" = 5 agrees with "5.00" >= 5 / <= 5 instead of
        # contradicting them.
        ln, rn = _num(left), _num(right)
        if ln is not None and rn is not None:
            return ln == rn
        return str(left).strip().lower() == str(right).strip().lower()
    if op == "!=":
        return not _cmp(left, "=", right)
    # Ordering operators: numeric when both sides are numbers, else string.
    ln, rn = _num(left), _num(right)
    if ln is not None and rn is not None:
        left, right = ln, rn
    else:
        left, right = str(left), str(right)
    if op == ">":
        return left > right
    if op == "<":
        return left < right
    if op == ">=":
        return left >= right
    if op == "<=":
        return left <= right
    return False


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _row_matches(row: dict, predicate: dict) -> bool:
    clauses = predicate.get("clauses") or []
    connector = str(predicate.get("connector") or "AND").upper()
    results = []
    for c in clauses:
        field = c.get("field")
        if field not in row:
            results.append(False)
            continue
        results.append(_cmp(row[field], str(c.get("op")), c.get("value")))
    if not results:
        return False
    return all(results) if connector != "OR" else any(results)


def _apply(args: dict[str, Any]) -> str:
    rows = args.get("rows")
    predicate = args.get("predicate")
    if not isinstance(rows, list):
        return "ERROR: rows must be an array of objects"
    if isinstance(predicate, str):
        parsed = _parse(predicate)
        if isinstance(parsed, str):
            return parsed
        predicate = parsed
    if not isinstance(predicate, dict) or "clauses" not in predicate:
        return "ERROR: predicate must be a parsed dict {clauses, connector} or a query string"
    kept = [r for r in rows if isinstance(r, dict) and _row_matches(r, predicate)]
    import json
    return f"MATCHED {len(kept)}/{len(rows)} row(s):\n" + json.dumps(kept)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op") or "parse"
    if op == "parse":
        result = _parse(args.get("query"))
        if isinstance(result, str):
            return result
        import json
        return "PREDICATE: " + json.dumps(result)
    if op == "apply":
        return _apply(args)
    return f"ERROR: unknown op {op!r}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["parse", "apply"]},
        "query": {"type": "string", "description": "natural-language filter, e.g. 'cost > 5 and tool = shell'"},
        "rows": {
            "type": "array",
            "description": "rows to filter (objects)",
            "items": {"type": "object"},
        },
        "predicate": {
            "description": "a parsed predicate {clauses, connector} or a raw query string",
            "type": ["object", "string"],
        },
    },
}


def smart_nl_filter() -> Tool:
    return Tool(
        name="smart_nl_filter",
        description=(
            "Translate a natural-language filter into a structured predicate and "
            "apply it. op=parse(query) returns {clauses:[{field, op, value}], "
            "connector}; op=apply(rows, predicate) filters rows. Operators: > < "
            ">= <= = != contains, joined by AND/OR (one connector). Recognises "
            "'failed runs' and 'last N days'. Pure parsing, no LLM; offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
