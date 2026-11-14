"""Synthetic data generator tool.

Generate deterministic synthetic rows from a compact field spec — for seeding
tests, demos, and fixtures without touching real (or sensitive) data. Seeded so
the same spec + seed always yields the same rows (reproducible fixtures).

ops:
  - generate(fields, rows[, seed][, format])  — fields is a list of
    {name, type, ...}. Types: int (min,max), float (min,max), bool, choice
    (options), uuid, name, email, sequence (start). format: json (default) or csv.
"""
from __future__ import annotations

import random
import uuid
from typing import Any

from ..fastjson import dumps_compact
from . import Tool

_FIRST = ["Ada", "Linus", "Grace", "Alan", "Edsger", "Barbara", "Ken", "Margaret"]
_LAST = ["Lovelace", "Torvalds", "Hopper", "Turing", "Dijkstra", "Liskov", "Thompson"]
_MAX_ROWS = 10000


def _field_value(spec: dict, rng: random.Random, idx: int) -> Any:
    typ = spec.get("type", "string")
    if typ == "int":
        return rng.randint(int(spec.get("min", 0)), int(spec.get("max", 100)))
    if typ == "float":
        return round(rng.uniform(float(spec.get("min", 0.0)), float(spec.get("max", 1.0))), 4)
    if typ == "bool":
        return rng.random() < 0.5
    if typ == "choice":
        opts = spec.get("options") or []
        return rng.choice(opts) if opts else None
    if typ == "uuid":
        return str(uuid.UUID(int=rng.getrandbits(128)))
    if typ == "name":
        return f"{rng.choice(_FIRST)} {rng.choice(_LAST)}"
    if typ == "email":
        return f"{rng.choice(_FIRST).lower()}.{rng.choice(_LAST).lower()}{rng.randint(1, 999)}@example.com"
    if typ == "sequence":
        return int(spec.get("start", 1)) + idx
    return spec.get("const", "")  # default: a constant string


def _generate(fields: list[dict], n: int, seed: int, fmt: str) -> str:
    rng = random.Random(seed)
    names = [str(f.get("name") or f"col{i}") for i, f in enumerate(fields)]
    rows = [{names[i]: _field_value(f, rng, r) for i, f in enumerate(fields)}
            for r in range(n)]
    if fmt == "csv":
        out = [",".join(_csv_cell(name) for name in names)]
        for row in rows:
            out.append(",".join(_csv_cell(row[name]) for name in names))
        return "\n".join(out)
    return dumps_compact(rows)


def _csv_cell(v: Any) -> str:
    s = "" if v is None else str(v)
    if any(c in s for c in (",", '"', "\n")):
        return '"' + s.replace('"', '""') + '"'
    return s


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "generate"):
        return f"ERROR: unknown op {args.get('op')!r}"
    fields = args.get("fields")
    if not isinstance(fields, list) or not fields:
        return "ERROR: fields must be a non-empty array of {name, type, ...}"
    try:
        n = int(args.get("rows", 10))
    except (TypeError, ValueError):
        return "ERROR: rows must be an integer"
    if n < 1 or n > _MAX_ROWS:
        return f"ERROR: rows must be 1..{_MAX_ROWS}"
    try:
        seed = int(args.get("seed", 0))
    except (TypeError, ValueError):
        seed = 0
    fmt = (args.get("format") or "json").lower()
    if fmt not in ("json", "csv"):
        return "ERROR: format must be json or csv"
    return _generate(fields, n, seed, fmt)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["generate"]},
        "fields": {
            "type": "array",
            "description": "column specs; each {name, type, ...}",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "type": {"type": "string", "enum": [
                        "int", "float", "bool", "choice", "uuid", "name",
                        "email", "sequence", "string"]},
                    "min": {"type": "number"}, "max": {"type": "number"},
                    "options": {"type": "array"}, "start": {"type": "integer"},
                    "const": {},
                },
                "required": ["name", "type"],
            },
        },
        "rows": {"type": "integer", "description": "row count (default 10)"},
        "seed": {"type": "integer", "description": "RNG seed for reproducibility (default 0)"},
        "format": {"type": "string", "enum": ["json", "csv"]},
    },
    "required": ["fields"],
}


def synthetic_data() -> Tool:
    return Tool(
        name="synthetic_data",
        description=(
            "Generate deterministic synthetic rows from a field spec — for "
            "tests, demos, and fixtures without real data. op=generate with "
            "'fields' (each {name, type[, min/max/options/start/const]}; types: "
            "int, float, bool, choice, uuid, name, email, sequence, string), "
            "'rows', 'seed' (reproducible), and 'format' (json|csv)."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
