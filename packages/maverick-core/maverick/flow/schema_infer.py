"""Infer the SHAPE of a flow's data keys from real run outputs.

The designer's data pills know a node has an ``output`` key, but not what's
*inside* it -- so a user can't reference ``{{order.total}}`` until they guess.
After a real run this records, per output key, the value's type and (for a
dict / a list of dicts) its field names, so the pills can offer nested keys.

Only bounded ASCII identifier-shaped key names and types are stored, never
values. This excludes email addresses and other non-identifier data used as
keys; retained names can still carry business meaning. Shapes accumulate
across runs, so an occasionally-missing optional field still shows up.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

_MAX_KEYS = 60          # cap fields recorded per output (bound the hint size)
_MAX_OUTPUTS = 200      # cap distinct output keys tracked per flow
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")


def _field_names(keys: Iterable) -> list[str]:
    return sorted({key for key in keys
                   if isinstance(key, str) and _IDENTIFIER.fullmatch(key)})[:_MAX_KEYS]


def _clean_shape(shape: dict) -> dict:
    result = dict(shape)
    if "keys" in result:
        result["keys"] = _field_names(result["keys"] or [])
    return result


def infer_shape(value: Any) -> dict:
    """The recorded shape of one value: its type, plus field names for a dict or
    a list whose elements are dicts."""
    if isinstance(value, dict):
        return {"type": "object",
                "keys": _field_names(value)}
    if isinstance(value, (list, tuple)):
        el = next((x for x in value if isinstance(x, dict)), None)
        return {"type": "array",
                "keys": (_field_names(el) if el else [])}
    return {"type": type(value).__name__}


def infer_output_shapes(flow, data: dict) -> dict[str, dict]:
    """Map each node's ``output`` key to the shape of its value in ``data``."""
    out: dict[str, dict] = {}
    for n in flow.nodes.values():
        key = getattr(n, "output", "")
        if key and key in data and len(out) < _MAX_OUTPUTS:
            out[key] = infer_shape(data[key])
    return out


def merge_shapes(prior: dict[str, dict], fresh: dict[str, dict]) -> dict[str, dict]:
    """Union a newly-observed shape map into the accumulated one: newest type
    wins, field-name sets are unioned (so an optional field seen once persists)."""
    merged = {key: _clean_shape(shape) for key, shape in (prior or {}).items()}
    for key, shape in (fresh or {}).items():
        old = merged.get(key)
        if not old or old.get("type") != shape.get("type"):
            merged[key] = _clean_shape(shape)
            continue
        keys = _field_names([*(old.get("keys") or []), *(shape.get("keys") or [])])
        merged[key] = {"type": shape["type"], "keys": keys}
    return dict(list(merged.items())[:_MAX_OUTPUTS])


__all__ = ["infer_shape", "infer_output_shapes", "merge_shapes"]
