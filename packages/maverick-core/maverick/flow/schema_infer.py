"""Infer the SHAPE of a flow's data keys from real run outputs.

The designer's data pills know a node has an ``output`` key, but not what's
*inside* it -- so a user can't reference ``{{order.total}}`` until they guess.
After a real run this records, per output key, the value's type and (for a
dict / a list of dicts) its field names, so the pills can offer nested keys.

Only key NAMES and types are stored -- never values -- so this leaks no data;
it is a schema hint, not a data cache. Shapes accumulate across runs (the union
of fields ever seen), so an occasionally-missing optional field still shows up.
"""
from __future__ import annotations

from typing import Any

_MAX_KEYS = 60          # cap fields recorded per output (bound the hint size)
_MAX_OUTPUTS = 200      # cap distinct output keys tracked per flow


def infer_shape(value: Any) -> dict:
    """The recorded shape of one value: its type, plus field names for a dict or
    a list whose elements are dicts."""
    if isinstance(value, dict):
        return {"type": "object",
                "keys": sorted(str(k) for k in value)[:_MAX_KEYS]}
    if isinstance(value, (list, tuple)):
        el = next((x for x in value if isinstance(x, dict)), None)
        return {"type": "array",
                "keys": (sorted(str(k) for k in el)[:_MAX_KEYS] if el else [])}
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
    merged = dict(prior or {})
    for key, shape in (fresh or {}).items():
        old = merged.get(key)
        if not old or old.get("type") != shape.get("type"):
            merged[key] = dict(shape)
            continue
        keys = sorted(set(old.get("keys") or []) | set(shape.get("keys") or []))[:_MAX_KEYS]
        merged[key] = {"type": shape["type"], "keys": keys}
    return dict(list(merged.items())[:_MAX_OUTPUTS])


__all__ = ["infer_shape", "infer_output_shapes", "merge_shapes"]
