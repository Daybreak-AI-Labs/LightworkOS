"""JSON serialization used by tool results and cache snapshots.

The optional orjson backend previously changed values that it accepted, such
as non-finite floats, datetimes and integers beyond its supported range.
Use stdlib JSON for consistent behavior regardless of installed extras. The
``perf-fastjson`` extra remains installable for compatibility, but does not
currently change this module's backend.
"""
from __future__ import annotations

import json as _json
from typing import Any


def backend() -> str:
    """Return the serialization backend used by this module."""
    return "stdlib"


def dumps(obj: Any, *, sort_keys: bool = False) -> str:
    """Serialize to a JSON string, stringifying unsupported values."""
    return _json.dumps(obj, sort_keys=sort_keys, default=str)


def dumps_compact(obj: Any, *, sort_keys: bool = False) -> str:
    """Serialize without separator whitespace to conserve context space."""
    return _json.dumps(obj, sort_keys=sort_keys, separators=(",", ":"), default=str)


def loads(data: str | bytes) -> Any:
    """Parse JSON, preserving Python's arbitrary-precision integers."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return _json.loads(data)


__all__ = ["dumps", "dumps_compact", "loads", "backend"]
