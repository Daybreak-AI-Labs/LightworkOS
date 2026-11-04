"""Small helpers for environment-driven config without import-time crashes."""
from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)


def env_int(name: str, default: int) -> int:
    """Read an int env var, falling back to ``default`` (with a log) on
    bad input. Without this, a typo like ``MAVERICK_MAX_SWARM_FANOUT=high``
    raises ValueError at module import, taking the whole package down."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        log.warning(
            "%s=%r is not an int; using default %s", name, raw, default,
        )
        return default


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        log.warning(
            "%s=%r is not a float; using default %s", name, raw, default,
        )
        return default


_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})


def is_truthy(value: str | None) -> bool:
    """True iff ``value`` is a recognized truthy token (1/true/yes/on),
    case-insensitively. The canonical string test so call sites stop
    re-spelling the literal set (and disagreeing — some omitted ``on``).
    Use for config values already read as strings."""
    return (value or "").strip().lower() in _TRUE


def coerce_bool(value: object, default: bool = False) -> bool:
    """Coerce a value of unknown type (env/config string, bool, int, None)
    to bool. Strings parse via the canonical truthy/falsy sets and fall back
    to ``default`` when unrecognized; ``None`` is ``default``; anything else
    uses Python truthiness. Covers the common
    ``v in _TRUE if isinstance(v, str) else bool(v)`` pattern."""
    if value is None:
        return default
    if isinstance(value, str):
        v = value.strip().lower()
        if v in _TRUE:
            return True
        if v in _FALSE:
            return False
        return default
    return bool(value)


def env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean env var. Recognizes 1/true/yes/on and 0/false/no/off
    (case-insensitive). Anything unrecognized falls back to ``default``.
    One canonical truthy-set so call sites stop disagreeing (some omitted
    ``on``)."""
    return coerce_bool(os.environ.get(name), default)
