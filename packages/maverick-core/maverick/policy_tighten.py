"""Tighten-only merging: a lower layer may make policy stricter, never looser.

A tenant's ``config.toml`` and a workspace agent overlay sit below the
organisation's own settings. For governance, safety, capabilities and sandbox
keys a lower layer's value applies only where it is at least as strict; the
looser part is ignored and reported, never a refusal to start.

What "looser" means depends on the kind of key, and :func:`tighten` is the one
place that decides it:

* ``deny_list`` -- a deny list may only grow.
* ``allow_list`` -- an allow list may only shrink (empty means "everything").
* ``subset`` -- a list that may only shrink, where empty means "nothing".
* ``protection`` -- a boolean protection may only go to on.
* ``permission`` -- a boolean permission may only go to off.
* ``limit`` -- a numeric limit (or a per-action threshold table, where ``*``
  applies to every action) may only go down; ``None`` is no limit.
* ``approval`` -- an approval requirement may only be added: a list grows and
  a switch may only go to on.
* ``rank`` -- an ordered choice, ``order`` listed from strictest to loosest.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

_RISK_ORDER = ("low", "medium", "high", None)


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("a limit must be a finite, non-negative number")
    return float(value)


def _table(value: object) -> dict[str, float] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        return {str(k): _number(v) for k, v in value.items()}
    return {"*": _number(value)}


def _limit(upper: object, lower: object) -> tuple[Any, bool]:
    up, low = _table(upper), _table(lower)
    if up is None:
        return lower, False
    if low is None:
        return upper, True
    merged = dict(up)
    loosened = False
    for key, amount in low.items():
        ceiling = up.get(key, up.get("*"))
        if ceiling is not None and amount > ceiling:
            loosened = True
            continue
        merged[key] = amount
    if not isinstance(upper, dict) and not isinstance(lower, dict):
        return merged["*"], loosened
    return merged, loosened


def _list(value: object) -> list:
    if not isinstance(value, list):
        raise ValueError("expected a list")
    return value


def _bool(value: object) -> bool:
    from ._envparse import coerce_bool
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and coerce_bool(value, True) == coerce_bool(value, False):
        return coerce_bool(value)
    raise ValueError("expected true or false")


def tighten(kind: str, upper: object, lower: object, *,
            order: Sequence[object] = ()) -> tuple[Any, bool]:
    """The effective value of ``lower`` applied under ``upper``.

    Returns ``(value, loosened)``; ``loosened`` is true when some or all of
    ``lower`` was looser than ``upper`` and was ignored. A ``lower`` value of
    the wrong type raises ``ValueError``; callers ignore it as looser.
    """
    if kind == "approval":
        kind = "protection" if isinstance(lower, bool) else "deny_list"
    if kind == "deny_list":
        up, low = _list(upper), _list(lower)
        return up + [item for item in low if item not in up], any(item not in low for item in up)
    if kind == "allow_list":
        up, low = _list(upper), _list(lower)
        if not up:
            return low, False
        kept = [item for item in low if item in up]
        if not kept:
            return up, True
        return kept, len(kept) < len(low)
    if kind == "subset":
        up, low = _list(upper), _list(lower)
        kept = [item for item in low if item in up]
        return kept, len(kept) < len(low)
    if kind == "protection":
        up_on, low_on = _bool(upper), _bool(lower)
        return up_on or low_on, up_on and not low_on
    if kind == "permission":
        up_on, low_on = _bool(upper), _bool(lower)
        return up_on and low_on, low_on and not up_on
    if kind == "limit":
        return _limit(upper, lower)
    if kind == "rank":
        if lower not in order:
            raise ValueError("not one of the known choices")
        if upper not in order:
            return upper, True
        return (upper, True) if order.index(lower) > order.index(upper) else (lower, False)
    raise ValueError(f"unknown policy kind {kind!r}")


def _risk(value: object) -> object:
    from .governance import _risk_floor
    try:
        return _risk_floor(value)
    except Exception as exc:
        raise ValueError("not a risk level") from exc


def _block_default(section: dict) -> str:
    profile = str(section.get("profile", "balanced")).strip().lower()
    return {"strict": "medium", "permissive": "critical"}.get(profile, "high")


# section -> key -> (kind, default, order). A default may be a callable of the
# organisation's section. A key not listed here is fixed by the organisation:
# a lower layer cannot change it at all.
TENANT_RULES: dict[str, dict[str, tuple]] = {
    "governance": {
        "deny_actions": ("deny_list", [], ()),
        "require_human_actions": ("approval", [], ()),
        "deny_min_risk": ("risk", None, _RISK_ORDER),
        "require_human_min_risk": ("risk", None, _RISK_ORDER),
        "deny_above": ("limit", None, ()),
        "require_human_above": ("limit", None, ()),
        "require_fresh_human_approval": ("approval", False, ()),
    },
    "safety": {
        "profile": ("rank", "balanced", ("strict", "balanced", "permissive")),
        "block_threshold": ("rank", _block_default, ("low", "medium", "high", "critical")),
        "scan_input": ("protection", True, ()),
        "scan_tool_calls": ("protection", True, ()),
        "scan_output": ("protection", True, ()),
        "constitution": ("deny_list", [], ()),
        "compartments": ("protection", False, ()),
        "compartment_unseal": ("rank", "human", ("human", "orchestrator", "both")),
        "require_shield": ("protection", False, ()),
    },
    "capabilities": {
        **dict.fromkeys(("computer_use", "browser", "web_search", "mobile_tools", "ros", "code_exec"),
                        ("permission", False, ())),
        "enforce": ("protection", False, ()),
    },
    "sandbox": {
        "require_container": ("protection", False, ()),
        "allow_network": ("permission", True, ()),
        "allow_root": ("permission", False, ()),
        "timeout": ("limit", 60, ()),
    },
}


def _merge_key(rule: tuple | None, section: dict, key: str, value: object) -> tuple[bool, Any, bool]:
    """``(changed, value, loosened)`` for one lower-layer key of a tight section."""
    present = key in section
    if rule is None:
        return False, None, not (present and section[key] == value)
    kind, default, order = rule
    upper = section[key] if present else (default(section) if callable(default) else default)
    try:
        if kind == "risk":
            _, loosened = tighten("rank", _risk(upper), _risk(value), order=order)
            effective = upper if loosened else value
        else:
            effective, loosened = tighten(kind, upper, value, order=order)
    except ValueError:
        return False, None, True
    if effective == upper:
        return False, None, loosened
    return True, effective, loosened


def merge_tenant_section(name: str, upper: dict, lower: dict) -> tuple[dict, list[str]]:
    """Apply ``lower`` (a tenant's section) under ``upper`` (the organisation's).

    Returns the merged section and the dotted names of the keys whose looser
    value was ignored.
    """
    rules = TENANT_RULES[name]
    merged = dict(upper)
    ignored: list[str] = []
    for key, value in lower.items():
        changed, effective, loosened = _merge_key(rules.get(key), upper, key, value)
        if changed:
            merged[key] = effective
        if loosened:
            ignored.append(f"{name}.{key}")
    return merged, ignored


def merge_tenant_overlay(upper: dict, lower: dict, deep_merge) -> tuple[dict, list[str]]:
    """Merge a tenant's whole config file under the organisation's config.

    The governance, safety, capabilities and sandbox tables are tighten-only;
    every other table merges as before through ``deep_merge``.
    """
    merged = deep_merge(upper, {k: v for k, v in lower.items() if k not in TENANT_RULES})
    ignored: list[str] = []
    for name in TENANT_RULES:
        if name not in lower:
            continue
        section = upper.get(name, {})
        if not isinstance(lower[name], dict) or not isinstance(section, dict):
            ignored.append(name)
            continue
        merged[name], missed = merge_tenant_section(name, section, lower[name])
        ignored.extend(missed)
    return merged, ignored
