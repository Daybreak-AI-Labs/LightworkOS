"""Tighten-only merging: a lower layer may make policy stricter, never looser.

A tenant's ``config.toml`` and a workspace agent overlay sit below the
organisation's own settings. For governance, safety, capabilities, sandbox and
security keys a lower layer's value applies only where it is at least as
strict; the looser part is ignored and reported, never a refusal to start.

Every rule compares against what the key's consumer does: an unset key counts
as the consumer's own default, and "stricter" means what restricts more there.
What "looser" means depends on the kind of key, and :func:`tighten` is the one
place that decides it:

* ``deny_list`` -- a deny list may only grow.
* ``allow_list`` -- an allow list may only shrink (empty means "everything").
* ``subset`` -- a list that may only shrink, where empty means "nothing".
* ``protection`` -- a boolean protection may only go to on.
* ``permission`` -- a boolean permission may only go to off.
* ``limit`` -- a numeric limit (or a per-key table, where ``*`` applies to
  every key) may only go down; ``None``, zero or a negative number is no limit.
* ``minimum`` -- a numeric floor (or per-key table, with a ``default`` key)
  may only go up.
* ``approval`` -- an approval requirement may only be added: a list grows and
  a switch may only go to on.
* ``rank`` -- an ordered choice, ``order`` listed from strictest to loosest;
  an entry may be a tuple of equally strict spellings.

Keys whose consumer has its own parser (governance thresholds, approval
counts, tool risk ratings, sandbox limits, ...) are compared by what that
consumer does with each value (:mod:`maverick._tighten_consumers`), and a
tenant value the consumer cannot read is ignored. An organisation value that
cannot be compared (an unranked choice such as a plugin sandbox backend)
keeps the organisation's value; that key is reported as set by the
organisation rather than as a looser choice.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

_RISK_ORDER = ("low", "medium", "high", None)


class Incomparable(ValueError):
    """The upper (organisation) value has no place in the key's order."""


def _num(value: object) -> float:
    """A TOML number or its string form (``"30"``, ``"0.5"``)."""
    if isinstance(value, str):
        try:
            value = float(value.strip())
        except ValueError as exc:
            raise ValueError("expected a number") from exc
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("expected a finite number")
    return float(value)


def _number(value: object) -> float:
    amount = _num(value)
    if amount < 0:
        raise ValueError("expected a non-negative number")
    return amount


def _ceiling(value: object) -> float | None:
    """A limit's value; ``None`` when it sets no limit (unset, zero or less)."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    amount = _num(value)
    return amount if amount > 0 else None


def _table(value: object, read) -> dict[str, float | None] | None:
    if isinstance(value, dict):
        return {str(k): read(v) for k, v in value.items()}
    amount = read(value)
    return None if amount is None else {"*": amount}


def _per_key(upper: object, lower: object, read, looser) -> tuple[Any, bool]:
    """Compare per key; a table's ``*`` or ``default`` entry covers the rest."""
    up, low = _table(upper, read), _table(lower, read)
    if up is None:
        return lower, False
    if low is None:
        return upper, True
    merged = dict(upper) if isinstance(upper, dict) else {"*": upper}
    loosened = False
    for key, amount in low.items():
        bound = up.get(key, up.get("*", up.get("default")))
        if bound is not None and looser(amount, bound):
            loosened = True
            continue
        merged[key] = lower[key] if isinstance(lower, dict) else lower
    if not isinstance(upper, dict) and not isinstance(lower, dict):
        return merged["*"], loosened
    return merged, loosened


def _limit(upper: object, lower: object) -> tuple[Any, bool]:
    return _per_key(upper, lower, _ceiling, lambda amount, bound: amount is None or amount > bound)


def _floor(value: object) -> float | None:
    return None if value is None or (isinstance(value, str) and not value.strip()) else _number(value)


def _minimum(upper: object, lower: object) -> tuple[Any, bool]:
    return _per_key(upper, lower, _floor, lambda amount, bound: amount is None or amount < bound)


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


def _ranked(upper: object, lower: object, order: Sequence[object], unknown: object) -> tuple[Any, bool]:
    low_rank = _rank(order, lower)
    if low_rank is None and unknown is not None:
        low_rank = _rank(order, unknown)
    if low_rank is None:
        raise ValueError("not one of the known choices")
    up_rank = _rank(order, upper)
    if up_rank is None and unknown is not None:
        up_rank = _rank(order, unknown)
    if up_rank is None:
        raise Incomparable("the organisation's choice cannot be compared")
    return (upper, True) if low_rank > up_rank else (lower, False)


_KINDS = {"limit": _limit, "minimum": _minimum}


def tighten(kind: str, upper: object, lower: object, *,
            order: Sequence[object] = (), unknown: object = None) -> tuple[Any, bool]:
    """The effective value of ``lower`` applied under ``upper``.

    Returns ``(value, loosened)``; ``loosened`` is true when some or all of
    ``lower`` was looser than ``upper`` and was ignored. A ``lower`` value of
    the wrong type raises ``ValueError``; callers ignore it as looser. For
    ``rank``, ``unknown`` is the choice the consumer treats an unlisted value
    as; :class:`Incomparable` means the upper value has no such meaning.
    """
    if kind == "approval":
        kind = "deny_list" if isinstance(lower, list) else "protection"
    if kind in _KINDS:
        return _KINDS[kind](upper, lower)
    if kind == "rank":
        return _ranked(upper, lower, order, unknown)
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
    raise ValueError(f"unknown policy kind {kind!r}")


def _rank(order: Sequence[object], value: object) -> int | None:
    probe = value.strip().lower() if isinstance(value, str) else value
    for index, entry in enumerate(order):
        if probe == entry or (isinstance(entry, tuple) and probe in entry):
            return index
    return None


def _risk(value: object) -> object:
    from .governance import _risk_floor
    try:
        return _risk_floor(value)
    except Exception as exc:
        raise ValueError("not a risk level") from exc


def _block_default(section: dict) -> str:
    profile = str(section.get("profile", "balanced")).strip().lower()
    return {"strict": "medium", "permissive": "critical"}.get(profile, "high")


def _consumer(key: str, default: object = None) -> tuple:
    """A rule whose comparison mirrors the key's consumer (:mod:`._tighten_consumers`)."""
    from ._tighten_consumers import MERGES
    return ("consumer", default, MERGES[key], None)


_BACKENDS = (("firecracker",), ("gvisor",), ("kubernetes", "docker", "podman", "devcontainer"), ("local",))
_NETWORK = (("deny-all", "deny_all", "deny", "blocked", "none-allowed"),
            ("allowlist", "allow-list", "allow_list"), ("", "open", "allow", "allow-all", "allow_all"))
_ACL_RISK = ("low", "medium", "high", (None, ""))

# section -> key -> (kind, default, order, unknown). The default is what the
# key's consumer uses when it is unset (a callable gets the organisation's
# section); ``unknown`` is the choice the consumer treats an unlisted value as.
# A key not listed has no stricter direction (a path, an image, a key name or
# a place the owner chooses to run work) and merges as an ordinary setting.
TENANT_RULES: dict[str, dict[str, tuple]] = {
    # A workspace may charge paid tool calls more, never less.
    "budget": {
        "unpriced_tool_call_dollars": ("minimum", 0.10, (), None),
        # The full hold is the charge when usage is not reported: only up.
        "max_unmetered_hold_dollars": ("minimum", 1.00, (), None),
        "tool_prices": _consumer("budget.tool_prices", {}),
    },
    "governance": {
        "deny_actions": _consumer("governance.deny_actions"),
        "require_human_actions": _consumer("governance.require_human_actions"),
        "deny_min_risk": ("risk", None, _RISK_ORDER, None),
        "require_human_min_risk": ("risk", None, _RISK_ORDER, None),
        "deny_above": _consumer("governance.deny_above"),
        "require_human_above": _consumer("governance.require_human_above"),
        "require_fresh_human_approval": ("approval", False, (), None),
        "profile": ("rank", "", (("regulated",), ("standard",), ("essentials", "")), ""),
    },
    "safety": {
        "profile": ("rank", "balanced", ("strict", "balanced", "permissive"), "balanced"),
        "block_threshold": ("rank", _block_default, ("low", "medium", "high", "critical"), None),
        "scan_input": ("protection", True, (), None),
        "scan_tool_calls": ("protection", True, (), None),
        "scan_output": ("protection", True, (), None),
        "constitution": _consumer("safety.constitution"),
        "compartments": ("protection", False, (), None),
        "compartment_unseal": ("rank", "human", ("human", "orchestrator", "both"), None),
        "require_shield": ("protection", False, (), None),
        "consent_mode": _consumer("safety.consent_mode"),
        "review_checkpoint": _consumer("safety.review_checkpoint"),
        "max_scan_chars": _consumer("safety.max_scan_chars", 262_144),
        "supply_chain_pinning": ("protection", False, (), None),
        "cascade": ("protection", False, (), None),
        "decode_hidden": ("protection", True, (), None),
        "shield_rate_limit": _consumer("safety.shield_rate_limit"),
        "quorum_required": _consumer("safety.quorum_required"),
        "quorum_protected_keys": _consumer("safety.quorum_protected_keys"),
        "quorum_ttl_days": _consumer("safety.quorum_ttl_days", 7),
        "goal_risk_floor": ("rank", "low", ("high", "medium", "low"), "low"),
        "goal_risk_require_human": ("rank", "never", ("medium", "high", ("never", "")), "high"),
    },
    "capabilities": {
        **dict.fromkeys(("computer_use", "browser", "web_search", "mobile_tools", "ros", "code_exec"),
                        ("permission", False, (), None)),
        "enforce": ("protection", False, (), None),
        "per_call_tokens": ("protection", False, (), None),
        "per_call_token_ttl": _consumer("capabilities.per_call_token_ttl", 30),
    },
    "sandbox": {
        "backend": ("rank", "local", _BACKENDS, None),
        "network_policy": ("rank", "open", _NETWORK, "deny-all"),
        "network": ("rank", "egress-deny", ("egress-deny", "egress-allow"), "egress-allow"),
        "host_key_checking": ("rank", "accept-new", ("yes", "accept-new", "no"), "accept-new"),
        "require_container": ("protection", False, (), None),
        "firecracker_strict": ("protection", True, (), None),
        "allow_network": ("permission", False, (), None),
        "allow_root": ("permission", False, (), None),
        "reuse_container": ("permission", False, (), None),
        "cross_run_pool": ("permission", False, (), None),
        "run_as_user": _consumer("sandbox.run_as_user", 1000),
        "pids_limit": _consumer("sandbox.pids_limit", 512),
        "memory": _consumer("sandbox.memory", "4g"),
        "memory_mb": _consumer("sandbox.memory_mb"),
        "cpus": _consumer("sandbox.cpus"),
        "long_command_timeout": _consumer("sandbox.long_command_timeout", 600),
        "timeout": _consumer("sandbox.timeout", 60),
    },
    "security": {
        "allowed_tools": _consumer("security.allowed_tools"),
        "denied_tools": _consumer("security.denied_tools"),
        "max_risk": ("rank", None, _ACL_RISK, "low"),
        "channels": ("acl", {}, (), None),
        "users": ("acl", {}, (), None),
        "network_policy": ("rank", "open", _NETWORK, "deny-all"),
        "approvals_required": _consumer("security.approvals_required"),
        "approvals_required_by_risk": _consumer("security.approvals_required_by_risk"),
        "tool_risk": _consumer("security.tool_risk"),
        "auto_fix": ("permission", False, (), None),
        "allow_self_approval": ("permission", False, (), None),
        "isolate_parsers": ("protection", False, (), None),
        "secure_defaults": ("protection", True, (), None),
    },
    # maverick.config.get_codebase; the defaults mirror CODEBASE_LOOP_DEFAULTS.
    # An unreadable protection mode is read as "block".
    "codebase": {
        "default_protect": ("rank", "block", ("block", "approve", "audit"), "block"),
        "checker": ("protection", True, (), None),
        "require_container": ("protection", False, (), None),
        "repair_rounds": ("minimum", 2, (), None),
        "check_rounds": ("minimum", 2, (), None),
    },
}

_ACL_RULES = {key: TENANT_RULES["security"][key] for key in ("allowed_tools", "denied_tools", "max_risk")}


def _acl(upper: object, lower: object) -> tuple[Any, bool]:
    """Per-channel or per-user ``[security]`` tables, each tighten-only."""
    if not isinstance(upper, dict) or not isinstance(lower, dict):
        raise ValueError("expected a table of tables")
    merged, loosened = dict(upper), False
    for name, table in lower.items():
        if not isinstance(table, dict):
            loosened = True
            continue
        section = upper.get(name) if isinstance(upper.get(name), dict) else {}
        merged[name], ignored, fixed = _merge_rules(_ACL_RULES, "", section, table)
        loosened = loosened or bool(ignored or fixed)
    return merged, loosened


def _merge_key(rule: tuple | None, section: dict, key: str, value: object,
               deep_merge=None) -> tuple[bool, Any, str | None]:
    """``(changed, value, status)`` for one lower-layer key of a tight section;
    ``status`` is ``"looser"``, ``"fixed"`` (incomparable) or ``None``."""
    present = key in section
    if rule is None:  # no stricter direction: an ordinary setting
        if deep_merge is not None and isinstance(value, dict) and isinstance(section.get(key), dict):
            return True, deep_merge(section[key], value), None
        return True, value, None
    kind, default, order, unknown = rule
    upper = section[key] if present else (default(section) if callable(default) else default)
    try:
        if kind == "risk":
            if not isinstance(value, str):  # the governance parser refuses it
                raise ValueError("expected a risk level")
            _, loosened = tighten("rank", _risk(upper), _risk(value), order=order)
            effective = upper if loosened else value
        elif kind == "consumer":
            effective, loosened = order(upper, value)
        elif kind == "acl":
            effective, loosened = _acl(upper, value)
        else:
            effective, loosened = tighten(kind, upper, value, order=order, unknown=unknown)
    except Incomparable:
        return False, None, "fixed"
    except ValueError:
        return False, None, "looser"
    status = "looser" if loosened else None
    if effective == upper:
        return False, None, status
    return True, effective, status


def _merge_rules(rules: dict, prefix: str, upper: dict, lower: dict,
                 deep_merge=None) -> tuple[dict, list[str], list[str]]:
    merged = dict(upper)
    ignored: list[str] = []
    fixed: list[str] = []
    for key, value in lower.items():
        changed, effective, status = _merge_key(rules.get(key), upper, key, value, deep_merge)
        if changed:
            merged[key] = effective
        if status == "looser":
            ignored.append(prefix + key)
        elif status == "fixed":
            fixed.append(prefix + key)
    return merged, ignored, fixed


def merge_tenant_section(name: str, upper: dict, lower: dict,
                         deep_merge=None) -> tuple[dict, list[str], list[str]]:
    """Apply ``lower`` (a tenant's section) under ``upper`` (the organisation's).

    Returns the merged section, the dotted names of keys whose looser value
    was ignored, and those kept because the organisation's value cannot be
    compared (set by the organisation).
    """
    return _merge_rules(TENANT_RULES[name], f"{name}.", upper, lower, deep_merge)


def merge_tenant_overlay(upper: dict, lower: dict, deep_merge) -> tuple[dict, list[str], list[str]]:
    """Merge a tenant's whole config file under the organisation's config.

    The tables in :data:`TENANT_RULES` are tighten-only; every other table
    merges as before through ``deep_merge``.
    """
    merged = deep_merge(upper, {k: v for k, v in lower.items() if k not in TENANT_RULES})
    ignored: list[str] = []
    fixed: list[str] = []
    for name in TENANT_RULES:
        if name not in lower:
            continue
        section = upper.get(name, {})
        if not isinstance(lower[name], dict) or not isinstance(section, dict):
            ignored.append(name)
            continue
        merged[name], missed, kept = merge_tenant_section(name, section, lower[name], deep_merge)
        ignored.extend(missed)
        fixed.extend(kept)
    return merged, ignored, fixed
