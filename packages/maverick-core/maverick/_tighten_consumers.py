"""How each tighten-only key's consumer reads its raw setting.

:mod:`maverick.policy_tighten` compares a tenant's value with the
organisation's by what the code that reads the key will DO with each, not by
the raw values. Every reader here mirrors one consumer: what it accepts, what
it falls back to, and which way is stricter. A tenant value the consumer
cannot read raises ``ValueError`` and is ignored and reported; an
organisation value the consumer cannot read counts as what the consumer then
falls back to.

Each merge function takes ``(upper, lower)`` raw values and returns
``(value to write, loosened)`` like :func:`maverick.policy_tighten.tighten`.
"""
from __future__ import annotations

import fnmatch
import math
import re
from typing import Any


def _real(value: object) -> float:
    """A finite number from a TOML number or text, as ``float()`` reads it."""
    if isinstance(value, bool) or isinstance(value, (dict, list, tuple)):
        raise ValueError("expected a number")
    try:
        amount = float(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("expected a number") from exc
    if not math.isfinite(amount):
        raise ValueError("expected a finite number")
    return amount


def _positive(value: object) -> float:
    amount = _real(value)
    if amount <= 0:
        raise ValueError("expected a positive number")
    return amount


def _optional(value: object) -> float | None:
    """A cap read by truthiness: unset, empty or zero or less is no cap."""
    if value is None or value is False or (isinstance(value, str) and not value.strip()):
        return None
    amount = _real(value)
    return amount if amount > 0 else None


def _whole(value: object) -> float:
    """A whole number as ``int(str(value))`` reads it (``"1.5"`` fails)."""
    if isinstance(value, bool) or isinstance(value, (dict, list, tuple, float)):
        raise ValueError("expected a whole number")
    try:
        return float(int(str(value).strip()))
    except ValueError as exc:
        raise ValueError("expected a whole number") from exc


# go-units RAMInBytes, which Docker and Podman use for --memory.
_MEMORY = re.compile(r"(\d+(?:\.\d+)?) ?([kmgtp])?i?b?", re.IGNORECASE)
_UNITS = {None: 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4, "p": 1024 ** 5}


def _memory(value: object) -> float | None:
    """Bytes for a memory size; ``None`` when there is no cap (unset or zero)."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("not a memory size")
    match = _MEMORY.fullmatch(str(value).strip())
    if not match:
        raise ValueError("not a memory size")
    size = float(match.group(1)) * _UNITS[(match.group(2) or "").lower() or None]
    return size if size > 0 else None


def _rate(value: object) -> float | None:
    """Scans per second for ``[safety] shield_rate_limit``; ``None`` when off."""
    if value is None or str(value).strip().lower() in {"", "0", "off", "false", "no", "none", "disabled"}:
        return None
    from .safety.shield_rate_limit import parse_rate
    calls, seconds = parse_rate(str(value))
    return calls / seconds


def _scalar(read, fallback, *, higher_is_stricter: bool = False):
    """A one-number setting: ``read`` gives the consumer's effective number
    (``None`` for no cap) and raises when the consumer cannot read it."""
    def merge(upper: object, lower: object) -> tuple[Any, bool]:
        try:
            up = read(upper)
        except ValueError:
            up = fallback
        low = read(lower)
        if higher_is_stricter:
            looser = low is None or (up is not None and low < up)
        else:
            looser = up is not None and (low is None or low > up)
        return (upper, True) if looser else (lower, False)
    return merge


def _text(value: object) -> str:
    """The text ``env_setting.env_or_config`` hands its consumer, which then
    parses it; a table is not readable (the consumer uses its default)."""
    if isinstance(value, dict):
        raise ValueError("expected a value, not a table")
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return str(value)


def _quorum(value: object) -> float:
    """Approvers ``quorum.configured_policy`` requires: unset, empty or a
    switch means off (one); text is read with ``int()``."""
    if value is None or isinstance(value, bool) or not str(value).strip():
        return 1.0
    return float(max(1, int(_whole(value))))


SCALARS = {
    "sandbox.timeout": _scalar(_positive, 60.0),
    "sandbox.long_command_timeout": _scalar(lambda v: _positive(_text(v)), 600.0),
    "sandbox.pids_limit": _scalar(_optional, None),
    "sandbox.cpus": _scalar(_optional, None),
    "sandbox.memory_mb": _scalar(_optional, None),
    "sandbox.memory": _scalar(_memory, 4 * 1024 ** 3),
    "capabilities.per_call_token_ttl": _scalar(lambda v: max(1.0, _real(_text(v))), 30.0),
    "safety.max_scan_chars": _scalar(lambda v: _positive(_whole(_text(v))), 262_144.0),
    "safety.quorum_ttl_days": _scalar(lambda v: min(7.0, _positive(v)), 7.0),
    "safety.shield_rate_limit": _scalar(_rate, None),
    # Text that is not a whole number leaves the consumer's default of two.
    "safety.quorum_required": _scalar(_quorum, 2.0, higher_is_stricter=True),
}


def thresholds(key: str):
    """``[governance] deny_above`` / ``require_human_above``: the governance
    parser's table, where ``*`` covers every action and zero is the strictest
    gate (any amount above it, or one that cannot be verified, is gated)."""
    def read(value: object) -> dict[str, float]:
        from .governance import GovernancePolicyError, _policy_thresholds
        try:
            return _policy_thresholds({key: value}, key)
        except GovernancePolicyError as exc:
            raise ValueError(str(exc)) from exc

    def merge(upper: object, lower: object) -> tuple[Any, bool]:
        try:
            up = read(upper) if upper is not None else {}
        except ValueError:
            up = {}
        low = read(lower)
        merged, loosened = dict(up), False
        for action, amount in low.items():
            bound = up.get(action, up.get("*"))
            if bound is not None and amount > bound:
                loosened = True
                continue
            merged[action] = amount
        return (upper if merged == up else merged), loosened
    return merge


_CHECKPOINT = ("dollars", "tool_calls", "wall_seconds")


def checkpoint(upper: object, lower: object) -> tuple[Any, bool]:
    """``[safety.review_checkpoint]``: each interval is on only as a positive
    TOML number (``review_checkpoint._num``); a shorter interval is stricter."""
    from .review_checkpoint import _num
    if not isinstance(lower, dict) or any(key not in _CHECKPOINT or _num(value) is None
                                          for key, value in lower.items()):
        raise ValueError("expected positive numbers for dollars, tool_calls or wall_seconds")
    up = upper if isinstance(upper, dict) else {}
    merged, loosened = dict(up), False
    for key, value in lower.items():
        bound = _num(up.get(key))
        if bound is not None and _num(value) > bound:
            loosened = True
            continue
        merged[key] = value
    return merged, loosened


def protected_keys(upper: object, lower: object) -> tuple[Any, bool]:
    """``[safety] quorum_protected_keys``: an empty or missing list means the
    four default patterns; the tenant's patterns are added to the org's."""
    from .quorum import DEFAULT_PROTECTED_KEYS

    def read(value: object) -> frozenset[str]:
        if not isinstance(value, (list, tuple, set)):
            raise ValueError("expected a list")
        return frozenset(str(p).strip() for p in value if str(p).strip()) or DEFAULT_PROTECTED_KEYS

    try:
        up = read(upper)
    except ValueError:
        up = DEFAULT_PROTECTED_KEYS
    return sorted(up | read(lower)), False


_TIERS = (None, "low", "medium", "high", "critical")


def _tiers(value: object) -> dict[str | None, int]:
    from .safety.dual_control import _base_approvals
    return {tier: _base_approvals(value, tier) for tier in _TIERS}


def approvals(upper: object, lower: object) -> tuple[Any, bool]:
    """``[security] approvals_required``: approvers per risk tier as
    ``dual_control._base_approvals`` reads them; the larger count wins per
    tier and the result is written as a full per-tier table."""
    from .safety.dual_control import _coerce_int
    named = list(lower) if isinstance(lower, dict) else ["default", *_TIERS[1:]]
    values = lower.values() if isinstance(lower, dict) else [lower]
    if lower is None or any(isinstance(v, bool) or not _coerce_int(v, 0) for v in values):
        raise ValueError("expected positive whole numbers")
    up, low = _tiers(upper), _tiers(lower)
    loosened = any(low[None if name == "default" else name] < up[None if name == "default" else name]
                   for name in named if name == "default" or name in _TIERS)
    if all(low[tier] <= up[tier] for tier in _TIERS):
        return upper, loosened  # nothing stricter to apply
    merged = {("default" if tier is None else tier): max(up[tier], low[tier]) for tier in _TIERS}
    return merged, loosened


def approvals_by_risk(upper: object, lower: object) -> tuple[Any, bool]:
    """``[security] approvals_required_by_risk`` only ever raises a tier, so a
    tenant entry applies as the larger of the two counts."""
    from .safety.dual_control import _coerce_int
    if not isinstance(lower, dict) or any(isinstance(v, bool) or not _coerce_int(v, 0)
                                          for v in lower.values()):
        raise ValueError("expected a table of positive whole numbers")
    up = upper if isinstance(upper, dict) else {}
    merged, loosened = dict(up), False
    for tier, count in lower.items():
        if tier in up and _coerce_int(count, 0) < _coerce_int(up[tier], 0):
            loosened = True
            continue
        merged[tier] = count
    return merged, loosened


def tool_ratings(upper: object, lower: object) -> tuple[Any, bool]:
    """``[security.tool_risk]``: a tenant rating applies only where it does not
    lower the organisation's EFFECTIVE rating (``tool_risk(name, overrides)``).
    An exact name is checked against that rating; a pattern, which may also
    cover tools nobody has rated (high by default), only at the top level or
    above the organisation's own rating for the same pattern."""
    from .safety.tool_risk import _DEFAULT_RISK, RISK_LEVELS, risk_rank, tool_risk
    if not isinstance(lower, dict):
        raise ValueError("expected a table")
    up = {k: v for k, v in upper.items() if v in RISK_LEVELS} if isinstance(upper, dict) else {}
    accepted_globs: dict[str, str] = {}
    exact: dict[str, str] = {}
    loosened = False
    for name, level in lower.items():
        if level not in RISK_LEVELS:
            loosened = True
            continue
        if any(ch in name for ch in "*?["):
            covered = [tool for tool in _DEFAULT_RISK if fnmatch.fnmatchcase(tool, name)]
            ok = (level == RISK_LEVELS[-1] or (name in up and risk_rank(level) >= risk_rank(up[name]))) and all(
                risk_rank(level) >= risk_rank(tool_risk(tool, overrides=up)) or tool in up for tool in covered)
            target = accepted_globs
        else:
            ok = risk_rank(level) >= risk_rank(tool_risk(name, overrides=up))
            target = exact
        if ok:
            target[name] = level
        else:
            loosened = True
    merged = dict(accepted_globs)  # a stricter pattern is matched before the org's
    for name, level in up.items():
        merged.setdefault(name, level)
    merged.update(exact)
    return merged, loosened


def gov_names(upper: object, lower: object) -> tuple[Any, bool]:
    """``[governance] deny_actions`` / ``require_human_actions``: a list of
    non-empty names (anything else stops every governed call). The tenant's
    names are added to the organisation's."""
    if not isinstance(lower, list) or not all(isinstance(i, str) and i.strip() for i in lower):
        raise ValueError("expected a list of names")
    up = list(upper) if isinstance(upper, list) else []
    folded = {str(i).strip().casefold() for i in up}
    return up + [i for i in lower if i.strip().casefold() not in folded], False


def _tool_names(value: object) -> list[str]:
    """``tool_acl._names``: one string is one name; blank means unset."""
    from .safety.tool_acl import _names
    try:
        return sorted(str(name) for name in _names(value))
    except TypeError as exc:
        raise ValueError("expected a tool name or a list of them") from exc


def denied_tools(upper: object, lower: object) -> tuple[Any, bool]:
    try:
        up = _tool_names(upper)
    except ValueError:
        up = []
    return up + [name for name in _tool_names(lower) if name not in up], False


def allowed_tools(upper: object, lower: object) -> tuple[Any, bool]:
    """An empty allow list allows every tool, so it may only shrink."""
    try:
        up = _tool_names(upper)
    except ValueError:
        up = []
    low = _tool_names(lower)
    if not up:
        return low, False
    kept = [name for name in low if name in up]
    if not kept:
        return up, True
    return kept, len(kept) < len(low)


def deny_list(upper: object, lower: object) -> tuple[Any, bool]:
    """A plain list that may only grow (``[safety] constitution``)."""
    if not isinstance(lower, list):
        raise ValueError("expected a list")
    up = list(upper) if isinstance(upper, list) else []
    return up + [item for item in lower if item not in up], False


def _consent_modes(configured: str) -> list[int]:
    """Strictness per risk level of ``safety.consent.installation_mode_for``.

    That function asks the enterprise and secure-by-default switches, which
    read the merged configuration; asking them here, inside the merge, would
    recurse. Both switches are therefore read from the organisation's own
    layers, which a tenant cannot loosen.
    """
    import os

    from .config import load_global_config
    from .enterprise import deployment_enterprise_enabled
    from .safety.consent import _CONSENT_MODES, _strictness
    from .security_defaults import _FALSE, _TRUE

    configured = configured.strip().lower()
    env = os.environ.get("MAVERICK_SECURE_DEFAULT", "").strip().lower()
    if env in _TRUE | _FALSE:
        secure = env in _TRUE
    else:
        value = (load_global_config().get("security") or {}).get("secure_defaults")
        secure = value is None or (str(value).strip().lower() not in _FALSE if isinstance(value, str)
                                   else bool(value))
    enterprise = deployment_enterprise_enabled()
    modes = []
    for risk in ("low", "medium", "high", "critical"):
        if configured:
            mode = configured if configured in _CONSENT_MODES else "ask"
        elif enterprise or (secure and risk in ("high", "critical")):
            mode = "ask"
        else:
            mode = "auto-approve"
        modes.append(_strictness(mode))
    return modes


def consent_mode(upper: object, lower: object) -> tuple[Any, bool]:
    """``[safety] consent_mode``: the mode ``safety.consent`` gives an action
    at each risk level. Unset asks only for risky actions in a secure or
    enterprise install, so it is compared risk by risk, never as one rank."""
    if not isinstance(lower, str):
        raise ValueError("expected a consent mode")
    # As ``consent._configured_mode``: only unset or blank text means unset.
    up = _consent_modes("" if upper is None else str(upper))
    low = _consent_modes(lower)
    looser = any(new > old for old, new in zip(up, low, strict=True))
    return (upper, True) if looser else (lower, False)


def _uid(value: object) -> int:
    """The user number as the Kubernetes sandbox reads it (``int(value)``)."""
    try:
        return int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError) as exc:
        raise ValueError("expected a user number") from exc


def run_as_user(upper: object, lower: object) -> tuple[Any, bool]:
    """``[sandbox] run_as_user``: user 0 is root. A lower layer may leave 0
    and may name another ordinary user, but may not choose 0, in any spelling
    the sandbox would read as 0 (``"0"``, ``0.5``, ``false``)."""
    from .policy_tighten import Incomparable

    chosen = _uid(lower)
    try:
        current = _uid(upper)
    except ValueError as exc:  # the sandbox cannot start with it either
        raise Incomparable("the organisation's user number cannot be read") from exc
    if chosen == 0 and current != 0:
        return upper, True
    return lower, False


MERGES = {
    "sandbox.run_as_user": run_as_user,
    "safety.consent_mode": consent_mode,
    **SCALARS,
    "governance.deny_above": thresholds("deny_above"),
    "governance.require_human_above": thresholds("require_human_above"),
    "governance.deny_actions": gov_names,
    "governance.require_human_actions": gov_names,
    "safety.review_checkpoint": checkpoint,
    "safety.quorum_protected_keys": protected_keys,
    "safety.constitution": deny_list,
    "security.approvals_required": approvals,
    "security.approvals_required_by_risk": approvals_by_risk,
    "security.tool_risk": tool_ratings,
    "security.allowed_tools": allowed_tools,
    "security.denied_tools": denied_tools,
}
