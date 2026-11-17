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


def organisation_only(upper: object, lower: object) -> tuple[Any, bool]:
    """``[codebase] checker_image``, ``checker_models``,
    ``protected_checker_model`` and ``allow_self_changes``: which image runs
    the checks (and so decides every re-run's result), which models check, and
    whether the factory may change the Lightwork that runs it. Only the
    organisation sets them; a lower layer's different value is ignored."""
    return upper, lower != upper


def tool_prices(upper: object, lower: object) -> tuple[Any, bool]:
    """``[budget.tool_prices]``: a lower layer may only raise a service's price
    in the unit the organisation set. A price for a service the organisation
    left unpriced (charged the per-call ceiling) cannot be compared, so it is
    ignored, as is one the budget cannot read."""
    from .budget import tool_price_entry

    if not isinstance(lower, dict):
        raise ValueError("expected a table of service prices")
    up = upper if isinstance(upper, dict) else {}
    merged, loosened = dict(up), False
    for service, entry in lower.items():
        mine, theirs = tool_price_entry(entry), tool_price_entry(up.get(service))
        if mine is None or theirs is None or mine[1] != theirs[1] or mine[0] < theirs[0]:
            loosened = True
            continue
        merged[service] = entry
    return merged, loosened


def task_cap(key: str):
    """``[budget] max_dollars`` and the other task caps, read as
    ``budget._configured_task_limits`` reads them: unset is no cap, zero is a
    cap of nothing, and anything else it refuses. A workspace may only lower
    one; an organisation cap the budget cannot read stays the organisation's."""
    from .budget import _BUDGET_KEY_TYPES
    from .policy_tighten import Incomparable

    caster = _BUDGET_KEY_TYPES[key]

    def read(value: object) -> float:
        if isinstance(value, bool) or isinstance(value, (dict, list, tuple)):
            raise ValueError("expected a number")
        try:
            amount = float(caster(value))
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("expected a number") from exc
        if not math.isfinite(amount) or amount < 0:
            raise ValueError("expected a finite non-negative number")
        return amount

    def merge(upper: object, lower: object) -> tuple[Any, bool]:
        low = read(lower)
        if upper is None:
            return lower, False
        try:
            up = read(upper)
        except ValueError as exc:
            raise Incomparable("the organisation's cap cannot be read") from exc
        return (upper, True) if low > up else (lower, False)
    return merge


def _provider_caps(value: object) -> dict[str, float]:
    """``provider_cost_cap.caps_from_config``: names in any case, positive
    numbers only (zero or less is no cap)."""
    from .provider_cost_cap import _canon

    if not isinstance(value, dict):
        raise ValueError("expected a table of caps")
    caps: dict[str, float] = {}
    for name, amount in value.items():
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise ValueError("expected a number")
        if _canon(name) and math.isfinite(amount) and amount > 0:
            caps[_canon(name)] = float(amount)
    return caps


def provider_caps(upper: object, lower: object) -> tuple[Any, bool]:
    """``[budget.provider_caps]``: a workspace may lower a service's cap or add
    one, in any spelling, never raise or remove one."""
    from .provider_cost_cap import _canon

    if not isinstance(lower, dict):
        raise ValueError("expected a table of caps")
    up = _provider_caps(upper) if isinstance(upper, dict) else {}
    merged, loosened = dict(up), False
    for name, value in lower.items():
        key, amount = _canon(name), _provider_caps({name: value}).get(_canon(name))
        if key in up and (amount is None or amount > up[key]):
            loosened = True
        elif amount is not None:
            merged[key] = amount
    return merged, loosened


def warning_thresholds(upper: object, lower: object) -> tuple[Any, bool]:
    """``[budget] warning_thresholds`` as ``budget_guidance.policy`` reads
    them: a workspace may add warnings, never remove the organisation's."""
    from .config_contracts import NUMBER_LIST_SETTINGS
    from .policy_tighten import Incomparable

    contract = NUMBER_LIST_SETTINGS["budget.warning_thresholds"]

    def read(value: object) -> list[float]:
        if (not isinstance(value, list) or not value or len(value) > contract.max_items
                or any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
                       or not contract.minimum_exclusive < v <= contract.maximum for v in value)):
            raise ValueError("expected warning thresholds")
        return sorted(set(value))

    low = read(lower)
    try:
        up = read(list(contract.default) if upper is None else upper)
    except ValueError as exc:
        raise Incomparable("the organisation's thresholds cannot be read") from exc
    merged = read(sorted(set(up) | set(low)))
    return merged, any(item not in low for item in up)


def _switch(default: bool, *, protection: bool):
    """A switch whose consumer reads only ``true`` or ``false``; anything
    else is the consumer's default. A protection may only go to on, a
    permission only to off."""
    def merge(upper: object, lower: object) -> tuple[Any, bool]:
        if not isinstance(lower, bool):
            raise ValueError("expected true or false")
        current = upper if isinstance(upper, bool) else default
        looser = (current and not lower) if protection else (lower and not current)
        return (upper, True) if looser else (lower, False)
    return merge


def _hosts(value: object) -> list:
    """Host patterns as ``sandbox.network_policy`` and ``tenant.egress`` read
    them: one text is one pattern."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise ValueError("expected a list of host names")


def _narrowed(up: list, low: list) -> tuple[list, bool]:
    """An allow list a lower layer may only narrow. Where the organisation
    set none, a lower layer's list would approve hosts under the allowlist
    posture, so it is ignored."""
    from .policy_tighten import tighten

    if not up:
        return up, bool(low)
    return tighten("allow_list", up, low)


def host_deny(upper: object, lower: object) -> tuple[Any, bool]:
    """``[egress] deny``: denied hosts may only grow."""
    from .policy_tighten import tighten

    return tighten("deny_list", _hosts(upper), _hosts(lower))


def host_allow(upper: object, lower: object) -> tuple[Any, bool]:
    """``[egress] allow``: only narrows a list the organisation set."""
    value, loosened = _narrowed(_hosts(upper), _hosts(lower))
    return (upper, True) if loosened and not value else (value, loosened)


def _host_lists(upper: dict, lower: object, allow: str, deny: str) -> tuple[dict, bool]:
    """One table of host lists: ``deny`` may only grow, ``allow`` only narrow
    a list the organisation set; any other key is ignored."""
    from .policy_tighten import tighten

    if not isinstance(lower, dict):
        raise ValueError("expected a table")
    merged, loosened = dict(upper), False
    for key, value in lower.items():
        try:
            current = _hosts(upper.get(key))
            if key == deny:
                result, looser = tighten("deny_list", current, _hosts(value))
            elif key == allow:
                result, looser = _narrowed(current, _hosts(value))
            else:
                raise ValueError("not a host list")
        except ValueError:
            result, looser = None, True
        if result is not None and result != current:
            merged[key] = result
        loosened = loosened or looser
    return merged, loosened


def _tables(upper: object, lower: object, *, new: bool, allow: str, deny: str) -> tuple[Any, bool]:
    """Named tables of host lists; ``new`` says whether a lower layer may add
    a table the organisation did not set."""
    from .policy_tighten import Incomparable

    if not isinstance(lower, dict):
        raise ValueError("expected a table of tables")
    if upper is not None and not isinstance(upper, dict):
        raise Incomparable("the organisation's table cannot be read")
    merged, loosened = dict(upper or {}), False
    for name, table in lower.items():
        base = merged.get(name, {} if new else None)
        if not isinstance(base, dict) or not isinstance(table, dict):
            loosened = True
            continue
        merged[name], looser = _host_lists(base, table, allow, deny)
        loosened = loosened or looser
    return merged, loosened


def egress_rules(upper: object, lower: object) -> tuple[Any, bool]:
    """``[sandbox.tool.<name>]``: a lower layer may add hosts a tool must not
    reach and narrow a list of hosts the organisation lets it reach."""
    return _tables(upper, lower, new=True, allow="allow_egress", deny="deny_egress")


def tenant_planes(upper: object, lower: object) -> tuple[Any, bool]:
    """``[tenancy.egress.<id>]`` replaces ``[egress]`` for that workspace, so a
    lower layer may only tighten a plane the organisation set."""
    return _tables(upper, lower, new=False, allow="allow", deny="deny")


def compliance_profiles(upper: object, lower: object) -> tuple[Any, bool]:
    """``[compliance] profiles``: a lower layer may add known profiles, never
    remove one (a profile can lock egress)."""
    from .compliance_profiles import ComplianceProfileError, _validated_profile_keys
    from .policy_tighten import Incomparable

    try:
        added = _validated_profile_keys(lower, source="workspace")
    except ComplianceProfileError as exc:
        raise ValueError("not a list of known profiles") from exc
    if upper is not None and not isinstance(upper, list):
        raise Incomparable("the organisation's profiles cannot be read")
    up = list(upper or [])
    return up + [key for key in added if key not in up], False


def disclosure_text(upper: object, lower: object) -> tuple[Any, bool]:
    """``[compliance] disclosure_text`` (maverick.compliance): a lower layer may
    word the AI disclosure its own way, never empty it (empty turns it off).
    Invisible format characters and spaces do not count: the text needs at
    least one letter or digit."""
    import unicodedata

    visible = "" if not isinstance(lower, str) else "".join(
        ch for ch in lower if unicodedata.category(ch) != "Cf" and not ch.isspace())
    if not any(ch.isalnum() for ch in visible):
        raise ValueError("expected the disclosure text")
    return lower, False


# kubectl reads these as a value after --context / -n, and the namespace also
# inside a "namespace/pod:path" copy target: plain names only.
_PLAIN_NAMES = {"namespace": re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"),
                "context": re.compile(r"[A-Za-z0-9@._:][A-Za-z0-9@._:/-]{0,199}")}


def plain_name(key: str):
    """``[sandbox] context`` or ``namespace`` a workspace chooses, with the
    organisation's switch on: any plain name in the organisation's own cluster
    settings file; anything the cluster tools could read otherwise is ignored."""
    def merge(upper: object, lower: object) -> tuple[Any, bool]:
        if not isinstance(lower, str) or not _PLAIN_NAMES[key].fullmatch(lower):
            raise ValueError("expected a plain name")
        return lower, False
    return merge


def listed_host(allowed: object):
    """``[sandbox] host`` a workspace chooses, with the organisation's switch
    on: a plain ``user@host`` or ``host`` (:data:`config_contracts.SSH_DESTINATION`)
    matching one of the organisation's ``workspace_hosts`` patterns (none when
    unset); brackets in a pattern are literal. The ssh backend refuses a
    destination it could read as an option in any case."""
    from .config_contracts import SSH_DESTINATION, SSH_DESTINATION_PATTERN

    patterns = [re.sub(r"[][]", lambda bracket: f"[{bracket.group()}]", p)
                for p in (allowed if isinstance(allowed, list) else [])
                if isinstance(p, str) and re.fullmatch(SSH_DESTINATION_PATTERN, p)]

    def merge(upper: object, lower: object) -> tuple[Any, bool]:
        if (not isinstance(lower, str) or not re.fullmatch(SSH_DESTINATION, lower)
                or not any(fnmatch.fnmatchcase(lower, p) for p in patterns)):
            return upper, True
        return lower, False
    return merge


MERGES = {
    "codebase.checker_image": organisation_only,
    "codebase.checker_models": organisation_only,
    "codebase.protected_checker_model": organisation_only,
    "codebase.allow_self_changes": organisation_only,
    "budget.tool_prices": tool_prices,
    "budget.provider_caps": provider_caps,
    "budget.warning_thresholds": warning_thresholds,
    "budget.task_limits_enabled": _switch(True, protection=True),
    "budget.strict_pricing": _switch(True, protection=True),
    **{f"budget.{key}": task_cap(key) for key in (
        "max_dollars", "max_wall_seconds", "max_tool_calls", "max_input_tokens", "max_output_tokens")},
    "codebase.enable": _switch(False, protection=False),
    "approval.record_checks": _switch(True, protection=True),
    "approval.require_acknowledgement": _switch(True, protection=True),
    "sandbox.tool": egress_rules,
    "egress.deny": host_deny,
    "egress.allow": host_allow,
    "tenancy.egress": tenant_planes,
    "compliance.profiles": compliance_profiles,
    "compliance.disclosure_text": disclosure_text,
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
