"""N-of-M dual control (segregation of duties) for the approvals queue.

A high-/critical-risk action can require **N distinct approvers** before it is
granted, and by default the requester cannot approve their own request. This is
the "two-person rule" auditors test for under SOX / SOC 2 CC / HIPAA. Off by
default (``required = 1`` -> the legacy single approver); opt-in per risk band::

    [security]
    approvals_required = 2          # applies to every parked approval
    allow_self_approval = false     # default: the requester can't self-approve

    # ...or require more approvers only for the riskiest actions:
    [security.approvals_required]
    high = 2
    critical = 3
    default = 1

    # ...or keep one number for everything and raise it for some risk levels
    # (the dashboard's per-level table; it can only ADD approvers):
    [security.approvals_required_by_risk]
    critical = 3

The enforcement lives in ``WorldModel.decide_approval`` (distinctness via the
``approval_signoffs`` PK + the self-approval bar); this module only resolves the
configured quorum at park time.

With one approver, ``[approval] separate_approver`` (see
:func:`separate_approver_mode`) decides whether the person who asked for a high
or critical risk action may approve it themselves; the shared decision path
(``maverick.channel_approvals``) enforces it on every surface.
"""
from __future__ import annotations

import os
from typing import Any

from ..config_contracts import CHOICE_SETTINGS

_RISK_ORDER = ("low", "medium", "high", "critical")


def _security_cfg() -> dict[str, Any]:
    try:
        from ..config import load_config
        sec = (load_config() or {}).get("security") or {}
    except Exception:  # pragma: no cover -- config never blocks a request
        return {}
    return sec if isinstance(sec, dict) else {}


def _coerce_int(value: object, default: int = 1) -> int:
    try:
        n = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return n if n >= 1 else default


def required_approvals(risk: str | None = None) -> int:
    """Quorum (N distinct approvers) required for an action at ``risk``.

    Resolution: ``MAVERICK_APPROVALS_REQUIRED`` env (global) wins; else
    ``[security] approvals_required`` -- an int (applies to all) or a per-risk
    table (``high``/``critical``/... with an optional ``default``). Always >= 1;
    1 means the legacy single-approver behaviour (no dual control).

    ``[security] approvals_required_by_risk`` (a per-risk table) then raises
    the number for the levels it names: it never lowers it, so a stale row can
    only ask for more people, never fewer."""
    env = os.environ.get("MAVERICK_APPROVALS_REQUIRED")
    if env is not None and env.strip() != "":
        return _coerce_int(env, 1)
    sec = _security_cfg()
    base = _base_approvals(sec.get("approvals_required"), risk)
    by_risk = sec.get("approvals_required_by_risk")
    r = str(risk or "").strip().lower()
    if isinstance(by_risk, dict) and r in by_risk:
        return max(base, _coerce_int(by_risk[r], 1))
    return base


def _base_approvals(val: object, risk: str | None) -> int:
    if isinstance(val, dict):
        r = str(risk or "").strip().lower()
        if r in val:
            return _coerce_int(val[r], 1)
        if "default" in val:
            return _coerce_int(val["default"], 1)
        return 1
    if val is None:
        return 1
    return _coerce_int(val, 1)


def allow_self_approval() -> bool:
    """Whether the requester may approve their own request. Default **False**
    (segregation of duties). ``MAVERICK_ALLOW_SELF_APPROVAL`` env wins over
    ``[security] allow_self_approval``."""
    env = os.environ.get("MAVERICK_ALLOW_SELF_APPROVAL")
    if env is not None and env.strip() != "":
        return env.strip().lower() in {"1", "true", "yes", "on"}
    v = _security_cfg().get("allow_self_approval")
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "on"}
    return bool(v)


SEPARATE_APPROVER_MODES = CHOICE_SETTINGS["approval.separate_approver"].options
_SEPARATE_APPROVER_RISKS = frozenset({"high", "critical"})


def separate_approver_mode() -> str:
    """Who approves a high or critical risk action the requester asked for.

    ``[approval] separate_approver``:

    * ``"when_available"`` (default) -- someone else, whenever at least one
      other person could decide the request; where the requester is the only
      one who can, they may approve it themselves (recorded as a self-approval).
    * ``"always"`` -- someone else, even if nobody else can: the request then
      waits and expires, which refuses the action.
    * ``"never"`` -- the requester may approve it.

    ``MAVERICK_SEPARATE_APPROVER`` wins. A value this module does not know is
    treated as ``"always"``, so a typo never loosens the rule."""
    env = os.environ.get(CHOICE_SETTINGS["approval.separate_approver"].dashboard_env[0], "").strip().lower()
    if env:
        return env if env in SEPARATE_APPROVER_MODES else "always"
    try:
        from ..config import load_config

        raw = ((load_config() or {}).get("approval") or {}).get("separate_approver")
    except Exception:  # pragma: no cover -- config never blocks a request
        raw = None
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return CHOICE_SETTINGS["approval.separate_approver"].default
    value = str(raw).strip().lower()
    return value if value in SEPARATE_APPROVER_MODES else "always"


def separate_approver_applies(risk: str | None, approvals_required: object = 1) -> bool:
    """Whether :func:`separate_approver_mode` governs a request.

    High or critical risk with one approver. With two or more, distinct people
    approve anyway, and :func:`allow_self_approval` alone decides whether the
    requester's vote counts as one of them."""
    return (str(risk or "").strip().lower() in _SEPARATE_APPROVER_RISKS
            and _coerce_int(approvals_required, 1) <= 1)


__all__ = ["SEPARATE_APPROVER_MODES", "allow_self_approval", "required_approvals",
           "separate_approver_applies", "separate_approver_mode"]
