"""The Finance Operating Profile: five finance keys compiled into live controls.

finance-agent-suite §3.8 bundles a client's finance posture into one profile
that compiles to governance policy and consent behaviour, with hard floors no
configuration can lower. This module is that compiler plus the two action-time
checks the policy cannot express on its own (separation of duties and the
finance approval timeout). Every key is read only while the finance layer is
on (``[finance_operations] enable = true`` in the deployment-global
configuration); with the layer off, or a key unset, behaviour is unchanged.

``[finance] framework``
    ``us_gaap`` | ``ifrs``: adds that accounting framework's policy pack
    (:data:`maverick.finance.regimes.FRAMEWORKS`), unioned strictest-wins with
    ``[finance] regimes``.
``[finance] materiality``
    A positive amount in the reporting currency. Anomaly findings at or above
    it are raised to high severity, so closing them needs a second, independent
    person (:mod:`maverick.finance.anomaly_engine`), and an ``auto_threshold``
    action never runs on its own above it.
``[finance.automation]``
    ``default`` sets the automation level of every finance action
    (:data:`FINANCE_ACTIONS`); any other key names one action class
    (``release_payment`` or ``ap.release_payment``) and sets its level. Levels
    are :data:`maverick.governance.AUTOMATION_LEVELS`. While the ladder is in
    use, the hard floors (:data:`HARD_FLOOR_ACTIONS`) stay at ``approve`` or
    stricter: a default above ``approve`` is held down for them, and an explicit
    entry that tries to lower one is refused (the policy fails closed).
``[finance.sod] mode``
    ``enforce`` | ``warn``: when an agent takes a duty-bearing action
    (record / authorize / custody / reconcile) its grant, and every pack sharing
    its compartment, is linted with :mod:`maverick.finance.sod_linter`. A
    conflict is refused under ``enforce``; under ``warn`` it is recorded as a
    compensating-control finding and the action waits for a person (§3.6).
    Conflicts on a hard-floored action are refused in both modes.
``[finance.approvals] timeout``
    ``fail_closed`` (the only value): a finance action waiting for approval is
    decided by a person on the Approvals page, never by the automatic consent
    mode or an earlier "remember this" grant; no decision in time is a refusal
    and the request is withdrawn.
"""
from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal

from ..governance import AUTOMATION_LEVELS, Policy, automation_rank, stricter_level
from . import regimes
from .sod_linter import SoDConflict, classify_duty, incompatible_duties, lint_compartment

FRAMEWORK_KEYS: tuple[str, ...] = tuple(regimes.FRAMEWORKS)
SOD_MODES: tuple[str, ...] = ("enforce", "warn")
#: Finance never fail-opens an approval, so there is no second value.
APPROVAL_TIMEOUTS: tuple[str, ...] = ("fail_closed",)
_MAX_MATERIALITY = 1e15

#: The committing finance actions the automation default applies to: money
#: movement, posting, master-data, filing and tax actions no finance pack may
#: allow (tests/test_finance_roster.py), with plain names for the dashboard.
FINANCE_ACTIONS: dict[str, str] = {
    "post_journal_entry": "Post a journal entry",
    "close_period": "Close an accounting period",
    "edit_chart_of_accounts": "Change the chart of accounts",
    "release_payment": "Release a payment",
    "send_payment": "Send a payment",
    "wire_transfer": "Send a wire transfer",
    "ach_send": "Send a bank transfer (ACH)",
    "release_payroll_payment": "Release a payroll payment",
    "run_payroll": "Run payroll",
    "edit_employee_bank_details": "Change an employee's bank details",
    "vendor_master_change": "Change a supplier's master record",
    "approve_vendor": "Approve a new supplier",
    "approve_po": "Approve a purchase order",
    "approve_expense": "Approve an expense",
    "send_invoice": "Send an invoice",
    "set_credit_limit": "Set a customer's credit limit",
    "write_off_balance": "Write off a balance",
    "dispose_asset": "Dispose of an asset",
    "place_trade": "Place a trade",
    "execute_fx_trade": "Make a currency trade",
    "remit_tax": "Pay tax to a tax authority",
    "file_return": "File a return",
    "file_tax_return": "File a tax return",
    "file_with_sec": "File with the SEC",
}

#: §3.2 hard floors: never below ``approve`` while the automation ladder is in
#: use -- money release, posting, payroll, bank-detail and master-data changes,
#: period close, chart-of-accounts changes, tax remittance and filings.
HARD_FLOOR_ACTIONS: frozenset[str] = frozenset({
    "post_journal_entry", "close_period", "edit_chart_of_accounts",
    "release_payment", "send_payment", "wire_transfer", "ach_send",
    "release_payroll_payment", "run_payroll", "edit_employee_bank_details",
    "vendor_master_change", "remit_tax", "file_return", "file_tax_return",
    "file_with_sec",
})

_CLASS_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}(\.[a-z][a-z0-9_]{0,63})?")
_APPROVE = "approve"


@dataclass(frozen=True)
class FinanceProfile:
    framework: str | None = None
    materiality: float | None = None
    sod_mode: str | None = None
    approvals_timeout: str | None = None
    automation_default: str | None = None
    #: ``(class key, level)`` pairs from ``[finance.automation]``, sorted.
    automation_classes: tuple[tuple[str, str], ...] = ()

    def is_empty(self) -> bool:
        return not (
            self.framework or self.materiality is not None or self.sod_mode
            or self.approvals_timeout or self.automation_default
            or self.automation_classes
        )

    @property
    def automation_on(self) -> bool:
        return bool(self.automation_default or self.automation_classes)


def class_action(key: str) -> str:
    """The action a class key names: ``ap.release_payment`` -> ``release_payment``."""
    return key.rsplit(".", 1)[-1]


def _table(parent: Mapping, key: str, where: str) -> Mapping:
    value = parent.get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"[{where}] must be a table")
    return value


def _choice(table: Mapping, key: str, allowed: Iterable[str], where: str) -> str | None:
    value = table.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str) or value.strip().lower() not in allowed:
        raise ValueError(f"{where} must be one of {', '.join(allowed)}")
    return value.strip().lower()


def _materiality(finance: Mapping) -> float | None:
    value = finance.get("materiality")
    if value is None:
        return None
    if (
        isinstance(value, bool) or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) <= _MAX_MATERIALITY
    ):
        raise ValueError("finance.materiality must be a positive amount")
    return float(value)


def _classes(automation: Mapping) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    for raw_key in automation:
        if raw_key == "default":
            continue
        key = str(raw_key).strip().lower()
        if not _CLASS_KEY.fullmatch(key):
            raise ValueError(f"finance.automation key {raw_key!r} is not an action class")
        level = _choice(automation, raw_key, AUTOMATION_LEVELS, f"finance.automation.{key}")
        if level is None:
            continue
        if class_action(key) in HARD_FLOOR_ACTIONS and automation_rank(level) > \
                automation_rank(_APPROVE):
            # §3.2: the compiler refuses to build a profile that lowers a floor.
            raise ValueError(
                f"finance.automation.{key} cannot be {level}: "
                f"{class_action(key)} is hard-floored at approve"
            )
        out.append((key, level))
    return tuple(sorted(out))


def parse_profile(config: Mapping) -> FinanceProfile:
    """Strictly parse the profile keys; a present malformed key raises."""
    finance = _table(config, "finance", "finance")
    automation = _table(finance, "automation", "finance.automation")
    return FinanceProfile(
        framework=_choice(finance, "framework", FRAMEWORK_KEYS, "finance.framework"),
        materiality=_materiality(finance),
        sod_mode=_choice(_table(finance, "sod", "finance.sod"), "mode", SOD_MODES,
                         "finance.sod.mode"),
        approvals_timeout=_choice(_table(finance, "approvals", "finance.approvals"),
                                  "timeout", APPROVAL_TIMEOUTS,
                                  "finance.approvals.timeout"),
        automation_default=_choice(automation, "default", AUTOMATION_LEVELS,
                                   "finance.automation.default"),
        automation_classes=_classes(automation),
    )


def operations_enabled() -> bool:
    """The deployment-global finance-layer switch (a tenant cannot turn it off)."""
    from ..config import load_global_config

    section = (load_global_config() or {}).get("finance_operations")
    return isinstance(section, Mapping) and section.get("enable") is True


def configured_profile(config: Mapping | None = None) -> FinanceProfile | None:
    """The live profile, or ``None`` while the layer is off or nothing is set.

    ``config`` is the caller's trusted snapshot (governance passes the one it
    evaluates); without it the tenant-effective configuration is read.
    """
    if not operations_enabled():
        return None
    if config is None:
        from ..config import load_config

        config = load_config() or {}
    if not isinstance(config, Mapping):
        raise ValueError("config root must be a table")
    profile = parse_profile(config)
    return None if profile.is_empty() else profile


def automation_levels(profile: FinanceProfile) -> dict[str, str]:
    """Action -> level, hard floors applied; ``straight_through`` adds nothing."""
    if not profile.automation_on:
        return {}
    levels: dict[str, str] = {}
    if profile.automation_default:
        levels = dict.fromkeys(FINANCE_ACTIONS, profile.automation_default)
    explicit: dict[str, str] = {}
    for key, level in profile.automation_classes:
        action = class_action(key)
        explicit[action] = stricter_level(explicit.get(action), level) or level
    levels.update(explicit)
    for action in HARD_FLOOR_ACTIONS:
        levels[action] = stricter_level(levels.get(action), _APPROVE) or _APPROVE
    return {action: level for action, level in levels.items()
            if level != "straight_through"}


def compile_policy(profile: FinanceProfile) -> Policy | None:
    """The governance overlay the profile compiles to, or ``None`` if none."""
    automation = automation_levels(profile)
    parts: list[Policy] = []
    if automation:
        # Materiality caps what may run on its own: an auto_threshold action
        # above it always waits for a person (lowest threshold wins in the
        # union, so a smaller [governance] require_human_above still applies).
        ceiling = {} if profile.materiality is None else {
            action: profile.materiality
            for action, level in automation.items() if level == "auto_threshold"
        }
        parts.append(Policy(automation=automation, require_human_above=ceiling))
    if profile.framework:
        parts.append(regimes.FRAMEWORKS[profile.framework].policy)
    return regimes.union_policies(parts) if parts else None


def configured_policy(config: Mapping | None = None) -> Policy | None:
    """Compile the live profile (``Policy.from_config`` calls this)."""
    profile = configured_profile(config)
    return None if profile is None else compile_policy(profile)


def configured_materiality(config: Mapping | None = None) -> Decimal | None:
    profile = configured_profile(config)
    if profile is None or profile.materiality is None:
        return None
    return Decimal(str(profile.materiality))


def is_finance_action(action: str, profile: FinanceProfile | None = None) -> bool:
    """A committing finance action, a duty-bearing one, or one a finance pack gates."""
    name = (action or "").strip().lower()
    if name in FINANCE_ACTIONS or classify_duty(name) is not None:
        return True
    if profile is not None and any(
        class_action(key) == name for key, _level in profile.automation_classes
    ):
        return True
    packs = (*regimes.REGIMES.values(), *regimes.FRAMEWORKS.values())
    return any(name in pack.policy.require_human_actions or name in pack.policy.deny_actions
               for pack in packs)


def approval_fail_closed(action: str, config: Mapping | None = None) -> bool:
    """True when a finance approval for ``action`` must go to a person, fail closed."""
    profile = configured_profile(config)
    return bool(
        profile is not None and profile.approvals_timeout == "fail_closed"
        and is_finance_action(action, profile)
    )


# ------------------------------------------------ separation of duties


@dataclass(frozen=True)
class SoDCheck:
    """A separation-of-duties conflict found when an action was about to run."""

    action: str
    duty: str
    mode: str
    compartment: str
    conflicts: tuple[SoDConflict, ...]
    hard_floor: bool

    @property
    def blocks(self) -> bool:
        return self.mode == "enforce" or self.hard_floor

    @property
    def rule(self) -> str:
        return f"finance_sod:{self.mode}"

    @property
    def reason(self) -> str:
        head = f"separation-of-duties conflict: {self.conflicts[0]}"
        if self.mode == "enforce":
            return f"{head}; separation of duties is enforced"
        if self.hard_floor:
            return f"{head}; a hard-floored action is never allowed with a conflict"
        return (f"{head}; allowed only with a person's approval as the "
                "compensating control")


def _held_tools(allow_tools, deny_tools, compartment: str | None) -> set[str] | None:
    """Tools the acting principal holds, or ``None`` for an unrestricted grant."""
    held = {str(t).strip().lower() for t in (allow_tools or ()) if str(t).strip()}
    if not held:
        return None
    if compartment:
        from ..domain import available_domains

        for prof in available_domains().values():
            if getattr(prof, "compartment", None) == compartment:
                held.update(str(t).strip().lower()
                            for t in getattr(prof, "allow_tools", None) or ())
    held -= {str(t).strip().lower() for t in (deny_tools or ())}
    return held


def _conflicts(name: str, duty: str, held: set[str] | None,
               label: str) -> tuple[SoDConflict, ...]:
    if held is None:
        # No allow-list: the grant can reach every tool, so it holds every duty.
        out = []
        for other in incompatible_duties(duty):
            a, b = sorted((duty, other))
            out.append(SoDConflict(
                compartment=label, duty_a=a, duty_b=b,
                tools_a=(name,) if a == duty else ("*",),
                tools_b=(name,) if b == duty else ("*",),
            ))
        return tuple(out)
    return tuple(c for c in lint_compartment(label, [*held, name])
                 if duty in (c.duty_a, c.duty_b))


def check_action_sod(
    action: str,
    *,
    allow_tools: Iterable[str] | None = None,
    deny_tools: Iterable[str] | None = None,
    compartment: str | None = None,
    config: Mapping | None = None,
) -> SoDCheck | None:
    """The conflict this action would complete, or ``None``.

    ``allow_tools`` / ``deny_tools`` are the acting principal's grant; empty
    ``allow_tools`` is an unrestricted grant, which holds every duty. Tools of
    every pack sharing ``compartment`` are added, as :func:`lint_roster` does.
    """
    name = (action or "").strip().lower()
    duty = classify_duty(name)
    if duty is None:
        return None
    profile = configured_profile(config)
    if profile is None or profile.sod_mode is None:
        return None
    label = compartment or "unrestricted"
    conflicts = _conflicts(name, duty, _held_tools(allow_tools, deny_tools, compartment),
                           label)
    if not conflicts:
        return None
    return SoDCheck(action=name, duty=duty, mode=profile.sod_mode, compartment=label,
                    conflicts=conflicts, hard_floor=name in HARD_FLOOR_ACTIONS)


def record_sod_finding(
    check: SoDCheck,
    *,
    agent: str,
    outcome: str,
    goal_id: int | None = None,
    principal: str | None = None,
    origin: str = "agent",
) -> bool:
    """Write the finding to the signed audit chain; True when it was written."""
    from ..audit import EventKind, audit_event

    return audit_event(
        EventKind.FINANCE_SOD_FINDING, agent=agent, goal_id=goal_id,
        tool=check.action, principal=principal, origin=origin,
        mode=check.mode, outcome=outcome, compartment=check.compartment,
        duty=check.duty, hard_floor=check.hard_floor,
        conflicts=[str(c) for c in check.conflicts[:8]],
    )


__all__ = [
    "APPROVAL_TIMEOUTS", "FINANCE_ACTIONS", "FRAMEWORK_KEYS", "FinanceProfile",
    "HARD_FLOOR_ACTIONS", "SOD_MODES", "SoDCheck", "approval_fail_closed",
    "automation_levels", "check_action_sod", "class_action", "compile_policy",
    "configured_materiality", "configured_policy", "configured_profile",
    "is_finance_action", "operations_enabled", "parse_profile", "record_sod_finding",
]
