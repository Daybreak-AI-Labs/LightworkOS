"""Segregation-of-Duties (SoD) conflict linter over the finance domain packs.

The cardinal finance control (finance-agent-suite §2.1): the four incompatible
duties — **record, authorize, custody, reconcile** — must never sit with one
party. We enforce it structurally: each duty is a separate compartment, and no
single compartment's capability may span two incompatible duties. This is the
static check that proves it — the finance analogue of the capability tests, meant
to gate CI so the separation can't silently rot.

Each tool maps to at most one duty by name pattern; a compartment's duties are the
union over its packs' ``allow_tools``. A compartment that holds an *incompatible*
pair (e.g. ``stage_payment_batch`` = record **and** ``release_payment`` = custody)
is a conflict. Record + reconcile in one compartment is allowed (the same closer
records and reconciles); custody and authorize are incompatible with everything.
The linter is pure and dependency-free; :func:`lint_finance_roster` loads the
installed finance packs for it (``maverick finance lint-sod`` and the dashboard).
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass

# Duty classification by tool-name pattern. The first matching duty wins.
_DUTY_PATTERNS: list[tuple[str, str]] = [
    # custody — moving cash / executing trades / running payroll (the money act)
    ("custody", "release_*"),
    ("custody", "wire_transfer"),
    ("custody", "ach_send"),
    ("custody", "send_payment"),
    ("custody", "run_payroll"),
    ("custody", "place_trade"),
    ("custody", "execute_fx_trade"),
    ("custody", "create_order_instruction"),
    ("custody", "delete_order_instruction"),
    # authorize — approving / posting / closing / filing (committing to the SoR)
    ("authorize", "approve_*"),
    ("authorize", "post_journal_entry"),
    ("authorize", "close_period"),
    ("authorize", "file_return"),
    ("authorize", "file_tax_return"),
    ("authorize", "remit_tax"),
    ("authorize", "file_with_sec"),
    ("authorize", "set_credit_limit"),
    ("authorize", "vendor_master_change"),
    ("authorize", "edit_chart_of_accounts"),
    ("authorize", "edit_employee_bank_details"),
    # record — staging / drafting entries, invoices, batches (entering data)
    ("record", "stage_*"),
    ("record", "draft_invoice"),
    ("record", "draft_journal*"),
    # reconcile — matching one side of the books to another
    ("reconcile", "reconcile_*"),
]

# Duty pairs that may never coexist in one compartment. Custody is incompatible
# with every other duty; authorize with record/custody/reconcile. Record +
# reconcile is deliberately NOT a conflict (one accountant closes the books).
_INCOMPATIBLE: frozenset[frozenset[str]] = frozenset({
    frozenset({"record", "custody"}),
    frozenset({"authorize", "custody"}),
    frozenset({"authorize", "record"}),
    frozenset({"reconcile", "custody"}),
    frozenset({"authorize", "reconcile"}),
})


#: The four duties, in a fixed order.
DUTIES: tuple[str, ...] = ("authorize", "custody", "reconcile", "record")


def incompatible_duties(duty: str) -> tuple[str, ...]:
    """The duties that may never share a compartment with ``duty``."""
    return tuple(other for other in DUTIES
                 if frozenset({duty, other}) in _INCOMPATIBLE)


def classify_duty(tool: str) -> str | None:
    """Return the SoD duty a tool belongs to, or ``None`` (read/analysis/propose).

    Matching is case-insensitive: a control linter must never let a mis-cased
    tool name (``Release_Payment``) silently escape classification and hide a
    real segregation-of-duties conflict."""
    name = (tool or "").strip().lower()
    for duty, pattern in _DUTY_PATTERNS:
        if fnmatch.fnmatchcase(name, pattern):
            return duty
    return None


@dataclass(frozen=True)
class SoDConflict:
    compartment: str
    duty_a: str
    duty_b: str
    tools_a: tuple[str, ...]
    tools_b: tuple[str, ...]

    def __str__(self) -> str:
        return (f"compartment {self.compartment!r} spans incompatible duties "
                f"{self.duty_a!r} ({', '.join(self.tools_a)}) and "
                f"{self.duty_b!r} ({', '.join(self.tools_b)})")


def _duty_tools(allow_tools) -> dict[str, list[str]]:
    """Map each duty present in ``allow_tools`` to the tools that triggered it."""
    out: dict[str, list[str]] = {}
    for tool in allow_tools or []:
        duty = classify_duty(tool)
        if duty:
            out.setdefault(duty, []).append(tool)
    return out


def lint_compartment(compartment: str, allow_tools) -> list[SoDConflict]:
    """Conflicts within one compartment's combined ``allow_tools``."""
    duties = _duty_tools(allow_tools)
    present = sorted(duties)
    conflicts: list[SoDConflict] = []
    for i, a in enumerate(present):
        for b in present[i + 1:]:
            if frozenset({a, b}) in _INCOMPATIBLE:
                conflicts.append(SoDConflict(
                    compartment=compartment, duty_a=a, duty_b=b,
                    tools_a=tuple(sorted(duties[a])),
                    tools_b=tuple(sorted(duties[b])),
                ))
    return conflicts


def lint_roster(profiles) -> list[SoDConflict]:
    """Lint a collection of :class:`DomainProfile`, grouping packs by compartment.

    ``profiles`` is an iterable (or dict.values()) of domain profiles. Packs that
    share a compartment have their ``allow_tools`` unioned before linting, so two
    packs that *together* break SoD within one seal boundary are caught.
    """
    by_compartment: dict[str, list[str]] = {}
    for prof in (profiles.values() if hasattr(profiles, "values") else profiles):
        comp = getattr(prof, "compartment", None) or getattr(prof, "name", "?")
        by_compartment.setdefault(comp, [])
        by_compartment[comp].extend(getattr(prof, "allow_tools", []) or [])
    conflicts: list[SoDConflict] = []
    for comp, tools in by_compartment.items():
        conflicts.extend(lint_compartment(comp, tools))
    return conflicts


def lint_finance_roster() -> tuple[dict, list[SoDConflict]]:
    """Lint every installed finance pack as one roster: the built-in packs plus
    the active workspace's own (a workspace pack replaces a built-in one of the
    same name). Returns ``(packs, conflicts)``."""
    from ..domain import builtin_dir, load_domains, user_dir
    packs = {n: p for n, p in {**load_domains(builtin_dir()),
                               **load_domains(user_dir())}.items()
             if n.startswith("finance_")}
    return packs, lint_roster(packs)


def assert_no_conflicts(profiles) -> None:
    """Raise ``SoDViolation`` if the roster has any SoD conflict (CI gate)."""
    conflicts = lint_roster(profiles)
    if conflicts:
        raise SoDViolation(
            "segregation-of-duties conflicts:\n  " +
            "\n  ".join(str(c) for c in conflicts))


class SoDViolation(Exception):
    """Raised when a compartment holds two incompatible duties."""


__all__ = [
    "DUTIES", "classify_duty", "incompatible_duties", "SoDConflict", "SoDViolation",
    "lint_compartment", "lint_roster", "lint_finance_roster", "assert_no_conflicts",
]
