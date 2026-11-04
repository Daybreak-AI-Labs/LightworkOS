"""Governance audit surface for the specialist roster.

``maverick domains-lint`` answers "is each pack well-formed?". This answers the
enterprise question: "what can these agents do, and what stops them?" — the
auditable inventory a GRC reviewer, security assessment, or procurement needs.

For each pack it records the governance posture the other modules enforce:
the compartment seal, the capability envelope (risk ceiling + whether any
state-mutating tool is reachable), the hard refusals it carries, the human
sign-off gate on its deliverable, and the reasoning tier. Pure functions: the
CLI renders them, tests assert the roster-wide invariants (e.g. no drafting
agent can reach a shell), and the JSON export feeds an external GRC system.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .domain import (
    DomainProfile,
    available_domains,
    declared_prompt_gate,
    domain_capability,
    enforced_gate,
    suite_for,
)
from .domain_refusals import refusals_for

# State-mutating / host-control tools a drafting agent must never reach.
_HOST_CONTROL = ("shell", "write_file", "code_exec", "computer", "browser")
_FILE_CODE_MUTATORS = ("apply_patch", "str_replace_editor", "ast_edit")
# Irreversible business actions; a pack denying these shows its segregation-of-
# duties posture ("agents draft; humans post, pay, file, certify").
_IRREVERSIBLE = (
    "release_payment", "wire_transfer", "ach_send", "run_payroll",
    "post_journal_entry", "file_return", "file_tax_return", "file_with_sec",
    "place_trade", "execute_fx_trade", "vendor_master_change", "send_payment",
    "approve_expense", "approve_po", "approve_vendor", "set_credit_limit",
    "send_invoice", "self_edit", "release_payroll_payment",
    "close_period", "edit_chart_of_accounts", "write_off_balance",
    "reimburse", "edit_employee_bank_details", "create_order_instruction",
    "delete_order_instruction", "dispose_asset", "remit_tax",
)


@dataclass
class PackAudit:
    name: str
    suite: str | None
    compartment: str
    max_risk: str | None
    effort: str | None
    is_builder: bool
    reachable_dangerous: list[str] = field(default_factory=list)
    denied_irreversible: list[str] = field(default_factory=list)
    n_refusals: int = 0
    refusals: list[str] = field(default_factory=list)
    # ``human_gate`` remains as a compatibility alias, but now means only a
    # persisted release control.  Prompt-only declarations are separate so a
    # GRC export cannot accidentally claim a control that does not execute.
    human_gate: str | None = None
    declared_prompt_gate: str | None = None
    enforced_gate: str | None = None
    deliverable: str = ""
    consumers: list[str] = field(default_factory=list)
    knowledge_sources: list[str] = field(default_factory=list)
    autonomy: str = "suggest"              # baseline authority rung (pack block or suite default)
    autonomy_onboarding: bool = True       # starts supervised until graduated
    # What the runtime capability (domain_capability: autonomy levels, data
    # grounding) grants beyond the declared allowlist under current settings,
    # and which dangerous tools that runtime capability can reach. The declared
    # posture above is what the pack asks for; this is what it actually gets.
    runtime_expansion: list[str] = field(default_factory=list)
    runtime_reachable_dangerous: list[str] = field(default_factory=list)


def audit_profile(profile: DomainProfile, *, levels: bool | None = None,
                  grounding: bool | None = None, runtime: bool = True) -> PackAudit:
    """The governance posture of one pack (pure).

    ``levels`` / ``grounding`` pass through to :func:`domain_capability`:
    ``None`` reads the deployment's dial, ``False`` is that dial off.
    ``runtime=False`` leaves ``runtime_expansion`` and
    ``runtime_reachable_dangerous`` empty instead of computing the runtime
    capability, for a caller that shows neither.
    """
    allow = set(profile.allow_tools)
    # Builder status is a roster classification, not something a drafting pack
    # can acquire merely by adding shell/code_exec to its allowlist.
    suite = suite_for(profile.name)
    is_builder = (
        suite == "product_engineering"
        and bool(allow & {"shell", "code_exec"})
    )
    cap = profile.capability(f"agent:{profile.name}")
    dangerous = sorted(
        set(_HOST_CONTROL) | set(_FILE_CODE_MUTATORS) | set(_IRREVERSIBLE)
    )
    reachable = [t for t in dangerous if cap.permits(t)]
    denied = [t for t in _IRREVERSIBLE if t in set(profile.deny_tools)]
    runtime_cap = (domain_capability(profile, None, f"agent:{profile.name}",
                                     levels=levels, grounding=grounding)
                   if runtime else None)
    refusals = refusals_for(profile.name, profile.refuse)
    from .agent_autonomy import effective_profile
    _auto = effective_profile(profile.name, profile.autonomy)
    declared = declared_prompt_gate(profile)
    enforced = enforced_gate(profile)
    return PackAudit(
        name=profile.name,
        suite=suite,
        compartment=profile.compartment,
        max_risk=profile.max_risk,
        effort=profile.effort,
        is_builder=is_builder,
        reachable_dangerous=reachable,
        denied_irreversible=denied,
        n_refusals=len(refusals),
        refusals=refusals,
        human_gate=enforced,
        declared_prompt_gate=declared,
        enforced_gate=enforced,
        deliverable=profile.output.deliverable,
        consumers=list(profile.output.consumers),
        knowledge_sources=list(profile.knowledge_sources),
        autonomy=_auto.default.value,
        autonomy_onboarding=_auto.onboarding,
        runtime_expansion=sorted(runtime_cap.allow_tools - allow) if runtime_cap else [],
        runtime_reachable_dangerous=[t for t in dangerous if runtime_cap.permits(t)] if runtime_cap else [],
    )


def audit_roster(domains: dict[str, DomainProfile] | None = None, *,
                 runtime: bool = True) -> list[PackAudit]:
    """Audit every discoverable pack (built-in + operator overrides).

    The whole roster is audited against one read of the configuration, so the
    workforce pages do not re-read it for each pack's workforce settings
    (about 6,400 reads).
    """
    from .agent_autonomy import levels_enabled
    from .config import single_read
    from .domain import data_grounding_enabled

    with single_read():
        domains = domains if domains is not None else available_domains()
        # A deployment-wide dial that is off is off for every pack: say so
        # once instead of reading the settings again for each one. A dial that
        # is on is still checked per pack, as before.
        levels = None if levels_enabled() else False
        grounding = None if data_grounding_enabled() else False
        return [audit_profile(domains[name], levels=levels, grounding=grounding, runtime=runtime)
                for name in sorted(domains)]


def autonomy_posture(domains: dict[str, DomainProfile] | None = None) -> dict:
    """The ``autonomy_posture`` and ``packs_onboarding`` of :func:`summarize`,
    from each pack's effective autonomy alone: the workforce posture call
    audited all 2,031 packs (165-210 ms) to count these two."""
    from .agent_autonomy import effective_profile
    from .config import single_read

    with single_read():
        domains = domains if domains is not None else available_domains()
        profiles = [effective_profile(domains[name].name, domains[name].autonomy) for name in sorted(domains)]
    return {
        "autonomy_posture": {
            rung: sum(1 for p in profiles if p.default.value == rung)
            for rung in ("observe", "suggest", "request", "auto")
        },
        "packs_onboarding": sum(1 for p in profiles if p.onboarding),
    }


def summarize(audits: list[PackAudit]) -> dict:
    """Roster-wide governance summary -- the headline numbers for an assessor."""
    total = len(audits)
    builders = [a for a in audits if a.is_builder]
    non_builders = [a for a in audits if not a.is_builder]
    gate_rank = {None: 0, "review": 1, "approval": 2}
    return {
        "packs": total,
        "suites": len({a.suite for a in audits if a.suite}),
        "builders": len(builders),
        # The load-bearing safety invariant: no drafting agent reaches a mutator.
        "drafting_agents_reaching_a_mutator": sum(
            1 for a in non_builders if a.reachable_dangerous),
        # Compatibility headline, now intentionally counts *enforced* gates.
        "packs_with_human_gate": sum(1 for a in audits if a.enforced_gate),
        "packs_with_declared_prompt_gate": sum(
            1 for a in audits if a.declared_prompt_gate
        ),
        "packs_with_unenforced_prompt_gate": sum(
            1
            for a in audits
            if gate_rank.get(a.declared_prompt_gate, 0)
            > gate_rank.get(a.enforced_gate, 0)
        ),
        "packs_with_refusals_beyond_universal": sum(
            1 for a in audits if a.n_refusals > 2),
        "packs_with_effort_tier": sum(1 for a in audits if a.effort),
        "packs_with_deliverable": sum(1 for a in audits if a.deliverable),
        # Per-agent authority posture (the agent-as-employee dial). Distribution
        # of the baseline rung each hire starts at, and how many begin supervised.
        "autonomy_posture": {
            rung: sum(1 for a in audits if a.autonomy == rung)
            for rung in ("observe", "suggest", "request", "auto")
        },
        "packs_onboarding": sum(1 for a in audits if a.autonomy_onboarding),
    }


def to_json(audits: list[PackAudit]) -> dict:
    """A machine-readable audit document for ingestion into a GRC system."""
    return {"summary": summarize(audits), "packs": [asdict(a) for a in audits]}


__all__ = ["PackAudit", "audit_profile", "audit_roster", "autonomy_posture", "summarize", "to_json"]
