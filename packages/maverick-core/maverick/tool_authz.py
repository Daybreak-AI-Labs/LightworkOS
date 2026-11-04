"""One authorization gate for tool dispatch outside the agent loop.

``Agent._run_tool`` runs an eleven-gate chain before any tool executes. It is
genuinely hardened -- but it is not the only path to the tool registry. A census
found four dispatch sites and exactly one of them gated:

===============================================  ==========================
site                                             status
===============================================  ==========================
``agent.py`` (``self.tools.run``)                the full eleven-gate chain
``flow/execution.py`` (``reg.run``)              partial: tool-policy only
``workflow.py`` (``registry.run``)               partial: tool-policy only
``perf_sla.py`` (``reg.run("noop", {})``)        fixed literal, not routable
===============================================  ==========================

The flow path is live -- bound at ``automation_queue`` -- and reaches every
registered connector, including high-risk ones (stripe, gmail, s3, salesforce,
sap, workday). It checked ``action_tool_policy_error`` (unsafe list plus a
risk-classification requirement) and nothing else: no shield scan, no
governance policy, and **no audit row**.

That last omission is the one that matters most for the platform's central
claim. The attestation bundle's ``policy_envelope`` asserts that *no recorded
action violated the envelope*. An action dispatched through an ungated path is
not recorded, so it satisfies that sentence trivially. The claim was not false
so much as **unfalsifiable**, and an unfalsifiable governance claim is worth
less than none: a hostile auditor cannot attack it, which is precisely why it
cannot be trusted.

This module does not attempt to relocate the agent's chain -- that chain reads
agent context (quarantine, per-agent capability attenuation, autonomy servo,
rehearsal twin, hooks) that does not exist at a flow node. It applies the
subset that is meaningful without an agent, and, critically, it records the
dispatch on the same signed chain so the envelope claim has something to be
false about.

Deliberately NOT covered here, so nobody reads this as more than it is:
per-agent capability attenuation, the autonomy servo, the rehearsal twin,
compartment quarantine, and PreToolUse hooks. Those need an agent. A flow node
is refused when capability enforcement is enabled; otherwise it is governed
less tightly than an agent tool call, and
:func:`gate_summary` states that in words for the operator rather than leaving
it to be inferred from an absence.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

log = logging.getLogger(__name__)
_PROFILE_KEYS_UNSET = object()


def non_agent_capability_required() -> bool:
    """Whether a non-agent runner lacks required effective authority."""
    try:
        from .capability import capability_enforced
        from .tools import tool_capability_active
        return capability_enforced() or tool_capability_active()
    except Exception:
        return True

#: Dispatch sites permitted to call the registry directly, enforced by
#: ``maverick.dispatch_contract``. Everything else must come through here.
SANCTIONED_DISPATCH = (
    "packages/maverick-core/maverick/agent.py",
    "packages/maverick-core/maverick/tool_authz.py",
)


def _audit_summary(value: Any, limit: int = 200) -> str:
    """Describe a dispatch without copying caller-controlled values to audit.

    Even a strict pattern redactor cannot recognize an arbitrary vault value
    embedded in a benign field (for example ``body='pin=4829-...'``).  The
    signed row needs to prove *which* tool ran and correlate its result, not
    retain the request body.  Avoid field names too: they are caller input.
    """
    count = len(value) if isinstance(value, dict) else 0
    return f"{count} parameter{'s' if count != 1 else ''} supplied"


def authorize(
    tool: str,
    params: dict | None = None,
    *,
    origin: str,
    goal_id: int | None = None,
    principal: str | None = None,
    risk: str | None = None,
    call_id: str | None = None,
) -> str | None:
    """Authorize a non-agent tool dispatch. ``None`` allows; a string denies.

    The returned string is the operator/model-facing refusal and is deliberately
    non-leaky -- it names the rule, never the policy internals.

    ``origin`` identifies the dispatch site (``"flow"``, ``"workflow"``) and
    lands in the audit row, so an auditor reading the chain can tell an agent
    tool call apart from a flow action rather than having to infer it.

    Ordered so that deny wins and the cheapest check runs first.
    """
    params = params or {}

    # Non-agent runners do not carry the originating agent's attenuated grant.
    # Creating a root grant here would silently widen its tool, host or path
    # authority, so refuse until the effective grant is enforced at dispatch.
    if non_agent_capability_required():
        _record_denial(tool, origin, goal_id, "capability_unavailable",
                       "non-agent dispatch has no enforceable capability")
        return (
            "ERROR: non-agent tool dispatch is unavailable while capability "
            "enforcement or an inherited grant is active; use a governed agent step"
        )

    # 1. Tool policy: unsafe-by-construction, or not risk-classified by an
    #    operator. Runtime repeats this even though the graph validator ran it,
    #    because a forged or stale graph must not bypass validation.
    from .flow.ir import action_tool_policy_error

    if policy_error := action_tool_policy_error(tool):
        _record_denial(tool, origin, goal_id, "tool_policy", policy_error)
        return f"ERROR: {policy_error}"

    # 2. Shield: the tool name and its rendered params are model- or
    #    template-derived, so they are attacker-reachable. This is the same
    #    tool-call screen the agent applies at its tool sink. The text screen on
    #    a repr of the call stays as a floor that an operator's
    #    ``[safety] scan_tool_calls = false`` cannot remove (it is what ran here
    #    before); on its own the repr quotes each value and hides
    #    ``rm -rf /`` from the destructive-command rules.
    from . import shield_policy

    reason = (shield_policy.scan_tool_call_block(tool, params)
              or shield_policy.scan_block(f"{tool} {params}"))
    if reason is not None:
        _record_denial(tool, origin, goal_id, "shield", reason)
        return f"ERROR: BLOCKED by Shield: {reason}"

    # 3. Org governance policy (deny / require-human). Default-open for
    #    non-enterprise installs, exactly as on the agent path.
    compliance_profiles: tuple[str, ...] | None = None
    try:
        from .governance import Decision, Policy, evaluate, transaction_value

        policy = Policy.from_config()
        amount, currency, unavailable = transaction_value(tool, params, policy)
        verdict = evaluate(tool, risk=risk, policy=policy, amount=amount,
                           currency=currency, amount_unavailable=unavailable)
    except Exception:
        log.warning(
            "governance enforcement unavailable for non-agent dispatch %r",
            tool,
            exc_info=True,
        )
        _record_denial(
            tool,
            origin,
            goal_id,
            "policy_unavailable",
            "governance enforcement unavailable (failed closed)",
            compliance_profiles=None,
        )
        return (
            "ERROR: governance enforcement was unavailable; dispatch refused "
            "under the fail-closed policy"
        )
    compliance_profiles = verdict.compliance_profiles
    if verdict.decision is Decision.DENY:
        _record_denial(
            tool,
            origin,
            goal_id,
            verdict.rule,
            verdict.reason,
            compliance_profiles=compliance_profiles,
        )
        return f"ERROR: DENIED by org policy ({verdict.rule}): {verdict.reason}"
    if verdict.decision is Decision.REQUIRE_HUMAN:
        # A flow node runs unattended by construction; there is nobody to ask.
        # Refusing is the only honest outcome -- silently downgrading a
        # require-human action to auto-run is the failure this gate prevents.
        _record_denial(
            tool,
            origin,
            goal_id,
            verdict.rule,
            "requires human approval; a flow node runs unattended",
            compliance_profiles=compliance_profiles,
        )
        return (
            f"ERROR: BLOCKED by org policy ({verdict.rule}): this action "
            "requires human sign-off and cannot run unattended in a flow. "
            "Route it through an agent node or an approval step."
        )

    # 3b. Finance separation of duties ([finance.sod] mode). A flow node holds
    #     no agent grant, so it cannot show the duties are separated, and the
    #     warn mode's compensating control (a person's approval) cannot run
    #     unattended: a conflict is refused in both modes.
    if (refusal := _finance_sod_refusal(tool, origin, goal_id, principal,
                                        compliance_profiles)) is not None:
        return refusal

    # 4. Record the dispatch on the signed chain. This is what makes the
    #    attestation's policy_envelope claim falsifiable for flow actions.
    from .audit import (
        TOOL_CALL_COMMITMENT_ALGORITHM,
        EventKind,
        audit_event,
        tool_call_commitment,
    )
    from .regulatory_compiler import checked_tags

    resolved_call_id = call_id or secrets.token_hex(12)
    try:
        commitment = tool_call_commitment(
            call_id=resolved_call_id,
        )
    except ValueError:
        return "ERROR: invalid tool-call evidence identifier; dispatch refused"
    written = audit_event(
        EventKind.TOOL_CALL, agent=f"{origin}:action", goal_id=goal_id,
        name=tool, origin=origin, principal=principal,
        call_id=resolved_call_id,
        call_commitment=commitment,
        call_commitment_algorithm=TOOL_CALL_COMMITMENT_ALGORITHM,
        input_summary=_audit_summary(params),
        **checked_tags(tool, keys=compliance_profiles),
    )
    if not written:
        return (
            "ERROR: dispatch refused because its required audit evidence "
            "could not be written"
        )
    return None


def _finance_sod_refusal(tool: str, origin: str, goal_id: int | None,
                         principal: str | None,
                         compliance_profiles: tuple[str, ...] | None) -> str | None:
    """Refuse a flow dispatch that completes a finance duty conflict."""
    try:
        from .finance import profile as finance_profile

        check = finance_profile.check_action_sod(tool)
        if check is not None:
            finance_profile.record_sod_finding(
                check, agent=f"{origin}:action", goal_id=goal_id,
                principal=principal, origin=origin, outcome="blocked",
            )
    except Exception:
        log.warning("finance separation-of-duties check unavailable for %r",
                    tool, exc_info=True)
        _record_denial(tool, origin, goal_id, "finance_sod:error",
                       "separation-of-duties check unavailable (failed closed)",
                       compliance_profiles=compliance_profiles)
        return ("ERROR: the separation-of-duties check was unavailable; dispatch "
                "refused under the fail-closed policy")
    if check is None:
        return None
    _record_denial(tool, origin, goal_id, check.rule, check.reason,
                   compliance_profiles=compliance_profiles)
    return (f"ERROR: BLOCKED by separation of duties ({check.rule}): "
            f"{check.reason}. A flow step holds no agent grant; route it "
            "through an agent whose pack separates the duties.")


def _record_denial(tool: str, origin: str, goal_id: int | None,
                   rule: str, reason: str, *,
                   compliance_profiles: object = _PROFILE_KEYS_UNSET) -> None:
    from .audit import EventKind, audit_event
    from .regulatory_compiler import audit_tags

    obligation_tags = (
        audit_tags(tool, rule)
        if compliance_profiles is _PROFILE_KEYS_UNSET
        else audit_tags(tool, rule, keys=compliance_profiles)
    )
    audit_event(
        EventKind.GOVERNANCE_DENIED, agent=f"{origin}:action", goal_id=goal_id,
        tool=tool, origin=origin, rule=rule, reason=reason,
        **obligation_tags,
    )


def gate_summary() -> dict[str, list[str]]:
    """What this gate does and does not check, for the operator and the docs.

    Published rather than implied. An absence in a governance product is a
    claim, and an unstated absence is the kind a reader fills in optimistically.
    """
    return {
        "enforced": [
            "non-agent dispatch refused when capability enforcement is enabled",
            "tool policy (unsafe list + operator risk classification)",
            "shield scan of the tool name and rendered params",
            "org governance policy (deny)",
            "org governance policy (require-human -> refused, not downgraded)",
            "finance separation of duties ([finance.sod] mode; a flow step "
            "holds no agent grant, so a duty conflict is refused)",
            "required audit row before every allowed dispatch (signed when "
            "audit signing is enabled or a compliance floor requires it)",
        ],
        "not_enforced_needs_an_agent": [
            "per-agent capability attenuation",
            "per-call tool-token exchange",
            "autonomy servo (run-trust risk ceiling)",
            "rehearsal twin / learned guardrails",
            "compartment quarantine seals",
            "PreToolUse hooks",
        ],
    }


__all__ = ["authorize", "gate_summary", "SANCTIONED_DISPATCH"]
