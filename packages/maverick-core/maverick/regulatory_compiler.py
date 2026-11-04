"""Regulatory compiler: declarative obligations -> executable governance gates.

A policy document says what must not happen. This module makes it *unable* to
happen. Each regulation is a small library of obligations -- a citation, a
scope (tool names or a risk floor) and an effect -- and ``compile_obligations``
turns the active ones into the same ``Policy`` the tool-call chokepoint
already evaluates (``governance.evaluate``) plus a capability attenuation that
can only ever narrow (``Capability.attenuate``). Nothing new is bolted onto the
chokepoint: an obligation is enforced by the gate that enforces everything
else, deny-wins, strictest-wins.

Two things this adds that a document cannot:

* **Evidence the gate decision.** Emitted denial rows retain the obligation
  that produced them (``obligation_id``, ``regulation``, ``article``), and
  every admitted dispatch has mandatory attempt evidence naming the obligations
  checked (``obligations_checked``). A receipt (``trust_receipt.py``) for that
  row can cite the regulation; an executed/failed claim additionally requires
  the correlated terminal-result row.
* **Anti-vacuity.** ``verify`` proves each active obligation actually bites:
  every bound tool name is a classified tool, the compiled policy denies or
  pauses it, a risk floor catches at least one real tool, an attenuation
  narrows a capability. ``python -m maverick.regulatory_compiler --ci`` fails
  the build on a stale tool name or a silent overlay, and exits 2 when it
  inspected nothing -- a gate that cannot tell "nothing wrong" from "nothing
  looked at" is a broken gate, not a passing one.

Scope is deliberately modest: obligations are expressed as tool-level rules
because that is what the runtime can enforce structurally. Prohibitions that
live in an agent's *conduct* (EU AI Act Art. 5 manipulation, social scoring)
stay as the packs' hard refusals; this module does not pretend a tool gate
covers them. Activation is ``[compliance] profiles`` -- the same switch the
existing compliance profiles use -- so a deployment turns a regulation on in
one place and both the policy overlay and the attenuation follow.
"""
from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, replace

from .finance.regimes import union_policies
from .governance import Policy

EFFECT_DENY = "deny"
EFFECT_REQUIRE_HUMAN = "require_human"
EFFECT_ATTENUATE = "attenuate"
_EFFECTS = (EFFECT_DENY, EFFECT_REQUIRE_HUMAN, EFFECT_ATTENUATE)

_RISK_ORDER = ("low", "medium", "high")
_MAX_AUDIT_CITATIONS = 16
_EVIDENCE_ERROR = "active compliance obligation evidence is unavailable"
_PROFILE_KEYS_UNSET = object()
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Obligation:
    """One enforceable clause of a regulation."""
    id: str
    regulation: str
    article: str
    title: str
    effect: str
    #: Exact tool names in scope (DENY / REQUIRE_HUMAN).
    actions: frozenset[str] = frozenset()
    #: Risk floor in scope: every tool at or above it (DENY / REQUIRE_HUMAN).
    min_risk: str | None = None
    #: Tools removed from every capability (ATTENUATE).
    deny_tools: frozenset[str] = frozenset()
    #: Primary source, for the operator and the auditor.
    source_url: str = ""

    def covers(self, action: str, risk: str | None) -> bool:
        """Whether ``action`` (at ``risk``) falls inside this obligation."""
        if action in self.actions or action in self.deny_tools:
            return True
        if self.min_risk and risk in _RISK_ORDER:
            return _RISK_ORDER.index(risk) >= _RISK_ORDER.index(self.min_risk)
        return False


_EURLEX = "https://eur-lex.europa.eu/eli/reg/2016/679/oj"
_AIACT = "https://eur-lex.europa.eu/eli/reg/2024/1689/oj"
_HIPAA = "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164"
_NIST_AI_RMF = "https://www.nist.gov/itl/ai-risk-management-framework"
_ISO_42001 = "https://www.iso.org/standard/81230.html"
_SOC2 = "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services"
# SR 26-2 (April 2026) supersedes SR 11-7.  The source itself says generative
# and agentic AI are outside its scope; the profile below is therefore a
# bounded control-by-analogy, never a claim of SR 26-2 applicability or approval.
_SR_26_2 = "https://www.federalreserve.gov/supervisionreg/srletters/SR2602.pdf"

# Raw personal-data stores. A GDPR erasure must go through the governed path
# (``maverick dsar`` / ``audit.erase``) that leaves a receipt; a direct write
# to the store from an agent is exactly the shortcut the receipt exists to
# rule out.
_RAW_STORES = frozenset({"sql_query", "dynamodb", "mongodb", "redis", "elasticsearch"})
# Outbound channels through which personal data leaves the boundary.
_OUTBOUND = frozenset({"email", "gmail", "ses", "sns", "twilio", "slack_bot", "discord_bot"})

#: The shipped library, keyed by the ``[compliance] profiles`` key that
#: activates it. Every bound tool name is a classified tool in
#: ``safety.tool_risk`` -- ``verify`` proves it, so a renamed tool cannot
#: silently turn an obligation into a no-op.
REGULATIONS: dict[str, tuple[Obligation, ...]] = {
    "gdpr": (
        Obligation(
            "gdpr-art17-erasure-governed-path", "GDPR", "Art. 17",
            "Erasure only through the governed path: a direct write to a "
            "personal-data store pauses for a human",
            EFFECT_REQUIRE_HUMAN, actions=_RAW_STORES, source_url=_EURLEX),
        Obligation(
            "gdpr-art32-outbound-transfer", "GDPR", "Art. 32",
            "A human confirms lawful basis and recipient before personal data "
            "is transmitted outbound",
            EFFECT_REQUIRE_HUMAN, actions=_OUTBOUND, source_url=_EURLEX),
        Obligation(
            "gdpr-art22-automated-decision", "GDPR", "Art. 22",
            "No solely automated decision with significant effect: every "
            "high-risk action pauses for a human",
            EFFECT_REQUIRE_HUMAN, min_risk="high", source_url=_EURLEX),
    ),
    "eu_ai_act": (
        Obligation(
            "eu-aia-art14-human-oversight", "EU AI Act", "Art. 14",
            "Effective human oversight of a high-risk AI system: every "
            "high-risk action pauses for a human",
            EFFECT_REQUIRE_HUMAN, min_risk="high", source_url=_AIACT),
    ),
    "hipaa": (
        Obligation(
            "hipaa-164-502b-minimum-necessary", "HIPAA", "45 CFR 164.502(b)",
            "Minimum necessary: PHI never leaves through an ungoverned "
            "communication channel, whatever the agent is otherwise allowed",
            EFFECT_ATTENUATE, deny_tools=_OUTBOUND, source_url=_HIPAA),
    ),
    # These are deliberately narrow *runtime compatibility* profiles.  They
    # prove the stated tool-gate behavior, not full framework coverage,
    # organizational adoption, certification, or legal/regulatory compliance.
    "nist_ai_rmf": (
        Obligation(
            "nist-ai-rmf-manage-2-human-review", "NIST AI RMF", "MANAGE 2",
            "Bounded runtime risk treatment: every high-risk action pauses for "
            "a human; this maps one enforceable control, not the full AI RMF",
            EFFECT_REQUIRE_HUMAN, min_risk="high", source_url=_NIST_AI_RMF),
    ),
    "iso_42001": (
        Obligation(
            "iso-42001-a9-2-human-oversight", "ISO/IEC 42001:2023", "A.9.2",
            "Bounded runtime human-oversight control: every high-risk action "
            "pauses for a human; this is not complete AIMS coverage",
            EFFECT_REQUIRE_HUMAN, min_risk="high", source_url=_ISO_42001),
    ),
    "soc2": (
        Obligation(
            "soc2-cc6-1-least-privilege-egress", "SOC 2 TSC", "CC6.1",
            "Bounded least-privilege runtime control: known outbound side-effect "
            "tools are removed from every capability; this is not an attestation",
            EFFECT_ATTENUATE, deny_tools=_OUTBOUND, source_url=_SOC2),
    ),
    "sr_11_7": (
        Obligation(
            "sr-26-2-model-risk-human-review",
            "SR 26-2 (successor to SR 11-7)",
            "Risk-based model risk management",
            "Bounded control-by-analogy: every high-risk action pauses for a "
            "human. SR 26-2 supersedes SR 11-7 and excludes generative and "
            "agentic AI from its stated scope.",
            EFFECT_REQUIRE_HUMAN, min_risk="high", source_url=_SR_26_2),
    ),
}

# One source of truth for selectable, CI-gated runtime profiles.  Do not derive
# this at call time from REGULATIONS: tests intentionally fault-inject that
# mutable library, while installer choices and CI must remain the released set.
SHIPPED_PROFILE_KEYS: tuple[str, ...] = tuple(REGULATIONS)


def shipped_profile_keys() -> tuple[str, ...]:
    """Released profile keys, in stable installer and CI display order."""
    return SHIPPED_PROFILE_KEYS


@dataclass(frozen=True)
class CompiledObligations:
    #: DENY / REQUIRE_HUMAN clauses, in the chokepoint's own policy shape.
    policy: Policy
    #: Tools every capability loses while these obligations are active.
    deny_tools: frozenset[str]
    #: Everything that was compiled, for tagging and verification.
    obligations: tuple[Obligation, ...]


def _known_keys(keys) -> list[str]:
    seen: list[str] = []
    for key in keys or ():
        norm = str(key).strip().lower()
        if norm in REGULATIONS and norm not in seen:
            seen.append(norm)
    return seen


def compile_obligations(keys) -> CompiledObligations:
    """Compile the obligations for ``keys`` (unknown keys ignored), strictest-wins."""
    known_keys = _known_keys(keys)
    obligations = tuple(o for k in known_keys for o in REGULATIONS[k])
    policies: list[Policy] = []
    deny_tools: set[str] = set()
    for ob in obligations:
        if ob.effect == EFFECT_DENY:
            policies.append(Policy(deny_actions=ob.actions, deny_min_risk=ob.min_risk))
        elif ob.effect == EFFECT_REQUIRE_HUMAN:
            policies.append(Policy(require_human_actions=ob.actions,
                                   require_human_min_risk=ob.min_risk))
        elif ob.effect == EFFECT_ATTENUATE:
            deny_tools |= set(ob.deny_tools)
        else:  # pragma: no cover -- library is validated by verify()
            raise ValueError(f"{ob.id}: unknown effect {ob.effect!r}")
    policy = replace(
        union_policies(policies), compliance_profiles=tuple(known_keys)
    )
    return CompiledObligations(policy, frozenset(deny_tools), obligations)


def active_keys() -> list[str]:
    """Regulations switched on for this deployment.

    ``[compliance] profiles`` is the single activation switch, shared with the
    compliance profiles that feed the same live policy; ``MAVERICK_COMPLIANCE_PROFILES``
    (comma-separated) adds to it for environments configured by variables.
    """
    from .compliance_profiles import configured_profiles

    # configured_profiles is the single strict config+environment resolver.
    # Do not catch its policy error here: capability_from_config and
    # Policy.from_config turn uncertainty into their existing deny-all paths.
    return configured_profiles()


def _active() -> CompiledObligations:
    return compile_obligations(active_keys())


def _tool_risk(action: str) -> str | None:
    try:
        from .safety.tool_risk import tool_risk
        return tool_risk(action)
    except Exception:
        return None


def _tags_for(ob: Obligation) -> dict:
    return {"obligation_id": ob.id, "regulation": ob.regulation, "article": ob.article}


_EFFECT_FOR_RULE = {
    "deny_actions": EFFECT_DENY,
    "deny_min_risk": EFFECT_DENY,
    "require_human_actions": EFFECT_REQUIRE_HUMAN,
    "require_human_min_risk": EFFECT_REQUIRE_HUMAN,
    "capability": EFFECT_ATTENUATE,
}


def _rule_matches(ob: Obligation, action: str, risk: str | None, rule: str) -> bool:
    """Whether this obligation independently supports the emitted verdict.

    ``evaluate`` reports the first strictest clause that fired. Another active
    obligation with the same effect can still cover the action (for example an
    action-specific GDPR rule plus the GDPR high-risk floor). Both were enforced
    and both must survive in evidence even though only one clause names the
    scalar ``Verdict.rule``.
    """
    if ob.effect != _EFFECT_FOR_RULE.get(rule):
        return False
    if rule == "capability":
        return action in ob.deny_tools
    return ob.covers(action, risk)


def _rule_specificity(ob: Obligation, action: str, risk: str | None, rule: str) -> int:
    """Prefer the exact verdict clause for stable legacy scalar aliases."""
    if rule.endswith("_actions") and action in ob.actions:
        return 0
    if rule.endswith("_min_risk") and ob.min_risk and ob.covers(action, risk):
        return 0
    if rule == "capability" and action in ob.deny_tools:
        return 0
    return 1


def _audit_tags_under(action: str, rule: str, obligations) -> dict:
    risk = _tool_risk(action)
    matches = sorted(
        (ob for ob in obligations if _rule_matches(ob, action, risk, rule)),
        key=lambda ob: (
            _rule_specificity(ob, action, risk, rule),
            ob.id,
            ob.regulation,
            ob.article,
        ),
    )
    if not matches:
        return {}
    # IDs are unique in the shipped library, but fault-injected/custom libraries
    # should not duplicate evidence rows. Preserve the first deterministic entry.
    unique: list[Obligation] = []
    seen: set[str] = set()
    for ob in matches:
        if ob.id not in seen:
            unique.append(ob)
            seen.add(ob.id)
    bounded = unique[:_MAX_AUDIT_CITATIONS]
    legacy = _tags_for(bounded[0])
    return {
        **legacy,
        "obligations_enforced": [_tags_for(ob) for ob in bounded],
        "obligations_enforced_count": len(unique),
        **(
            {"obligations_enforced_truncated": True}
            if len(unique) > len(bounded)
            else {}
        ),
    }


def _compiled_for_evidence(keys) -> CompiledObligations:
    if keys is _PROFILE_KEYS_UNSET:
        return _active()
    if keys is None:
        raise RuntimeError(_EVIDENCE_ERROR)
    return compile_obligations(keys)


def audit_tags(action: str, rule: str, *, keys=_PROFILE_KEYS_UNSET) -> dict:
    """Every obligation behind a chokepoint verdict, for the audit row.

    ``keys`` is the exact ``Verdict.compliance_profiles`` snapshot used by the
    policy decision. Supplying it prevents a concurrent config/tenant change
    from relabelling the decision. An explicit ``None`` means provenance was
    unavailable and produces an evidence-error marker; omitting ``keys`` keeps
    the legacy live-resolution helper behavior. The first deterministic citation
    is retained in the legacy scalar aliases; ``obligations_enforced`` retains
    all bounded applicable citations.
    """
    try:
        compiled = _compiled_for_evidence(keys)
        return _audit_tags_under(action, rule, compiled.obligations)
    except Exception:
        log.exception("regulatory obligation evidence is unavailable")
        return {"obligation_evidence_error": _EVIDENCE_ERROR}


def obligations_checked(action: str, *, keys=_PROFILE_KEYS_UNSET) -> list[str]:
    """Ids of every active obligation whose scope covers ``action``."""
    compiled = _compiled_for_evidence(keys)
    risk = _tool_risk(action)
    return sorted({ob.id for ob in compiled.obligations if ob.covers(action, risk)})


def checked_tags(action: str, *, keys=_PROFILE_KEYS_UNSET) -> dict:
    """``{"obligations_checked": [...]}`` for the success-path audit row, or ``{}``.

    Empty when nothing is active, so a deployment without obligations writes
    exactly the rows it always did.
    """
    try:
        ids = obligations_checked(action, keys=keys)
        return {"obligations_checked": ids} if ids else {}
    except Exception:
        log.exception("regulatory obligation evidence is unavailable")
        return {"obligation_evidence_error": _EVIDENCE_ERROR}


def attenuate(cap):
    """Narrow ``cap`` by the active ATTENUATE obligations. Never widens.

    Routes through ``Capability.attenuate``, so the result is contained in the
    input by construction and every child derived from it inherits the loss.
    """
    deny = _active().deny_tools
    if not deny:
        return cap
    return cap.attenuate(deny=deny)


# ---- anti-vacuity ------------------------------------------------------------

def _classified(name: str) -> bool:
    try:
        from .safety.tool_risk import tool_risk_is_classified
        return bool(tool_risk_is_classified(name))
    except Exception:
        return False


def _all_classified_tools() -> list[str]:
    try:
        from .safety.tool_risk import _DEFAULT_RISK
        return sorted(_DEFAULT_RISK)
    except Exception:
        return []


def classified_tools() -> list[str]:
    """Every tool the risk classifier knows, sorted: the compiler's universe.

    The console offers these as the completions for "check an action", so an
    operator asks about tools that exist rather than guessing names.
    """
    return _all_classified_tools()


def action_risk(action: str) -> str | None:
    """The classifier's risk tier for ``action``, or ``None`` when the name is
    not a classified tool (the classifier's fallback tier for an unknown name
    is not a classification, and a risk floor never reaches such a name)."""
    return _tool_risk(action) if _classified(action) else None


def _at_least(decision: str, effect: str) -> bool:
    """Whether a verdict is at least as strict as the obligation demands."""
    if effect == EFFECT_DENY:
        return decision == "deny"
    return decision in ("deny", "require_human")


def _verify_gate(ob: Obligation, policy: Policy) -> list[str]:
    """Prove a DENY / REQUIRE_HUMAN obligation bites under the compiled policy."""
    from .governance import evaluate
    problems: list[str] = []
    for action in sorted(ob.actions):
        if not _classified(action):
            problems.append(f"{ob.id}: binds unknown tool {action!r} (not a classified tool)")
            continue
        verdict = evaluate(action, policy=policy)
        if not _at_least(verdict.decision.value, ob.effect):
            problems.append(
                f"{ob.id}: compiled policy does not {ob.effect} {action!r} "
                f"(got {verdict.decision.value}: dead overlay)")
        elif not audit_tags_under(action, verdict.rule, (ob,)):
            problems.append(f"{ob.id}: verdict rule {verdict.rule!r} does not trace back "
                            "to the obligation (tagging would be vacuous)")
    if ob.min_risk:
        tier = [t for t in _all_classified_tools()
                if ob.covers(t, _tool_risk(t)) and t not in ob.actions]
        caught = [t for t in tier if _at_least(evaluate(t, policy=policy).decision.value,
                                               ob.effect)]
        if not tier:
            problems.append(f"{ob.id}: no classified tool sits at or above risk "
                            f"{ob.min_risk!r}, so the floor catches nothing")
        elif not caught:
            problems.append(f"{ob.id}: risk floor {ob.min_risk!r} catches none of "
                            f"{len(tier)} tool(s) at that tier (dead overlay)")
    return problems


def audit_tags_under(action: str, rule: str, obligations) -> dict:
    """``audit_tags`` against an explicit obligation set (used by verify)."""
    return _audit_tags_under(action, rule, obligations)


def _verify_attenuation(ob: Obligation, deny_tools: frozenset[str]) -> list[str]:
    """Prove an ATTENUATE obligation narrows a capability that could use its tools."""
    from .capability import Capability
    problems: list[str] = []
    unknown = sorted(t for t in ob.deny_tools if not _classified(t))
    problems.extend(f"{ob.id}: binds unknown tool {t!r} (not a classified tool)"
                    for t in unknown)
    probe = Capability(principal="ci:probe").attenuate(deny=deny_tools)
    still = sorted(t for t in ob.deny_tools if t not in unknown and probe.permits(t))
    if still:
        problems.append(f"{ob.id}: attenuation still permits {still} (dead attenuation)")
    return problems


def verify(keys) -> list[str]:
    """Every problem that would make an active obligation vacuous. Empty = sound."""
    compiled = compile_obligations(keys)
    problems: list[str] = []
    for ob in compiled.obligations:
        if ob.effect not in _EFFECTS:
            problems.append(f"{ob.id}: unknown effect {ob.effect!r}")
        elif ob.effect == EFFECT_ATTENUATE:
            problems.extend(_verify_attenuation(ob, compiled.deny_tools))
        elif not ob.actions and not ob.min_risk:
            problems.append(f"{ob.id}: has no scope (no actions, no risk floor)")
        else:
            problems.extend(_verify_gate(ob, compiled.policy))
    return problems


def describe(keys) -> dict:
    """A plain description of what ``keys`` compile to, for the CLI and JSON."""
    compiled = compile_obligations(keys)
    pol = compiled.policy
    return {
        "profiles": _known_keys(keys),
        "obligations": [
            {"id": o.id, "regulation": o.regulation, "article": o.article,
             "title": o.title, "effect": o.effect, "actions": sorted(o.actions),
             "min_risk": o.min_risk, "deny_tools": sorted(o.deny_tools),
             "source_url": o.source_url}
            for o in compiled.obligations
        ],
        "policy": {
            "deny_actions": sorted(pol.deny_actions),
            "deny_min_risk": pol.deny_min_risk,
            "require_human_actions": sorted(pol.require_human_actions),
            "require_human_min_risk": pol.require_human_min_risk,
        },
        "attenuation": {"deny_tools": sorted(compiled.deny_tools)},
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="regulatory_compiler",
        description="Compile regulatory obligations into governance gates and "
                    "prove they are not vacuous.")
    ap.add_argument("--ci", action="store_true",
                    help="exit 1 on any problem, exit 2 if nothing was inspected")
    selection = ap.add_mutually_exclusive_group()
    selection.add_argument("--profiles", default=None, metavar="K1,K2",
                           help="regulations to check (default: those active in config)")
    selection.add_argument("--all", action="store_true", dest="all_shipped",
                           help="check every profile shipped by this runtime")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    try:
        keys = (list(shipped_profile_keys()) if args.all_shipped else
                [p for p in args.profiles.split(",") if p.strip()]
                if args.profiles is not None else active_keys())
    except Exception as exc:
        print(f"regulatory compiler: invalid compliance activation: {exc}")
        return 2
    keys = _known_keys(keys)
    problems = verify(keys) if keys else []
    report = {**describe(keys), "problems": problems,
              "inspected": sum(len(REGULATIONS[k]) for k in keys)}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        if not keys:
            print("regulatory compiler: no regulation active "
                  "(set [compliance] profiles or pass --profiles/--all)")
        for ob in report["obligations"]:
            scope = ", ".join(ob["actions"] or ob["deny_tools"]) or f">= {ob['min_risk']} risk"
            print(f"  [{ob['effect']:13}] {ob['id']:36} {ob['regulation']} {ob['article']}: {scope}")
        for p in problems:
            print(f"  ! {p}")
        if keys and not problems:
            print(f"regulatory compiler: {report['inspected']} obligation(s) compile to "
                  "live, non-vacuous gates")
    # A verification command that inspected nothing is never successful. The
    # --ci switch remains accepted for compatibility, but vacuity is an error in
    # interactive use too: show/describe are the non-gating discovery surfaces.
    if not keys:
        return 2
    return 1 if problems else 0


__all__ = [
    "EFFECT_ATTENUATE", "EFFECT_DENY", "EFFECT_REQUIRE_HUMAN", "REGULATIONS",
    "SHIPPED_PROFILE_KEYS",
    "CompiledObligations", "Obligation", "action_risk", "active_keys", "attenuate",
    "audit_tags", "checked_tags", "classified_tools", "compile_obligations",
    "describe", "main", "obligations_checked", "shipped_profile_keys", "verify",
]


if __name__ == "__main__":  # pragma: no cover -- CI gate entry point
    raise SystemExit(main())
