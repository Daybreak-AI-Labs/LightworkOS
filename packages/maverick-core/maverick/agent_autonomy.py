"""Per-agent autonomy levels -- the "how much rope does this hire get" dial.

Every specialist pack is a *hire* (see :mod:`maverick.departments`: "one
specialist pack is a single hire"). A human employee is not given the same
authority on day one as after a year of a clean record, and not the same
authority for a $50 expense as for a $50k wire. This module gives each agent
that same graduated, per-action authority -- the missing per-agent binding on
top of primitives the platform already has:

  * :mod:`maverick.governance` -- the ALLOW / DENY / REQUIRE_HUMAN decision point
    (the EU AI Act Art. 14 human-oversight gate);
  * :mod:`maverick.approval_delegation` -- route an approval to *one* delegate
    (so not everyone is in the loop -- one person signs off);
  * :mod:`maverick.predictive_approvals` -- "you approved this 20/20 times --
    make it auto?" (the trust signal that justifies graduating an agent);
  * :mod:`maverick.review_checkpoint` + consent modes -- the human heartbeat.

Four rungs, lowest to highest authority:

  ``OBSERVE``  -- read-only; never takes a consequential action.
  ``SUGGEST``  -- prepares and *stages* the action; a human executes it. This is
                  the platform's historical default (draft, a human commits).
  ``REQUEST``  -- executes the action itself, but only after a human approves
                  *this* action; once approved it proceeds (and a clean record
                  can graduate the action class to ``AUTO`` via predictive
                  approvals).
  ``AUTO``     -- executes autonomously, within capability, budget, and the
                  pack's hard refusals.

A profile sets a ``default`` rung plus optional per-risk overrides (an agent can
be ``auto`` for low-risk actions and ``human`` for high-risk ones -- the
delegation-of-authority tier). An agent in its **onboarding** phase is clamped
one rung down (the "training phase": supervised until it earns trust); the
client graduates it by setting ``onboarding = false`` once the record is clean.

Two hard floors this dial can never cross:

  * **Refusals** (:mod:`maverick.domain_refusals`) are absolute -- a refused
    action is never available at any rung, with or without approval.
  * **Ungovernable raw tools** (shell, apply_patch, ...) bypass the governed
    action layer, so they stay denied even at ``AUTO`` -- a high-autonomy agent
    acts through *governed* connectors/Actions, not raw effectors.

Off by default (kernel rule 1): when ``[workforce] levels`` is not enabled the
resolver returns ``SUGGEST`` for every consequential action -- byte-for-byte the
historical "draft, a human commits" behavior. Pure and fail-open: any error
degrades to ``SUGGEST`` (more cautious), never to ``AUTO``.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, replace
from enum import Enum

from .safety.tool_risk import RISK_LEVELS, tool_risk

log = logging.getLogger(__name__)


# The control-plane tools that let a specialist participate in the workforce
# (discover peers, spawn specialists, fan out a swarm, message/delegate across
# the agent bus). Canonically defined in :mod:`maverick.capability` (it is the
# capability FLOOR there); re-exported here because the autonomy dial also EXEMPTS
# them -- coordinating is not a consequential external action, so it is never held
# for human approval; the spawned children, budget, and depth limits govern it.
from .capability import COORDINATION_TOOLS  # noqa: E402


class AutonomyLevel(str, Enum):
    """The four authority rungs, ordered OBSERVE < SUGGEST < REQUEST < AUTO."""

    OBSERVE = "observe"
    SUGGEST = "suggest"
    REQUEST = "request"
    AUTO = "auto"

    @property
    def rank(self) -> int:
        return _ORDER.index(self)


_ORDER: tuple[AutonomyLevel, ...] = (
    AutonomyLevel.OBSERVE,
    AutonomyLevel.SUGGEST,
    AutonomyLevel.REQUEST,
    AutonomyLevel.AUTO,
)

# Words a pack/operator may use for a rung. "human"/"hitl"/"review" are friendly
# aliases for SUGGEST (a human executes); "approve"/"ask" for REQUEST.
_ALIASES: dict[str, AutonomyLevel] = {
    "observe": AutonomyLevel.OBSERVE,
    "read_only": AutonomyLevel.OBSERVE,
    "readonly": AutonomyLevel.OBSERVE,
    "suggest": AutonomyLevel.SUGGEST,
    "human": AutonomyLevel.SUGGEST,
    "hitl": AutonomyLevel.SUGGEST,
    "human_in_loop": AutonomyLevel.SUGGEST,
    "review": AutonomyLevel.SUGGEST,
    "draft": AutonomyLevel.SUGGEST,
    "request": AutonomyLevel.REQUEST,
    "approve": AutonomyLevel.REQUEST,
    "approval": AutonomyLevel.REQUEST,
    "ask": AutonomyLevel.REQUEST,
    "auto": AutonomyLevel.AUTO,
    "autonomous": AutonomyLevel.AUTO,
    "full": AutonomyLevel.AUTO,
}


def parse_level(value: object, default: AutonomyLevel | None = None) -> AutonomyLevel | None:
    """Coerce a config/TOML value to an :class:`AutonomyLevel`.

    Unknown / empty values return ``default`` (``None`` unless given) so a typo
    falls through to the profile default rather than silently broadening
    authority.
    """
    if isinstance(value, AutonomyLevel):
        return value
    if isinstance(value, str):
        got = _ALIASES.get(value.strip().lower())
        if got is not None:
            return got
    return default


def _onboarding_value(value: object, *, default: bool) -> bool:
    """Strict supervision flag: malformed input can only restore the clamp."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return True


@dataclass(frozen=True)
class AutonomyProfile:
    """A hire's authority dial: a baseline rung + per-risk overrides + phase.

    ``default`` applies to any action whose risk tier has no explicit override.
    ``low`` / ``medium`` / ``high`` override per the action's classified risk
    (:func:`maverick.safety.tool_risk.tool_risk`). ``onboarding`` True clamps the
    resolved rung one step down until the client graduates the hire.
    """

    default: AutonomyLevel = AutonomyLevel.SUGGEST
    low: AutonomyLevel | None = None
    medium: AutonomyLevel | None = None
    high: AutonomyLevel | None = None
    onboarding: bool = True

    def level_for(self, risk: str) -> AutonomyLevel:
        """The configured rung for an action of ``risk`` tier (before clamp)."""
        override = {"low": self.low, "medium": self.medium, "high": self.high}.get(risk)
        return override or self.default

    def with_overrides(
        self,
        *,
        default: object = None,
        low: object = None,
        medium: object = None,
        high: object = None,
        onboarding: object = None,
    ) -> AutonomyProfile:
        """A copy with client overrides applied (each unset arg leaves the pack
        value). Used to layer ``[workforce.agents]`` config over a pack default."""
        return replace(
            self,
            default=parse_level(default, self.default),
            low=parse_level(low, self.low),
            medium=parse_level(medium, self.medium),
            high=parse_level(high, self.high),
            onboarding=_onboarding_value(onboarding, default=self.onboarding),
        )

    @classmethod
    def from_toml(cls, raw: object) -> AutonomyProfile:
        """Parse a pack's ``[autonomy]`` table. Forgiving: a missing/non-table
        block yields the default (``SUGGEST``, onboarding) profile, never raises."""
        if not isinstance(raw, dict):
            return cls()
        onboarding = raw.get("onboarding")
        return cls(
            default=parse_level(raw.get("default"), AutonomyLevel.SUGGEST) or AutonomyLevel.SUGGEST,
            low=parse_level(raw.get("low")),
            medium=parse_level(raw.get("medium")),
            high=parse_level(raw.get("high")),
            onboarding=_onboarding_value(onboarding, default=True),
        )


def clamp_down(level: AutonomyLevel, steps: int = 1) -> AutonomyLevel:
    """Lower ``level`` by ``steps`` rungs (never below OBSERVE)."""
    return _ORDER[max(0, level.rank - max(0, steps))]


# Governance decisions this module speaks in (kept as strings so the pure
# resolver does not import the governance module; callers compare to
# governance.Decision values, which are these same strings).
_DECISION_ALLOW = "allow"
_DECISION_DENY = "deny"
_DECISION_REQUIRE_HUMAN = "require_human"


@dataclass(frozen=True)
class AutonomyVerdict:
    """How a hire may take one action, given its profile and the action's risk.

    ``level`` is the effective rung after per-risk selection and onboarding
    clamp. ``decision`` is the governance decision this rung implies
    (``allow`` / ``require_human`` / ``deny``), composable strictest-wins with
    :func:`maverick.governance.evaluate`. ``execute_by`` distinguishes the two
    REQUIRE_HUMAN rungs: ``human`` (SUGGEST -- a person executes the staged
    action) vs ``agent`` (REQUEST -- the agent executes after approval).
    """

    level: AutonomyLevel
    decision: str
    execute_by: str  # "agent" | "human" | "none"
    reason: str
    onboarding_clamped: bool = False

    @property
    def autonomous(self) -> bool:
        return self.decision == _DECISION_ALLOW

    @property
    def needs_human(self) -> bool:
        return self.decision == _DECISION_REQUIRE_HUMAN


def _decision_for(level: AutonomyLevel) -> tuple[str, str]:
    """(governance decision, execute_by) for an effective rung."""
    if level is AutonomyLevel.AUTO:
        return _DECISION_ALLOW, "agent"
    if level is AutonomyLevel.REQUEST:
        return _DECISION_REQUIRE_HUMAN, "agent"
    if level is AutonomyLevel.SUGGEST:
        return _DECISION_REQUIRE_HUMAN, "human"
    return _DECISION_DENY, "none"  # OBSERVE: no consequential action


def resolve(
    profile: AutonomyProfile | None,
    *,
    action: str = "",
    risk: str | None = None,
    levels_enabled: bool = False,
) -> AutonomyVerdict:
    """The authority verdict for ``action`` under ``profile``.

    ``risk`` may be given directly (a known tier) or classified from ``action``
    via :func:`tool_risk`. When ``levels_enabled`` is False (the default, kernel
    rule 1) every consequential action resolves to ``SUGGEST`` -- the historical
    "draft, a human commits" behavior -- regardless of the profile, so enabling
    the feature is what unlocks higher autonomy, never a silent default.

    Fail-open: any internal error degrades to ``SUGGEST`` (more cautious).
    """
    try:
        tier = risk if risk in RISK_LEVELS else None
        if tier is None:
            tier = tool_risk(action) if action else "medium"
        if not levels_enabled or profile is None:
            decision, execute_by = _decision_for(AutonomyLevel.SUGGEST)
            return AutonomyVerdict(
                AutonomyLevel.SUGGEST, decision, execute_by,
                "autonomy levels disabled -- staging for human execution",
            )
        configured = profile.level_for(tier)
        effective = clamp_down(configured, 1) if profile.onboarding else configured
        clamped = profile.onboarding and effective is not configured
        decision, execute_by = _decision_for(effective)
        why = f"{effective.value} for {tier}-risk action"
        if clamped:
            why += f" (onboarding: clamped from {configured.value})"
        return AutonomyVerdict(effective, decision, execute_by, why, onboarding_clamped=clamped)
    except Exception:  # pragma: no cover -- resolver must never block a run
        log.warning("agent_autonomy: resolve failed; defaulting to SUGGEST", exc_info=True)
        decision, execute_by = _decision_for(AutonomyLevel.SUGGEST)
        return AutonomyVerdict(AutonomyLevel.SUGGEST, decision, execute_by, "resolver error -- staged")


# -- suite-level defaults (the hire's starting authority by department) -----
#
# Like SUITE_DISCIPLINE / SUITE_REFUSALS, the baseline posture is keyed by suite
# in code rather than copied into every pack TOML -- a pack may still override
# with its own [autonomy] block, and the client overrides per agent via
# [workforce.agents]. Two tiers:
#
#   STRICT   -- high-stakes / regulated work: every consequential action is
#               staged for a human (default SUGGEST). Finance, legal, clinical,
#               safety-critical, fund, and irreversible-filing suites.
#   STANDARD -- operational / routine work: low-risk actions run autonomously,
#               routine ones act after a one-time approval (REQUEST), high-risk
#               stays human. Sales, CX, marketing, ops, logistics, etc.
#
# Both start in onboarding (one rung lower until graduated). Unknown / legacy
# packs fall to STRICT -- the safe default.

_STRICT = AutonomyProfile(default=AutonomyLevel.SUGGEST, onboarding=True)
_STANDARD = AutonomyProfile(
    default=AutonomyLevel.REQUEST, low=AutonomyLevel.AUTO,
    high=AutonomyLevel.SUGGEST, onboarding=True,
)

# Suites whose work is high-stakes / regulated / irreversible -> STRICT.
_STRICT_SUITES: frozenset[str] = frozenset({
    "finance", "tax", "banking", "capital_markets", "insurance", "legal",
    "healthcare", "pharma_lifesciences", "medical_devices", "security_ops",
    "it_grc", "public_sector", "government_contracting", "crypto_digital_assets",
    "private_equity_vc", "aerospace_defense", "oil_gas", "chemicals",
    "utilities", "water_utilities", "renewables_cleantech", "semiconductors",
    "maritime", "mining_metals", "nuclear_power", "executive_office",
    "esg_sustainability", "enterprise_risk", "trust_safety",
    # Commerce moves money and changes a live store: every cart handoff and
    # store change is staged for a person.
    "commerce",
})


def default_profile_for(name: str) -> AutonomyProfile:
    """The suite-level baseline authority for a pack with no explicit
    ``[autonomy]`` block. Falls to STRICT for high-stakes suites and for
    unknown / legacy packs; STANDARD for operational suites."""
    try:
        from .domain import suite_for
        suite = suite_for(name)
    except Exception:  # pragma: no cover -- never block resolution
        suite = None
    if suite is None or suite in _STRICT_SUITES:
        return _STRICT
    return _STANDARD


# -- config binding (impure; fail-open) ------------------------------------

def levels_enabled(override: bool | None = None) -> bool:
    """Whether the client has turned on per-agent autonomy levels.

    Off by default (kernel rule 1); ``MAVERICK_WORKFORCE_LEVELS`` overrides the
    ``[workforce] levels`` config either way. ``override`` (a what-if analysis)
    takes the environment override's place for this one call, with the same
    fail-closed rules, and changes nothing global. Never raises."""
    import os
    if override is None:
        env = os.environ.get("MAVERICK_WORKFORCE_LEVELS", "").strip().lower()
    else:
        env = "1" if override else "0"
    if env in {"0", "false", "no", "off"}:
        return False
    try:
        from .config import config_source_errors, get_workforce

        settings = get_workforce()
        if config_source_errors():
            return False
        if env in {"1", "true", "yes", "on"}:
            return True
        if env:
            # A present malformed override cannot fall through to a permissive
            # config value and accidentally turn the authority dial on.
            return False
        return settings.get("levels") is True
    except Exception:  # pragma: no cover -- config must never block a run
        return False


def effective_profile(
    name: str,
    pack_profile: AutonomyProfile | None,
    *,
    graduated: bool | None = None,
) -> AutonomyProfile:
    """The effective authority for ``name``: the pack's explicit ``[autonomy]``
    block if it set one, else the suite-level default
    (:func:`default_profile_for`), with the client's ``[workforce.agents]``
    override layered on top.

    ``graduated=True`` lifts the onboarding clamp (the agent has earned trust).
    The caller supplies the signal (from :func:`graduation_status`) so this stays
    pure and cheap -- no approvals-history read on the hot path. Stays pure with
    ``graduated=None`` (the default)."""
    base = pack_profile or default_profile_for(name)
    try:
        from .config import get_workforce
        override = get_workforce().get("agents", {}).get(name)
    except Exception:  # pragma: no cover
        override = None
    if override:
        base = base.with_overrides(**override)
    if graduated and base.onboarding:
        base = replace(base, onboarding=False)
    return base


def decide(
    name: str,
    pack_profile: AutonomyProfile | None,
    *,
    action: str = "",
    risk: str | None = None,
) -> AutonomyVerdict:
    """One-call resolution against live config: layer the client override on the
    pack profile and resolve the verdict for ``action``. This is the seam a
    runtime gate calls; pure :func:`resolve` stays test-friendly."""
    return resolve(
        effective_profile(name, pack_profile),
        action=action,
        risk=risk,
        levels_enabled=levels_enabled(),
    )


# -- graduation (onboarding -> trusted) ------------------------------------
#
# A hire starts supervised (onboarding, clamped one rung down). It graduates the
# way a person does: a clean record. This reads the same approvals history
# predictive_approvals learns from -- the human decisions on THIS agent's gated
# actions -- and reports whether the agent has earned graduation. Advisory by
# default (the client lifts onboarding in [workforce.agents], matching the
# suggestion-only contract of predictive_approvals). The parsed
# ``[workforce] auto_graduate`` intent remains advisory until graduation is
# backed by tenant/owner-scoped durable evidence plus explicit approval and
# revocation semantics; the runtime does not lift authority from it today.

# Earn graduation only after this many decided actions, at/above this approval
# share -- mirrors predictive_approvals' _MIN_SAMPLE / _DOMINANCE philosophy but
# tuned a touch stricter (graduating an employee is a bigger step than auto-ing
# one action class).
_GRAD_MIN_SAMPLE = 8
_GRAD_DOMINANCE = 0.9


@dataclass(frozen=True)
class GraduationVerdict:
    """Whether an agent has earned graduation from its supervised phase."""

    name: str
    graduated: bool
    sample: int
    approve_rate: float
    confidence: float
    reason: str


def _agent_of(record: dict) -> str:
    """The agent a history record belongs to (``requested_by`` principal).
    Principals look like ``agent:<name>-<depth>``."""
    return str(record.get("requested_by") or record.get("agent") or record.get("role") or "")


# ``agent:<name>-<depth>`` -> ``<name>`` (depth suffix optional). A bare principal
# with no ``agent:`` prefix is returned unchanged so an exact raw name still
# matches. Used to match graduation history by EXACT agent identity -- the prior
# ``name in principal`` substring test graduated e.g. ``analyst`` on
# ``agent:data_analyst-0``'s record (one agent escalating on another's history).
_PRINCIPAL_NAME_RE = re.compile(r"^agent:(?P<name>.+?)(?:-\d+)?$")


def _principal_name(principal: str) -> str:
    m = _PRINCIPAL_NAME_RE.match(principal)
    return m.group("name") if m else principal


def graduation_status(
    name: str,
    history,
    *,
    min_sample: int = _GRAD_MIN_SAMPLE,
    dominance: float = _GRAD_DOMINANCE,
) -> GraduationVerdict:
    """Has agent ``name`` earned graduation, per its approvals ``history``?

    Pure: ``history`` is a list of approval records (or an object exposing
    ``.list_approvals()`` / ``.records()``), filtered here to this agent and
    aggregated into an approve/deny record. Graduates when there are at least
    ``min_sample`` decided actions and the approval share is at/above
    ``dominance``. Never raises.
    """
    return _graduation_verdict(name, _coerce_approvals(history),
                               min_sample=min_sample, dominance=dominance)


def _graduation_verdict(
    name: str,
    rows: list[dict],
    *,
    min_sample: int = _GRAD_MIN_SAMPLE,
    dominance: float = _GRAD_DOMINANCE,
) -> GraduationVerdict:
    """:func:`graduation_status` over records already passed through
    :func:`_coerce_approvals`."""
    from . import predictive_approvals as _pa
    approvals = denials = 0
    for rec in rows:
        if not isinstance(rec, dict) or _principal_name(_agent_of(rec)) != name:
            continue
        d = _pa._decided(rec)
        if d is True:
            approvals += 1
        elif d is False:
            denials += 1
    sample = approvals + denials
    rate = round(approvals / sample, 4) if sample else 0.0
    conf = _pa._confidence(approvals, denials)
    if sample < min_sample:
        return GraduationVerdict(
            name, False, sample, rate, conf,
            f"only {sample} decided action(s) (need {min_sample}) — stay supervised.")
    if rate >= dominance:
        return GraduationVerdict(
            name, True, sample, rate, conf,
            f"clean record: {approvals}/{sample} approved ({rate:.0%}) — ready to graduate.")
    return GraduationVerdict(
        name, False, sample, rate, conf,
        f"record not clean enough: {approvals}/{sample} approved ({rate:.0%}).")


def _coerce_approvals(history) -> list[dict]:
    """Approvals history as a list of dict records (duck-typed source)."""
    if history is None:
        return []
    rows = history
    if not isinstance(history, list):
        for attr in ("list_approvals", "records", "approvals", "history"):
            fn = getattr(history, attr, None)
            if callable(fn):
                try:
                    rows = list(fn() or [])
                except Exception:  # pragma: no cover
                    return []
                break
        else:
            return []
    out: list[dict] = []
    for r in rows:
        if isinstance(r, dict):
            out.append(r)
        elif hasattr(r, "__dict__"):
            out.append(vars(r))
    # Oversight canaries measure people, not agents: never learn from them.
    try:
        from .immune.oversight import canary_ids
        canaries = canary_ids()
    except Exception:
        # Fail closed: unknown canaries could inflate an agent's record and
        # graduate it; no evidence means no graduation.
        return []
    return [r for r in out if r.get("id") not in canaries]


def auto_graduate_enabled() -> bool:
    """The client's strictly parsed auto-graduation intent (advisory only).

    Default off. Runtime authority is not raised from this flag until a scoped,
    durable approval/revocation design is wired; clients still graduate agents
    explicitly today.
    """
    try:
        from .config import config_source_errors, get_workforce

        settings = get_workforce()
        if config_source_errors():
            return False
        return settings.get("auto_graduate") is True
    except Exception:  # pragma: no cover
        return False


def graduation_candidates(history, names: list[str]) -> list[GraduationVerdict]:
    """The agents in ``names`` that have earned graduation, most-confident
    first -- the advisory list a CLI / dashboard surfaces to the client."""
    rows = _coerce_approvals(history)
    # One pass over the history: each verdict reads only its own agent's
    # records, instead of every agent re-reading all of them and the canary
    # ledger (about 1 s for 2,031 agents by 500 decisions).
    by_agent: dict[str, list[dict]] = {}
    for rec in rows:
        by_agent.setdefault(_principal_name(_agent_of(rec)), []).append(rec)
    out = [_graduation_verdict(n, by_agent.get(n, [])) for n in names]
    return sorted(
        (v for v in out if v.graduated),
        key=lambda v: (-v.confidence, v.name),
    )


# -- prompt rendering ------------------------------------------------------

_RUNG_PROSE: dict[AutonomyLevel, str] = {
    AutonomyLevel.OBSERVE: "observe only -- you do not take this action; you report",
    AutonomyLevel.SUGGEST: "prepare and stage it for a human to execute",
    AutonomyLevel.REQUEST: "execute it yourself, but only after a human approves this action",
    AutonomyLevel.AUTO: "execute it autonomously, within your budget and refusals",
}


def render_autonomy_prompt(name: str, pack_profile: AutonomyProfile | None) -> str:
    """The autonomy-posture block for a hire's system prompt.

    Returns ``""`` when the feature is off (kernel rule 1) so the default spawn
    path is byte-for-byte unchanged. When on, it tells the agent -- per action
    risk tier -- whether to act, stage, request approval, or only observe, and
    whether it is still in its supervised onboarding phase.
    """
    if not levels_enabled():
        return ""
    try:
        prof = effective_profile(name, pack_profile)
    except Exception:  # pragma: no cover
        return ""
    lines = [
        "",
        "",
        "Your authority (autonomy level) for this role -- act within it and never "
        "exceed it; a refused action is never available at any level:",
    ]
    for tier in RISK_LEVELS:
        configured = prof.level_for(tier)
        effective = clamp_down(configured) if prof.onboarding else configured
        lines.append(f"- {tier}-risk actions: {_RUNG_PROSE[effective]}")
    if prof.onboarding:
        lines.append(
            "- You are ONBOARDING (supervised/training): your authority is held one "
            "rung lower until you are graduated on a clean record. When in doubt, "
            "ask."
        )
    return "\n".join(lines)


__all__ = [
    "AutonomyLevel",
    "AutonomyProfile",
    "AutonomyVerdict",
    "parse_level",
    "clamp_down",
    "resolve",
    "levels_enabled",
    "effective_profile",
    "default_profile_for",
    "decide",
    "render_autonomy_prompt",
    "GraduationVerdict",
    "graduation_status",
    "graduation_candidates",
    "auto_graduate_enabled",
    "COORDINATION_TOOLS",
]
