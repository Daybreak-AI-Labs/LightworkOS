"""Hire from a job description: map a JD onto the specialist roster, or draft
a new clamped specialist pack from it.

HR uploads a job description. :func:`match_jd` ranks the full roster (shipped
packs plus tenant custom packs) against the JD via the hybrid domain router --
deterministic, offline, no LLM required. :func:`draft_from_jd` turns the JD
into a generated :class:`~maverick.domain.DomainProfile` through the same
intake pipeline ``maverick onboard`` uses, so a JD-authored agent arrives
clamped (``validate_profile``: shell/write/exec denied, risk capped at medium)
and only becomes real through the existing human-approved save paths
(``intake.save_profile`` / the dashboard pack editor). :func:`add_pack_to_fleet`
puts a hired specialist on a team roster so fleets and department deploys can
dispatch it like any shipped pack.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from .domain import available_domains, suite_for
from .domain_router import rank_specialists
from .intake import IntakeSpec, build_llm_proposer, generate_profile

log = logging.getLogger(__name__)

# JD text flows into ranking and (bounded) into a generated pack draft; cap it
# like the dashboard caps goal descriptions so an unbounded upload can't bloat
# prompts or the saved pack.
MAX_JD_CHARS = 16_000

_WORD = re.compile(r"[a-z0-9]{3,}")
_STOPWORDS = frozenset({
    "the", "and", "for", "with", "you", "will", "are", "our", "this", "that",
    "have", "has", "your", "their", "them", "who", "what", "job",
    "role", "work", "team", "years", "experience", "ability", "strong",
    "skills", "including", "required", "preferred", "etc", "all", "any",
    "per", "into", "from", "across", "within", "such", "other", "more",
    "specialist", "assistant", "process", "prepare", "support", "maintain",
    "match", "matching", "manage", "help", "provide", "responsible",
})


def _tokens(text: str) -> set[str]:
    return {w for w in _WORD.findall((text or "").lower()) if w not in _STOPWORDS}


@dataclass(frozen=True)
class JDMatch:
    """One roster hit for a job description."""

    name: str
    fit: float                      # 0..1, relative to the best hit
    description: str
    suite: str | None               # department key (None = generic pack)
    department: str | None          # human department label
    max_risk: str | None
    matched_terms: list[str] = field(default_factory=list)
    relevance: str = "weak"          # absolute evidence band, not model confidence

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "suite": self.suite,
            "department": self.department,
            "max_risk": self.max_risk,
            "matched_terms": list(self.matched_terms),
            "relevance": self.relevance,
        }


def match_jd(jd_text: str, k: int = 5, domains=None) -> list[JDMatch]:
    """Rank the specialist roster against a job description.

    Pure and offline: hybrid lexical(+embedding when installed) scoring via
    :func:`maverick.domain_router.rank_specialists` over ``available_domains()``
    -- which already overlays tenant custom packs -- so "do we already employ
    this role?" is answered against the whole workforce. The internal ``fit``
    score is relative to the top hit and is deliberately not sent to the UI;
    the visible relevance band counts distinctive shared terms instead.
    """
    jd_text = (jd_text or "").strip()[:MAX_JD_CHARS]
    if not jd_text:
        return []
    if domains is None:
        domains = available_domains()
    ranked = rank_specialists(jd_text, k=max(1, int(k)), domains=domains)
    if not ranked:
        return []
    from .departments import SUITE_LABELS

    top = ranked[0][1] or 1.0
    jd_toks = _tokens(jd_text)
    out: list[JDMatch] = []
    for name, score in ranked:
        prof = domains.get(name)
        if prof is None:  # roster changed under the cached index; skip stale
            continue
        pack_toks = _tokens(
            f"{name.replace('_', ' ')} {prof.description} {prof.persona}")
        shared = jd_toks & pack_toks
        matched = sorted(shared)[:8]
        relevance = "strong" if len(shared) >= 4 else "partial" if len(shared) >= 2 else "weak"
        suite = suite_for(name)
        label = SUITE_LABELS[suite][0] if suite in SUITE_LABELS else None
        out.append(JDMatch(
            name=name,
            fit=round(score / top, 3),
            description=prof.description,
            suite=suite,
            department=label,
            max_risk=prof.max_risk,
            matched_terms=matched,
            relevance=relevance,
        ))
    return out


# Bullet lines ("- own the monthly close", "3. reconcile ledgers") become the
# draft's playbook steps on the deterministic (keyless) path.
_BULLET = re.compile(r"^\s*(?:[-*•·]|\d{1,2}[.)])\s+(.{3,})$")
_MAX_DRAFT_STEPS = 5


def _jd_proposer(spec: IntakeSpec) -> dict:
    """Deterministic proposer: derive a draft pack from the JD's structure.

    No LLM: responsibilities (bullet lines) become playbook steps, while the
    role title becomes the short display name. Everything returned here is coerced and
    clamped by ``generate_profile``/``validate_profile`` exactly like an LLM
    proposal, so this path grants nothing an LLM path couldn't.
    """
    steps: list[dict] = []
    for line in spec.description.splitlines():
        m = _BULLET.match(line)
        if m and len(steps) < _MAX_DRAFT_STEPS:
            steps.append({"name": m.group(1).strip(), "gate": None})
    title_lines = (spec.name or "").strip().splitlines()
    title = title_lines[0][:120] if title_lines else "Specialist"
    proposed: dict = {
        "description": title,
        "persona": (
            "You carry out this specialist's configured work steps. Ground each result "
            "in the available source records, flag gaps, and hand consequential "
            "decisions to the accountable person for review."
        ),
    }
    if len(steps) >= 3:
        # The deliverable is a human handoff: the last step carries the review
        # gate, matching the intake default-workflow convention.
        steps[-1]["gate"] = "review"
        proposed["workflow"] = steps
    return proposed


def draft_from_jd(role_title: str, jd_text: str, *, industry: str = "",
                  llm=None, model: str | None = None, budget=None,
                  return_source: bool = False):
    """Draft (do NOT save) a specialist pack for a job description.

    With ``llm`` the intake proposer writes the persona/playbook; without it a
    deterministic draft is derived from the JD's structure. Either way the
    result is clamped by ``validate_profile`` (generated deny-floor, risk
    capped at medium) and carries ``authoring="generated"``. Persisting is the
    caller's explicit, human-approved act -- ``intake.save_profile`` or the
    dashboard pack editor's save.
    """
    # These user-controlled fields cross the provider boundary on the LLM path.
    # Reject credentials before constructing/calling the proposer; doing this
    # inside the proposer would be swallowed by generate_profile's deterministic
    # fallback and could falsely report that an LLM draft was generated.
    if llm is not None:
        try:
            from .safety.secret_detector import scan
        except Exception as exc:  # pragma: no cover - built-in module is required
            raise ValueError("provider input could not be safely screened") from exc

        for label, value in (
            ("role title", role_title),
            ("job description", jd_text),
            ("industry", industry),
        ):
            try:
                matches = scan(str(value or ""))
            except Exception as exc:
                raise ValueError("provider input could not be safely screened") from exc
            if matches:
                raise ValueError(f"{label} contains a credential and cannot be sent")

    spec = IntakeSpec(
        name=role_title,
        description=(jd_text or "").strip()[:MAX_JD_CHARS],
        industry=industry,
    )
    fallback = _jd_proposer(spec)
    source = "bullet_points" if "workflow" in fallback else "standard_outline"
    proposal = fallback
    if llm is not None:
        try:
            candidate = build_llm_proposer(llm, model=model, budget=budget)(spec)
            steps = candidate.get("workflow") if isinstance(candidate, dict) else None
            if (isinstance(candidate, dict)
                    and str(candidate.get("persona") or "").strip()
                    and isinstance(steps, list)
                    and len([step for step in steps if isinstance(step, dict)
                             and str(step.get("name") or "").strip()
                             and str(step.get("instruction") or "").strip()]) >= 3):
                # The editor's Name field is always the short role title, not
                # a model paraphrase or the entire uploaded description.
                proposal = {**candidate, "description": fallback["description"]}
                source = "ai"
            else:
                log.warning("jd_hiring: AI proposal was incomplete; using the job description outline")
        except Exception as exc:
            log.warning("jd_hiring: AI proposal failed (%s); using the job description outline", exc)
    profile = generate_profile(spec, propose=lambda _spec: proposal)
    return (profile, source) if return_source else profile


def add_pack_to_fleet(pack_name: str, fleet_name: str, owner: str, *,
                      role: str | None = None, tenant: str | None = "__active__"):
    """Add a specialist pack to a fleet roster (creating the fleet if needed).

    The FleetAgent carries ``domain=pack_name`` so dispatch binds the pack's
    capability envelope and the kernel's department-grant gate
    (:func:`maverick.fleet.ensure_dispatch_allowed`) applies. Idempotent: a
    pack already on the roster is not added twice.
    """
    from .fleet import Fleet, FleetAgent, load_fleet, save_fleet

    domains = available_domains()
    prof = domains.get(pack_name)
    if prof is None:
        raise ValueError(f"no such specialist pack: {pack_name!r}")

    fleet = load_fleet(fleet_name, tenant=tenant)
    if fleet is None:
        fleet = Fleet(name=fleet_name, owner=owner)
    if any(a.domain == pack_name for a in fleet.agents):
        return fleet
    agent = FleetAgent(
        name=pack_name,
        role=role or (suite_for(pack_name) or "specialist"),
        description=prof.description,
        domain=pack_name,
    )
    fleet = Fleet(name=fleet.name, owner=fleet.owner,
                  agents=(*fleet.agents, agent), created_at=fleet.created_at)
    save_fleet(fleet, tenant=tenant)
    return fleet


def jd_hiring_enabled() -> bool:
    """The ``[agent_factory] jd_hiring`` config knob (default on).

    Gates the dashboard's JD-hiring surface; the underlying primitives
    (router, intake, fleets) keep their own independent gates regardless.
    """
    try:
        from .config import config_source_errors, load_config

        config = load_config()
        if config_source_errors() or not isinstance(config, dict):
            return False
        section = config.get("agent_factory")
        if section is None:
            return True
        if not isinstance(section, dict):
            return False
        value = section.get("jd_hiring", True)
        return value if isinstance(value, bool) else False
    except Exception:  # unreadable/invalid security gate => disabled
        return False
