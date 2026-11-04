"""Capability provisioning -- the agent factory equips a pack at birth.

A generated :class:`~maverick.domain.DomainProfile` names the tools it needs
and carries a workflow, but a freshly drafted pack can reference a *skill*
that isn't installed or a *tool* that doesn't exist yet -- so the agent ships
with a capability hole that only surfaces mid-run when it gets stuck. This
module closes that gap as part of the factory, proactively, instead of
reactively in the loop:

  1. ANALYSE a profile for capability gaps (``analyze_profile``) -- pure,
     read-only, no LLM, no writes. Safe to run for any draft, and the natural
     thing to surface at the human-approval gate ("this pack will also pull in
     skill X and synthesize tool Y").
  2. APPLY the safe acquisitions (``apply_plan``) through the EXISTING governed
     paths: ``self_learning.acquire_skill`` for catalog skills (hash-pinned)
     and ``self_learning.write_generated_tool`` for synthesized tools
     (stdlib-only, import-validated out-of-host, consent-gated).

Posture (kernel rule 1): analysis is always safe. Application is OFF unless
``self_learning.enabled()`` AND the pack was human-approved (the same gate
``save_profile`` enforces); every per-item step fails soft so provisioning can
never block onboarding. Provisioning NEVER widens the pack's envelope -- it
only satisfies tools already inside the already-clamped ``allow_tools`` and
installs skills (which carry no tool grant of their own). The generator that
drafted the pack can't smuggle a high-impact tool in through provisioning: the
allow-list was clamped by ``intake.validate_profile`` first.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .domain import DomainProfile

log = logging.getLogger(__name__)

# Cap how much of a free-text phrase we feed the catalog search -- a whole
# workflow instruction is a fine *need*, but trimming keeps the lexical/embed
# ranking focused and the displayed plan readable.
_MAX_PHRASE_CHARS = 200
# A generated-tool module name must be a lowercase identifier (self_learning's
# _NAME_RE); we sanitize a declared tool name to that shape before synthesis.
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")


@dataclass
class CapabilityGap:
    """One missing capability a pack needs and how the factory would close it.

    ``kind`` is ``"skill"`` (the workflow wants know-how we can install) or
    ``"tool"`` (the pack declares a tool that isn't satisfiable yet).
    ``resolution`` is the proposed action: ``acquire_skill`` (install
    ``candidate`` from the catalog), ``generate_tool`` (synthesize it), or
    ``manual`` (needs an operator -- e.g. an MCP server or a credentialed
    integration provisioning won't auto-add).
    """

    kind: str
    need: str
    resolution: str
    candidate: str = ""
    summary: str = ""
    score: float = 0.0

    def describe(self) -> str:
        if self.resolution == "acquire_skill":
            extra = f" -> install skill {self.candidate!r}"
            if self.summary:
                extra += f" ({self.summary})"
        elif self.resolution == "generate_tool":
            extra = " -> synthesize tool"
        else:
            extra = " -> needs an operator (manual)"
        return f"[{self.kind}] {self.need}{extra}"


@dataclass
class ProvisioningPlan:
    """The set of gaps found for a profile, with convenience views."""

    profile_name: str
    gaps: list[CapabilityGap] = field(default_factory=list)

    @property
    def skill_gaps(self) -> list[CapabilityGap]:
        return [g for g in self.gaps if g.kind == "skill"]

    @property
    def tool_gaps(self) -> list[CapabilityGap]:
        return [g for g in self.gaps if g.kind == "tool"]

    def is_empty(self) -> bool:
        return not self.gaps

    def summary(self) -> str:
        if not self.gaps:
            return f"{self.profile_name}: no capability gaps -- pack is complete."
        lines = [f"{self.profile_name}: {len(self.gaps)} capability gap(s) to provision:"]
        lines += [f"  - {g.describe()}" for g in self.gaps]
        return "\n".join(lines)


@dataclass
class ProvisionResult:
    """Outcome of applying a plan."""

    acquired: list[str] = field(default_factory=list)        # skill names installed
    generated: list[str] = field(default_factory=list)       # tool names synthesized
    failed: list[tuple[str, str]] = field(default_factory=list)   # (name, reason)
    skipped: list[str] = field(default_factory=list)         # name + why

    def summary(self) -> str:
        parts = []
        if self.acquired:
            parts.append(f"installed skills: {', '.join(self.acquired)}")
        if self.generated:
            parts.append(f"synthesized tools: {', '.join(self.generated)}")
        if self.failed:
            parts.append(
                "failed: " + ", ".join(f"{n} ({why})" for n, why in self.failed)
            )
        if self.skipped:
            parts.append(f"skipped: {', '.join(self.skipped)}")
        return "; ".join(parts) or "nothing to provision"


# --------------------------------------------------------------------------
# analysis (pure, read-only)
# --------------------------------------------------------------------------
def _capability_phrases(profile: DomainProfile) -> list[str]:
    """Natural-language *needs* to search the skill catalog for.

    A workflow step's name + instruction reads as a capability phrase already
    ("Run quantitative impairment test: compute recoverable amount ..."), and
    the description seeds one more. De-duplicated, order-preserving, trimmed.
    """
    raw: list[str] = []
    desc = (getattr(profile, "description", "") or "").strip()
    if desc:
        raw.append(desc)
    for step in getattr(profile, "workflow", []) or []:
        name = (getattr(step, "name", "") or "").strip()
        instr = (getattr(step, "instruction", "") or "").strip()
        phrase = f"{name}: {instr}" if name and instr else (name or instr)
        if phrase:
            raw.append(phrase)
    seen: set[str] = set()
    out: list[str] = []
    for p in raw:
        p = p[:_MAX_PHRASE_CHARS].strip()
        key = p.lower()
        if p and key not in seen:
            seen.add(key)
            out.append(p)
    return out


def _installed_skill_names() -> set[str]:
    """Skills already on disk (user-installed + shipped). Best-effort."""
    try:
        from .skills import load_builtin_skills, load_skills
        return {s.name for s in load_skills()} | {s.name for s in load_builtin_skills()}
    except Exception:  # pragma: no cover -- skills layer never blocks analysis
        return set()


def _generated_tool_names() -> set[str]:
    """Names of consented tools in the durable store, without executing them."""
    try:
        from .self_learning import generated_tool_names
        return generated_tool_names()
    except Exception:  # pragma: no cover
        return set()


def analyze_profile(
    profile: DomainProfile, *, known_tools: set[str] | None = None,
    max_skill_gaps: int = 6, min_score: float = 0.2,
) -> ProvisioningPlan:
    """Find a pack's capability gaps. Pure: no LLM, no writes, never raises.

    Two kinds of gap:

    * **skill** -- for each capability phrase derived from the workflow, the
      best catalog skill that isn't already installed (one per phrase, capped
      at ``max_skill_gaps``, scored at or above ``min_score``).
    * **tool** -- only computed when ``known_tools`` (the live registry's tool
      names) is supplied: any tool the pack declares in ``allow_tools`` that is
      neither a known builtin nor an already-synthesized generated tool.
      Resolution is ``acquire_skill`` if a strong catalog skill provides it,
      else ``generate_tool``. Without ``known_tools`` we can't tell a missing
      tool from one of the ~200 builtins, so tool gaps are skipped rather than
      guessed (no false "missing").
    """
    from .self_learning import search_capabilities

    gaps: list[CapabilityGap] = []
    have_skills = _installed_skill_names()
    proposed: set[str] = set()

    for phrase in _capability_phrases(profile):
        if len([g for g in gaps if g.kind == "skill"]) >= max(1, max_skill_gaps):
            break
        try:
            cands = search_capabilities(phrase, kinds=("skills",), max_n=3)
        except Exception:  # pragma: no cover -- catalog never blocks analysis
            cands = []
        for c in cands:
            if c.score < min_score or c.name in have_skills or c.name in proposed:
                continue
            proposed.add(c.name)
            gaps.append(CapabilityGap(
                kind="skill", need=phrase, resolution="acquire_skill",
                candidate=c.name, summary=c.summary, score=float(c.score),
            ))
            break  # one skill per phrase keeps the plan proportionate

    if known_tools is not None:
        known = set(known_tools) | _generated_tool_names()
        seen_tools: set[str] = set()
        for tool in getattr(profile, "allow_tools", []) or []:
            if tool in known or tool in seen_tools:
                continue
            seen_tools.add(tool)  # a duplicated allow_tools entry is one gap, not N
            gaps.append(_classify_missing_tool(tool))

    return ProvisioningPlan(profile_name=getattr(profile, "name", "") or "", gaps=gaps)


def _classify_missing_tool(tool: str) -> CapabilityGap:
    """Decide how to close a declared-but-absent tool: install a catalog skill
    that provides it if one matches strongly, otherwise synthesize it."""
    from .self_learning import search_capabilities

    try:
        cands = search_capabilities(tool, kinds=("skills", "plugins", "mcp"), max_n=1)
    except Exception:  # pragma: no cover
        cands = []
    if cands and cands[0].kind == "skill" and cands[0].score >= 0.5:
        c = cands[0]
        return CapabilityGap(
            kind="tool", need=tool, resolution="acquire_skill",
            candidate=c.name, summary=c.summary, score=float(c.score),
        )
    return CapabilityGap(kind="tool", need=tool, resolution="generate_tool")


# --------------------------------------------------------------------------
# application (gated: self-learning on + human-approved)
# --------------------------------------------------------------------------
def _sanitize_tool_name(tool: str) -> str:
    """Coerce a declared tool name to a valid generated-module identifier."""
    s = re.sub(r"[^a-z0-9_]", "_", (tool or "").lower())
    s = re.sub(r"_+", "_", s).strip("_")
    if s and not s[0].isalpha():
        s = "t_" + s
    return s[:41]


def _generate_tool(
    tool: str, *, llm: Any, sandbox: Any = None,
) -> Any | None:
    """Synthesize a tool for a declared name via the governed path.

    Mirrors the in-loop ``learn_capability`` create_tool op: ask the coder LLM
    for a stdlib-only module, then hand it to ``write_generated_tool`` which
    statically audits, Shield-scans, import-validates out-of-host, and
    consent-gates it before persisting. Returns the Tool or None (fail-soft).
    """
    from . import self_learning
    from .llm import model_for_role

    name = _sanitize_tool_name(tool)
    if not _TOOL_NAME_RE.match(name):
        return None
    spec = (
        f"A tool named {tool!r} that a specialist agent's workflow calls. "
        "Infer a sensible input/output contract from the name."
    )
    try:
        resp = llm.complete(
            system=self_learning.TOOL_AUTHOR_SYSTEM,
            messages=[{"role": "user", "content": f"Build a tool named {name!r}.\nIt should: {spec}"}],
            model=model_for_role("coder"), max_tokens=2048,
        )
    except Exception as e:
        log.debug("provision: tool generation call for %s failed: %s", tool, e)
        return None
    source = getattr(resp, "text", "") or ""
    try:
        return self_learning.write_generated_tool(
            name, source, need=f"factory-provisioned tool for pack workflow: {tool}",
            sandbox=sandbox,
        )
    except Exception as e:
        log.debug("provision: generated tool %s rejected: %s", name, e)
        return None


def apply_plan(
    plan: ProvisioningPlan, *, approved: bool, llm: Any = None,
    sandbox: Any = None, register: Any = None, max_acquisitions: int | None = None,
) -> ProvisionResult:
    """Execute a plan's safe acquisitions. Gated and fail-soft.

    Refuses entirely unless ``approved`` is True (the pack passed the human
    gate) AND ``self_learning.enabled()``. Within that: installs catalog skills
    for ``acquire_skill`` gaps; synthesizes ``generate_tool`` gaps when an
    ``llm`` is supplied and ``create_tools`` is on; leaves ``manual`` gaps for
    the operator. ``register(tool)`` -- when given -- adds a synthesized tool to
    a live registry (otherwise it just persists for the next run). Capped at the
    ``[self_learning] max_acquisitions`` budget. Never raises.
    """
    from . import self_learning

    res = ProvisionResult()
    if not approved:
        res.skipped += [g.need for g in plan.gaps]
        return res
    if not self_learning.enabled():
        res.skipped += [f"{g.need} (self-learning off)" for g in plan.gaps]
        return res

    st = self_learning.settings()
    if not st.get("provision_packs", True):
        res.skipped += [f"{g.need} (pack provisioning off)" for g in plan.gaps]
        return res
    cap = max_acquisitions if max_acquisitions is not None else int(st.get("max_acquisitions", 5))
    create_tools = bool(st.get("create_tools", True))
    count = 0

    for g in plan.gaps:
        # Honor cap==0 as "acquire nothing" (don't floor it to 1). Config clamps
        # max_acquisitions to >=1, but a direct caller may pass 0 to mean none.
        if count >= cap:
            res.skipped.append(f"{g.need} (acquisition budget reached)")
            continue
        if g.resolution == "acquire_skill" and g.candidate:
            try:
                self_learning.acquire_skill(g.candidate, need=g.need)
                res.acquired.append(g.candidate)
                count += 1
            except Exception as e:
                res.failed.append((g.candidate, str(e)))
        elif g.resolution == "generate_tool":
            if llm is None:
                res.skipped.append(f"{g.need} (no LLM for tool synthesis)")
                continue
            if not create_tools:
                res.skipped.append(f"{g.need} (tool creation disabled)")
                continue
            tool = _generate_tool(g.need, llm=llm, sandbox=sandbox)
            if tool is None:
                res.failed.append((g.need, "generation failed or denied"))
                continue
            if register is not None:
                try:
                    register(tool)
                except Exception as e:  # pragma: no cover -- registration is best-effort
                    log.debug("provision: register %s failed: %s", tool.name, e)
            res.generated.append(tool.name)
            count += 1
        else:
            res.skipped.append(f"{g.need} (manual)")

    return res


def provision_profile(
    profile: DomainProfile, *, approved: bool, known_tools: set[str] | None = None,
    llm: Any = None, sandbox: Any = None, register: Any = None,
) -> tuple[ProvisioningPlan, ProvisionResult]:
    """Analyse a profile and apply the plan in one call. Returns both, so a
    caller can show what was found and what was done. Analysis always runs;
    application obeys the same gates as :func:`apply_plan`."""
    plan = analyze_profile(profile, known_tools=known_tools)
    result = apply_plan(
        plan, approved=approved, llm=llm, sandbox=sandbox, register=register,
    )
    return plan, result



class BudgetedLLM:
    """Route every ``complete`` call of ``llm`` through ``budget``.

    Tool synthesis calls the model without a budget of its own; wrapping the
    model checks the caps before each call and hands the budget to the model
    call, so its spend is reserved, recorded and refused like any other run."""

    def __init__(self, llm: Any, budget: Any) -> None:
        self._llm = llm
        self.budget = budget

    def complete(self, *args: Any, **kwargs: Any) -> Any:
        self.budget.check()
        kwargs["budget"] = self.budget
        return self._llm.complete(*args, **kwargs)


def apply_approved_plan(profile, plan, *, llm: Any = None, budget: Any = None) -> ProvisionResult:
    """Equip an approved onboarding pack: install catalog skills and generate
    declared tools through the governed paths (a no-op unless self-learning is
    on), then record the gaps as factory-learning signals (a no-op unless that
    is on). With ``budget``, every model call goes through it (see
    :class:`BudgetedLLM`). Shared by ``maverick onboard`` and the dashboard's
    business setup."""
    if llm is not None and budget is not None:
        llm = BudgetedLLM(llm, budget)
    result = apply_plan(plan, approved=True, llm=llm)
    try:
        from . import factory_learning
        factory_learning.record_provisioning(profile, plan, result)
    except Exception:  # pragma: no cover -- learning must never break onboarding
        pass
    return result


__all__ = [
    "apply_approved_plan", "BudgetedLLM",
    "CapabilityGap", "ProvisioningPlan", "ProvisionResult",
    "analyze_profile", "apply_plan", "provision_profile",
]
