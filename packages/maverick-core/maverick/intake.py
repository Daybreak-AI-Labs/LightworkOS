"""Intake -- the agent factory's front door.

Turns "what the business does" + its uploaded documents into a live, sealed,
knowledge-loaded domain agent:

    IntakeSpec --generate(LLM)--> DomainProfile --validate/clamp--> human approve
        --> save to ~/.maverick/domains/ --> agent_from_profile

The pack is LLM-generated (persona *and* capability envelope) from the business
description, but ALWAYS passed through ``validate_profile`` first -- a freshly
generated pack can never auto-grant high-impact tools or escalate risk. A human
widens the envelope at approval. This is the compartment "door" philosophy
applied to onboarding: an unvetted, model-authored agent starts locked down.

This module is the generation + safety core. The conversational intake agent
(interview + document/diagram collection) and the ``maverick onboard`` UX build
on top of it, supplying the ``propose`` callable and the human-approval step.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import logging
import secrets
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from .agent_tests_policy import (
    NEW_SPECIALIST_NEEDS_TESTS,
    NewSpecialistNeedsTests,
    require_for_new_specialists,
)
from .domain import (
    _DOMAIN_ID_RE,
    DomainProfile,
    OutputContract,
    WorkflowStep,
    _coerce_output,
    _coerce_workflow,
    builtin_domains,
    load_domain,
    load_domains,
    user_dir,
)

log = logging.getLogger(__name__)

# A freshly-generated pack must not auto-grant high-impact tools; a human widens
# the envelope at approval. Generation cannot self-escalate past this floor.
_GENERATED_DENY = frozenset({
    "shell", "write_file", "edit_file", "delete_file", "code_exec",
    "computer", "browser", "clipboard",
})
_MAX_GENERATED_RISK = "medium"


@dataclass
class IntakeSpec:
    """What we learned about a business during intake."""
    name: str
    description: str = ""
    industry: str = ""
    goals: list[str] = field(default_factory=list)
    doc_paths: list[str] = field(default_factory=list)


def _slug(name: str) -> str:
    original = unicodedata.normalize("NFC", name or "").casefold()
    folded = unicodedata.normalize("NFKD", original)
    ascii_name = "".join(c for c in folded if not unicodedata.combining(c))
    s = "".join(c if c.isascii() and c.isalnum() else "_" for c in ascii_name)
    base = "_".join(filter(None, s.split("_"))) or "business"
    # Different original names can fold to the same ASCII spelling. Keep
    # identities stable and distinct without writing non-ASCII pack filenames.
    suffix = "_" + hashlib.sha256(original.encode("utf-8")).hexdigest()[:8] if not original.isascii() else ""
    return base[:128 - len(suffix)].rstrip("_") + suffix


def _pending_collection(name: str) -> str:
    """Return an isolated, non-predictable collection for unapproved intake docs."""
    return f"intake_pending_{_slug(name)}_{secrets.token_urlsafe(8)}"


def _default_persona(_spec: IntakeSpec) -> str:
    """Return a safe fallback persona that does not echo intake text.

    Intake fields are user-controlled and this persona is appended to the agent's
    system prompt, so the fallback must be constant rather than interpolating
    business names, descriptions, or industries that may contain prompt
    injection instructions.
    """
    return (
        "You are a specialist assistant for this business. Answer from the "
        "company's uploaded documents first and cite them; say plainly when the "
        "documents don't cover something rather than guessing."
    )


_MAX_PERSONA_CHARS = 2000
_MAX_REFUSAL_CHARS = 500
_MAX_REFUSALS = 20
_MAX_WORKFLOW_NAME_CHARS = 120
_MAX_WORKFLOW_INSTRUCTION_CHARS = 600


def _shield_allows_generated_prompt(text: str) -> bool:
    """Screen generated prompt text before it becomes system instruction.

    The in-kernel injection tripwire is mandatory and fail-closed. Optional
    Shield adds a second opinion; when it is absent or unavailable, a clean
    deterministic verdict preserves the kernel's no-Shield deployment mode.
    """
    try:
        from .memory_guard import injection_markers

        if injection_markers(text):
            return False
    except Exception:
        log.exception("intake: deterministic generated-prompt screen failed")
        return False

    try:
        shield_mod = importlib.import_module("maverick_shield")
        shield = shield_mod.Shield.from_config(warn_if_missing=False)
        verdict = shield.scan_output(text)
        allowed = getattr(verdict, "allowed", None)
        return allowed is True
    except (ImportError, ModuleNotFoundError):
        return True
    except Exception:
        log.warning(
            "intake: optional Shield generated-prompt scan failed; "
            "using deterministic verdict",
            exc_info=True,
        )
        return True


def _safe_persona(persona: str, spec: IntakeSpec) -> str:
    """Cap and Shield-scan generated persona text before prompt use."""
    persona = (persona or "").strip()[:_MAX_PERSONA_CHARS]
    if not persona:
        return _default_persona(spec)
    if not _shield_allows_generated_prompt(persona):
        log.warning("intake: generated persona tripped the shield; using the "
                    "safe default persona")
        return _default_persona(spec)
    return persona


def _safe_refusals(refusals: list[str]) -> list[str]:
    """Sanitize generated refusal text before it can become prompt material.

    Pack-specific refusals are rendered into future specialists' system prompts,
    just like personas. Treat proposer-supplied entries as untrusted model output:
    trim and cap them, Shield-scan each entry, and drop entries that trip the
    shield while preserving safe refusal functionality.
    """
    clean: list[str] = []
    for raw in refusals[:_MAX_REFUSALS]:
        item = str(raw or "").strip()[:_MAX_REFUSAL_CHARS]
        if not item:
            continue
        if not _shield_allows_generated_prompt(item):
            log.warning("intake: generated refusal tripped the shield; dropping it")
            continue
        clean.append(item)
    return clean


def _safe_workflow_text(text: str, *, max_chars: int) -> str:
    return (text or "").strip()[:max_chars]


def _safe_workflow_step(step: WorkflowStep) -> WorkflowStep | None:
    """Cap and Shield-scan generated workflow text before prompt use.

    Workflow names and instructions are rendered into the same system-prompt
    surface as the persona, so a blocked step is dropped rather than persisted.
    """
    name = _safe_workflow_text(step.name, max_chars=_MAX_WORKFLOW_NAME_CHARS)
    instruction = _safe_workflow_text(
        step.instruction, max_chars=_MAX_WORKFLOW_INSTRUCTION_CHARS,
    )
    if not name:
        return None
    prompt_text = name if not instruction else f"{name}: {instruction}"
    if not _shield_allows_generated_prompt(prompt_text):
        log.warning("intake: generated workflow step tripped the shield; dropping it")
        return None
    return WorkflowStep(
        name=name, instruction=instruction,
        tools=step.tools, gate=step.gate,
    )


def _default_workflow() -> list[WorkflowStep]:
    """A generic professional playbook for a generated pack -- the same shape the
    built-in roster carries, so a synthesized specialist is first-class out of
    the gate. A proposer may supply a tailored one; this is the safe fallback."""
    return [
        WorkflowStep("Gather inputs",
                     "Collect the documents, data, and context the task needs and "
                     "ask up front for anything missing."),
        WorkflowStep("Verify against source",
                     "Check names, numbers, dates, and claims against their source "
                     "before relying on them."),
        WorkflowStep("Draft the deliverable",
                     "Produce the requested output grounded in the company's own "
                     "documents, citing the source for each material claim."),
        WorkflowStep("Flag gaps",
                     "Call out anything unsupported, ambiguous, or out of scope "
                     "rather than guessing."),
        WorkflowStep("Route for review",
                     "Hand the draft to the accountable human to review before it "
                     "is acted on.", gate="review"),
    ]


def _default_output(description: str) -> OutputContract:
    """A safe default consumption contract for a generated pack: a prose
    deliverable, reviewed before use, routed to the person who requested it."""
    label = (description or "").strip() or "specialist deliverable"
    if len(label) > 60:
        label = label[:57].rstrip() + "..."
    return OutputContract(shape="prose", deliverable=label,
                          consumers=["requester"], cadence="on-demand",
                          gate="review")


def _sanitize_consumption(profile: DomainProfile) -> None:
    """Make a generated pack's playbook + output contract lint-clean: workflow
    steps name only granted tools and unique names; the output uses valid
    shape/gate. Runs after the envelope is clamped, so tool references match the
    final allowlist."""
    from .domain import _VALID_EFFORTS, _VALID_GATES, _VALID_SHAPES
    allow = set(profile.allow_tools)
    seen: set[str] = set()
    clean: list[WorkflowStep] = []
    for step in profile.workflow:
        safe_step = _safe_workflow_step(step)
        if safe_step is None or safe_step.name in seen:
            continue
        seen.add(safe_step.name)
        clean.append(WorkflowStep(
            name=safe_step.name, instruction=safe_step.instruction,
            tools=[t for t in safe_step.tools if t in allow],
            gate=safe_step.gate if safe_step.gate in _VALID_GATES else None,
        ))
    profile.workflow = clean or _default_workflow()
    o = profile.output
    if o.deliverable:
        profile.output = OutputContract(
            shape=o.shape if o.shape in _VALID_SHAPES else "prose",
            deliverable=o.deliverable,
            consumers=o.consumers or ["requester"],
            cadence=o.cadence or "on-demand",
            gate=o.gate if o.gate in _VALID_GATES else None,
        )
    if profile.effort is not None and profile.effort not in _VALID_EFFORTS:
        profile.effort = None


def validate_profile(profile: DomainProfile) -> DomainProfile:
    """Clamp a generated pack to a safe envelope: union a baseline deny set,
    strip denied or over-ceiling tools out of allow, and cap ``max_risk``.
    Mutates and returns the profile. A human widens this at approval; the
    generator cannot."""
    from .safety.tool_risk import risk_rank, tool_risk

    if profile.max_risk is None or risk_rank(profile.max_risk) > risk_rank(_MAX_GENERATED_RISK):
        profile.max_risk = _MAX_GENERATED_RISK
    ceiling = risk_rank(profile.max_risk)
    over_ceiling = {
        tool for tool in profile.allow_tools
        if risk_rank(tool_risk(tool)) > ceiling
    }
    deny = set(profile.deny_tools) | _GENERATED_DENY | over_ceiling
    profile.deny_tools = sorted(deny)
    profile.allow_tools = [t for t in profile.allow_tools if t not in deny]
    if not profile.compartment:
        profile.compartment = profile.name
    profile.authoring = "generated"
    _sanitize_consumption(profile)
    return profile


def generate_profile(spec: IntakeSpec, propose=None) -> DomainProfile:
    """Turn an IntakeSpec into a validated DomainProfile.

    ``propose(spec) -> dict`` is the pluggable generator: an LLM in production
    (keys: persona, description, allow_tools, deny_tools, max_risk), or ``None``
    for a deterministic fallback. The proposed envelope is ALWAYS run through
    ``validate_profile``, so the result is safe regardless of what the model
    returned (or if it failed)."""
    name = _slug(spec.name)
    if name in builtin_domains():
        suffix = hashlib.sha256((spec.name or "").encode("utf-8")).hexdigest()[:8]
        name = f"business_{name[:110]}_{suffix}"
    proposed: dict = {}
    if propose is not None:
        try:
            proposed = propose(spec) or {}
        except Exception as e:  # generation must fail soft to a safe default
            log.warning("intake: proposer failed (%s); using default pack", e)

    description = str(proposed.get("description") or spec.description)
    workflow = _coerce_workflow(proposed.get("workflow")) or _default_workflow()
    output = (_coerce_output(proposed["output"])
              if isinstance(proposed.get("output"), dict)
              else _default_output(description))
    profile = DomainProfile(
        name=name,
        compartment=name,
        description=description,
        persona=str(proposed.get("persona") or _default_persona(spec)),
        allow_tools=list(proposed.get("allow_tools") or ["read_file", "web_search"]),
        deny_tools=list(proposed.get("deny_tools") or []),
        max_risk=proposed.get("max_risk"),
        effort=proposed.get("effort"),
        refuse=[str(r) for r in (proposed.get("refuse") or []) if str(r).strip()],
        knowledge_sources=[name],
        authoring="generated",
        workflow=workflow,
        output=output,
    )
    profile.persona = _safe_persona(profile.persona, spec)
    profile.refuse = _safe_refusals(profile.refuse)
    return validate_profile(profile)


def ingest_docs(spec: IntakeSpec, kb, collection: str | None = None,
                *, ingested_by: str = "") -> int:
    """Ingest the spec's uploaded documents into the pack's knowledge collection.
    Returns the number of chunks stored. Fail-soft per document.

    Each document is stamped with provenance (``ingested_by``, source, content
    hash) and the ingestion is recorded on the signed audit chain so a governed
    corpus has a tamper-evident record of what was loaded and by whom. The audit
    write is best-effort: a missing audit backend never blocks onboarding.
    """
    collection = collection or _slug(spec.name)
    total = 0
    docs = 0
    for path in spec.doc_paths:
        try:
            n = kb.ingest_path(collection, path, ingested_by=ingested_by)
            total += n
            if n:
                docs += 1
        except Exception as e:  # one bad upload must not abort onboarding
            log.warning("intake: failed to ingest %s (%s)", path, e)
    if total:
        try:
            from .audit import record
            record("evidence_capture", agent="intake",
                   knowledge_collection=collection, documents=docs,
                   chunks=total, ingested_by=ingested_by or "unknown")
        except Exception:  # pragma: no cover -- audit is optional, never blocks
            log.debug("intake: knowledge ingest audit event not recorded")
    return total


def _to_toml(p: DomainProfile) -> str:
    # json.dumps emits valid TOML string/array literals (incl. \n-escaped
    # multi-line personas), so a generated pack round-trips through load_domain.
    lines = [
        f"name = {json.dumps(p.name)}",
        f"compartment = {json.dumps(p.compartment)}",
        f"description = {json.dumps(p.description)}",
        f"persona = {json.dumps(p.persona)}",
        f"allow_tools = {json.dumps(p.allow_tools)}",
        f"deny_tools = {json.dumps(p.deny_tools)}",
        f"max_risk = {json.dumps(p.max_risk)}" if p.max_risk else "",
        f"effort = {json.dumps(p.effort)}" if p.effort else "",
        f"refuse = {json.dumps(p.refuse)}" if p.refuse else "",
        f"knowledge_sources = {json.dumps(p.knowledge_sources)}",
        f"authoring = {json.dumps(p.authoring)}",
    ]
    body = "\n".join(line for line in lines if line) + "\n"
    # The [output] table and [[workflow]] array-of-tables MUST follow all the
    # top-level scalars (TOML rule), so they are appended last.
    if p.output.deliverable:
        out = ["", "[output]", f"shape = {json.dumps(p.output.shape)}",
               f"deliverable = {json.dumps(p.output.deliverable)}",
               f"consumers = {json.dumps(p.output.consumers)}",
               f"cadence = {json.dumps(p.output.cadence)}"]
        if p.output.gate:
            out.append(f"gate = {json.dumps(p.output.gate)}")
        body += "\n".join(out) + "\n"
    for step in p.workflow:
        blk = ["", "[[workflow]]", f"name = {json.dumps(step.name)}"]
        if step.instruction:
            blk.append(f"instruction = {json.dumps(step.instruction)}")
        if step.tools:
            blk.append(f"tools = {json.dumps(step.tools)}")
        if step.gate:
            blk.append(f"gate = {json.dumps(step.gate)}")
        body += "\n".join(blk) + "\n"
    return body


def save_profile(profile: DomainProfile, *, approved: bool,
                 dest_dir: str | Path | None = None) -> str:
    """Persist an APPROVED pack so ``available_domains()`` picks it up. Refuses
    to write a pack that hasn't been human-approved -- the safety gate is here."""
    if not approved:
        raise PermissionError("refusing to save an unapproved generated pack")
    if not _DOMAIN_ID_RE.fullmatch(profile.name):
        raise ValueError("specialist name cannot be used as a saved identity")
    if profile.name in builtin_domains():
        raise FileExistsError("specialist name belongs to a built-in specialist")
    d = Path(dest_dir) if dest_dir else user_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{profile.name}.toml"
    if profile.name in load_domains(d):
        raise FileExistsError("specialist name belongs to an existing workspace specialist")
    # Names that reach this point are new: existing specialists were refused above.
    if require_for_new_specialists():
        raise NewSpecialistNeedsTests(NEW_SPECIALIST_NEEDS_TESTS)
    created = False
    try:
        with path.open("x", encoding="utf-8") as target:
            created = True
            target.write(_to_toml(profile))
        load_domain(path)
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise
    return str(path)


_PROPOSER_SYSTEM = (
    "You configure a specialist business-assistant agent. Given a business "
    "description, return ONLY a JSON object with these keys:\n"
    '  "persona": the agent\'s system instructions (string),\n'
    '  "description": a one-line summary (string),\n'
    '  "allow_tools": array of tool names it needs (e.g. read_file, web_search),\n'
    '  "max_risk": "low" or "medium",\n'
    '  "workflow": array of 3-6 steps, each {"name","instruction","gate"} where\n'
    "      gate is null except the final human-handoff step (\"review\", or\n"
    '      "approval" for anything irreversible),\n'
    '  "output": {"shape","deliverable","consumers","cadence","gate"} describing\n'
    "      the deliverable (shape = prose|report|table|forecast).\n"
    "Never include shell, code-execution, or file-writing tools. Output JSON only."
)


def _intake_prompt(spec: IntakeSpec) -> str:
    parts = [f"Business name: {spec.name}"]
    if spec.industry:
        parts.append(f"Industry: {spec.industry}")
    if spec.description:
        parts.append(f"What they do: {spec.description}")
    if spec.goals:
        parts.append("Goals: " + "; ".join(spec.goals))
    return "\n".join(parts)


def _parse_proposal(text: str) -> dict:
    """Extract the JSON pack from an LLM response and sanitize it to expected
    types. Returns {} on anything unparseable -- generate_profile then uses its
    safe default, and validate_profile clamps the result regardless."""
    if not text:
        return {}
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return {}
    try:
        data = json.loads(text[start:end + 1])
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict = {}
    for key in ("persona", "description", "max_risk", "effort"):
        if isinstance(data.get(key), str):
            out[key] = data[key]
    for key in ("allow_tools", "deny_tools", "refuse"):
        v = data.get(key)
        if isinstance(v, list):
            out[key] = [str(x) for x in v if isinstance(x, str)]
    # The playbook + consumption contract pass through as-is; generate_profile
    # coerces and validate_profile sanitizes them, so junk can't break a pack.
    if isinstance(data.get("workflow"), list):
        out["workflow"] = data["workflow"]
    if isinstance(data.get("output"), dict):
        out["output"] = data["output"]
    return out


def build_llm_proposer(llm, *, model: str | None = None, budget=None):
    """A ``propose(spec)`` callable backed by an LLM -- the generative authoring
    path ("describe the business, we synthesize the pack"). The result is still
    run through ``validate_profile``, so the model can't widen the envelope."""
    def propose(spec: IntakeSpec) -> dict:
        system = _PROPOSER_SYSTEM
        try:  # fold in promoted factory guidance (no-op while self-improvement off)
            from .domain import suite_for
            from .factory_learning import augment_system_prompt
            system = augment_system_prompt(_PROPOSER_SYSTEM, suite=suite_for(_slug(spec.name)))
        except Exception:  # pragma: no cover -- guidance must never break generation
            pass
        resp = llm.complete(
            system=system,
            messages=[{"role": "user", "content": _intake_prompt(spec)}],
            model=model, budget=budget, max_tokens=1500,
        )
        return _parse_proposal(getattr(resp, "text", "") or "")

    return propose


def attach_docs_to_profile(spec: IntakeSpec, profile: DomainProfile, kb) -> int:
    """Ingest approved intake documents and bind the profile to their collection.

    The collection is isolated and non-predictable so newly onboarded documents
    do not collide with or poison existing domain collections. Call this only
    after the user has approved activation.
    """
    if not spec.doc_paths:
        return 0
    collection = _pending_collection(profile.name)
    total = ingest_docs(spec, kb, collection=collection)
    if total:
        profile.knowledge_sources = [collection]
    return total


def onboarding_knowledge_base():
    """The knowledge base approved onboarding documents are loaded into.

    Returns ``(kb, None)``, ``(None, "disabled")`` when ``[knowledge]`` is off
    (the knowledge package is then never imported), or ``(None, exc)`` when the
    optional knowledge layer could not be built. Uploads persist to the active
    workspace's knowledge store (an explicit ``[knowledge] path`` still wins),
    are Shield-scanned at ingest when Shield is installed, and diagrams/images
    are read with OCR when the vision extra is installed.
    """
    try:
        from .config import get_knowledge
        from .workspace import Workspace
        kcfg = get_knowledge()
        if not kcfg.get("enable"):
            return None, "disabled"
        from maverick_knowledge import KnowledgeBase, build_embedder, build_store
        if not kcfg.get("path"):
            kcfg = {**kcfg, "path": str(Workspace.current().knowledge_path)}
        shield = None
        try:
            from maverick_shield import Shield
            shield = Shield.from_config(warn_if_missing=False)
        except Exception:
            pass
        kb = KnowledgeBase(store=build_store(kcfg), embedder=build_embedder(kcfg), shield=shield)
        try:  # OCR uploaded diagrams/images when the vision extra is installed
            from maverick_knowledge.image import build_ocr_describer
            kb.image_describer = build_ocr_describer()
        except Exception:
            pass  # no vision extra -> images are skipped, not read as bytes
        return kb, None
    except Exception as e:  # knowledge layer is optional
        return None, e


def run_intake(spec: IntakeSpec, *, llm=None, kb=None,
               model: str | None = None, budget=None) -> DomainProfile:
    """Generate a validated (but UNSAVED) DomainProfile for human approval.

    Pass ``llm`` to use the generative path; omit it for the deterministic
    fallback. Persisting and document ingestion are separate, approved steps
    (``save_profile`` and ``attach_docs_to_profile``), so drafting never stores
    or sends uploaded document contents before the human approval gate. The
    ``kb`` argument is accepted for backward-compatible callers but is not used
    during draft generation.
    """
    propose = (
        build_llm_proposer(llm, model=model, budget=budget) if llm is not None else None
    )
    return generate_profile(spec, propose=propose)


INTAKE_PERSONA = (
    "You are Lightwork's onboarding specialist. Interview the business to learn "
    "what it does, its industry, and its goals, and ask for any documents or "
    "process diagrams it can share. As you learn, call record_business, "
    "add_goal, and add_document. Ask one focused question at a time -- don't "
    "overwhelm. Once you have the business's name and a clear sense of what it "
    "does, call finalize_intake to draft its specialist agent, then tell the "
    "user the draft is ready for review. You NEVER activate an agent yourself; "
    "a human approves it."
)


@dataclass
class IntakeSession:
    """Evolving state of a conversational intake. The intake agent fills it via
    the intake tools; ``finalize`` turns it into a validated (unsaved) pack."""
    name: str = ""
    description: str = ""
    industry: str = ""
    goals: list[str] = field(default_factory=list)
    doc_paths: list[str] = field(default_factory=list)

    def to_spec(self) -> IntakeSpec:
        return IntakeSpec(
            name=self.name or "business", description=self.description,
            industry=self.industry, goals=list(self.goals),
            doc_paths=list(self.doc_paths),
        )

    def is_ready(self) -> bool:
        """Enough to draft a pack: a name plus some sense of what they do."""
        return bool(self.name and (self.description or self.industry))

    def finalize(self, *, llm=None, kb=None) -> DomainProfile:
        return run_intake(self.to_spec(), llm=llm, kb=kb)


def build_intake_agent(ctx, session: IntakeSession | None = None, *, llm=None, kb=None):
    """Construct the conversational intake agent: an Agent with the onboarding
    persona and the intake tools bound to a shared IntakeSession. Returns
    ``(agent, session)``. The live chat loop reuses the normal agent/channel
    surface; this just assembles the interviewer."""
    from .agent import Agent
    from .tools import ToolRegistry
    from .tools.intake_tools import intake_tools

    session = session or IntakeSession()
    agent = Agent(
        ctx=ctx, role="intake",
        brief="Interview the business and assemble its specialist agent.",
        persona=INTAKE_PERSONA,
    )
    # The intake chat is exposed to untrusted prospective users. A regular
    # Agent starts with the full base registry (shell, filesystem, MCP, etc.),
    # so replace it with an intake-only registry before adding onboarding tools.
    agent.tools = ToolRegistry()
    for tool in intake_tools(session, llm=llm or getattr(ctx, "llm", None),
                             kb=kb or getattr(ctx, "knowledge", None)):
        agent.tools.register(tool)
    return agent, session
