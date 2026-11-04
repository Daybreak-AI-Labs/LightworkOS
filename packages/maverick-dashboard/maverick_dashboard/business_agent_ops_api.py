"""Set up a specialist for your business (``maverick onboard``).

Describe the business, review the drafted specialist, then approve it with its
documents. The steps are the command's own kernel calls:
:func:`maverick.intake.run_intake` drafts an unsaved, clamped pack (with the AI
role ``writer`` when chosen and connected, else the deterministic draft, like
``--no-llm``); :func:`maverick.provision.analyze_profile` lists capability
gaps; on approval :func:`maverick.intake.onboarding_knowledge_base` and
:func:`maverick.intake.attach_docs_to_profile` load the documents,
:func:`maverick.intake.save_profile` saves it (its approval gate stays) and
:func:`maverick.provision.apply_approved_plan` equips it. Building missing
tools calls AI on the ``writer`` model under a capped budget admitted like any
AI request; if that budget is refused, only ready-made skills are added.

Specialists are saved for the whole workspace, so both steps need the same
permission as the specialist editor (``pack_editing``), the same-origin guard
and, for approval, an explicit confirmation and an audit row written first.
The AI draft is admitted like other AI requests (spending limits, capped
budget, provider admission, usage settlement). Both steps run as background
jobs the page polls. The drafted pack stays on the server; the page approves
it by its job, never by sending a pack back.
"""
from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, ConfigDict, Field

from .auth import caller_principal, execution_user_id_from_request

log = logging.getLogger(__name__)
router = APIRouter(tags=["business-agent-setup"])
DRAFT_DOLLARS = 0.5
TOOL_DOLLARS = 1.0
MAX_DOCS = 10
MAX_DOC_BYTES = 10 * 1024 * 1024
MAX_TOTAL_BYTES = 25 * 1024 * 1024
_DRAFT = "business-agent-draft"
_APPROVE = "business-agent-approve"
_RESOLUTION = {
    "acquire_skill": "Lightwork can add a ready-made skill for this",
    "generate_tool": "Lightwork can build a tool for this",
}


class DraftIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=4000)
    industry: str = Field(default="", max_length=120)
    use_ai: bool = True


def _guard(request: Request) -> None:
    from .app import _require_same_origin
    from .editor_policy import require_pack_editing as _require_pack_editing

    _require_pack_editing(request)
    _require_same_origin(request)


def _public(profile, plan) -> dict:
    return {
        "name": profile.name,
        "summary": str(profile.description or "")[:500],
        "risk": str(profile.max_risk or "low"),
        "can_use": list(profile.allow_tools)[:50],
        "cannot_use": list(profile.deny_tools)[:50],
        "refuses": [str(r)[:300] for r in profile.refuse][:20],
        "instructions": str(profile.persona or "")[:4000],
        "steps": [{"name": str(s.name)[:200], "instruction": str(s.instruction)[:1000],
                   "review": bool(getattr(s, "gate", None))} for s in profile.workflow][:12],
        "gaps": [{"need": str(g.need)[:200],
                  "how": _RESOLUTION.get(g.resolution, "Someone needs to set this up by hand")}
                 for g in (plan.gaps if plan is not None else [])][:20],
    }


def _draft(spec, use_ai: bool, principal: str, actor: str) -> dict:
    from maverick.intake import run_intake
    from maverick.provision import analyze_profile

    llm = budget = settlement = None
    with_ai = False
    if use_ai:
        from maverick.llm import LLM, model_for_role
        from maverick.orchestrator import _QuotaUsageSettlement

        from .viewpoints_api import _admit, _Refused

        try:
            budget = _admit(principal, DRAFT_DOLLARS)
        except _Refused as exc:
            return {"ran": False, "message": str(exc)}
        settlement = _QuotaUsageSettlement(principal=principal, budget=budget, domain=None)
        llm, with_ai = LLM(model=model_for_role("writer")), True
    try:
        from maverick.audit import audit_event

        audit_event("business_agent_drafted", agent="dashboard", actor=actor, with_ai=with_ai)
        if with_ai:
            from maverick.tenant.provider_admission import run_scope

            with run_scope(budget, principal):
                profile = run_intake(spec, llm=llm, budget=budget)
        else:
            profile = run_intake(spec)
    finally:
        if settlement is not None:
            settlement.record()
    try:
        from maverick.tools import base_tool_names

        plan = analyze_profile(profile, known_tools=base_tool_names())
    except Exception:  # analysis must never block onboarding
        plan = None
    return {"ran": True, "with_ai": with_ai, "agent": _public(profile, plan), "_profile": profile, "_plan": plan}


def _approve(profile, plan, docs: list[tuple[str, bytes]], actor: str, principal: str = "") -> dict:
    from maverick.audit import AuditRefused, audit_event
    from maverick.domain import available_domains
    from maverick.intake import (
        IntakeSpec,
        attach_docs_to_profile,
        onboarding_knowledge_base,
        save_profile,
    )
    try:
        audit_event("business_agent_approval_requested", agent="dashboard", actor=actor,
                    agent_name=profile.name, documents=len(docs))
    except AuditRefused:
        return {"saved": False, "message": "The activity log couldn't record this approval, so nothing was saved."}
    from maverick.agent_tests_policy import NEW_SPECIALIST_NEEDS_TESTS, NewSpecialistNeedsTests
    try:
        saved_path = Path(save_profile(profile, approved=True))
    except NewSpecialistNeedsTests:
        return {"saved": False, "message": NEW_SPECIALIST_NEEDS_TESTS}
    except PermissionError:
        return {"saved": False, "message": "This installation's plan doesn't include new agents, so it wasn't saved."}
    except FileExistsError:
        return {"saved": False, "message": "An agent or specialist with this name already exists. Open it from the list or use a different name."}
    except (ValueError, OSError):
        return {"saved": False, "message": "This agent could not be saved. Check its name and try again."}
    try:
        if profile.name not in available_domains():
            saved_path.unlink(missing_ok=True)
            return {"saved": False, "message": "This agent did not pass its final setup check. Nothing was added."}
        audit_event("business_agent_approved", agent="dashboard", actor=actor,
                    agent_name=profile.name, documents=len(docs))
    except AuditRefused:
        saved_path.unlink(missing_ok=True)
        return {"saved": False, "message": "The activity log couldn't record this approval, so nothing was saved."}
    except Exception:
        saved_path.unlink(missing_ok=True)
        return {"saved": False, "message": "This agent could not be confirmed. Nothing was added."}
    loaded, note = 0, ""
    with tempfile.TemporaryDirectory(prefix="lw-onboard-") as folder:
        paths = []
        for index, (name, data) in enumerate(docs):
            safe = "".join(c for c in Path(name).name if c.isalnum() or c in "._- ")[:100] or f"document-{index}"
            target = Path(folder) / f"{index:02d}-{safe}"
            target.write_bytes(data)
            paths.append(str(target))
        if paths:
            kb, problem = onboarding_knowledge_base()
            if kb is None:
                note = ("Company documents are turned off, so the documents weren't loaded. An administrator can turn "
                        "them on in settings." if problem == "disabled"
                        else "The documents couldn't be loaded right now, so the agent has no document memory yet.")
            else:
                spec = IntakeSpec(name=profile.name, doc_paths=paths)
                loaded = attach_docs_to_profile(spec, profile, kb)
    added = ""
    if plan is not None and not plan.is_empty():
        try:
            added = _equip(profile, plan, principal or actor, actor)
        except Exception:
            log.warning("capability provisioning after onboarding failed", exc_info=True)
    return {"saved": True, "name": profile.name, "documents_loaded": int(loaded or 0),
            "message": " ".join(part for part in (note, added) if part)}


def _equip(profile, plan, principal: str, actor: str) -> str:
    """Close the pack's capability gaps. Tool generation calls AI, so it runs
    on the ``writer`` model (as ``maverick onboard`` does) under a budget
    admitted like any other AI request; when that budget is refused, only
    ready-made skills are added (the no-model path)."""
    from maverick.audit import audit_event
    from maverick.provision import apply_approved_plan

    from .viewpoints_api import _admit, _Refused

    needs_model = any(g.resolution == "generate_tool" for g in plan.gaps)
    budget = llm = settlement = None
    refused = ""
    if needs_model:
        try:
            budget = _admit(principal, TOOL_DOLLARS)
        except _Refused as exc:
            refused = str(exc)
    if budget is not None:
        from maverick.llm import LLM, model_for_role
        from maverick.orchestrator import _QuotaUsageSettlement
        from maverick.tenant.provider_admission import run_scope

        settlement = _QuotaUsageSettlement(principal=principal, budget=budget, domain=None)
        audit_event("business_agent_tools", agent="dashboard", actor=actor, phase="start",
                    max_dollars=budget.max_dollars)
        llm = LLM(model=model_for_role("writer"))
        try:
            with run_scope(budget, principal):
                result = apply_approved_plan(profile, plan, llm=llm, budget=budget)
        finally:
            settlement.record()
            audit_event("business_agent_tools", agent="dashboard", actor=actor, phase="end",
                        dollars=round(float(budget.dollars), 4))
    else:
        result = apply_approved_plan(profile, plan, llm=None)
    parts = []
    if result.acquired or result.generated:
        parts.append("Lightwork added what it could for the missing skills.")
    if refused:
        parts.append("No tools were built because of spending limits: " + refused)
    return " ".join(parts)


@router.post("/api/v1/agents/business-setup/draft", status_code=202)
def start_business_agent_draft(request: Request, body: DraftIn) -> dict:
    """Draft (never save) a specialist from a business description."""
    from maverick.domain import available_domains, user_dir
    from maverick.intake import IntakeSpec, _slug
    from maverick.orchestrator import _execution_principal

    from ._shared import require_provider_or_400
    from .ops_jobs import JOBS, Busy, identity

    _guard(request)
    name = body.name.strip()
    if not name:
        raise HTTPException(422, "Enter a name for the new agent.")
    candidate = _slug(name)
    if candidate in available_domains() or (user_dir() / f"{candidate}.toml").exists():
        from .agent_changelog import agent_kind

        kind = agent_kind(candidate)  # owner glossary: built-in packs are specialists
        raise HTTPException(
            409,
            f"{'A specialist' if kind == 'specialist' else 'An agent'} called “{name}” already exists. "
            f"Choose another name for the new agent. The existing {kind} and its safeguards have not changed.",
        )
    use_ai = body.use_ai
    if use_ai:
        try:
            require_provider_or_400(role="writer")
        except HTTPException:
            use_ai = False  # the command's fallback: a deterministic draft, not an error
    principal = _execution_principal(user_id=execution_user_id_from_request(request), capability=None)
    actor = caller_principal(request) or principal
    spec = IntakeSpec(name=name, description=body.description.strip(), industry=body.industry.strip())
    owner, tenant = identity(request)
    try:
        job = JOBS.start(owner=owner, tenant=tenant, kind=_DRAFT, work=lambda: _draft(spec, use_ai, principal, actor))
    except Busy as exc:
        raise HTTPException(429, "A draft is already being prepared. Wait for it to finish.") from exc
    return {"job": job}


@router.post("/api/v1/agents/business-setup/{job_id}/approve", status_code=202)
async def approve_business_agent(request: Request, job_id: str, confirm: bool = Form(False),
                                 documents: list[UploadFile] = File(default=[])) -> dict:
    """Save the reviewed draft for this workspace and load its documents."""
    from .ops_jobs import JOBS, Busy, identity

    _guard(request)
    if confirm is not True:
        raise HTTPException(409, "Confirm that you reviewed this agent and want to add it.")
    if len(documents) > MAX_DOCS:
        raise HTTPException(413, f"Attach at most {MAX_DOCS} documents.")
    docs, total = [], 0
    for upload in documents:
        data = await upload.read(MAX_DOC_BYTES + 1)
        total += len(data)
        if len(data) > MAX_DOC_BYTES or total > MAX_TOTAL_BYTES:
            raise HTTPException(413, "The documents are too large. Keep each under 10 MB and all under 25 MB.")
        docs.append((upload.filename or "document", data))
    owner, tenant = identity(request)
    key = job_id[:64]
    draft = JOBS.private_result(key, owner=owner, tenant=tenant, kind=_DRAFT)
    if not draft or draft.get("ran") is not True or "_profile" not in draft:
        raise HTTPException(404, "This draft is no longer available. Make a new draft.")
    from maverick.orchestrator import _execution_principal

    principal = _execution_principal(user_id=execution_user_id_from_request(request), capability=None)
    actor = caller_principal(request) or principal

    def work() -> dict:
        taken = JOBS.consume(key, owner=owner, tenant=tenant, kind=_DRAFT)  # one approval per draft
        if not taken or "_profile" not in taken:
            return {"saved": False, "message": "This draft was already used. Make a new draft."}
        return _approve(taken["_profile"], taken.get("_plan"), docs, actor, principal)

    try:
        job = JOBS.start(owner=owner, tenant=tenant, kind=_APPROVE, work=work)
    except Busy as exc:
        raise HTTPException(429, "Something is already being saved. Wait for it to finish.") from exc
    return {"job": job}


@router.get("/api/v1/agents/business-setup/{job_id}")
def business_agent_job(request: Request, job_id: str, step: str = "draft") -> dict:
    from .editor_policy import require_pack_editing as _require_pack_editing
    from .ops_jobs import JOBS, identity

    _require_pack_editing(request)
    owner, tenant = identity(request)
    job = JOBS.get(job_id[:64], owner=owner, tenant=tenant, kind=_APPROVE if step == "approve" else _DRAFT)
    if job is None:
        raise HTTPException(404, "no such job")
    return job
