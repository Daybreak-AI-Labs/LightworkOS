"""Account-bound in-app pilot planning and observation entry."""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import asdict
from functools import partial
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.candidate_promotion import CandidatePromotionConflict, CandidatePromotionNotFound
from maverick.learning_guard import Halted, check_learning_halt
from maverick.outcome_accounting import COST_COVERAGE_FAMILIES
from maverick.privacy_ops import RecordConflict
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.concurrency import run_in_threadpool

from . import (
    outcome_accounting_bridge,
    outcome_pilot_releases,
    outcome_pilot_sources,
    outcome_pilots,
)
from .auth import (
    caller_principal,
    constant_time_equals,
    require_global_permission,
    require_permission,
)
from .draft_api import context_for

REVIEW_PURPOSE = "lightwork.outcome-pilot-review.v1"
_KINDS = Literal["prepare", "plan", "observe", "review"]


class GuidedIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: _KINDS
    pilot: str = Field(default="", pattern=r"^(?:OPL-[a-f0-9]{48})?$" )
    case: str = Field(default="", pattern=r"^(?:[1-9][0-9]?|100)?$")
    values: dict = Field(default_factory=dict, max_length=32)


class GuidedSaveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=2097152)
    confirmed: bool

router = APIRouter(tags=["outcome-pilots"])


class StrictIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True, allow_inf_nan=False)


class CoverageDeclarationIn(StrictIn):
    status: Literal["included", "zero", "unknown"]
    note: str = Field(..., min_length=1, max_length=1000)


class CaseIn(StrictIn):
    kind: Literal["goal", "vendor"]
    reference: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9-]+$")
    label: str = Field(..., min_length=1, max_length=200)


class PlanIn(StrictIn):
    operation_id: str = Field(..., min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    title: str = Field(..., min_length=1, max_length=200)
    customer: str = Field(..., min_length=1, max_length=200)
    workflow: str = Field(..., min_length=1, max_length=1000)
    criteria: str = Field(..., min_length=1, max_length=4000)
    cases: list[CaseIn] = Field(..., min_length=4, max_length=100)
    learning_mode: Literal["observational", "exclude_local_learning"] = "observational"
    prior_exposure_statement: str = Field(default="", max_length=2000)
    candidate_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class IndependentReviewIn(StrictIn):
    expected_revision: int = Field(..., ge=1)
    operation_id: str = Field(..., min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    evidence_version: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    decision: Literal["accepted_local_scope", "needs_more_evidence"]
    notes: str = Field(..., min_length=20, max_length=4000)
    confirm: bool


class ObservationIn(StrictIn):
    expected_revision: int = Field(..., ge=1)
    operation_id: str = Field(..., min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    source_version: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    baseline_minutes: float | None = Field(None, ge=0, le=1000000)
    ai_hands_on_minutes: float | None = Field(None, ge=0, le=1000000)
    review_minutes: float | None = Field(None, ge=0, le=1000000)
    rework_minutes: float | None = Field(None, ge=0, le=1000000)
    corrections: int | None = Field(None, ge=0, le=1000000)
    baseline_wall_minutes: float | None = Field(None, ge=0, le=1000000)
    ai_wall_minutes: float | None = Field(None, ge=0, le=1000000)
    baseline_cost: str | None = Field(None, pattern=r"^(0|[1-9][0-9]{0,11})(\.[0-9]{1,6})?$")
    ai_total_cost: str | None = Field(None, pattern=r"^(0|[1-9][0-9]{0,11})(\.[0-9]{1,6})?$")
    human_cost: str | None = Field(None, pattern=r"^(0|[1-9][0-9]{0,11})(\.[0-9]{1,6})?$")
    rework_cost: str | None = Field(None, pattern=r"^(0|[1-9][0-9]{0,11})(\.[0-9]{1,6})?$")
    currency: str | None = Field(None, pattern=r"^[A-Z]{3}$")
    evidence: str = Field(..., min_length=1, max_length=4000)
    note: str = Field(..., min_length=1, max_length=4000)
    criteria_met: bool | None = None
    cost_coverage: dict[str, CoverageDeclarationIn] | None = None

    @model_validator(mode="after")
    def cost_currency(self):
        if any(value is not None for value in (self.baseline_cost, self.ai_total_cost, self.human_cost, self.rework_cost)) and self.currency is None:
            raise ValueError("Currency is required for a reported cost.")
        if self.cost_coverage is not None and set(self.cost_coverage) != set(COST_COVERAGE_FAMILIES):
            raise ValueError("Declare every required delivered-cost family exactly once.")
        return self


class PreparedTaskIn(StrictIn):
    operation_id: str = Field(..., min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=4000)
    domain: str = Field(..., min_length=1, max_length=100)


def _context(request, *, mutation=False):
    require_permission(request, "operate")
    if config.config_source_errors(include_tenant=True) or config.get_features().get("outcome_measurement") is not True:
        raise HTTPException(403, "Outcome measurement is disabled in Settings or configuration is unavailable.")
    context = context_for(request)
    header = request.headers.get("X-Lightwork-Pilot-Context")
    if (mutation or header is not None) and not constant_time_equals(header or "", context):
        raise HTTPException(409, {
            "code": "pilot_context_changed",
            "message": "The account or workspace changed. Reload the pilot page.",
        })
    return context


async def _call(function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except HTTPException:
        raise
    except RecordConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except CandidatePromotionConflict as exc:
        raise HTTPException(409, "The candidate changed. Review its current release state and try again.") from exc
    except CandidatePromotionNotFound as exc:
        raise HTTPException(404, "The selected candidate is unavailable in this workspace.") from exc
    except LookupError as exc:
        raise HTTPException(404, "The pilot or source is unavailable in this account and workspace.") from exc
    except PermissionError as exc:
        raise HTTPException(403, "This source is no longer accessible.") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "Pilot records are unavailable. Refresh before retrying; your inputs have been retained.") from exc


def _resolver(request, *, independent_review=False):
    if independent_review:
        return partial(outcome_pilot_sources.resolve, request, independent_review=True)
    return partial(outcome_pilot_sources.resolve, request)


@router.get("/outcome-pilots")
async def page(request: Request):
    from .app import templates

    context = context_for(request)
    _current_actor(request, context)
    enabled = not config.config_source_errors(include_tenant=True) and config.get_features().get("outcome_measurement") is True
    return templates.TemplateResponse(request, "outcome_pilots.html", {"pilot_context": context, "pilot_enabled": enabled},
                                      headers={"Cache-Control": "private, no-store"})


@router.get("/api/v1/outcome-pilots")
async def list_pilots(
    request: Request,
    response: Response,
    limit: int = Query(100, ge=1, le=200),
    cursor: str = Query("", max_length=256, pattern=r"^[A-Za-z0-9_.:-]*$"),
):
    context = _context(request)
    response.headers["Cache-Control"] = "private, no-store"
    return {
        **await _call(outcome_pilots.listing, context, cursor=cursor, limit=limit),
        "context": context,
    }


@router.post("/api/v1/outcome-pilots")
async def create_pilot(request: Request, response: Response, body: PlanIn):
    _context(request, mutation=True)
    response.headers["Cache-Control"] = "private, no-store"
    return await _call(_legacy_mutation, request, "plan", body)


@router.get("/api/v1/outcome-pilots/release-candidates")
async def release_candidates(request: Request, response: Response):
    context = _context(request)
    response.headers["Cache-Control"] = "private, no-store"
    return {**await _call(outcome_pilot_releases.choices, request), "context": context}


@router.get("/api/v1/outcome-pilots/sources")
async def pilot_sources(request: Request, response: Response):
    context = _context(request)
    response.headers["Cache-Control"] = "private, no-store"
    return {**await _call(outcome_pilot_sources.choices, request), "context": context}


@router.get("/api/v1/outcome-pilots/independent-review")
async def review_queue(request: Request, response: Response):
    """Pilots in this workspace waiting for this administrator's independent
    review, so a reviewer picks one instead of typing its reference."""
    context = _context(request)
    require_global_permission(request, "admin")
    actor = caller_principal(request) or ""
    if not actor.startswith("user:"):
        raise HTTPException(403, "A different named global administrator must review this pilot.")
    response.headers["Cache-Control"] = "private, no-store"
    return {"items": await _call(outcome_pilots.review_queue, actor), "context": context}


@router.get("/api/v1/outcome-pilots/{pilot_id}")
async def pilot_report(request: Request, response: Response, pilot_id: str):
    from .outcome_pilot_costs_api import report_for

    context = _context(request)
    actor = caller_principal(request) or "local:dashboard"
    resolver = _resolver(request)
    response.headers["Cache-Control"] = "private, no-store"
    record = await _call(
        outcome_pilots.prepare_admission, pilot_id, context=context,
        resolve=resolver,
    )
    manifest = await _call(
        outcome_accounting_bridge.admit_pilot, record, resolve=resolver,
    )
    record = await _call(
        outcome_pilots.complete_admission, record["id"], manifest,
        context=context, actor=actor, resolve=resolver,
    )
    admissions = await _call(
        outcome_accounting_bridge.require_complete_admission, record,
    )
    for accounting in admissions.values():
        await _call(
            outcome_accounting_bridge.reconcile_record,
            request,
            context,
            accounting["id"],
        )
    return {**await _call(outcome_pilots.report, record, resolve=resolver),
            "provider_costs": await report_for(request, record), "context": context}


@router.get("/api/v1/outcome-pilots/{pilot_id}/release-status")
async def release_status(request: Request, response: Response, pilot_id: str):
    context = _context(request)
    response.headers["Cache-Control"] = "private, no-store"
    record = await _call(outcome_pilots.get, pilot_id, context)
    raw_binding = record.get("release_binding")
    if raw_binding is None:
        raise HTTPException(404, "This pilot has no candidate release binding.")
    binding = await _call(outcome_pilot_releases.ReleaseBinding, **raw_binding)
    return {**await _call(outcome_pilot_releases.status, request, binding),
            "pilot_id": pilot_id, "plan_version": record["plan_version"], "context": context}


@router.post("/api/v1/outcome-pilots/prepared-tasks")
async def prepare_task(request: Request, response: Response, body: PreparedTaskIn):
    # The goal rate limit is charged once, in execute_native, which every
    # route to a new prepared task passes through.
    _context(request, mutation=True)
    response.headers["Cache-Control"] = "private, no-store"
    return await _call(_legacy_mutation, request, "prepare", body)


@router.put("/api/v1/outcome-pilots/{pilot_id}/cases/{case_id}")
async def observation(request: Request, response: Response, pilot_id: str, case_id: str, body: ObservationIn):
    _context(request, mutation=True)
    response.headers["Cache-Control"] = "private, no-store"
    return await _call(_legacy_mutation, request, "observe", body, pilot_id, case_id)


@router.get("/api/v1/outcome-pilots/independent-review/{pilot_id}")
async def independent_packet(request: Request, response: Response, pilot_id: str):
    context = _context(request)
    require_global_permission(request, "admin")
    actor = caller_principal(request) or ""
    record = await _call(outcome_pilots.STORE.get, pilot_id)
    if record is None or not actor.startswith("user:") or actor == record["actor"]:
        raise HTTPException(403, "A different named global administrator must review this pilot.")
    await _call(outcome_accounting_bridge.require_complete_admission, record)
    for case in record["cases"]:
        await _call(outcome_pilot_sources.resolve, request, case["kind"], case["reference"])
    response.headers["Cache-Control"] = "private, no-store"
    return {**await _call(outcome_pilots.report, record, resolve=_resolver(request)), "context": context}


@router.post("/api/v1/outcome-pilots/independent-review/{pilot_id}")
async def independent_decision(request: Request, response: Response, pilot_id: str, body: IndependentReviewIn):
    _context(request, mutation=True)
    require_global_permission(request, "admin")
    response.headers["Cache-Control"] = "private, no-store"
    return await _call(_legacy_mutation, request, "review", body, pilot_id)


def _current_actor(request, context, *, write=False, review=False):
    """One current authority contract for ordinary and conversational controls."""
    from . import auth
    from .app import _require_same_origin

    with auth.fresh_configuration():
        auth.require_permission(request, "operate")
        if context_for(request) != context:
            raise HTTPException(409, "Your account, workspace or access changed. Reload the pilot page.")
        if review:
            auth.require_global_permission(request, "admin")
            if write:
                auth.require_api_key_scope(request, "approvals:decide")
        actor = caller_principal(request) or "local:dashboard"
        if write:
            _require_same_origin(request)
            _context(request)
            try:
                check_learning_halt("outcome-pilots", "write")
            except Halted as exc:
                raise HTTPException(409, "Learning is stopped. Resume it in Settings before changing this pilot.") from exc
        return actor


def _display(value):
    if value is None or value == "":
        return "Not recorded"
    if type(value) is bool:
        return "Yes" if value else "No"
    return str(value)


def _record(request, pilot, context, *, review=False):
    actor = _current_actor(request, context, review=review)
    row = outcome_pilots.STORE.get(pilot) if review else outcome_pilots.get(pilot, context)
    if row is None or (review and (not actor.startswith("user:") or actor == row["actor"])):
        raise HTTPException(403, "A different named administrator must review this pilot.")
    return row


def _material(request, body):
    """Pure full review of the current native inputs; never repairs admission."""
    context = _context(request)
    actor = _current_actor(request, context, write=True, review=body.kind == "review")
    values = {**body.values, "operation_id": "reviewed-pilot-operation"}
    row, sources = None, []
    if body.kind == "prepare":
        values = PreparedTaskIn.model_validate(values).model_dump()
        catalogue = outcome_pilot_sources.choices(request)
        specialist = next((item for item in catalogue["specialists"] if item["domain"] == values["domain"]), None)
        if specialist is None:
            raise HTTPException(409, "Choose a currently permitted agent or specialist with a reviewed result.")
        source_binding = catalogue["specialists"]
        changes = [{"label": "Task name", "after": values["title"]},
                   {"label": "Agent or specialist", "after": specialist["label"]},
                   {"label": "Task instructions", "after": values["description"]},
                   {"label": "What happens", "after": "Save one blocked task. No AI runs or spending occur. Start it separately after freezing the pilot plan."}]
    elif body.kind == "plan":
        values = PlanIn.model_validate(values).model_dump(exclude_none=True)
        resolver = _resolver(request)
        for case in values["cases"]:
            source = resolver(case["kind"], case["reference"])
            if not source["unstarted"]:
                raise HTTPException(409, "Every selected case must still be unstarted. Keep your plan and choose current cases.")
            sources.append({"kind": case["kind"], "reference": case["reference"], "title": source["title"], "version": source["version"], "input_version": source["input_version"]})
        candidate = outcome_pilot_releases.bind(request, values["candidate_id"]) if values.get("candidate_id") else None
        source_binding = [sources, {key: value for key, value in asdict(candidate).items() if key != "observed_at"} if candidate else None]
        changes = [{"label": label, "after": _display(values.get(name))} for name, label in
                   (("title", "Pilot name"), ("customer", "Customer or team"), ("workflow", "Workflow"),
                    ("criteria", "Acceptance criteria"), ("prior_exposure_statement", "Prior exposure checks and limitations"))]
        changes += [{"label": "Case " + str(index + 1), "after": case["label"] + " · source: " + sources[index]["title"] + " · unstarted · " + ("Task" if case["kind"] == "goal" else "Vendor intake")} for index, case in enumerate(values["cases"])]
        if candidate:
            changes.append({"label": "Candidate release", "after": "Candidate for " + candidate.target_id + ". Current release decision: " + {"awaiting_review": "waiting for review", "authorized": "approved for the release process", "staged": "staged for release"}[candidate.promotion_state] + ". The exact currently checked candidate and deployed baseline are retained with this fixed plan."})
        changes += [{"label": "Learning-data treatment", "after": "Keep the fixed evaluation tasks out of automatic local learning." if values["learning_mode"] == "exclude_local_learning" else "Record observations; local learning is unchanged."},
                    {"label": "Freeze this plan", "after": "The plan, criteria and random half-cohort evaluation allocation cannot be edited after saving. All cases receive outcome-accounting admission before they can be paired. No task starts. A partly saved plan is not automatically repeated."},
                    {"label": "Release evidence", "after": "A release is selected, but which release served each case remains unverified." if candidate else "No release is selected. This pilot records a workflow comparison, not proof that a release caused improvement."}]
    else:
        row = _record(request, body.pilot, context, review=body.kind == "review")
        outcome_accounting_bridge.require_complete_admission(row)
        resolver = _resolver(request, independent_review=body.kind == "review")
        report = outcome_pilots.report(row, resolve=resolver)
        sources = [{"id": case["id"], "version": (case.get("source") or {}).get("version")} for case in report["cases"]]
        source_binding = [row["revision"], row["plan_version"], sources, report["learning_policy"]["evidence_version"]]
        changes = [{"label": "Pilot", "after": row["title"]}, {"label": "Frozen acceptance criteria", "after": row["criteria"]}]
        if body.kind == "observe":
            case = next((item for item in report["cases"] if item["id"] == body.case), None)
            if case is None or not case.get("source"):
                raise HTTPException(409, "Choose a currently accessible case on the pilot page.")
            source = case["source"]
            if values.get("expected_revision", row["revision"]) != row["revision"] or values.get("source_version", source["version"]) != source["version"]:
                raise HTTPException(409, "The pilot or case changed. Keep your observations and review the current source again.")
            values.update(expected_revision=row["revision"], source_version=source["version"])
            values = ObservationIn.model_validate(values).model_dump()
            changes += [{"label": "Case and current outcome", "after": source["title"] + " · " + ("accepted" if source["accepted"] else "acceptance not established")},
                        {"label": "Group", "after": "Fixed evaluation" if case["allocation"] == "holdout" else "Process refinement"}]
            labels = {"baseline_minutes": "Baseline hands-on minutes", "ai_hands_on_minutes": "AI workflow hands-on minutes", "review_minutes": "Review minutes", "rework_minutes": "Rework minutes", "corrections": "Corrections requested", "baseline_wall_minutes": "Baseline elapsed minutes", "ai_wall_minutes": "AI workflow elapsed minutes", "baseline_cost": "Total baseline cost", "ai_total_cost": "Total AI workflow cost", "human_cost": "Human preparation and review cost", "rework_cost": "Rework cost", "currency": "Currency", "evidence": "Observation and cost evidence", "note": "Method and limitations", "criteria_met": "Met the frozen criteria"}
            changes += [{"label": label, "before": _display((case.get("measurement") or {}).get(key)), "after": _display(values[key])} for key, label in labels.items()]
            for name in COST_COVERAGE_FAMILIES:
                coverage = (values.get("cost_coverage") or {}).get(name)
                changes.append({"label": name.replace("_", " ").capitalize() + " cost coverage", "after": "Not recorded" if not coverage else {"included": "Included in total", "zero": "Confirmed zero", "unknown": "Unknown"}[coverage["status"]] + ". " + coverage["note"]})
            changes.append({"label": "What changes", "after": "Replace this case’s current observation and retain its prior observation. These are attributed reports; they do not establish causal improvement, savings or provider-invoice accuracy."})
        else:
            policy = report["learning_policy"]
            if values.get("expected_revision", row["revision"]) != row["revision"] or values.get("evidence_version", policy["evidence_version"]) != policy["evidence_version"]:
                raise HTTPException(409, "The pilot or learning evidence changed. Review the current complete evidence again.")
            values.update(expected_revision=row["revision"], evidence_version=policy["evidence_version"])
            values = IndependentReviewIn.model_validate(values).model_dump()
            changes += [{"label": "Prior exposure checks", "after": row.get("prior_exposure_statement") or "Not recorded"},
                        {"label": "Automatic local learning exclusion", "after": "Recorded for every evaluation task" if policy["automatic_local_exclusion_enforced"] else "Not established for every evaluation task"}]
            for case in report["cases"]:
                if not case.get("source"):
                    raise HTTPException(403, "Every case must have current permitted source access before independent review.")
                changes.append({"label": "Case " + case["id"], "after": case["source"]["title"] + " · " + ("fixed evaluation" if case["allocation"] == "holdout" else "process refinement") + " · " + ("exclusion recorded" if (case.get("learning_exclusion") or {}).get("enforced") else "exclusion not established")})
            previous = row.get("independent_review") or {}
            changes += [{"label": "Independent decision", "before": "No previous decision" if not previous else {"accepted_local_scope": "Accepted for this installation", "needs_more_evidence": "More evidence needed"}[previous["decision"]], "after": "Accept the stated local scope" if values["decision"] == "accepted_local_scope" else "More evidence needed"},
                        {"label": "Evidence checked and limitations", "before": previous.get("notes") or "Not recorded", "after": values["notes"]},
                        {"label": "What this decision covers", "after": "Only this installation’s fixed plan and local learning exclusions. It does not certify provider training or causal customer improvement. Publishing and starting work remain separate."}]
    values.pop("operation_id")
    revision = outcome_pilots.digest([context, actor, body.kind, body.pilot, body.case, values, source_binding])
    _current_actor(request, context, write=True, review=body.kind == "review")
    return {"kind": body.kind, "pilot": body.pilot, "case": body.case, "values": values,
            "context": context, "actor": actor, "revision": revision, "changes": changes}


def prepare_native(request, body):
    prepared = _material(request, GuidedIn.model_validate(body))
    return {**prepared, "expires": time.time() + 300}


def _legacy_mutation(request, kind, body, pilot="", case=""):
    """Keep legacy input/response shapes while using the same guarded writer."""
    values = body.model_dump(exclude_none=kind == "plan")
    operation = values.pop("operation_id")
    # An exact saved legacy operation remains a read, never admission repair.
    original = original_native(request, kind, operation, pilot, case)
    if original["found"]:
        if not original["confirmed"]:
            raise HTTPException(503, "The original change is not confirmed. Check current records; it was not repeated.")
        original_native(request, kind, operation, pilot, case, prepared={"values": values})
        if kind == "review":
            # Reading an independent review's receipt still requires current
            # access to every source it judged, exactly like its review packet.
            row = outcome_pilots.STORE.get(pilot) or {"cases": []}
            for item in row["cases"]:
                outcome_pilot_sources.resolve(request, item["kind"], item["reference"], independent_review=True)
    else:
        prepared = prepare_native(request, {"kind": kind, "pilot": pilot, "case": case, "values": values})
        original = execute_native(request, prepared, operation)
        if not original["confirmed"]:
            raise HTTPException(503, original["message"])
    if kind == "prepare":
        return {"id": int(original["href"].rsplit("/", 1)[1]), "title": original["title"], "href": original["href"], "context": original["context"]}
    identifier = "OPL-" + outcome_pilots.digest([original["context"], operation])[:48] if kind == "plan" else pilot
    row = outcome_pilots.STORE.get(identifier)
    return {"id": identifier, "revision": row["revision"], "context": original["context"]}


def original_native(request, kind, operation, pilot="", case="", *, prepared=None):
    """Read exact native operation custody. No admission repair or audit flush."""
    context = context_for(request)
    actor = _current_actor(request, context, review=kind == "review")
    if not isinstance(operation, str) or not 16 <= len(operation) <= 100 or not operation.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(422, "Choose an original request from this page.")
    confirmed, found, title, href = False, False, "", "/outcome-pilots"
    if kind == "prepare":
        from .app import _world
        from .auth import can_access_goal

        world = _world()
        identifier = world.lookup_processed_message("outcome-pilot-preparation", outcome_pilots.digest([context, operation]))
        found = identifier is not None
        goal = world.get_goal(identifier) if identifier else None
        if goal is not None and goal.owner == (caller_principal(request) or "") and can_access_goal(request, goal):
            if prepared and (goal.title, goal.description, goal.domain) != tuple(prepared["values"][key] for key in ("title", "description", "domain")):
                raise HTTPException(409, "This original request belongs to other task inputs.")
            confirmed, title, href = True, goal.title, f"/chat/goal/{goal.id}"
    else:
        identifier = "OPL-" + outcome_pilots.digest([context, operation])[:48] if kind == "plan" else pilot
        row = outcome_pilots.STORE.get(identifier)
        if row is None and kind == "plan":
            found = outcome_pilots.original_plan_claim(identifier, outcome_pilots.digest({**prepared["values"], "operation_id": operation}) if prepared else None)
        if row is not None:
            if kind == "review":
                if actor == row["actor"]:
                    raise HTTPException(403, "The pilot’s creator cannot perform its independent review.")
            else:
                outcome_pilots._owned(row, context)
                if row["actor"] != actor:
                    raise HTTPException(403, "This original request belongs to another account.")
            values = {**prepared["values"], "operation_id": operation} if prepared else None
            if kind == "plan":
                found = True
                if values and row["creation_request"] != outcome_pilots.digest(values):
                    raise HTTPException(409, "This original request belongs to another plan.")
                try:
                    outcome_pilots.validate_admission_manifest(row, require_complete=True)
                    confirmed = row.get("state") == "frozen"
                except RecordConflict:
                    confirmed = False
            else:
                marker = row.get("review_operations" if kind == "review" else "operations", {}).get(operation)
                found = marker is not None
                if values:
                    expected = outcome_pilots.digest([actor if kind == "review" else case, {key: value for key, value in values.items() if key != "expected_revision"}])
                    if marker is not None and marker != expected:
                        raise HTTPException(409, "This original request belongs to another reviewed action.")
                # The independent native marker binds actor even when the
                # source subsequently changes. A bare public reference cannot
                # authenticate another administrator’s review receipt.
                if kind == "review" and not prepared:
                    history = [*(row.get("independent_review_history") or []), row.get("independent_review") or {}]
                    found = found and any(item.get("actor") == actor and item.get("operation_id") == operation for item in history)
                confirmed = found
            confirmed = confirmed and not row.get("_audit_pending")
            if found:
                title, href = row["title"], "/outcome-pilots?pilot=" + identifier
    _current_actor(request, context, review=kind == "review")
    return {"confirmed": confirmed, "found": found, "context": context, "kind": kind, "operation": operation,
            "title": title, "href": href, "message": ("The original observation is recorded. Linked accounting may still be incomplete; check the current report. No work was repeated." if kind == "observe" else "The original request is recorded. No work was repeated.") if confirmed else "The original result is not confirmed. It may be partly saved. Check current records; this request was not repeated."}


def execute_native(request, prepared, operation):
    kind, pilot, case = prepared["kind"], prepared["pilot"], prepared["case"]
    with authority_effect_fence():
        original = original_native(request, kind, operation, pilot, case, prepared=prepared)
        if original["found"]:
            return original
        def guard():
            _current_actor(request, prepared["context"], write=True, review=kind == "review")
            if time.time() >= prepared["expires"]:
                raise HTTPException(409, "This review expired. Keep your inputs and prepare a fresh review.")
            current = _material(request, GuidedIn(kind=kind, pilot=pilot, case=case, values=prepared["values"]))
            if current["revision"] != prepared["revision"]:
                raise HTTPException(409, "The current source or permissions changed after review. Keep your inputs and review again.")
        guard()
        values = {**prepared["values"], "operation_id": operation}
        try:
            if kind == "prepare":
                from .app import check_goal_rate_limit

                check_goal_rate_limit(request)
                outcome_pilot_sources.prepare_task(request, values, prepared["context"], before_write=guard)
            elif kind == "plan":
                resolver = _resolver(request)
                row = outcome_pilots.create(values, context=prepared["context"], actor=prepared["actor"], resolve=resolver,
                    resolve_release=partial(outcome_pilot_releases.bind, request), before_write=guard)
                manifest = outcome_accounting_bridge.admit_pilot(row, resolve=resolver)
                outcome_pilots.complete_admission(row["id"], manifest, context=prepared["context"], actor=prepared["actor"], resolve=resolver, before_write=guard)
            elif kind == "observe":
                row = outcome_pilots.observe(pilot, case, values, context=prepared["context"], actor=prepared["actor"], resolve=_resolver(request), before_write=guard)
                selected = next(item for item in row["cases"] if item["id"] == case)
                source = outcome_pilot_sources.resolve(request, selected["kind"], selected["reference"])
                outcome_accounting_bridge.sync_case(row, case, source, source_operation_id=operation, actor=prepared["actor"])
            else:
                outcome_pilots.independent_review(pilot, values, actor=prepared["actor"], resolve=_resolver(request, independent_review=True), before_write=guard)
        except Exception:
            original = original_native(request, kind, operation, pilot, case, prepared=prepared)
            if not original["found"]:
                raise
            return {**original, "confirmed": False, "message": "The change may be partly saved. Its completion could not be confirmed. Check current records; no work was repeated."}
        return original_native(request, kind, operation, pilot, case, prepared=prepared)


@router.get("/api/v1/outcome-pilot-controls")
async def current_controls(request: Request, response: Response):
    context = context_for(request)
    response.headers["Cache-Control"] = "private, no-store"
    _current_actor(request, context)
    return {"context": context, "enabled": not config.config_source_errors(include_tenant=True) and config.get_features().get("outcome_measurement") is True}


@router.post("/api/v1/outcome-pilot-controls/review")
async def guided_review(request: Request, response: Response, body: GuidedIn):
    prepared = await _call(prepare_native, request, body.model_dump())
    material = {"purpose": REVIEW_PURPOSE, "prepared": prepared, "operation": secrets.token_hex(16)}
    token = crypto_at_rest.seal_to_str(json.dumps(material, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 2097152:
        raise HTTPException(413, "The complete review is too large. Keep your work and use fewer cases.")
    response.headers["Cache-Control"] = "private, no-store"
    return {"token": token, "operation": material["operation"], "context": prepared["context"], "changes": prepared["changes"]}


@router.post("/api/v1/outcome-pilot-controls/save")
async def guided_save(request: Request, response: Response, body: GuidedSaveIn):
    if body.confirmed is not True:
        raise HTTPException(422, "Confirm the complete displayed review before saving.")
    try:
        material = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if material["purpose"] != REVIEW_PURPOSE:
            raise ValueError("wrong purpose")
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(409, "This review is unavailable. Keep your inputs and review again.") from exc
    response.headers["Cache-Control"] = "private, no-store"
    return await _call(execute_native, request, material["prepared"], material["operation"])


@router.get("/api/v1/outcome-pilot-controls/original")
async def guided_original(request: Request, response: Response, kind: _KINDS,
                          operation: str = Query(min_length=16, max_length=100),
                          pilot: str = Query("", max_length=52), case: str = Query("", max_length=3)):
    response.headers["Cache-Control"] = "private, no-store"
    return await _call(original_native, request, kind, operation, pilot, case)
