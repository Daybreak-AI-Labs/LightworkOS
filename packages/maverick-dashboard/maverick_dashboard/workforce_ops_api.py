"""Workforce and task-page buttons for commands that were terminal-only:
``domains-audit`` (what each specialist can do and what stops it, with the
full document as a download), ``domains-lint`` (check every specialist's
setup, as a background job), ``domains-eval`` (check the specialist test
suite), ``forward`` (tasks coming due) and ``fleet-memory --register`` (add
an outside agent to the shared-memory list).

Reads need ``view`` and follow the page's own scoping: the coming-due list
shows only the tasks the person may see. The downloadable inventory, the
setup check and adding an outside agent need a workspace administrator; the
changes write one activity-record row naming the person first.
"""
from __future__ import annotations

import json
import time
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .auth import domain_suites_allowed, goal_owner_filter, require_permission
from .learning_ops_api import _choice, _clip, _world, start_job

router = APIRouter(prefix="/workforce-ops", tags=["workforce-ops"])

_FINDINGS = (
    ("allow_tools is empty", "It has no list of allowed tools, so it could use every tool."),
    ("max_risk is unset", "It has no limit on how risky its actions may be."),
    ("max_risk", "Its risk limit is not a level Lightwork recognises."),
    ("effort", "Its effort level is not a level Lightwork recognises."),
    ("both allowed and denied", "Some tools are both allowed and blocked. Blocked wins."),
    ("persona under", "Its description of who it is, is very short."),
    ("description is empty", "It has no description for the list of agents and specialists."),
    ("no knowledge_sources", "It has no reference sources to base its work on."),
    ("no deny_tools", "It does not explicitly block any tools."),
    ("read-only pack", "It only reads, but does not explicitly block tools that change things."),
    ("output.gate", "Its sign-off rule is lighter than the sign-off on its last step."),
    ("workflow", "A step in its playbook has a problem."),
    ("step", "A step in its playbook has a problem."),
    ("tool", "It lists a tool that is not available, or is riskier than its limit allows."),
)
_VENDORS = {"salesforce": "Salesforce Agentforce", "microsoft": "Microsoft Copilot",
            "google": "Google Gemini", "servicenow": "ServiceNow", "openai": "OpenAI",
            "anthropic": "Anthropic", "open-source": "Open-source agent", "custom": "Built in-house"}


class AgentIn(BaseModel):
    vendor: Literal["salesforce", "microsoft", "google", "servicenow", "openai", "anthropic",
                    "open-source", "custom"]
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    description: str = Field(default="", max_length=200)


class ToolCallExpectIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    contains: str = Field(default="", max_length=100)


class ToolResultIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=500)


class SpecialistCaseIn(BaseModel):
    specialist: str = Field(min_length=1, max_length=100)
    task: str = Field(min_length=8, max_length=1000)
    includes: list[str] = Field(default_factory=list, max_length=8)
    excludes: list[str] = Field(default_factory=list, max_length=8)
    refusal: bool = False
    citation: bool = False
    # Tool checks ([agent_tests] tool_checks): which tools the specialist must or must not call.
    with_tools: bool = False
    tools_called: list[ToolCallExpectIn] = Field(default_factory=list, max_length=10)
    tools_not_called: list[str] = Field(default_factory=list, max_length=10)
    tool_results: list[ToolResultIn] = Field(default_factory=list, max_length=10)
    identity: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    expected_revision: int | None = Field(default=None, ge=1)


class SpecialistCaseDelete(BaseModel):
    specialist: str = Field(min_length=1, max_length=100)
    identity: str = Field(pattern=r"^[a-f0-9]{32}$")
    expected_revision: int = Field(ge=1)


class SpecialistRunIn(BaseModel):
    specialist: str = Field(min_length=1, max_length=100)
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    # A whole saved set can run at once, up to the [agent_tests] limit (checked when the run starts).
    case_ids: list[str] = Field(default_factory=list, max_length=200)
    case_revisions: dict[str, int] = Field(min_length=1, max_length=200)


class SpecialistCompareIn(SpecialistRunIn):
    case_ids: list[str] = Field(min_length=1, max_length=200)
    proposed_instructions: str = Field(min_length=8, max_length=6000)
    baseline_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_context: str = Field(pattern=r"^[a-f0-9]{64}$")


def _audit(request: Request, action: str, **detail: Any) -> None:
    from maverick.audit import AuditRefused, EventKind, audit_event

    from .auth import caller_principal
    try:
        audit_event(EventKind.CONTROL_PLANE_ACTION, agent="dashboard", verb=action,
                    actor=caller_principal(request) or "local administrator", ok=True, **detail)
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail=(
            "The activity record could not be written, so nothing was done.")) from exc


def _name(pack: str) -> str:
    from .plain_labels import pack_display_name
    return pack_display_name(pack)


def _finding(text: str) -> str:
    low = text.lower()
    return next((plain for needle, plain in _FINDINGS if needle in low), "Another setup problem.")


# ---- what each specialist can do (domains-audit) ----------------------------------

def _audits(suite: str | None, *, runtime: bool = True):
    from maverick.domain_audit import audit_roster
    audits = audit_roster(runtime=runtime)
    suites = sorted({a.suite for a in audits if a.suite})
    if suite:
        if suite not in suites:
            raise HTTPException(status_code=422, detail="Choose a department from the list.")
        audits = [a for a in audits if a.suite == suite]
    return audits, suites


def _inventory(suite: str | None) -> dict:
    from maverick.agent_autonomy import levels_enabled
    from maverick.departments import department_title
    from maverick.domain_audit import summarize
    # The inventory shows no runtime capability: skip computing it (about 80 ms).
    audits, suites = _audits(suite, runtime=False)
    s = summarize(audits)
    flagged = [a for a in audits if a.reachable_dangerous and not a.is_builder]
    return {
        "suites": [{"value": x, "label": department_title(x)}
                   for x in sorted(suites, key=department_title)],
        "specialists": s["packs"], "departments": s["suites"], "builders": s["builders"],
        "can_change_things_while_drafting": s["drafting_agents_reaching_a_mutator"],
        "sign_off_enforced": s["packs_with_human_gate"],
        "sign_off_only_asked": s["packs_with_unenforced_prompt_gate"],
        "extra_refusals": s["packs_with_refusals_beyond_universal"],
        "with_deliverable": s["packs_with_deliverable"],
        "levels_enabled": levels_enabled(),
        "independence": s.get("autonomy_posture", {}),
        "still_supervised": s.get("packs_onboarding", 0),
        "flagged": [{"specialist": _name(a.name),
                     "can_reach": [x.replace("_", " ") for x in a.reachable_dangerous][:10]}
                    for a in flagged][:100],
    }


@router.get("/inventory")
async def inventory(request: Request, suite: str | None = Query(default=None, max_length=80)) -> dict:
    require_permission(request, "view")
    return await run_in_threadpool(_inventory, suite or None)


@router.get("/inventory/download")
async def inventory_download(request: Request, suite: str | None = Query(default=None, max_length=80)) -> Response:
    require_permission(request, "admin")
    from maverick.domain_audit import to_json
    audits, _suites = await run_in_threadpool(_audits, suite or None)
    await run_in_threadpool(lambda: _audit(request, "specialist_inventory_download",
                                           suite=suite or "", specialists=len(audits)))
    body = json.dumps(to_json(audits), indent=2)
    return Response(body, media_type="application/json", headers={
        "Content-Disposition": 'attachment; filename="Lightwork-specialist-inventory.json"',
        "Cache-Control": "private, no-store"})


# ---- check every specialist's setup (domains-lint) -----------------------------------

@router.post("/setup-check")
async def setup_check(request: Request) -> dict:
    require_permission(request, "admin")

    def _run(job) -> dict:
        from maverick.domain import available_domains, lint_profile
        domains = available_domains()
        rows, n_err, n_warn = [], 0, 0
        for name in sorted(domains):
            if job.cancelled:
                break
            errors, warnings = lint_profile(domains[name])
            n_err += len(errors)
            n_warn += len(warnings)
            if errors or warnings:
                rows.append({"specialist": _name(name), "must_fix": sorted({_finding(e) for e in errors}),
                             "could_improve": sorted({_finding(w) for w in warnings}),
                             "technical": [_clip(x, 240) for x in (errors + warnings)[:10]]})
        rows.sort(key=lambda r: (-len(r["must_fix"]), r["specialist"]))
        return {"specialists": len(domains), "must_fix": n_err, "could_improve": n_warn,
                "findings": rows[:300], "more": max(0, len(rows) - 300)}
    return start_job(request, "specialist_setup_check", "Checking every specialist's setup", _run,
                     needs_global=False, cancellable=True)


# ---- specialist test suite (domains-eval --check) ----------------------------------

def _test_suite() -> dict:
    from maverick.domain_eval import GOLDEN_CASES, check_suite
    problems = check_suite()
    cases = []
    for c in GOLDEN_CASES[:200]:
        checks = []
        if c.expect_includes:
            checks.append("mentions " + ", ".join(c.expect_includes))
        if c.expect_excludes:
            checks.append("never mentions " + ", ".join(c.expect_excludes))
        if c.expect_refusal:
            checks.append("refuses")
        if c.expect_citation:
            checks.append("cites a source")
        cases.append({"specialist": _name(c.domain), "task": _clip(c.task, 200), "expects": checks})
    return {"cases": len(GOLDEN_CASES), "specialists": len({c.domain for c in GOLDEN_CASES}),
            "problems": len(problems), "technical": [_clip(p, 240) for p in problems[:50]],
            "list": cases}


@router.get("/test-suite")
async def test_suite(request: Request) -> dict:
    require_permission(request, "view")
    return await run_in_threadpool(_test_suite)


def _test_profile(request: Request, name: str):
    from maverick.domain import available_domains

    from . import specialist_drafts
    # A specialist not yet published keeps its saved checks against its own saved draft.
    profile = available_domains().get(name) or specialist_drafts.unpublished_profiles(request, name=name).get(name)
    if profile is None:
        raise HTTPException(status_code=404, detail="Choose an agent or specialist from the list.")
    if not domain_suites_allowed(request, name):
        raise HTTPException(status_code=403, detail="You cannot access the department this one belongs to.")
    return profile


@router.get("/test-suite/specialists")
async def test_specialists(request: Request) -> dict:
    require_permission(request, "view")
    from maverick.domain import available_domains

    from .plain_labels import pack_display_name
    profiles = _test_profiles(request)
    published = set(available_domains())
    return {"specialists": [{"value": name, "label": pack_display_name(name, profile.persona, profile.description)
                             + ("" if name in published else " · not published yet")}
                           for name, profile in sorted(profiles.items())]}


def _test_profiles(request: Request) -> dict:
    from maverick.domain import available_domains, suites_for_domain

    from . import specialist_drafts
    from .auth import caller_suites
    # Published specialists first; a specialist not yet published appears once, from its own saved draft.
    profiles = {**specialist_drafts.unpublished_profiles(request), **available_domains()}
    allowed = caller_suites(request)
    return {name: profile for name, profile in profiles.items()
            if allowed is None or suites_for_domain(name, profile) <= allowed}


@router.get("/test-suite/customer")
async def customer_tests(request: Request, specialist: str = Query(max_length=100)) -> dict:
    require_permission(request, "view")
    profile = _test_profile(request, specialist)
    from maverick.agent_tests_policy import tool_checks_enabled
    from maverick.llm import model_for_role

    from . import specialist_test_sets as saved
    from .draft_api import context_for
    revision = saved.instruction_digest(saved.answer_system(profile), model_for_role(specialist))
    cases = await run_in_threadpool(saved.cases_for, specialist)
    runs = await run_in_threadpool(saved.runs_for, specialist)
    # Complete private drafts are read only through their owned original route.
    # The older workspace test history keeps its existing audience and shape.
    runs = [run for run in runs if not run.get("comparison", {}).get("draft_profile")]
    require_permission(request, "view")
    _test_profile(request, specialist)
    for run in runs:
        _current_test_result(run, revision, cases)
    return {"specialist": specialist, "cases": cases, "max_checks": saved.max_cases_per_specialist(),
            "runs": runs, "current_instructions": profile.persona, "baseline_revision": revision,
            "context": context_for(request), "live_enabled": _live_tests_enabled(),
            "tool_checks_enabled": tool_checks_enabled()}


def _current_test_result(row, current_revision, cases):
    if row.get("comparison"):
        current = {case["id"]: case["revision"] for case in cases}
        row["baseline_current"] = row["instruction_hash"] == current_revision
        row["questions_current"] = all(current.get(case["id"]) == case["revision"] for case in row["case_revisions"])
    return row


def _match_test_comparison(row, actor, proposed, baseline, revisions):
    old = row.get("comparison") or {}
    if (row["actor"] != actor or old.get("proposed_instructions") != proposed
            or row["instruction_hash"] != baseline
            or {case["id"]: case["revision"] for case in row["case_revisions"]} != revisions):
        raise HTTPException(409, "This request no longer matches its original person, questions or instructions. No paid call was repeated.")


def _comparison_systems(profile, model, system, proposed, baseline):
    from dataclasses import replace

    from . import specialist_test_sets as saved
    if proposed is None:
        return {"current":system}, None
    if baseline != saved.instruction_digest(system, model):
        raise HTTPException(409, "The specialist instructions or model changed. Refresh and review the comparison before spending.")
    if not 8 <= len(proposed.strip()) <= 6000 or proposed.strip() == profile.persona.strip():
        raise HTTPException(422, "Write different proposed instructions of between 8 and 6,000 characters.")
    other = saved.answer_system(replace(profile, persona=proposed))
    return {"current":system, "proposed":other}, {"current_instructions":profile.persona,
        "proposed_instructions":proposed, "proposed_instruction_hash":saved.instruction_digest(other, model)}


class _ToolGuardStopped(Exception):
    """A tool check refused before its next provider call; nothing was sent."""


_STOPPED_BY_GUARD = "The questions, instructions, access or spending allowance changed. No further answers were requested."
_STOPPED_BY_BUDGET = "The spending or tool-call allowance was used up. No further answers were requested."


def _perform_answer_tests(job, *, specialist, model, instruction_hash, cases, actor,
                          operation_id, systems, comparison, budget, guard, instructions_key=None,
                          tested_instructions=None, draft_mode=False, persistence_guard=None,
                          tool_scope=((), ())):
    from maverick.agent_tests_policy import tool_checks_enabled
    from maverick.budget import BudgetExceeded
    from maverick.llm import LLM

    from . import specialist_test_sets as saved
    from .specialist_tool_checks import offered_tools, run_tool_check, tool_step_tokens
    run, created = saved.begin_run(specialist, model, instruction_hash, cases, actor, identity=operation_id,
                                   instructions_key=instructions_key, instructions=tested_instructions, effect_guard=persistence_guard)
    if not created:
        return {"run": run}
    llm = LLM(model)
    tools_on = tool_checks_enabled()
    allow, deny = tool_scope

    def tool_guard() -> None:
        # Tool requests cannot pass the guarded dispatch arguments (llm.complete fails them closed),
        # so the same authority check runs before every tool-check provider call instead.
        try:
            guard(job)
        except Exception as exc:  # noqa: BLE001 -- refuse before the next dispatch
            raise _ToolGuardStopped from exc
    final_state, message = "done", ""
    try:
        for index, case in enumerate(cases):
            variants = ["proposed"] if draft_mode else ((["proposed", "current"] if index % 2 else ["current", "proposed"]) if comparison else ["current"])
            for variant in variants:
                try:
                    guard(job)
                except Exception:  # noqa: BLE001 -- refuse before the next dispatch
                    final_state, message = "stopped", _STOPPED_BY_GUARD
                    break
                before = budget.dollars
                if case.get("with_tools") and not tools_on:
                    # Nothing is sent while the switch is off; the check counts as not passing.
                    result = saved.skipped_tool_check(case)
                elif case.get("with_tools"):
                    try:
                        text, tool_calls = run_tool_check(
                            llm, system=systems[variant], task=case["task"], case=case,
                            names=offered_tools(case, allow=list(allow), deny=list(deny)), budget=budget,
                            before_call=tool_guard, max_tokens=tool_step_tokens(budget.max_output_tokens))
                    except _ToolGuardStopped:
                        final_state, message = "stopped", _STOPPED_BY_GUARD
                        break
                    except BudgetExceeded:
                        final_state, message = "stopped", _STOPPED_BY_BUDGET
                        break
                    result = saved.grade(case, text, retain_full=draft_mode, tool_calls=tool_calls)
                else:
                    answer = llm.complete(systems[variant], [{"role": "user", "content": case["task"]}],
                                          tools=None, budget=budget, max_tokens=32 if draft_mode else (64 if comparison else 128),
                                          _no_failover=True, max_physical_attempts=1,
                                          dispatch_guard=lambda: guard(job))
                    result = saved.grade(case, answer.text, retain_full=draft_mode)
                if case.get("sample"):
                    result.update(sample=True, passed=False)
                if comparison:
                    result.update(variant=variant, spent_dollars=round(max(0.0, budget.dollars-before), 6))
                saved.append_result(run["id"], result, budget.dollars, effect_guard=persistence_guard)
            if final_state == "stopped":
                break
    except Exception:  # noqa: BLE001 -- provider dispatch may have been billable
        final_state = "unknown"
        message = ("A check could not finish. A provider call may have been billed; "
                   "no request was replayed. Review the completed answers and provider accounting.")
    return {"run": saved.finish_run(run["id"], final_state, budget.dollars, message, effect_guard=persistence_guard)}


def _live_tests_enabled() -> bool:
    from maverick import model_tests
    try:
        model_tests.policy()
    except PermissionError:
        return False
    return True


def _case_fields(body: SpecialistCaseIn) -> dict:
    def terms(values: list[str]) -> list[str]:
        cleaned = [" ".join(value.split()) for value in values]
        if any(not value or len(value) > 100 for value in cleaned):
            raise HTTPException(status_code=422, detail="Each phrase must be between 1 and 100 characters.")
        if len({value.casefold() for value in cleaned}) != len(cleaned):
            raise HTTPException(status_code=422, detail="Remove repeated phrases from this test.")
        return cleaned
    includes, excludes = terms(body.includes), terms(body.excludes)
    if not (includes or excludes or body.refusal or body.citation):
        raise HTTPException(status_code=422, detail="Say what the answer must or must not contain, or choose a refusal or source check.")
    if set(map(str.casefold, includes)) & set(map(str.casefold, excludes)):
        raise HTTPException(status_code=422, detail="The same phrase cannot be both required and forbidden.")
    task = " ".join(body.task.split())
    if len(task) < 8:
        raise HTTPException(status_code=422, detail="Write a question or request of at least 8 characters.")
    from maverick.agent_tests_policy import tool_checks_enabled

    from .specialist_tool_checks import normalized as tool_fields
    try:
        tools = tool_fields(enabled=tool_checks_enabled(), with_tools=body.with_tools,
                            called=[row.model_dump() for row in body.tools_called],
                            not_called=list(body.tools_not_called),
                            results=[row.model_dump() for row in body.tool_results])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"task": task, "includes": includes, "excludes": excludes,
            "refusal": body.refusal, "citation": body.citation, **tools}


@router.post("/test-suite/customer")
async def save_customer_test(request: Request, body: SpecialistCaseIn) -> dict:
    require_permission(request, "admin")
    _test_profile(request, body.specialist)
    fields = _case_fields(body)
    from . import specialist_test_sets as saved
    await run_in_threadpool(lambda: _audit(request, "specialist_test_save", specialist=body.specialist,
                                           test=body.identity or "new"))
    try:
        case = await run_in_threadpool(lambda: saved.save_case(
            body.specialist, fields, identity=body.identity, expected_revision=body.expected_revision))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"case": case}


@router.post("/test-suite/customer/remove")
async def remove_customer_test(request: Request, body: SpecialistCaseDelete) -> dict:
    require_permission(request, "admin")
    _test_profile(request, body.specialist)
    from . import specialist_test_sets as saved
    await run_in_threadpool(lambda: _audit(request, "specialist_test_remove", specialist=body.specialist,
                                           test=body.identity))
    try:
        await run_in_threadpool(lambda: saved.delete_case(body.specialist, body.identity,
                                                           body.expected_revision))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"removed": True}


def _start_customer_test_job(request: Request, specialist: str, *, operation_id: str | None = None,
                             case_ids: list[str] | None = None,
                             case_revisions: dict[str, int] | None = None,
                             proposed_instructions: str | None = None,
                             baseline_revision: str | None = None,
                             expected_context: str | None = None, draft=None, draft_guard=None, draft_started=None) -> dict:
    if draft is not None:
        return _start_draft_customer_test_job(request, specialist, operation_id, draft, draft_guard, draft_started)
    require_permission(request, "admin")
    profile = _test_profile(request, specialist)
    from maverick import model_tests
    from maverick.llm import model_for_role

    from . import learning_jobs
    from . import specialist_test_sets as saved
    from .auth import caller_principal
    from .draft_api import context_for
    actor = caller_principal(request) or "local administrator"
    if proposed_instructions is not None and expected_context != context_for(request):
        raise HTTPException(409, "Your account or workspace changed. Reload and review the comparison before spending.")
    if operation_id:
        existing = saved.run_by_id(operation_id)
        if existing is not None:
            if existing["specialist"] != specialist:
                raise HTTPException(status_code=409, detail="That test request belongs to another agent or specialist.")
            if existing.get("comparison") or proposed_instructions is not None:
                _match_test_comparison(existing, actor, proposed_instructions, baseline_revision, case_revisions)
            if existing["state"] != "prepared":
                return {"run": saved.public_run(existing), "replayed": True}
    try:
        model_tests.policy()
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=(
            "Turn on bounded model tests in Settings before checking live answers.")) from exc
    try:
        cases = saved.snapshot(specialist, case_ids)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if case_revisions is not None and {c["id"]: c["revision"] for c in cases} != case_revisions:
        raise HTTPException(status_code=409, detail="A selected check changed. Refresh and review it before spending.")
    model = model_for_role(specialist)
    system = saved.answer_system(profile)
    instruction_hash = saved.instruction_digest(system, model)
    systems, comparison = _comparison_systems(profile, model, system, proposed_instructions, baseline_revision)
    from .agent_publish_gate import instructions_key as _instructions_key
    from .learning_ops_api import _budget
    tested_key = None if comparison else _instructions_key(model, profile.persona)
    budget = _budget("specialist_eval")
    # Ceilings grow with the questions asked (5 questions keep the original
    # $0.25 / 640-token run), and still never exceed the configured caps.
    # A tool check counts as several questions and gets a few tool calls; none otherwise.
    from maverick.agent_tests_policy import tool_checks_enabled

    from .specialist_tool_checks import budget_questions, tool_call_ceiling
    tools_on = tool_checks_enabled()
    questions = budget_questions(cases, enabled=tools_on)
    for key, ceiling in (("max_dollars", round(.05 * questions, 2)), ("max_input_tokens", 2000 * questions),
                         ("max_output_tokens", 128 * questions), ("max_wall_seconds", max(120, 24 * questions)),
                         ("max_tool_calls", tool_call_ceiling(cases, enabled=tools_on))):
        current = getattr(budget, key)
        setattr(budget, key, ceiling if current is None else min(current, ceiling))
    try:
        budget.check()
    except Exception as exc:
        raise HTTPException(status_code=409, detail="The current spending limit does not allow this test run.") from exc

    def _guard(job) -> None:
        require_permission(request, "admin")
        current = _test_profile(request, specialist)
        model_tests.policy()
        if comparison and expected_context != context_for(request):
            raise ValueError("The reviewed account or workspace changed. No further answers were sent.")
        if (model_for_role(specialist) != model
                or saved.instruction_digest(saved.answer_system(current), model) != instruction_hash):
            raise ValueError("Its instructions or model changed. No further tests were sent.")
        if comparison and {case["id"]: case["revision"] for case in saved.snapshot(specialist, case_ids)} != case_revisions:
            raise ValueError("A selected question changed. No further comparison answers were sent.")
        if job.cancelled:
            raise ValueError("Stopped before the next answer check.")
        budget.check()

    def _run(job) -> dict:
        return _perform_answer_tests(job, specialist=specialist, model=model,
            instruction_hash=instruction_hash, cases=cases, actor=actor, operation_id=operation_id,
            systems=systems, comparison=comparison, budget=budget, guard=_guard,
            instructions_key=tested_key, tested_instructions=None if comparison else profile.persona,
            tool_scope=(tuple(profile.allow_tools), tuple(profile.deny_tools)))

    tool_cases = sum(1 for case in cases if case.get("with_tools")) if tools_on else 0
    _audit(request, "specialist_test_run", specialist=specialist,
           cases=len(cases), model=model, max_dollars=budget.max_dollars, comparison=comparison is not None,
           tool_checks=tool_cases)
    if operation_id:
        saved.reserve_run(specialist, model, instruction_hash, cases,
                          actor, operation_id, comparison=comparison, instructions_key=tested_key,
                          instructions=None if comparison else profile.persona)
    return start_job(request, "specialist_answer_test", "Checking specialist answers", _run,
                     needs_global=False, cancellable=True, on_cancel=learning_jobs.stop_budget(budget))


def _start_draft_customer_test_job(request, specialist, operation, draft, source_guard, started):
    """Use the unchanged answer runner with one exact, tool-free draft variant."""
    from maverick import domain, model_tests
    from maverick.authority_effects import authority_effect_fence
    from maverick.governed_operations import digest

    from . import learning_jobs
    from . import specialist_test_sets as saved
    from .learning_ops_api import _budget
    from .tools_ops_api import actor as current_actor

    require_permission(request, "admin")
    if not callable(source_guard) or not callable(started) or draft["name"] != specialist or draft["actor"] != current_actor(request):
        raise HTTPException(409, "The exact reviewed draft worker could not be admitted.")
    model_tests.policy()
    profile = domain._coerce(specialist, draft["profile"])
    model = draft["connection"]["model"]
    system = saved.answer_system(profile) + "\nEntered draft settings (instructions only; these grant no tools or connections):\n" + json.dumps(draft["profile"], ensure_ascii=False)
    cases = draft["cases"] if draft["action"] == "check" else [{"id": digest([operation, "sample"])[:32], "revision": 1,
        "specialist": specialist, "task": draft["task"], "includes": [], "excludes": [], "refusal": False, "citation": False, "sample": True}]
    if not 1 <= len(cases) <= saved.max_cases_per_specialist():
        raise HTTPException(409, "The complete chosen draft questions exceed the supported limit.")
    budget = _budget("specialist_eval")
    # Grows with the questions, as a saved-test run does; five or fewer keep the original $0.25 run.
    # A tool check counts as several questions and gets the same few tool calls as a saved-test run.
    from maverick.agent_tests_policy import tool_checks_enabled

    from .specialist_tool_checks import budget_questions, tool_call_ceiling
    tools_on = tool_checks_enabled()
    questions = budget_questions(cases, enabled=tools_on)
    for key, ceiling in (*saved.draft_answer_limits(questions).items(),
                         ("max_tool_calls", tool_call_ceiling(cases, enabled=tools_on))):
        current = getattr(budget, key)
        setattr(budget, key, ceiling if current is None else min(current, ceiling))
    source_guard(budget)
    comparison = {"draft_profile": draft["profile"], "connection": draft["connection"], "context": draft["context"],
        "proposed_instructions": profile.persona, "proposed_instruction_hash": saved.instruction_digest(system, model)}
    existing = saved.run_by_id(operation)
    if existing is not None:
        if existing["actor"] != draft["actor"] or existing.get("comparison") != comparison:
            raise HTTPException(409, "This original answer request belongs to a different complete draft.")
        raise HTTPException(409, "The original draft check already has a retained admission. Read it; no answer request was repeated.")
    saved.reserve_run(specialist, model, saved.instruction_digest(system, model), cases, draft["actor"], operation,
        comparison=comparison, single_variant=True, effect_guard=lambda: source_guard(budget))

    def guard(job):
        require_permission(request, "admin")
        model_tests.policy()
        source_guard(budget)
        if job.cancelled:
            raise ValueError("The draft answer check stopped before the next answer.")

    def run(job):
        with authority_effect_fence():
            guard(job)
            started(job, budget)
        result = _perform_answer_tests(job, specialist=specialist, model=model, instruction_hash=saved.instruction_digest(system, model),
            cases=cases, actor=draft["actor"], operation_id=operation, systems={"proposed": system}, comparison=comparison,
            budget=budget, guard=guard, draft_mode=True, persistence_guard=lambda: source_guard())
        # Private drafts, questions and answers remain in the owned native record,
        # never in the general background-job result visible to other admins.
        row = result["run"]
        return {"answer_check": {"state": row["state"], "received": len(row["results"]), "passed": row["passed"], "total": row["total"]}}

    return start_job(request, "specialist_answer_test", "Checking complete draft answers", run,
                     needs_global=False, cancellable=True, on_cancel=learning_jobs.stop_budget(budget))


@router.post("/test-suite/customer/run")
def run_customer_tests(request: Request, body: SpecialistRunIn) -> dict:
    return _start_customer_test_job(request, body.specialist, operation_id=body.operation_id,
                                    case_ids=body.case_ids, case_revisions=body.case_revisions)


@router.post("/test-suite/customer/compare")
def compare_customer_tests(request: Request, body: SpecialistCompareIn) -> dict:
    return _start_customer_test_job(request, body.specialist, operation_id=body.operation_id,
        case_ids=body.case_ids, case_revisions=body.case_revisions,
        proposed_instructions=body.proposed_instructions, baseline_revision=body.baseline_revision,
        expected_context=body.expected_context)


@router.get("/test-suite/customer/run/{operation_id}")
def customer_test_run_status(request: Request, operation_id: str) -> dict:
    require_permission(request, "admin")
    if len(operation_id) != 32 or any(c not in "0123456789abcdef" for c in operation_id):
        raise HTTPException(status_code=404, detail="This answer check was not found.")
    from . import specialist_test_sets as saved
    row = saved.run_by_id(operation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No saved answer check has this request reference.")
    profile = _test_profile(request, row["specialist"])
    from maverick.llm import model_for_role

    from .auth import caller_principal
    if row.get("comparison", {}).get("draft_profile"):
        from .draft_api import context_for
        from .tools_ops_api import actor
        if row["actor"] != actor(request) or row["comparison"]["context"] != context_for(request):
            raise HTTPException(404, "This private draft check is unavailable to this account and workspace.")
    if row.get("comparison") and row["actor"] != (caller_principal(request) or "local administrator"):
        raise HTTPException(403, "This comparison belongs to another person. Open Previous checks for workspace history.")
    revision = saved.instruction_digest(saved.answer_system(profile), model_for_role(row["specialist"]))
    return {"run": _current_test_result(saved.public_run(row), revision, saved.cases_for(row["specialist"]))}


# ---- tasks coming due (forward) -----------------------------------------------------

@router.get("/upcoming")
async def upcoming(request: Request, days: int = 30) -> dict:
    require_permission(request, "view")
    _choice(days, (7, 14, 30, 60, 90))
    from maverick.forward_ledger import upcoming as ledger
    world = _world()
    owner = goal_owner_filter(request)
    now = time.time()
    rows = await run_in_threadpool(lambda: ledger(world, days=days, now=now, owner=owner))
    return {"days": days, "tasks": [
        {"task": int(r.goal.id), "title": _clip(r.goal.title, 200),
         "department": (r.goal.domain or "").replace("_", " "), "due": r.deadline,
         "overdue": r.deadline < now, "questions": int(r.open_questions)}
        for r in rows[:200]]}


# ---- outside agents sharing memory (fleet-memory --register) --------------------------

@router.get("/outside-agents/vendors")
async def vendors(request: Request) -> dict:
    require_permission(request, "view")
    return {"vendors": [{"value": k, "label": v} for k, v in _VENDORS.items()]}


@router.post("/outside-agents")
async def add_outside_agent(request: Request, body: AgentIn) -> dict:
    require_permission(request, "admin")
    from maverick import fleet_memory
    if not fleet_memory.enabled():
        from .learning_ops_api import switch_place
        raise HTTPException(status_code=409, detail=f"Turn on {switch_place('fleet_memory')} first.")
    await run_in_threadpool(lambda: _audit(request, "fleet_memory_register", vendor=body.vendor,
                                           outside_agent=body.name))
    ok = await run_in_threadpool(lambda: fleet_memory.register_agent(
        body.name, body.vendor, description=" ".join(body.description.split())))
    if not ok:
        raise HTTPException(status_code=409, detail=(
            "That agent name is already used by another company's agent, or the list could not be saved."))
    return {"added": True, "agent": body.name, "vendor": _VENDORS[body.vendor]}


__all__ = ["router"]
