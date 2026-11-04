"""Copilot controls for the same customer specialist answer checks as Workforce."""
from __future__ import annotations

from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import specialist_test_sets as saved
from . import workforce_ops_api as native
from .draft_api import context_for
from .plain_labels import pack_display_name
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class ChooseInput(StrictInput):
    specialist: str = Field(min_length=1, max_length=100)


class RunInput(ChooseInput):
    checks: list[str] = Field(min_length=1, max_length=saved.MAX_CASES_PER_RUN)


class CompareInput(RunInput):
    proposed_instructions: str = Field(min_length=8, max_length=6000)


class CreateInput(ChooseInput):
    task: str = Field(min_length=8, max_length=1000)
    must_mention: str = Field(default="", max_length=100)
    must_never_say: str = Field(default="", max_length=100)
    must_refuse: Literal["yes", "no"] = "no"
    must_cite: Literal["yes", "no"] = "no"


def _snapshot(request, selection, *, admin=False, paid=False):
    auth.require_permission(request, "admin" if admin else "view")
    blocked = ""
    if paid and not native._live_tests_enabled():
        blocked = "Enable bounded model tests in All settings before checking live answers."
    fields = [{"name": "specialist", "label": "Specialist", "kind": "text", "required": True,
               "value": str(selection.get("specialist") or "")[:100], "max_length": 100}]
    return Snapshot(digest({"context": context_for(request), "admin": admin, "paid": paid,
                            "enabled": not blocked}),
                    "Current answer-check controls in this account and workspace",
                    "Use your saved examples to check the current answers of an agent or specialist; live checks use no tools or company knowledge.",
                    fields=fields, blocked=blocked)


def read_snapshot(request, selection):
    return _snapshot(request, selection)


def read_prepare(request, selection, arguments):
    name = arguments["specialist"]
    native._test_profile(request, name)
    rows = saved.cases_for(name)
    runs = saved.runs_for(name)[:5]
    return Preview(f"{len(rows)} saved answer checks. Open Workforce for full answers and editing.",
                   native={"specialist": name, "cases": [
                       {"task": r["task"], "must_mention": r["includes"], "must_never_say": r["excludes"],
                        "must_refuse": r["refusal"], "must_cite": r["citation"]} for r in rows],
                           "recent_runs": [{"state": r["state"], "passed": r["passed"], "total": r["total"],
                                            "started_at": r["started_at"], "message": r.get("message", "")}
                                           for r in runs], "href": "/workforce?specialist=" + name})


def create_snapshot(request, selection):
    state = _snapshot(request, selection, admin=True)
    return Snapshot(state.revision, state.source,
                    "Save one test question and exact phrases the answer must or must not contain.",
                    fields=state.fields + [
                        {"name": "task", "label": "Question or request", "kind": "textarea", "required": True, "max_length": 1000},
                        {"name": "must_mention", "label": "Must mention (optional exact phrase)", "kind": "text", "max_length": 100},
                        {"name": "must_never_say", "label": "Must never say (optional exact phrase)", "kind": "text", "max_length": 100},
                        {"name": "must_refuse", "label": "Should refuse?", "kind": "select", "value": "no",
                         "choices": [{"value": "no", "label": "No"}, {"value": "yes", "label": "Yes"}]},
                        {"name": "must_cite", "label": "Should show a source reference?", "kind": "select", "value": "no",
                         "choices": [{"value": "no", "label": "No"}, {"value": "yes", "label": "Yes"}]}])


def _fields(arguments):
    body = native.SpecialistCaseIn(specialist=arguments["specialist"], task=arguments["task"],
        includes=[arguments["must_mention"]] if arguments["must_mention"].strip() else [],
        excludes=[arguments["must_never_say"]] if arguments["must_never_say"].strip() else [],
        refusal=arguments["must_refuse"] == "yes", citation=arguments["must_cite"] == "yes")
    return native._case_fields(body)


def create_prepare(request, selection, arguments):
    auth.require_permission(request, "admin")
    name = arguments["specialist"]
    native._test_profile(request, name)
    fields = _fields(arguments)
    return Preview("Save this answer check for the selected agent or specialist. Nothing is sent to an AI provider yet.",
                   [{"label": "Agent or specialist", "after": native._name(name)},
                    {"label": "Question", "after": fields["task"]},
                    {"label": "Passing answer", "after": "; ".join(
                        (["mentions " + ", ".join(fields["includes"])] if fields["includes"] else [])
                        + (["never says " + ", ".join(fields["excludes"])] if fields["excludes"] else [])
                        + (["refuses"] if fields["refusal"] else [])
                        + (["shows a source reference"] if fields["citation"] else []))}],
                   {"case_digest": digest(saved.cases_for(name))})


def create_recover(request, selection, arguments, prepared, operation_id):
    auth.require_permission(request, "admin")
    native._test_profile(request, arguments["specialist"])
    row = saved.case_by_id(operation_id)
    if row is None:
        return None
    if row["specialist"] != arguments["specialist"] or any(
            row.get(key) != value for key, value in _fields(arguments).items()):
        raise HTTPException(409, "This reviewed action no longer matches its saved test.")
    return Outcome("replayed", "The original answer check was already saved; no duplicate was added.",
                   {"test": row, "href": "/workforce?specialist=" + row["specialist"]})


def create_execute(request, selection, arguments, prepared, operation_id):
    auth.require_permission(request, "admin")
    name = arguments["specialist"]
    native._test_profile(request, name)
    if digest(saved.cases_for(name)) != prepared["case_digest"]:
        raise HTTPException(409, "The test list changed. Review it again before saving.")
    fields = _fields(arguments)
    native._audit(request, "specialist_test_save", specialist=name, test=operation_id)
    row = saved.save_once(name, fields, operation_id)
    return Outcome("confirmed", "The answer check was saved. It has not been run yet.",
                   {"test": row, "href": "/workforce?specialist=" + name})


def run_snapshot(request, selection):
    state = _snapshot(request, selection, admin=True, paid=True)
    profiles = native._test_profiles(request)
    groups = saved.cases_for_specialists(set(profiles))
    labels = {name: pack_display_name(name, profiles[name].persona, profiles[name].description) for name in groups}
    names = sorted(groups, key=labels.get)
    specialist = selection.get("specialist") if selection.get("specialist") in groups else next(iter(names), "")
    chosen = groups.get(specialist, [])
    return Snapshot(digest({"controls": state.revision, "cases": groups}), state.source,
                    "Choose up to five saved questions for one bounded answer check. Review the questions before spending.",
                    fields=[{"name": "specialist", "label": "Specialist", "kind": "select", "required": True,
                             "value": specialist,
                             "choices": [{"value": name, "label": labels[name]} for name in names]},
                            {"name": "checks", "label": "Saved questions (choose up to 5)", "kind": "multiselect",
                             "required": True, "depends_on": "specialist", "presentation": "checkboxes",
                             "max_selections": saved.MAX_CASES_PER_RUN,
                             "value": [row["id"] for row in chosen] if len(chosen) <= saved.MAX_CASES_PER_RUN else [],
                             "choices": [{"value": row["id"], "label": row["task"]} for row in chosen],
                             "choices_by": {name: [{"value": row["id"], "label": row["task"]} for row in rows]
                                            for name, rows in groups.items()}}],
                    blocked=state.blocked or ("Add an answer check in Workforce before checking answers." if not names else ""))


def _chosen(name, checks):
    try:
        return saved.snapshot(name, checks)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


def run_prepare(request, selection, arguments):
    auth.require_permission(request, "admin")
    name = arguments["specialist"]
    profile = native._test_profile(request, name)
    from maverick.llm import model_for_role

    rows = _chosen(name, arguments["checks"])
    model = model_for_role(name)
    instructions = saved.instruction_digest(saved.answer_system(profile), model)
    return Preview(f"Check {len(rows)} selected answers using the current instructions and {model}. "
                   "At most $0.25 of model spend, no tools or outside systems, no automatic retry of uncertain calls.",
                   [{"label": "Agent or specialist", "after": pack_display_name(name, profile.persona, profile.description)},
                    {"label": "Questions", "after": "; ".join(row["task"] for row in rows)},
                    {"label": "Maximum spend", "after": "$0.25"}],
                   {"cases_digest": digest(rows), "instructions": instructions, "model": model,
                    "case_revisions": {row["id"]: row["revision"] for row in rows},
                    "context": context_for(request)})


def _match_original(request, name, prepared, row):
    if (prepared["context"] != context_for(request) or row["specialist"] != name
            or row["model"] != prepared["model"] or row["instruction_hash"] != prepared["instructions"]
            or {case["id"]: case["revision"] for case in row["case_revisions"]} != prepared["case_revisions"]):
        raise HTTPException(409, "The original run does not match these reviewed questions, instructions or workspace.")
    if prepared.get("proposed_instructions") is not None:
        proposed = row.get("comparison") or {}
        if (proposed.get("proposed_instructions") != prepared["proposed_instructions"]
                or proposed.get("proposed_instruction_hash") != prepared["proposed_instruction_hash"]):
            raise HTTPException(409, "The original comparison does not match these proposed instructions.")


def _run_details(row, request=None):
    details = {"status": {"prepared": "Not sent yet", "running": "Checking answers", "done": "Finished",
                       "stopped": "Stopped", "unknown": "Result needs review"}.get(row["state"], "Result needs review"),
            "questions": "; ".join(case["task"] for case in row["case_snapshots"]),
            "answers_checked": len(row["results"]), "passed": row["passed"],
            "review_results": {"href": "/workforce?specialist=" + row["specialist"],
                               "label": "Review answer results in Workforce"}}
    if row.get("comparison"):
        if request is not None:
            from maverick.llm import model_for_role
            profile = native._test_profile(request, row["specialist"])
            native._current_test_result(row, saved.instruction_digest(saved.answer_system(profile), model_for_role(row["specialist"])), saved.cases_for(row["specialist"]))
        details.update(current_passed=sum(r.get("passed", False) for r in row["results"] if r.get("variant") == "current"),
                       proposed_passed=sum(r.get("passed", False) for r in row["results"] if r.get("variant") == "proposed"),
                       recorded_cost=f"${row['spent_dollars']:.6f}",
                       interpretation="Recorded answers and literal rule checks only. This does not establish business improvement; no instructions were published.",
                       instructions_status="Current instructions still match" if row.get("baseline_current", True) else "Current instructions changed; this result is historical",
                       questions_status="Current questions still match" if row.get("questions_current", True) else "Saved questions changed; this result is historical",
                       answers=[{"question":case["task"], **{variant+"_answer":next((result["answer"] for result in row["results"] if result["case_id"]==case["id"] and result.get("variant")==variant), "Not checked") for variant in ("current", "proposed")}} for case in row["case_snapshots"]])
    return details


def compare_snapshot(request, selection):
    state = run_snapshot(request, selection)
    return Snapshot(state.revision, state.source,
        "Compare proposed answer instructions with the current specialist on the same chosen questions. Nothing is published.",
        fields=state.fields + [{"name":"proposed_instructions", "label":"Proposed answer instructions", "kind":"textarea",
                               "required":True, "max_length":6000}], blocked=state.blocked)


def compare_prepare(request, selection, arguments):
    from dataclasses import replace

    from maverick.llm import model_for_role
    state = run_prepare(request, selection, arguments)
    profile = native._test_profile(request, arguments["specialist"])
    proposed = arguments["proposed_instructions"]
    if len(proposed.strip()) < 8 or proposed.strip() == profile.persona.strip():
        raise HTTPException(422, "Write different proposed instructions before comparing.")
    return Preview("Compare both instruction versions on exactly these saved questions. At most $0.25 total, no tools or company knowledge, and no automatic retry. No instructions will change.",
        state.changes + [{"label":"Answer instructions", "before":profile.persona, "after":proposed}],
        {**state.native, "proposed_instructions":proposed,
         "proposed_instruction_hash":saved.instruction_digest(saved.answer_system(replace(profile, persona=proposed)), model_for_role(arguments["specialist"]))})


def run_recover(request, selection, arguments, prepared, operation_id):
    auth.require_permission(request, "admin")
    native._test_profile(request, arguments["specialist"])
    row = saved.run_by_id(operation_id)
    if row is None or row["state"] == "prepared":
        return None
    _match_original(request, arguments["specialist"], prepared, row)
    return Outcome("replayed", "The original run was found. No paid request was repeated.",
                   _run_details(saved.public_run(row), request))


def run_execute(request, selection, arguments, prepared, operation_id):
    auth.require_permission(request, "admin")
    name = arguments["specialist"]
    profile = native._test_profile(request, name)
    from maverick.llm import model_for_role

    existing = saved.run_by_id(operation_id)
    if existing is not None:
        _match_original(request, name, prepared, existing)
    if existing is not None and existing["state"] != "prepared":
        return Outcome("replayed", "The original run was found. No paid request was repeated.",
                       _run_details(saved.public_run(existing), request))
    model = model_for_role(name)
    rows = _chosen(name, arguments["checks"])
    if (prepared["context"] != context_for(request) or model != prepared["model"] or digest(rows) != prepared["cases_digest"]
            or saved.instruction_digest(saved.answer_system(profile), model) != prepared["instructions"]):
        raise HTTPException(409, "Its instructions or tests changed. Review again before spending.")
    started = native._start_customer_test_job(request, name, operation_id=operation_id,
        case_ids=arguments["checks"], case_revisions=prepared["case_revisions"],
        **({"proposed_instructions":arguments["proposed_instructions"], "baseline_revision":prepared["instructions"], "expected_context":prepared["context"]}
           if prepared.get("proposed_instructions") is not None else {}))
    if started.get("replayed"):
        return Outcome("replayed", "The original run was found. No paid request was repeated.",
                       _run_details(started["run"], request))
    return Outcome("queued", "The answer checks started. Open Workforce to see the exact results; no uncertain call is replayed.",
                   {"status": "Checking selected answers", "questions": "; ".join(row["task"] for row in rows),
                    "review_results": {"href": "/workforce?specialist=" + name,
                                       "label": "Review answer results in Workforce"}})


def entries():
    pages = ("/workforce", "/agents")
    return (
        Adapter("specialists.tests.read", "Read answer checks", "models", "/workforce", pages,
                ChooseInput, read_snapshot, read_prepare,
                aliases=("show specialist tests", "show agent tests", "show answer checks")),
        Adapter("specialists.tests.create", "Add an answer check", "models", "/workforce", pages,
                CreateInput, create_snapshot, create_prepare, create_execute, create_recover,
                aliases=("add an answer check", "create specialist test")),
        Adapter("specialists.tests.run", "Check answers", "models", "/workforce", pages,
                RunInput, run_snapshot, run_prepare, run_execute, run_recover,
                aliases=("run specialist tests", "check specialist answers", "check agent answers")),
        Adapter("specialists.tests.compare", "Compare specialist instructions", "models", "/workforce", pages,
                CompareInput, compare_snapshot, compare_prepare, run_execute, run_recover,
                aliases=("compare proposed instructions", "compare specialist answers", "check better specialist instructions")),
    )
