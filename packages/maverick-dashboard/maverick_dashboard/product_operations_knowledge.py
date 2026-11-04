"""Copilot uses the same bounded rebuild service and durable operation identity."""
from __future__ import annotations

from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field
from starlette.background import BackgroundTask

from .plain_labels import money
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class RebuildInput(StrictInput):
    collection: str = Field(min_length=1, max_length=128)


def _state(request):
    from maverick.knowledge_reindex_jobs import list_jobs

    from .knowledge_library_api import _overview, _reindex_authority
    context = _reindex_authority(request)
    return context, _overview(), list_jobs(context)


def rebuild_snapshot(request, selection):
    context, library, jobs = _state(request)
    collections = library["collections"]
    return Snapshot(digest([context, collections]), "Knowledge library", "Review and rebuild a complete search index within administrator limits.",
                    details={"jobs": jobs}, fields=[{"name": "collection", "label": "Collection", "kind": "select", "required": True,
                    "choices": [{"value": row["name"], "label": row["name"]} for row in collections]}],
                    blocked="Enable document search and add an authorized collection first." if not collections else "")


def rebuild_prepare(request, selection, arguments):
    from maverick.knowledge_reindex_jobs import preview

    from .knowledge_library_api import _reindex_authority, _reindex_call
    context = _reindex_authority(request)
    review = _reindex_call(preview, arguments["collection"])
    return Preview("Build a shadow index, then publish the complete replacement after current permission and source checks. Paid AI requests require verified cost admission.",
                   changes=[{"label": "Passages", "before": review["count"], "after": review["count"]},
                            {"label": "Provider admission ceiling", "before": "No rebuild", "after": f"{money(review['cost_ceiling'])}. {review['price_basis']}"},
                            {"label": "Embedding model", "before": "No rebuild", "after": review["model"]},
                            {"label": "Elapsed time limit", "before": "No rebuild", "after": str(review["limits"]["max_wall_seconds"]) + " seconds, checked between batches"}],
                   native={"context": context, "collection": arguments["collection"], "review": review["review"]})


def rebuild_recover(request, selection, arguments, native, operation):
    from maverick.knowledge_reindex_jobs import list_jobs

    from .knowledge_library_api import _reindex_authority
    _reindex_authority(request, native["context"])
    job = next((row for row in list_jobs(native["context"], include_archived=True) if row["job_id"] == operation), None)
    return Outcome("replayed", "This rebuild is already recorded. Use its native status to continue or cancel; no new job was started.", job) if job else None


def rebuild_execute(request, selection, arguments, native, operation):
    from maverick.knowledge_reindex_jobs import start

    from .knowledge_library_api import _reindex_authority, _reindex_call, _run_reindex
    _reindex_authority(request, native["context"])
    prior = rebuild_recover(request, selection, arguments, native, operation)
    if prior is not None:
        return prior
    job = _reindex_call(start, **native, job_id=operation)
    return Outcome("queued", "Rebuild recorded. Its progress survives leaving this conversation.", job,
                   background=BackgroundTask(_run_reindex, request, native["context"], operation))


class JobInput(StrictInput):
    job_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    action: Literal["status", "cancel", "resume", "archive"]


def job_snapshot(request, selection):
    context, _, jobs = _state(request)
    return Snapshot(digest([context, jobs]), "Knowledge rebuild history", "Inspect or control a recorded rebuild at a safe batch boundary.", fields=[
        {"name": "job_id", "label": "Rebuild", "kind": "select", "required": True, "choices": [{"value": job["job_id"], "label": job["collection"] + " / " + job["state"]} for job in jobs]},
        {"name": "action", "label": "Action", "kind": "select", "required": True, "choices": [{"value": value, "label": label} for value, label in (("status", "Refresh status"), ("cancel", "Cancel at safe boundary"), ("resume", "Continue interrupted job"), ("archive", "Archive finished rebuild"))]}], blocked="No rebuild job is recorded here." if not jobs else "")


def job_prepare(request, selection, arguments):
    context, _, jobs = _state(request)
    job = next((row for row in jobs if row["job_id"] == arguments["job_id"]), None)
    if job is None:
        raise HTTPException(404, "Rebuild unavailable.")
    return Preview("Review current progress before changing this rebuild. A published complete index is retained.",
                   changes=[{"label": job["collection"], "before": job["state"], "after": arguments["action"]}],
                   native={"context": context, **arguments})


def job_execute(request, selection, arguments, native, operation):
    from fastapi import BackgroundTasks
    from maverick.knowledge_reindex_jobs import list_jobs

    from .knowledge_library_api import JobActionIn, _reindex_authority, reindex_action
    _reindex_authority(request, native["context"])
    if native["action"] == "status":
        job = next((row for row in list_jobs(native["context"]) if row["job_id"] == native["job_id"]), None)
        if job is None:
            raise HTTPException(404, "Rebuild unavailable.")
        return Outcome("confirmed", "Recorded rebuild progress refreshed.", job)
    background = BackgroundTasks()
    value = reindex_action(request, native["job_id"], native["action"], JobActionIn(context=native["context"], confirmed=True), background)
    return Outcome("queued" if native["action"] == "resume" else "confirmed", "Rebuild action recorded. Refresh native progress for its confirmed outcome.", value["job"], background=background)


class AnalysisInput(StrictInput):
    purpose: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    source: str = Field(pattern=r"^[a-f0-9]{64}$")
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=16000)


def _analysis_catalog(request):
    from fastapi import Response
    from maverick.knowledge_task_context import enabled

    from .knowledge_access_api import _binding, _service, task_policy
    tenant, actor, context = _binding(request, Response())
    if not enabled():
        raise HTTPException(409, "An administrator can enable source analysis in Knowledge settings.")
    service = _service(request)
    purposes = service.available_purposes(tenant, actor)
    rows = []
    for purpose in purposes[:20]:
        page = service.search(tenant, actor, query="", purpose=purpose, limit=20)
        rows.extend({"key": digest(item["reference"]), "reference": item["reference"],
                     "title": item["title"], "purpose": purpose} for item in page["items"])
    return context, rows, task_policy(request, Response())


def analysis_snapshot(request, selection):
    context, rows, policy = _analysis_catalog(request)
    purposes = sorted({row["purpose"] for row in rows})
    choices = {purpose: [{"value": row["key"], "label": row["title"] + " / " + row["reference"]["version"]}
                         for row in rows if row["purpose"] == purpose] for purpose in purposes}
    return Snapshot(digest([context, rows, policy]), "Approved knowledge source versions",
        "Prepare one tool-free AI analysis. For multiple sources or further pages use Knowledge's source picker.",
        fields=[{"name": "purpose", "label": "Permitted use", "kind": "select", "required": True,
                 "choices": [{"value": purpose, "label": purpose} for purpose in purposes]},
                {"name": "source", "label": "Exact source version", "kind": "select", "required": True,
                 "depends_on": "purpose", "choices_by": choices},
                {"name": "title", "label": "Task title", "kind": "text", "required": True},
                {"name": "description", "label": "What should the analysis answer?", "kind": "textarea", "required": True}],
        blocked="No currently approved source is available. Open Knowledge to request fresh evidence." if not rows else "")


def analysis_prepare(request, selection, arguments):
    from maverick.knowledge_task_context import validate_selection

    from .auth import caller_principal
    context, rows, policy = _analysis_catalog(request)
    chosen = next((row for row in rows if row["key"] == arguments["source"] and row["purpose"] == arguments["purpose"]), None)
    if chosen is None:
        raise HTTPException(409, "Source changed. Select current evidence again.")
    source = {"references": [chosen["reference"]], "purpose": arguments["purpose"]}
    validate_selection(caller_principal(request), source)
    return Preview("Send the reviewed request and this exact source excerpt to the configured AI. No action tools; current source access is required to open the private analysis.",
                   changes=[{"label": "Source", "before": "No task", "after": chosen["title"] + " / " + chosen["reference"]["version"]},
                            {"label": "Spending ceiling", "before": "No AI request", "after": policy["max_dollars"]},
                            {"label": "Time limit in seconds", "before": "No AI request", "after": policy["max_wall_seconds"]}],
                   native={"title": arguments["title"], "description": arguments["description"], "max_depth": 1,
                           "knowledge_context": {"context": context, **source}})


def analysis_recover(request, selection, arguments, native, operation):
    from ._shared import _world
    from .auth import caller_principal
    from .goal_submission import lookup_receipt
    try:
        receipt, goal = lookup_receipt(_world(), key=operation, owner=caller_principal(request) or "", kind="api")
    except HTTPException as exc:
        if exc.status_code == 404:
            return None
        raise
    return Outcome("replayed", "Source-analysis request already recorded. Check its task state; no AI attempt was repeated.",
                   {"goal_id": goal.id, "state": goal.status, "submission_state": receipt["state"], "href": "/knowledge-access#analysis=" + str(goal.id)})


def analysis_execute(request, selection, arguments, native, operation):
    from fastapi import BackgroundTasks, Request, Response

    from .api import create_goal
    from .api_schemas import GoalIn
    headers = [(key, value) for key, value in request.scope["headers"] if key.lower() != b"idempotency-key"]
    scoped = Request({**request.scope, "headers": [*headers, (b"idempotency-key", operation.encode())]}, receive=request.receive)
    background = BackgroundTasks()
    goal = create_goal(scoped, GoalIn(**native), background, Response())
    return Outcome("queued", "Source-analysis task recorded. Open its current status and private analysis in Knowledge.",
                   {"goal_id": goal.id, "state": goal.status, "href": "/knowledge-access#analysis=" + str(goal.id)}, background=background)


class PrecedentInput(StrictInput):
    questionnaire: str = Field(min_length=1, max_length=64)
    subject: str = Field(min_length=1, max_length=300)


def _precedent_authority(request):
    from maverick.assessment_memory import enabled

    from .api import _permitted_memory_assessment_types
    from .auth import require_permission
    require_permission(request, "operate")
    if not enabled():
        raise HTTPException(409, "Assessment precedent suggestions are disabled in Memory settings.")
    return _permitted_memory_assessment_types(request)


def precedent_snapshot(request, selection):
    from maverick.assessment import list_templates, template_state

    from .draft_api import context_for
    allowed = _precedent_authority(request)
    choices = [{"value": template.type, "label": template.title} for template in list_templates() if template.type in allowed]
    revisions = [template_state(choice["value"]) for choice in choices]
    return Snapshot(digest([context_for(request), revisions]), "Assessment precedents", "Review past answers and exact source provenance. Prior agreement is not factual certainty; no answer is applied automatically.", fields=[
        {"name": "questionnaire", "label": "Questionnaire", "kind": "select", "required": True, "choices": choices},
        {"name": "subject", "label": "Subject to compare", "kind": "text", "required": True}])


def precedent_prepare(request, selection, arguments):
    from maverick.assessment_memory import suggest_answers
    allowed = _precedent_authority(request)
    if arguments["questionnaire"] not in allowed:
        raise HTTPException(403, "Current department access is required.")
    suggestions = suggest_answers(arguments["questionnaire"], arguments["subject"], allowed_types=allowed)
    return Preview("Each suggested answer keeps its supporting and conflicting exact source versions. Open the questionnaire to compare, reject or use one value in your draft.",
        changes=[{"label": (value["sources"][0]["question"] if value["sources"] else question),
                  "before": "No change to your answer", "after": value["answer"] + " / " + value["state"].replace("_", " ")}
                 for question, value in suggestions.items()], native={"suggestions": suggestions})


def sources_snapshot(request, _selection):
    import json

    from . import knowledge_sources_api

    value = json.loads(knowledge_sources_api.catalog(request).body)
    return Snapshot(digest(value), "Saved company Knowledge sources",
                    "Use named saved accounts and approved uses. New or refreshed content needs separate approval before specialists can use it.")


def sources_prepare(request, selection, _arguments):
    value = sources_snapshot(request, selection)
    return Preview(value.summary + " Open the complete Knowledge form to choose a source, review its schedule and cost, read original outcomes or save a specialist draft. This handoff does not refresh, publish or change access.",
                   native={"open": {"label": "Open company Knowledge sources", "href": "/knowledge-access#knowledge-sources"}})


def entries():
    from .product_operations_knowledge_feedback import feedback_entries
    return (*feedback_entries(), Adapter("knowledge.sources.configure", "Manage company Knowledge sources", "learning", "/knowledge-access#knowledge-sources",
                                        ("/knowledge-access", "/knowledge", "/agents", "/connections", "/research"),
                                        EmptyInput, sources_snapshot, sources_prepare,
                                        aliases=("connect company knowledge", "refresh SharePoint knowledge", "attach approved sources")),
            Adapter("knowledge.assessment_precedents", "Review precedent answers and sources", "learning", "/privacy", ("/privacy", "/finance", "/security", "/approvals", "/knowledge-access"), PrecedentInput, precedent_snapshot, precedent_prepare),
            Adapter("knowledge.source_analysis", "Analyze an approved source", "learning", "/knowledge-access#source-analysis", ("/knowledge-access",), AnalysisInput, analysis_snapshot, analysis_prepare, analysis_execute, analysis_recover),
            Adapter("knowledge.rebuild", "Rebuild document search", "learning", "/knowledge-access", ("/knowledge-access",), RebuildInput, rebuild_snapshot, rebuild_prepare, rebuild_execute, rebuild_recover),
            Adapter("knowledge.rebuild_job", "Review or control rebuild progress", "learning", "/knowledge-access", ("/knowledge-access",), JobInput, job_snapshot, job_prepare, job_execute))
