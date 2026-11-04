"""Owned job activation drafts, native task admission and current human acceptance."""
from __future__ import annotations

import hashlib
import io
import json
import time
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from maverick import config, crypto_at_rest
from maverick.attachment_submissions import SubmissionStore
from maverick.authority_effects import authority_effect_fence
from maverick.governed_records import GovernedRecordStore
from maverick.privacy_ops import RecordConflict
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers

from . import auth
from .draft_api import context_for
from .product_errors import product_error

router = APIRouter()
DRAFTS = GovernedRecordStore("employee_activation", "EAP", "employee_activation")
JOBS = {
    "weekly_update": {"label": "Write a useful weekly update", "suite": None,
        "brief": "Write a clear weekly update for the team from the selected source material.",
        "criteria": "Separate completed work, next steps and blockers. Keep statements grounded in the source. Identify missing facts instead of inventing them.",
        "sample": "Fictional training example: The Atlas team completed a draft help guide. Two colleagues reviewed it. The next step is a five-person usability review. The translated screenshots are still missing."},
    "project_plan": {"label": "Turn notes into a project plan", "suite": None,
        "brief": "Draft a practical project plan from the selected source material.",
        "criteria": "State the outcome, milestones, dependencies and questions. Distinguish proposed dates and owners from confirmed facts.",
        "sample": "Fictional training example: A team wants to update its internal handbook. The sponsor needs a reviewed outline before writing starts. The final handbook must be checked by a subject expert. No deadline or staffing has been confirmed."},
    "privacy_evidence": {"label": "Prepare a privacy evidence summary", "suite": "privacy",
        "brief": "Summarize the privacy evidence and missing information in the selected source. Produce a review draft, not an approval or legal conclusion.",
        "criteria": "List supported facts, missing evidence and follow-up questions. Do not mark an assessment approved or infer a legal basis.",
        "sample": "Fictional training example: Example Vendor describes retaining support tickets for 30 days. The document does not identify hosting location, subprocessors or deletion verification. No signed agreement is provided."},
    "security_review": {"label": "Prepare a security review brief", "suite": "security",
        "brief": "Organize the security evidence into a concise review brief. Do not execute changes or claim verification without evidence.",
        "criteria": "Separate reported controls, independently verified evidence and open questions. State evidence gaps and a useful next review step.",
        "sample": "Fictional training example: A service reports multi-factor sign-in and daily backups. No restore exercise or access review record is attached. The service owner requests an evidence checklist."},
    "finance_variance": {"label": "Explain a simple budget variance", "suite": "finance",
        "brief": "Explain the budget variance using only the selected source figures. Prepare a review draft and show calculations.",
        "criteria": "Preserve currency and period, show arithmetic and distinguish known causes from hypotheses. Do not approve spending or fabricate missing amounts.",
        "sample": "Fictional training example: September training budget was USD 1,000. Recorded September training spend was USD 850. A USD 200 invoice has been proposed but is not approved or recorded. Explain each amount separately."},
}


def _app():
    from . import app
    return app


def actor(request, *, operate=False):
    auth.require_permission(request, "operate" if operate else "view")
    if config.config_source_errors(include_tenant=True) or config.get_features().get("employee_activation") is not True:
        raise product_error(403, "activation_disabled", "Employee activation is disabled or its policy is unavailable.")
    value = auth.caller_principal(request)
    if not value:
        raise product_error(403, "activation_account_required", "Sign in with your own account to keep a private activation draft.")
    return value


def jobs(request):
    actor(request)
    suites = config.load_config().get("suites", {})
    enabled = config.get_employee_activation_jobs()
    return {key: value for key, value in JOBS.items()
            if key in enabled and auth.suite_allowed(request, value["suite"]) and (not value["suite"] or suites.get(value["suite"], True) is True)}


def readiness(request):
    from ._shared import require_provider_or_400
    value = {"can_start": auth.has_permission(request, "operate"), "provider_ready": False,
             "document_sources": [], "documents_state": "unavailable"}
    try:
        require_provider_or_400()
        value["provider_ready"] = True
    except HTTPException:
        pass
    try:
        from maverick import doc_discovery
        value["document_sources"] = doc_discovery.configured_sources(principal=actor(request), allow_ambient_credentials=False) if doc_discovery.enabled() else []
        value["documents_state"] = "available" if value["document_sources"] else "setup_required"
    except Exception:
        pass
    return value


def _read(request, identity, *, operate=False):
    owner = actor(request, operate=operate)
    row = DRAFTS.get(identity)
    if row is None or row.get("owner") != owner:
        raise product_error(404, "activation_draft_missing", "This draft is not available in your account and workspace.")
    if row.get("state") == "erased":
        raise product_error(410, "activation_draft_erased", "This activation draft was erased. Start a new draft instead of restoring old inputs.")
    if row["job"] not in jobs(request):
        raise product_error(403, "activation_job_unavailable", "This job is no longer enabled or allowed for your account. Its private draft is retained.")
    return row


def _contents(row):
    return json.loads(crypto_at_rest.unseal_from_str(row["sealed"]))


def _result(request, row):
    goal_id = row.get("goal_id")
    if not goal_id:
        receipt = SubmissionStore(_app()._world()).lookup(token="activation:" + row["id"], owner=row["owner"])
        goal_id = receipt["goal_id"] if receipt else None
    if not goal_id:
        return None
    goal = _app()._world().get_goal(goal_id)
    if goal is None or goal.owner != actor(request):
        raise product_error(404, "activation_task_missing", "The activation task is unavailable. Do not start another copy to reconcile this draft.")
    auth.assert_goal_access(request, goal)
    fingerprint = hashlib.sha256(json.dumps([goal.id, goal.owner, goal.status, goal.result, goal.updated_at], sort_keys=True).encode()).hexdigest()
    return {"id": goal.id, "status": goal.status, "href": f"/chat/goal/{goal.id}", "fingerprint": fingerprint,
            "text": goal.result or "", "complete": goal.status == "done" and bool(goal.result),
            "accepted": row.get("accepted_fingerprint") == fingerprint and row.get("accepted_by") == row["owner"]}


def public(request, row):
    result = _result(request, row)
    return {"id": row["id"], "revision": row["revision"], "job": row["job"], "state": row["state"],
            "values": _contents(row), "result": result, "workflow": row.get("workflow"),
            "audit_pending": bool(row.get("_audit_pending")), "context": context_for(request),
            "return_href": "/get-started/employee?draft=" + row["id"],
            "repair_href": "/connections?activation_draft=" + row["id"],
            "message": row.get("message", "")}


@router.get("/get-started/employee")
def page(request: Request, draft: str | None = None):
    choices = jobs(request)
    own = actor(request)
    rows = DRAFTS.list(limit=10001)
    if len(rows) > 10000:
        raise product_error(503, "activation_inventory_limit", "Activation drafts could not be listed completely. Keep the draft link and contact your administrator.")
    return _app().templates.TemplateResponse(request, "employee_activation.html", {"activation": {
        "jobs": choices, "readiness": readiness(request), "context": context_for(request),
        "draft": public(request, _read(request, draft)) if draft else None,
        "drafts": [{"id": row["id"], "label": choices[row["job"]]["label"], "state": row["state"]}
                   for row in rows if row.get("owner") == own and row.get("job") in choices][:100]}},
        headers={"Cache-Control": "private, no-store"})


class DraftIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(max_length=128)
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    expected_revision: int | None = Field(default=None, ge=1)
    job: str = Field(max_length=60)
    mode: Literal["sample", "real"]
    source_kind: Literal["text", "connected"] = "text"
    material: str = Field(default="", max_length=10000)
    source: dict = Field(default_factory=dict, max_length=6)
    criteria: str = Field(min_length=1, max_length=2000)


def _binding(request, context):
    _app()._require_same_origin(request)
    if not auth.constant_time_equals(context_for(request), context):
        raise product_error(409, "activation_context_changed", "Your account or workspace changed. Reopen the saved draft before continuing.")


def _validated(request, body):
    job = jobs(request).get(body.job)
    if job is None:
        raise product_error(403, "activation_job_unavailable", "Choose a currently enabled job for your account.")
    values = body.model_dump(exclude={"context", "operation_id", "expected_revision"})
    if not values["criteria"].strip():
        raise product_error(422, "activation_criteria_required", "Describe how you will judge this result.")
    if body.mode == "sample":
        values.update(material=job["sample"], source={}, source_kind="text")
    elif body.source_kind == "text" and not body.material.strip():
        raise product_error(422, "activation_source_required", "Add the source material you are authorized to use.")
    elif body.source_kind == "connected":
        from .api_schemas import SourceAttachIn
        if not body.source:
            values.update(source={}, material="")
            return values  # An incomplete private draft can survive connection setup.
        try:
            source = SourceAttachIn.model_validate(body.source).model_dump()
            if set(body.source) - set(source) or len(json.dumps(source)) > 12000:
                raise ValueError("Unbounded source")
        except ValueError:
            raise product_error(422, "activation_source_required", "Select one document from the connected-source results.") from None
        values.update(source=source, material="")
    return values


@router.post("/api/v1/employee-activation")
def save(request: Request, body: DraftIn, draft: str | None = None):
    with authority_effect_fence():
        owner = actor(request, operate=True)
        _binding(request, body.context)
        values = _validated(request, body)
        encoded = json.dumps(values, sort_keys=True)
        sealed = crypto_at_rest.seal_to_str(encoded)
        if not crypto_at_rest.is_sealed_str(sealed):
            raise product_error(503, "activation_encryption_unavailable", "Encrypted draft storage is unavailable. Nothing was started.")
        identity = draft or "EAP-" + hashlib.sha256((owner + ":" + body.operation_id).encode()).hexdigest()[:48]
        row = _read(request, draft, operate=True) if draft else DRAFTS.get(identity)
        if row:
            if row.get("owner") != owner:
                raise product_error(404, "activation_draft_missing", "This draft is unavailable.")
            if row.get("state") == "erased":
                raise product_error(410, "activation_draft_erased", "This saved operation was erased. It cannot restore the old activation draft.")
            if not draft:
                if _contents(row) != values:
                    raise product_error(409, "activation_operation_changed", "The draft reference belongs to different inputs. Reopen the saved draft.")
                return public(request, row)
            if _result(request, row) or row["state"] != "draft":
                raise product_error(409, "activation_already_started", "This draft has entered task admission. Keep its original inputs while reconciling; use a new draft for different work.")
            if body.expected_revision is None:
                raise product_error(409, "activation_revision_required", "Refresh the saved draft before changing it.")
            row = _update(row, {"sealed": sealed, "job": body.job}, body.expected_revision, owner, "edit_draft")
        else:
            row = DRAFTS.create({"id": identity, "owner": owner, "job": body.job, "sealed": sealed, "state": "draft"},
                action="create_draft", actor=owner, max_records=10000)
        return public(request, row)


def _update(row, changes, revision, owner, action):
    try:
        saved = DRAFTS.update(row["id"], lambda value: value.update(changes), expected_revision=revision, action=action, actor=owner)
    except RecordConflict:
        raise product_error(409, "activation_draft_changed", "This draft changed in another window. Refresh and compare before continuing.") from None
    if saved is None:
        raise product_error(404, "activation_draft_missing", "This draft is no longer available.")
    return saved


class ActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(max_length=128)
    expected_revision: int = Field(ge=1)
    confirmed: bool
    result_fingerprint: str = Field(default="", max_length=64)


def _action(request, identity, body):
    owner = actor(request, operate=True)
    _binding(request, body.context)
    if not body.confirmed:
        raise product_error(422, "activation_review_required", "Review the exact inputs and confirm this action.")
    row = _read(request, identity, operate=True)
    if row["revision"] != body.expected_revision:
        raise product_error(409, "activation_draft_changed", "Refresh this draft and review its current state.")
    return owner, row


async def _source_file(request, values):
    if values["mode"] == "sample" or values["source_kind"] == "text":
        return []
    from maverick import doc_discovery
    if not doc_discovery.enabled():
        raise product_error(403, "activation_source_disabled", "Connected document discovery is disabled. Your draft is retained.")
    source = values["source"]
    if not source or not source.get("doc_id"):
        raise product_error(409, "activation_source_required", "Select the intended connected document before starting this draft.")
    principal = actor(request, operate=True)
    try:
        data, mime = await run_in_threadpool(doc_discovery.fetch, source["source"], source["doc_id"], source["ref"],
            principal=principal, allow_ambient_credentials=False)
    except Exception:
        raise product_error(409, "activation_source_unavailable", "This source could not be read with your current access. Repair the connection, then return to this same draft. Nothing was retried automatically.") from None
    actor(request, operate=True)
    name = source["name"].strip() or "selected-document"
    return [UploadFile(file=io.BytesIO(data), filename=name, headers=Headers({"content-type": doc_discovery.resolve_mime(name, mime)}))]


@router.post("/api/v1/employee-activation/{identity}/launch")
async def launch(request: Request, identity: str, body: ActionIn, bg: BackgroundTasks):
    owner, row = _action(request, identity, body)
    result = _result(request, row)
    if result:
        return public(request, row)  # Read-only recovery never resubmits paid work.
    values = _contents(row)
    files = await _source_file(request, values)
    try:
        owner, row = _action(request, identity, body)
        job = jobs(request)[row["job"]]
        text = job["brief"] + "\n\nHuman acceptance criteria:\n" + values["criteria"] + "\n\n"
        text += "SAMPLE DATA: this is a fictional practice result, not live business evidence.\n" if values["mode"] == "sample" else "REAL DATA: use only the selected source; a human must review the result.\n"
        text += values["material"] if values["source_kind"] == "text" else "Use the one selected document attached to this task. Report absent or unreadable evidence explicitly."
        row = _update(row, {"state": "admitting", "message": "Task admission in progress; recover this same draft if the response is interrupted."}, row["revision"], owner, "admit_task")
        scope = {**request.scope, "headers": [(key, value) for key, value in request.scope["headers"] if key.lower() != b"idempotency-key"]}
        scope["headers"].append((b"idempotency-key", ("activation:" + identity).encode()))
        await _app().chat_send(Request(scope), bg, title=job["label"], description=text, files=files, submission_key="activation:" + identity, director_profile="")
        receipt = SubmissionStore(_app()._world()).lookup(token="activation:" + identity, owner=owner)
        if receipt is None:
            raise product_error(409, "activation_admission_unconfirmed", "Task admission is unconfirmed. Refresh this draft before taking another action.")
        row = _update(row, {"state": "started", "goal_id": receipt["goal_id"], "message": "Task admitted. Completion requires your review of the current result."}, row["revision"], owner, "task_admitted")
        return public(request, row)
    finally:
        for upload in files:
            await upload.close()


@router.get("/api/v1/employee-activation/{identity}")
def get(request: Request, identity: str):
    return JSONResponse(public(request, _read(request, identity)), headers={"Cache-Control": "private, no-store"})


def _accepted_result(request, row, fingerprint):
    result = _result(request, row)
    if not result or not result["complete"] or not auth.constant_time_equals(result["fingerprint"], fingerprint):
        raise product_error(409, "activation_result_changed", "The task is incomplete or its result changed. Review the current completed result before accepting it.")
    return result


@router.post("/api/v1/employee-activation/{identity}/accept")
def accept(request: Request, identity: str, body: ActionIn):
    with authority_effect_fence():
        owner, row = _action(request, identity, body)
        result = _accepted_result(request, row, body.result_fingerprint)
        row = _update(row, {"state": "reviewed", "accepted_fingerprint": result["fingerprint"], "accepted_by": owner,
                           "accepted_at": time.time(), "message": "Human acceptance recorded for this exact result."}, row["revision"], owner, "accept_result")
        return public(request, row)


def _workflow_spec(row):
    values = _contents(row)
    # Reusable instructions deliberately use a new input placeholder; source
    # documents, account bindings and the accepted result are never copied.
    return {"name": "activation-" + row["id"][4:36], "title": JOBS[row["job"]]["label"],
            "body": JOBS[row["job"]]["brief"] + "\n\nAcceptance criteria:\n" + values["criteria"] + "\n\nNew source material:\n{{ source_material }}",
            "params": ["source_material"]}


@router.post("/api/v1/employee-activation/{identity}/workflow")
def workflow(request: Request, identity: str, body: ActionIn):
    from maverick.templates import load_template

    from .api import save_workflow_native
    from .api_schemas import WorkflowSaveIn
    owner, row = _action(request, identity, body)
    result = _accepted_result(request, row, body.result_fingerprint)
    if not result["accepted"]:
        raise product_error(409, "activation_acceptance_required", "Accept the current completed result before saving a reusable workflow draft.")
    spec = _workflow_spec(row)
    try:
        existing = load_template(spec["name"])
    except FileNotFoundError:
        existing = None
    if existing:
        if existing.owner != owner or existing.title != spec["title"] or existing.body.strip() != spec["body"].strip():
            raise product_error(409, "activation_workflow_changed", "The saved workflow changed. Open its current draft; it has not been overwritten.")
    else:
        save_workflow_native(request, WorkflowSaveIn(**spec, overwrite=False))
    actor(request, operate=True)
    row = _update(row, {"workflow": spec["name"], "message": "Reusable private workflow draft saved. Review its inputs and publication in Workflow Builder before scheduling."}, row["revision"], owner, "save_workflow")
    return public(request, row)


def _erasure_block(row, world):
    """Do not remove reconciliation inputs for an active or uncertain admission."""
    if row.get("state") == "admitting":
        return "Task admission is unconfirmed; reconcile this same draft before erasure."
    receipt = SubmissionStore(world).lookup(token="activation:" + row["id"], owner=row["owner"])
    goal_ids = {value for value in (row.get("goal_id"), receipt.get("goal_id") if receipt else None) if value}
    for goal_id in goal_ids:
        goal = world.get_goal(goal_id)
        if goal is None or goal.owner != row["owner"]:
            return "A task receipt cannot be reconciled to the exact current owner; retain the draft for review."
        if goal.status not in {"done", "completed", "failed", "cancelled", "error"}:
            return "This draft has active or recoverable task work; finish or stop it before erasure."
    if row.get("state") not in {"draft", "erased"} and not goal_ids:
        return "The task admission outcome is unavailable; retain the draft for reconciliation."
    return ""


def owned_activation_inventory(owner, *, world=None):
    """Content-free exact-owner My Data inventory, independent of feature enablement."""
    if not isinstance(owner, str) or not owner.startswith("user:"):
        raise ValueError("Select an exact named activation-draft owner.")
    world = _app()._world() if world is None else world
    rows = DRAFTS.list(limit=10001)
    if len(rows) > 10000:
        raise ValueError("Activation drafts exceed the complete inventory window.")
    return [{"id": row["id"], "revision": row["revision"], "state": row["state"],
             "blocked": _erasure_block(row, world)} for row in rows
            if row.get("owner") == owner and row.get("state") != "erased"]


def erase_owned_activation(owner, identifier, *, expected_revision, actor, operation_id, world=None):
    """Caller owns consent/holds/reviewer authority; this enforces owner and CAS.

    A minimal revision tombstone prevents replaying an old deterministic create
    operation. The task, admission receipt, created workflow and audit records
    remain outside this draft erasure and are never claimed deleted.
    """
    if (not isinstance(owner, str) or not owner.startswith("user:") or not isinstance(actor, str)
            or not actor.startswith("user:") or not isinstance(operation_id, str) or not 8 <= len(operation_id) <= 192):
        raise ValueError("A verified owner, reviewer and bounded erasure reference are required.")
    world = _app()._world() if world is None else world
    with authority_effect_fence():
        row = DRAFTS.get(identifier)
        if row is None or row.get("owner") != owner:
            raise ValueError("The activation draft is outside the reviewed owner scope.")
        if row.get("state") == "erased" and row.get("erasure_operation") == operation_id and row.get("erasure_reviewer") == actor:
            return {"status": "unconfirmed" if row.get("_audit_pending") else "replayed", "revision": row["revision"]}
        if row["revision"] != expected_revision:
            raise RecordConflict("Activation draft changed after erasure review")
        blocked = _erasure_block(row, world)
        if blocked:
            raise ValueError(blocked)
        def erase(record):
            if record.get("owner") != owner:
                raise ValueError("Activation owner changed during erasure")
            # Store bookkeeping is retained by GovernedRecordStore; remove every
            # application payload field, including source refs and acceptance.
            keep = {"id", "revision", "owner", "created_at", "updated_at", "tenant_id"}
            for key in list(record):
                if key not in keep and not key.startswith("_"):
                    record.pop(key)
            record.update(state="erased", erasure_operation=operation_id, erasure_reviewer=actor)
        saved = DRAFTS.update(identifier, erase, expected_revision=expected_revision,
                              action="erase_activation_draft", actor=actor)
        if saved is None:
            raise RecordConflict("Activation draft disappeared during erasure")
        return {"status": "unconfirmed" if saved.get("_audit_pending") else "confirmed", "revision": saved["revision"]}
