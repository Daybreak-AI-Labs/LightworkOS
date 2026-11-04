"""Owned, reviewed viewpoints admission and durable original answer custody."""
from __future__ import annotations

import json
import math
import re
import secrets
import time

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.budget import resolve_budget_caps
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.llm import LLM, _parse_spec, model_for_role

from . import ops_jobs, viewpoints_api, workspace_tenants
from .auth import caller_principal, require_permission
from .draft_api import context_for
from .plain_labels import model_label

PAGE = "/chat#viewpoints"
PURPOSE = "lightwork.viewpoints-review.v1"
NOTICE = ("One side argues for your decision, another against it, and a judge weighs their answers. "
          "This sends the question and both positions to your connected AI service, within your current spending limits "
          "and at most $1.00. It is advice, not verified facts or a decision made for you. No task or external action is started.")


def operation():
    return secrets.token_hex(16)


def records():
    return GovernedRecordStore("viewpoints-requests", "VPR", "viewpoints_request")


def authority(request, context=None, *, write=False):
    require_permission(request, "operate")
    current = context_for(request)
    if context is not None and context != current:
        raise HTTPException(409, "Your account or workspace changed. Refresh before continuing.")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
    return current


def seal(value):
    return crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def opened(value):
    if not crypto_at_rest.is_sealed_str(value):
        raise ValueError("missing private viewpoints envelope")
    return json.loads(crypto_at_rest.unseal_from_str(value))


def current(request):
    context = authority(request)
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(409, "The current AI settings could not be checked. Refresh before starting viewpoints.")
    from ._shared import require_provider_or_400
    try:
        require_provider_or_400(role="analyst")
    except HTTPException as exc:
        if exc.status_code != 400:
            raise
        raise HTTPException(400, "AI is not connected for viewpoints. An administrator can review the connection in Settings. Original answers remain available.") from exc
    model = model_for_role("analyst")
    provider, _ = _parse_spec(model)
    connection = LLM(model=model)._provider_client_config(provider).fingerprint
    owner, tenant = ops_jobs.identity(request)
    selected = workspace_tenants.get_selection_binding(caller_principal(request) or "")
    caps = resolve_budget_caps()
    cap = min(viewpoints_api.MAX_DOLLARS, float(caps["max_dollars"])) if caps.get("max_dollars") is not None else viewpoints_api.MAX_DOLLARS
    if not math.isfinite(cap) or cap <= 0:
        raise HTTPException(409, "AI spending is currently disabled. Ask an administrator to review the spending limits.")
    revision = digest([context, owner, tenant, selected, model, connection, config.load_config(), caps])
    authority(request, context)
    return {"context": context, "revision": revision, "model": model, "model_label": model_label(model),
            "owner": owner, "tenant": tenant, "selected": list(selected), "cap": cap}


def listing(request):
    context = authority(request)
    state = {"context": context, "ready": False, "notice": NOTICE}
    try:
        value = current(request)
        state.update(ready=True, revision=value["revision"], model=value["model_label"], cap=value["cap"])
    except HTTPException as exc:
        if exc.status_code in {401, 403}:
            raise
        state["message"] = str(exc.detail)
    state["history"] = history(request)["requests"]
    authority(request, context)
    return state


def prepare(request, values, *, context=None, revision=None):
    body = viewpoints_api.ViewpointsIn.model_validate(values)
    state = current(request)
    authority(request, context, write=True)
    if revision is not None and revision != state["revision"]:
        raise HTTPException(409, "The AI connection, model or spending settings changed. Your question is kept; refresh and review again.")
    # Keep literal entered text. Only empty optional positions use defaults.
    if len(body.question.strip()) < 3:
        raise HTTPException(422, "Type a question or decision to weigh up.")
    return {"body": body.model_dump(), "state": state, "expires": time.time() + 600}


def review_rows(prepared):
    body, state = prepared["body"], prepared["state"]
    return [{"label": "Question or decision", "after": body["question"]},
            {"label": "The case for", "after": " ".join((body["for_side"] or "").split()) or "The answer is yes; the idea is sound"},
            {"label": "The case against", "after": " ".join((body["against_side"] or "").split()) or "The answer is no; the idea is flawed"},
            {"label": "Arguments per side", "after": str(body["rounds"])},
            {"label": "AI service model", "after": state["model_label"]},
            {"label": "Spending ceiling", "after": f"${state['cap']:.2f}; current personal, workspace and provider limits also apply"},
            {"label": "What happens", "after": NOTICE}]


def _check(request, prepared, *, spending=True):
    authority(request, prepared["state"]["context"], write=True)
    expires = prepared["expires"]
    if type(expires) not in {int, float} or not math.isfinite(expires) or not time.time() < expires <= time.time() + 601:
        raise HTTPException(409, "This viewpoints review expired. Review your current question and spending settings again.")
    state = current(request)
    if digest(state) != digest(prepared["state"]):
        raise HTTPException(409, "Your access, selected workspace or AI settings changed. The original request will not be repeated.")
    # A queue wait must not inherit an allowance that has since been used.
    from maverick import killswitch, quotas, spending_limits
    from maverick.orchestrator import _execution_principal
    from maverick.paths import current_tenant_id
    from maverick.tenant.registry import assert_tenant_active

    from .auth import execution_user_id_from_request
    try:
        killswitch.check()
    except killswitch.Halted as exc:
        raise HTTPException(409, "Lightwork is paused by an emergency stop. An administrator can resume it. The original request will not be repeated.") from exc
    assert_tenant_active(current_tenant_id())
    if not spending:
        return
    principal = _execution_principal(user_id=execution_user_id_from_request(request), capability=None)
    if quotas.quotas_enforced() and quotas.over_quota(principal):
        raise HTTPException(409, "Your current spending allowance is used up. The original request will not be repeated.")
    refusal = spending_limits.start_refusal(principal)
    if refusal:
        raise HTTPException(409, refusal)


def owned(request, operation_id):
    context = authority(request)
    if not re.fullmatch(r"[a-f0-9]{32}", operation_id):
        raise HTTPException(404, "That original viewpoints request is unavailable.")
    row = records().get("VPR-" + operation_id)
    owner, tenant = ops_jobs.identity(request)
    if row and (row["owner"] != owner or row["tenant"] != tenant or row["context"] != context):
        raise HTTPException(404, "That original viewpoints request is unavailable to your account.")
    authority(request, context)
    if row and row.get('_audit_pending'):
        row = records()._flush(row)
        authority(request, context)
    return row


def original(request, operation_id):
    context = authority(request)
    row = owned(request, operation_id)
    value = {"operation": operation_id, "context": context, "confirmed": False, "result": None,
             "message": "This original request is unavailable. Absence does not establish failure. Nothing was started again.", "worker": None}
    if row:
        private = opened(row["payload"])
        value["question"] = private["prepared"]["body"]["question"]
        value["model"] = private["prepared"]["state"]["model_label"]
        value["confirmed"] = row["state"] == "completed" and not row.get("_audit_pending")
        value["result"] = private.get("result") if value["confirmed"] else None
        value["message"] = ("These are the saved answers from your original request. Nothing was repeated." if value["confirmed"] and value["result"]["ran"] else
                            "The original request ended without a complete answer. Nothing was repeated." if value["confirmed"] else
                            "The original request is retained, but its final answer is unconfirmed. Nothing was started again.")
        job = ops_jobs.JOBS.get(operation_id, owner=row["owner"], tenant=row["tenant"], kind="viewpoints")
        value["worker"] = job["state"] if job else None
        if job is None and not value["confirmed"]:
            value["message"] += " Its live progress is unavailable after a restart or removal; that does not prove it failed."
        elif job and job["state"] == "running" and not value["confirmed"]:
            value["message"] += " The original work is still being observed; check this same request again."
    authority(request, context)
    return value


def history(request):
    context = authority(request)
    owner, tenant = ops_jobs.identity(request)
    retained = records().list(limit=1001)
    if len(retained) > 1000:
        raise HTTPException(503, "The complete original history exceeds its supported bound. Nothing was omitted; original results remain readable individually.")
    found = [row for row in retained if row.get("owner") == owner and row.get("tenant") == tenant and row.get("context") == context]
    found.sort(key=lambda row: row["created_at"], reverse=True)
    rows = []
    for row in found:
        private = opened(row["payload"])
        rows.append({"value": row["id"][4:], "label": private["prepared"]["body"]["question"][:120], "created_at": row["created_at"],
                     "completed": row["state"] == "completed" and not row.get("_audit_pending")})
    authority(request, context)
    return {"context": context, "requests": rows}


def start(request, prepared, operation_id):
    context = authority(request, prepared["state"]["context"], write=True)
    owner, tenant = ops_jobs.identity(request)
    binding = digest([owner, tenant, context, operation_id, prepared])
    with authority_effect_fence():
        existing = owned(request, operation_id)
        if existing:
            if existing["binding"] != binding:
                raise HTTPException(409, "This original request belongs to another review. Read it without repeating work.")
            return original(request, operation_id)
        _check(request, prepared)
        from .app import check_goal_rate_limit
        check_goal_rate_limit(request, source="viewpoints")
        claim = records().create({"id": "VPR-" + operation_id, "owner": owner, "tenant": tenant, "context": context,
                                  "binding": binding, "state": "admitting", "payload": seal({"prepared": prepared})},
                                 action="viewpoints.prepare", actor=owner, max_records=1000)
        if claim.get("_audit_pending"):
            return original(request, operation_id)

    def work():
        with authority_effect_fence():
            def admitted(row):
                _check(request, prepared)
                row["state"] = "running"
            running = records().update(claim["id"], admitted, expected_revision=claim["revision"], action="viewpoints.admitted", actor=owner)
            if running.get("_audit_pending"):
                raise ValueError("The original admission activity is unconfirmed. No AI request was sent.")
        def guard():
            # The SDK repeats this immediately before physical dispatch. The
            # fence is released before any provider/network work takes place.
            with authority_effect_fence():
                _check(request, prepared)
        from maverick.orchestrator import _execution_principal

        from .auth import execution_user_id_from_request
        principal = _execution_principal(user_id=execution_user_id_from_request(request), capability=None)
        body = prepared["body"]
        try:
            result = viewpoints_api._run(body["question"], body["rounds"], principal, owner,
                                         (body["for_side"], body["against_side"]), model=prepared["state"]["model"], guard=guard)
        except viewpoints_api._Refused as exc:
            result = {"ran": False, "message": str(exc)}
        with authority_effect_fence():
            def finished(row):
                _check(request, prepared, spending=False)
                row.update(state="completed", payload=seal({"prepared": prepared, "result": result}))
            records().update(claim["id"], finished, expected_revision=running["revision"], action="viewpoints.completed", actor=owner)
        return result

    try:
        ops_jobs.JOBS.start(owner=owner, tenant=tenant, kind="viewpoints", work=work, job_id=operation_id)
    except ops_jobs.Busy:
        # The exact claim is already durable. No second start can be inferred
        # safe; history separates that custody from a live worker observation.
        pass
    return original(request, operation_id)
