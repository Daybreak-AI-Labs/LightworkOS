"""An owner-bound, read-only conversation beside the existing task runtime.

Draft conversations use the configured model facade without agent tools. Closed
supervision intents read the caller's current tasks; existing durable chat/runner
admission is unchanged. Companion text never becomes a goal or an ordinary audit
payload. Companion content remains within its separate owner-bound policy.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Callable
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response
from maverick import config
from maverick import employee_companion_model as companion_model
from maverick.authority_effects import authority_effect_fence
from maverick.conversational_supervisor import DEFAULT_GRAMMAR, parse_utterance
from maverick.domain import suites_for_domain
from maverick.ediscovery import LegalHoldApplies
from maverick.employee_companion import (
    CompanionConflictError,
    CompanionError,
    CompanionPolicyDenied,
    CompanionValidationError,
    EmployeeCompanionStore,
)
from maverick.governed_operations import digest
from maverick.paths import current_tenant_id_strict, tenant_scope
from maverick.suite_grants import granted_suites
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth, rbac, scim_groups
from .identity_format import humanize_principal

router = APIRouter(tags=["employee-companion"])
BASE = "/api/v1/employee-companion"
_HEADER = "X-Lightwork-Companion-Context"
_GRAMMAR = [(intent, pattern) for intent, pattern in DEFAULT_GRAMMAR if intent in {"status", "failures"}]
_GRAMMAR += [("failures", "what needs attention"), ("status", "show my tasks")]
_HELP = ("I can show the status of your own tasks. Try ‘what is running?’ or "
         "‘what needs attention?’. This preview cannot start, stop, or change work.")
_STATUSES = ("active", "pending", "blocked", "failed", "error", "draft")
_STATUS_LABELS = {"active": "running", "pending": "queued", "blocked": "needs attention",
                  "failed": "failed", "error": "needs attention", "draft": "awaiting submission"}


class MessageIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    message: str = Field(min_length=1, max_length=4000)
    expected_revision: int = Field(ge=0)
    mode: Literal["task_status", "conversation"] = "task_status"
    request_id: str | None = Field(default=None, min_length=1, max_length=64)
    expected_history_generation: int | None = Field(default=None, ge=0)


class PolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    owner: str = Field(min_length=6, max_length=320)
    expected_revision: int = Field(ge=0)
    enabled: bool
    allowed_sources: list[str] = Field(max_length=1)
    allowed_tools: list[str] = Field(max_length=2)
    retention_days: int


class HistoryClearIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: str = Field(pattern=r"^[a-f0-9]{64}$")


def _enabled() -> bool:
    return config.get_features().get("employee_companions") is True


def _credential_binding(request, actor, tenant):
    """Revalidate ambient credentials locally and bind long replies to sign-in.

    Cookie identities discard issued-at claims after middleware verification,
    so use their existing local verifier again. OIDC bearer claims already have
    a verified signature; only expiry/revocation are rechecked here, without a
    fresh identity-provider network request.
    """
    from . import session_revocation, workspace_tenants

    principal = getattr(request.state, "principal", None)
    if principal is not None:
        claims = principal.claims or {}
        via = claims.get("via")
        if via in {"session", "invite"}:
            fresh = (auth._session_principal(request) if via == "session"
                     else auth._invite_session_principal(request))
            if fresh is None or fresh.principal != actor:
                raise HTTPException(401, "Sign in again before using your companion.")
        elif via != "proxy":
            expiry = claims.get("exp")
            if (session_revocation.is_revoked(actor.removeprefix("user:"), claims.get("iat"))
                    or (expiry is not None and (not isinstance(expiry, (int, float))
                        or isinstance(expiry, bool) or not math.isfinite(expiry) or expiry <= time.time()))):
                raise HTTPException(401, "Sign in again before using your companion.")
    selection = workspace_tenants.get_selection_binding(actor)
    if getattr(request.state, "workspace_tenant_source", None) == "principal_selection" and selection[0] != tenant:
        raise HTTPException(409, {"code": "companion_context_changed", "message": "Your workspace changed. Reload your companion."})
    return {"epoch": session_revocation.revocation_epoch(actor.removeprefix("user:")), "selection": selection}


def _authority(request: Request, *, admin: bool = False, write: bool = False,
               reviewed_context: str | None = None):
    """Named, current workspace membership is mandatory, including for admins."""
    auth.require_permission(request, "admin" if admin else "view")
    actor = auth.caller_principal(request)
    tenant = current_tenant_id_strict()
    if not actor or not actor.startswith("user:") or not tenant:
        raise HTTPException(403, "Sign in with a named account and select a workspace to use a companion.")
    membership = rbac.get_tenant_role(tenant, actor)
    if "view" not in rbac.permissions_for(membership) or scim_groups.active_for_principal(actor) is False:
        raise HTTPException(403, "Current workspace membership is required to use a companion.")
    _credential_binding(request, actor, tenant)
    context = hashlib.sha256(json.dumps(["employee-companion-v1", tenant, actor]).encode()).hexdigest()
    supplied = request.headers.get(_HEADER)
    if reviewed_context is not None:
        if supplied is not None and not auth.constant_time_equals(supplied, reviewed_context):
            raise HTTPException(409, "Your account or workspace changed. Review the companion policy again.")
        supplied = reviewed_context
    if write:
        from .app import _require_same_origin

        _require_same_origin(request)
    if (write and supplied is None) or (supplied is not None and not auth.constant_time_equals(supplied, context)):
        raise HTTPException(409, {"code": "companion_context_changed",
                                  "message": "Your account or workspace changed. Reload the companion before continuing."})
    return actor, tenant, context


def _call_sync(request: Request, operation: Callable, *, admin=False, write=False,
               reviewed_context: str | None = None):
    """The native authority/effect contract, shared by HTTP and sealed Copilot."""
    try:
        with authority_effect_fence():
            actor, tenant, context = _authority(request, admin=admin, write=write,
                                               reviewed_context=reviewed_context)
            return operation(actor, tenant, context, EmployeeCompanionStore())
    except HTTPException:
        raise
    except CompanionConflictError as exc:
        raise HTTPException(409, "Companion policy changed. Refresh and review your request again.") from exc
    except CompanionPolicyDenied as exc:
        raise HTTPException(403, "Your administrator has not allowed this companion operation.") from exc
    except CompanionValidationError as exc:
        raise HTTPException(422, "Choose the supported read-only companion options.") from exc
    except LegalHoldApplies as exc:
        raise HTTPException(409, str(exc)) from exc
    except (CompanionError, OSError, ValueError) as exc:
        raise HTTPException(503, "Companion state is unavailable. Refresh before retrying; no task was changed.") from exc
    except Exception as exc:
        # Role/group or source-store outages must not fall back to broader
        # defaults, disclose internal paths, or show an unaudited answer.
        raise HTTPException(503, "Companion access is unavailable. Refresh before retrying; no task was changed.") from exc


async def _call(request: Request, response: Response, operation: Callable, *, admin=False, write=False,
                reviewed_context: str | None = None):
    response.headers["Cache-Control"] = "private, no-store"
    return await run_in_threadpool(_call_sync, request, operation, admin=admin, write=write,
                                 reviewed_context=reviewed_context)


def _status_available(policy):
    return (_enabled() and policy["enabled"] and "own_tasks" in policy["allowed_sources"]
            and "task_status" in policy["allowed_tools"])


def _conversation_available(policy):
    return _enabled() and policy["enabled"] and "draft_reply" in policy["allowed_tools"]


def _available(policy):
    return _status_available(policy) or _conversation_available(policy)


def _explanation(policy):
    if not _enabled():
        return "Employee companions are turned off for this installation. An administrator can enable them in Settings."
    if not policy["enabled"]:
        return "Your administrator has not enabled your companion in this workspace."
    if not _available(policy):
        return "Your companion policy does not currently allow conversations or task status. Saved conversation can still be cleared."
    return "Draft replies and task status follow your current policy. Connected sources, actions, and learned memory are unavailable."


def _goal_allowed(world, goal, actor, suites):
    if goal is None or goal.owner != actor:
        return False
    if suites is not None and not suites_for_domain(goal.domain) <= suites:
        return False
    if goal.project_id is not None:
        project = world.get_project(goal.project_id)
        if not project or project.get("owner") != actor:
            return False
    return True


def _task_item(goal):
    return {"goal_id": goal.id, "title": goal.title, "status": goal.status,
            "href": f"/chat/goal/{goal.id}", "checked_at": time.time()}


def _sources(actor, refs):
    """Reauthorize explicit provenance, including tasks that have since ended."""
    if not refs:
        return {}
    from .app import _world

    world = _world()
    suites = granted_suites(actor)
    permitted = {}
    for ref in refs:
        goal = world.get_goal(int(ref.removeprefix("task:")))
        if _goal_allowed(world, goal, actor, suites):
            permitted[ref] = _task_item(goal)
    return permitted


def _tasks(actor, *, attention=False):
    from .app import _world

    world = _world()
    # Deliberately do not use goal_owner_filter/caller_suites: their bootstrap
    # administrator bypass is not authority over another person's companion.
    suites = granted_suites(actor)
    statuses = ("blocked", "failed", "error", "draft") if attention else _STATUSES
    rows = {}
    for status in statuses:
        for goal in world.list_goals(owner=actor, status=status, limit=50, order="desc"):
            if not _goal_allowed(world, goal, actor, suites):
                continue
            # Running work may change status between the bounded queries.
            # Keep one source per task rather than duplicate its receipt.
            rows[goal.id] = _task_item(goal)
    return sorted(rows.values(), key=lambda item: item["goal_id"], reverse=True)[:50]


def _eligible_history(store, actor):
    policy = store.policy(actor)
    history = store.history(actor)
    refs = {ref for item in history for ref in item["source_refs"]}
    permitted = _sources(actor, refs) if "own_tasks" in policy["allowed_sources"] else {}
    return [item for item in history if all(ref in permitted for ref in item["source_refs"])]


def _history(store, actor):
    # Suppress complete exchanges whose source permissions have been removed.
    # Historic links are not reconstructed in the browser.
    turns = []
    for item in _eligible_history(store, actor):
        turns.extend([{"role": "user", "content": item["message"]},
                      {"role": "assistant", "content": item["response"], "sources": [],
                       "kind": item.get("kind", "task_status"), "model_route": item.get("model_route")}])
    return turns


def _snapshot(store, actor, context):
    policy = store.policy(actor)
    history = _history(store, actor)  # Expiration can change the generation.
    return {"context": context, "policy": policy, "available": _available(policy),
            "status_available": _status_available(policy),
            "conversation_available": _conversation_available(policy),
            "explanation": _explanation(policy), "history": history,
            "tasks": _tasks(actor) if _available(policy) and "own_tasks" in policy["allowed_sources"] else [],
            **store.conversation_state(actor),
            "history_revision": store.history_review(actor)["revision"]}


def _conversation_review(store, actor, context):
    """Current owner-only work and history metadata, without prior private text."""
    policy = store.policy(actor)
    _eligible_history(store, actor)  # Expiry and source access affect admission.
    tasks = _tasks(actor) if _available(policy) and "own_tasks" in policy["allowed_sources"] else []
    tasks = [{key: value for key, value in task.items() if key != "checked_at"} for task in tasks]
    state = {"context": context, "owner": actor, "policy": policy, "tasks": tasks,
             "status_available": _status_available(policy), "conversation_available": _conversation_available(policy),
             "explanation": _explanation(policy), "history": store.history_review(actor),
             **store.conversation_state(actor)}
    return {**state, "revision": digest(state)}


def conversation_review(request: Request):
    return _call_sync(request, lambda actor, _tenant, context, store: _conversation_review(store, actor, context))


def _turn_fingerprint(actor, tenant, body):
    return hashlib.sha256(json.dumps(
        [tenant, actor, body.message.strip(), body.expected_revision, body.expected_history_generation],
        ensure_ascii=False, separators=(",", ":"),
    ).encode()).hexdigest()


def _request_result(store, actor, request_id):
    result = store.turn_result(actor, request_id)
    reply = result["reply"]
    if reply is not None:
        policy = store.policy(actor)
        permitted = _sources(actor, reply["source_refs"]) if "own_tasks" in policy["allowed_sources"] else {}
        if any(ref not in permitted for ref in reply["source_refs"]):
            reply = None
    return {**result, "reply": reply}


def conversation_request(request: Request, request_id: str):
    return _call_sync(request, lambda actor, _tenant, context, store:
                      {"context": context, **_request_result(store, actor, request_id)})


def admit_reviewed_draft(request: Request, body: MessageIn, *, reviewed_context: str,
                         expected_state: str, expected_route: dict, expected_limits: dict):
    """Consume the same native request receipt; never perform paid I/O here."""
    def prepare(actor, tenant, context, store):
        if _conversation_review(store, actor, context)["revision"] != expected_state:
            raise CompanionConflictError("conversation or task context changed")
        route = companion_model.prepare_route()
        if vars(route) != expected_route or companion_model.draft_limits() != expected_limits:
            raise CompanionConflictError("configured AI or allowance changed")
        admitted = _prepare_draft_turn(request, body, body.message.strip(), actor, tenant, context, store)
        if "duplicate" not in admitted:
            admitted["reviewed_route"] = expected_route
            admitted["reviewed_limits"] = expected_limits
        return admitted
    return _call_sync(request, prepare, write=True, reviewed_context=reviewed_context)


@router.get(BASE)
async def current(request: Request, response: Response):
    def operation(actor, _tenant, context, store):
        return _snapshot(store, actor, context)

    return await _call(request, response, operation)


@router.post(BASE + "/messages")
async def message(request: Request, response: Response, body: MessageIn):
    if body.mode == "conversation":
        return await _draft_message(request, response, body)

    def operation(actor, _tenant, context, store):
        policy = store.policy(actor)
        if policy["revision"] != body.expected_revision:
            raise CompanionConflictError("policy changed")
        if not _status_available(policy):
            raise CompanionPolicyDenied("operation disabled")
        if (body.expected_history_generation is not None
                and store.conversation_state(actor)["history_generation"] != body.expected_history_generation):
            raise CompanionConflictError("conversation changed")
        text = body.message.strip()
        if not text:
            raise HTTPException(422, "Write a message before sending.")
        parsed = parse_utterance(text, _GRAMMAR)
        tasks = _tasks(actor, attention=parsed[0] == "failures") if parsed else []
        if parsed:
            counts = {status: sum(item["status"] == status for item in tasks) for status in _STATUSES}
            summary = ", ".join(f"{count} {_STATUS_LABELS[status]}" for status, count in counts.items() if count)
            reply = (f"Your current task view shows {summary}. Open a source below to review its work."
                     if tasks else "No matching tasks are visible in your current task view.")
            reply += " This view includes at most 50 tasks and reflects your current access."
        else:
            reply = _HELP
        result = store.record_exchange(actor, message=text, response=reply,
                                       source_refs=[f"task:{item['goal_id']}" for item in tasks],
                                       expected_revision=body.expected_revision)
        return {**_snapshot(store, actor, context),
                "message": {"role": "assistant", "kind": "task_status", "content": reply,
                            "sources": tasks, "trace": result["trace"]}}

    return await _call(request, response, operation, write=True)


def _prepare_draft_turn(request, body, text, actor, tenant, context, store):
    """Bind source access and consume one request receipt before model I/O."""
    credentials = _credential_binding(request, actor, tenant)
    policy = store.policy(actor)
    if not _conversation_available(policy):
        raise CompanionPolicyDenied("model conversation disabled")
    # Prune expired history before checking the browser's generation.
    history = _eligible_history(store, actor)
    tasks = _tasks(actor) if "own_tasks" in policy["allowed_sources"] else []
    refs = {f"task:{task['goal_id']}" for task in tasks}
    selected = []
    # Bound both the prompt and the complete transitive source provenance.
    for exchange in reversed(history[-6:]):
        combined = refs | set(exchange["source_refs"])
        if len(combined) <= 50:
            selected.insert(0, exchange)
            refs = combined
    sources = _sources(actor, sorted(refs))
    if set(sources) != refs:
        raise CompanionPolicyDenied("task source permission changed")
    fingerprint = _turn_fingerprint(actor, tenant, body)
    ticket = store.reserve_turn(actor, request_id=body.request_id,
                                expected_revision=body.expected_revision,
                                expected_history_generation=body.expected_history_generation,
                                fingerprint=fingerprint)
    if not ticket["acquired"]:
        return {"duplicate": {**_snapshot(store, actor, context), "request": store.turn_status(actor, body.request_id)}}
    try:
        from .app import check_goal_rate_limit

        check_goal_rate_limit(request, source="employee_companion")
        route = companion_model.prepare_route()
    except Exception:
        store.abandon_turn(actor, request_id=body.request_id, token=ticket["token"])
        raise
    return {"actor": actor, "tenant": tenant, "context": context, "ticket": ticket,
            "route": route, "history": selected, "sources": list(sources.values()), "refs": sorted(refs),
            "credentials": credentials}


async def _draft_message(request: Request, response: Response, body: MessageIn):
    """Reserve briefly, perform model I/O outside authority locks, then publish.

    A request receipt is consumed even if delivery or the provider fails. Neither
    this coordinator nor the client automatically retries a paid request.
    """
    text = body.message.strip()
    if not text or body.request_id is None or body.expected_history_generation is None:
        raise HTTPException(422, "A message, request identifier, and current conversation generation are required.")

    def prepare(actor, tenant, context, store):
        return _prepare_draft_turn(request, body, text, actor, tenant, context, store)

    admitted = await _call(request, response, prepare, write=True)
    if "duplicate" in admitted:
        return admitted["duplicate"]
    return await complete_admitted_draft(request, response, body, admitted)


async def complete_admitted_draft(request: Request, response: Response, body: MessageIn, admitted: dict,
                                  *, reviewed_context: str | None = None):
    """Shared native completion, run only after the admission fence is released."""
    text = body.message.strip()
    actor, tenant, ticket = admitted["actor"], admitted["tenant"], admitted["ticket"]
    binding = {"request_id": body.request_id, "token": ticket["token"],
               "expected_revision": body.expected_revision, "history_generation": ticket["history_generation"]}

    def validate():
        with authority_effect_fence():
            current_actor, current_tenant, context = _authority(request, write=True, reviewed_context=reviewed_context)
            if (current_actor, current_tenant, context) != (actor, tenant, admitted["context"]):
                raise CompanionPolicyDenied("identity changed")
            if _credential_binding(request, actor, tenant) != admitted["credentials"]:
                raise HTTPException(409, {"code": "companion_context_changed", "message": "Your sign-in or workspace changed. Reload your companion."})
            store = EmployeeCompanionStore()
            if not _conversation_available(store.policy(actor)):
                raise CompanionPolicyDenied("model conversation disabled")
            store.validate_turn(actor, **binding)
            if set(_sources(actor, admitted["refs"])) != set(admitted["refs"]):
                raise CompanionPolicyDenied("task source permission changed")
            companion_model.validate_route(admitted["route"])
            if (admitted.get("reviewed_route") is not None
                    and (vars(admitted["route"]) != admitted["reviewed_route"]
                         or companion_model.draft_limits() != admitted["reviewed_limits"])):
                raise CompanionConflictError("configured AI or allowance changed")

    completed = False
    try:
        def generate():
            validate()
            return companion_model.generate_draft(
                actor=actor, tenant=tenant, route=admitted["route"], message=text,
                history=admitted["history"], tasks=admitted["sources"], dispatch_guard=validate,
            )

        # No policy/store lock crosses the potentially slow provider call. The
        # facade invokes validate again at physical dispatch; publication repeats
        # it. Already dispatched data cannot be recalled by later revocation.
        reply = await run_in_threadpool(generate)

        def publish(_actor, _tenant, context, store):
            validate()
            result = store.finish_turn(actor, **binding, message=text, response=reply,
                                       source_refs=admitted["refs"], model_route=admitted["route"].model)
            return {**_snapshot(store, actor, context), "request_id": body.request_id,
                    "request": store.turn_status(actor, body.request_id),
                    "message": {"role": "assistant", "kind": "draft", "content": reply,
                                "model_route": admitted["route"].model, "sources": list(_sources(actor, admitted["refs"]).values()),
                                "trace": result["trace"]}}

        result = await _call(request, response, publish, write=True, reviewed_context=reviewed_context)
        completed = True
        return result
    except HTTPException:
        raise
    except CompanionPolicyDenied as exc:
        raise HTTPException(403, "Your administrator has not allowed this companion operation.") from exc
    except CompanionConflictError as exc:
        raise HTTPException(409, "Companion conversation changed. Refresh before sending another message.") from exc
    except Exception as exc:
        raise HTTPException(503, "The draft could not be published. Check its request status before sending another message; the provider may already have processed it.") from exc
    finally:
        if not completed:
            def abandon():
                # Cleanup may run after offboarding. Only the captured opaque
                # lease may be closed; no history/content is read or returned.
                if current_tenant_id_strict() == tenant:
                    EmployeeCompanionStore().abandon_turn(actor, request_id=body.request_id, token=ticket["token"])

            try:
                await run_in_threadpool(abandon)
            except Exception:
                pass  # Its bounded lease expires; never retry the model.


async def continue_reviewed_draft(request: Request, body: MessageIn, admitted: dict, reviewed_context: str):
    """Complete once outside Copilot's effect fence; status recovers failures."""
    with tenant_scope(tenant=admitted["tenant"]):
        try:
            await complete_admitted_draft(request, Response(), body, admitted, reviewed_context=reviewed_context)
        except HTTPException:
            # The native coordinator consumes/ends the request even on failure.
            # The owner reads its saved status; another paid call is never sent.
            return


@router.get(BASE + "/requests/{request_id}")
async def request_status(request_id: str, request: Request, response: Response):
    def operation(actor, _tenant, context, store):
        snapshot = _snapshot(store, actor, context)
        result = _request_result(store, actor, request_id)
        return {**snapshot, "request": result["request"],
                "retained_reply": ({"role": "assistant", "kind": "draft", "content": result["reply"]["response"]}
                                   if result["reply"] is not None else None)}

    return await _call(request, response, operation)


@router.delete(BASE + "/history")
async def clear_history(request: Request, response: Response, body: HistoryClearIn):
    def operation(actor, _tenant, context, store):
        trace = store.clear_history(actor, actor=actor, expected_revision=body.expected_revision)
        return {"context": context, "history": [], "trace": trace,
                **store.conversation_state(actor),
                "history_revision": store.history_review(actor)["revision"]}

    return await _call(request, response, operation, write=True)


def _employees(tenant):
    people = []
    for principal, role in rbac.list_tenant_roles(tenant).items():
        if (principal.startswith("user:") and "view" in rbac.permissions_for(role)
                and scim_groups.active_for_principal(principal) is not False):
            identity = humanize_principal(principal)
            label = identity.name + (f" ({identity.detail})" if identity.detail and identity.detail != "Email" else "")
            people.append({"principal": principal, "label": label})
    return sorted(people, key=lambda item: (item["label"].casefold(), item["principal"]))


@router.get(BASE + "/admin")
async def administration(request: Request, response: Response):
    def operation(_actor, tenant, context, store):
        return {"context": context, "available": _enabled(),
                "explanation": ("Policies apply only to this read-only companion. Administrators cannot read companion conversation text here."
                                if _enabled() else "Turn on Employee companions in Settings. You can prepare employee policies here first."),
                "policies": store.policies(), "employees": _employees(tenant), "events": store.events()}

    return await _call(request, response, operation, admin=True)


@router.put(BASE + "/admin/policy")
async def update_policy(request: Request, response: Response, body: PolicyIn):
    response.headers["Cache-Control"] = "private, no-store"
    return await run_in_threadpool(administration_update, request, body)


def administration_update(request: Request, body: PolicyIn, *, reviewed_context: str | None = None):
    """Apply the existing exact policy revision with current native authority."""
    def operation(actor, tenant, context, store):
        if body.owner not in {item["principal"] for item in _employees(tenant)}:
            raise HTTPException(404, "Choose a current member of this workspace.")
        policy = store.update_policy(body.owner, actor=actor, **body.model_dump(exclude={"owner"}))
        return {"context": context, "policy": policy}

    return _call_sync(request, operation, admin=True, write=True, reviewed_context=reviewed_context)


def administration_employee(request: Request, owner: str):
    """Current member policy and bounded activity metadata, never history text."""
    def operation(_actor, tenant, context, store):
        employees = _employees(tenant)
        employee = next((item for item in employees if item["principal"] == owner), None)
        if employee is None:
            raise HTTPException(404, "Choose a current member of this workspace.")
        labels = {item["principal"]: item["label"] for item in employees}
        return {"context": context, "employee": employee, "available": _enabled(),
                "policy": store.policy(owner),
                "events": [{**event, "actor_label": labels.get(event["actor"], "Workspace member")}
                           for event in store.events() if event["owner"] == owner]}
    return _call_sync(request, operation, admin=True)


def navigation_available(request, *, admin=False):
    """Use the page's current named-member gate for advisory shell links."""
    try:
        with authority_effect_fence():
            _authority(request, admin=admin)
        return True
    except (HTTPException, OSError, ValueError):
        return False


def _page(request, *, admin=False):
    from .app import templates

    with authority_effect_fence():
        _actor, _tenant, context = _authority(request, admin=admin)
    name = "employee_companion_admin.html" if admin else "employee_companion.html"
    return templates.TemplateResponse(request, name, {"companion_context": context},
                                      headers={"Cache-Control": "private, no-store"})


@router.get("/companion")
def companion_page(request: Request):
    return _page(request)


@router.get("/companion/admin")
def companion_admin_page(request: Request):
    return _page(request, admin=True)
