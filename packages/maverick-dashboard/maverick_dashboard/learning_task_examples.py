"""Explicit owned-task selection for the existing reviewed question writer."""
from __future__ import annotations

import base64
import json
import math
import time

from fastapi import HTTPException
from maverick import crypto_at_rest
from maverick import self_harness_eval as corpus
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest

from . import auth
from . import learning_ops_api as native
from .draft_api import context_for

USE = ("Store the reviewed question and expected answer in this installation's shared self-coaching collection. "
       "Only the question text and expected answer are saved; attachments, conversation history and other task inputs are not included. "
       "If those are needed to understand the answer, write a separate question that stands on its own. "
       "Administrators managing that storage can access retained information. Future checks may send these texts to configured AI providers, "
       "only in the original workspace while the task and its copied sources still permit this use. "
       "While its source remains available, retire the question to remove it from future checks. "
       "Withdrawing access to its source also excludes it from future checks. Neither change erases past checks or provider exposure.")
_PURPOSE = "lightwork.owned-task-question.v1"


def authority(request, context=None):
    """Current named owner, session/key, administrator and page authority."""
    with auth.fresh_configuration():
        principal = getattr(request.state, "principal", None)
        claims = getattr(principal, "claims", None) or {}
        via = claims.get("via")
        fresh = principal
        if via == "api_key":
            fresh = auth._authenticate_api_key(request, auth._api_key_bearer(request))
        elif via in {"session", "invite", "proxy"}:
            fresh = {"session": auth._session_principal, "invite": auth._invite_session_principal,
                     "proxy": auth._proxy_principal}[via](request)
        if principal is None or fresh is None or fresh.principal != principal.principal:
            raise HTTPException(401, "Sign in with the account that owns the completed task.")
        request.state.principal = fresh
        claims = fresh.claims or {}
        expiry = claims.get("exp")
        if expiry is not None and (type(expiry) not in {int, float} or not time.time() < expiry < math.inf):
            raise HTTPException(401, "Sign in again before using this completed task.")
        auth._enforce_scim_active(fresh)
        auth._enforce_workspace_policies(request, fresh)
        auth.require_global_permission(request, "admin")
        auth.require_permission(request, "operate")
        auth.require_page_permission(request, "/learned")
        from .app import require_page_visible
        require_page_visible(request, "/learned")
        actor = auth.caller_principal(request)
        current = context_for(request)
        if not actor or not actor.startswith("user:"):
            raise HTTPException(403, "Use your named sign-in account to choose your completed work.")
        if context is not None and current != context:
            raise HTTPException(409, "Your account or workspace changed. Refresh the task choices.")
        return current, actor


def source(request, goal_id, context=None):
    with authority_effect_fence(), auth.fresh_configuration():
        current, actor = authority(request, context)
        world = native._world()
        goal = world.get_goal(goal_id)
        if goal is None or goal.owner != actor or not auth.can_access_goal(request, goal):
            raise HTTPException(404, "This completed task is unavailable to your current account.")
        try:
            binding = corpus.task_question_source(world, goal_id, actor)
        except (ValueError, PermissionError, OSError) as exc:
            raise HTTPException(409, "This task or a copied source does not currently permit learning. Protected evaluations and Knowledge analyses are not offered here.") from exc
        question, answer = goal.description or goal.title, goal.result or ""
        if (not question.strip() or not answer.strip() or len(question) > 4000 or len(answer) > 4000
                or len(goal.title) > 4000):
            raise HTTPException(409, "This task's complete question or answer cannot fit this editor. Nothing was copied. Write a separate question and expected answer explicitly instead.")
        if corpus.task_question_source(world, goal_id, actor) != binding:
            raise HTTPException(409, "The completed task changed while it was read. Choose it again.")
        authority(request, current)
        return {"context": current, "source": binding, "title": goal.title, "question": question, "answer": answer}


def catalog(request, *, offset=0):
    current, actor = authority(request)
    world = native._world()
    rows = world.list_goals("done", owner=actor, limit=51, offset=offset, order="desc")
    tasks = []
    for goal in rows[:50]:
        if auth.can_access_goal(request, goal):
            tasks.append({"value": str(goal.id), "label": goal.title or "Completed task"})
    authority(request, current)
    return {"context": current, "revision": digest([current, [[row.id, row.updated_at] for row in rows]]),
            "tasks": tasks, "next": offset + 50 if len(rows) > 50 else None, "offset": offset, "scope": USE}


def selected(request, goal_id, context):
    value = source(request, goal_id, context)
    material = {**value, "purpose": _PURPOSE, "expires": time.time() + 600}
    token = base64.b64encode(crypto_at_rest.seal_bound(json.dumps(material, ensure_ascii=False).encode(), _PURPOSE)).decode()
    return {"context": value["context"], "title": value["title"], "question": value["question"],
            "answer": value["answer"], "source_reference": token, "scope": USE}


def reviewed_source(request, reference, context):
    try:
        value = json.loads(crypto_at_rest.unseal_bound(base64.b64decode(reference, validate=True), _PURPOSE))
        if (set(value) != {"context", "source", "title", "question", "answer", "purpose", "expires"}
                or value["purpose"] != _PURPOSE or type(value["expires"]) not in {int, float}
                or not time.time() < value["expires"] <= time.time() + 600):
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This selected task review changed or expired. Choose the current task again; your entered question is kept.") from exc
    current = source(request, value["source"]["goal_id"], context)
    if value["context"] != context or any(current[key] != value[key] for key in current):
        raise HTTPException(409, "The selected task changed. Choose its current answer and review it again.")
    return value


def case_access(request, row):
    binding = row.get("task_source")
    if binding is None:
        return True
    try:
        return source(request, binding["goal_id"])["source"] == binding
    except (HTTPException, KeyError, TypeError):
        return False
