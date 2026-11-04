"""Complete human review and original admission of alternative Chat messages."""
from __future__ import annotations

import json
import re
import secrets
import time

from fastapi import BackgroundTasks, HTTPException
from maverick import chat_message_actions as native
from maverick import config, crypto_at_rest
from maverick.attachment_submissions import SubmissionConflict, SubmissionStore
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.knowledge_task_context import SourceContextUnavailable
from maverick.paths import current_tenant_id_strict

from . import _shared, api, auth
from .api_flow_operator_review import _workspace_authority
from .api_schemas import GoalIn
from .draft_api import context_for

PURPOSE = "lightwork.chat-alternative.v1"
TTL = 600
LABELS = {"retry": "Try again", "edit": "Edit and resend", "branch": "Branch from here"}
NOTICE = "This creates a separate conversation. The original messages, answers and completed actions stay unchanged. Answer only generates text without taking actions. Allowing actions starts new work under your current permissions and may repeat earlier changes; it cannot undo them. AI use counts toward current spending and time limits."


def authority(request, expected=None, *, write=False):
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
        if principal is not None:
            if fresh is None or fresh.principal != principal.principal:
                raise HTTPException(401, "Sign in again before continuing this conversation.")
            expiry = claims.get("exp")
            if expiry is not None and (type(expiry) not in {int, float} or not time.time() < expiry < float("inf")):
                raise HTTPException(401, "Sign in again before continuing this conversation.")
            from . import session_revocation
            if via not in {"session", "invite", "proxy", "api_key"} and session_revocation.is_revoked(principal.sub, claims.get("iat")):
                raise HTTPException(401, "Sign in again before continuing this conversation.")
            auth._enforce_scim_active(fresh)
            auth._enforce_workspace_policies(request, fresh)
        auth.require_permission(request, "operate" if write else "view")
        from .app import require_page_visible
        require_page_visible(request, "/chat")
        current = context_for(request)
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected) or current != expected):
            raise HTTPException(409, "Your account or workspace changed. Reload Chat before continuing.")
        suites = auth.caller_suites(request)
        bound = {"context": current, "actor": auth.caller_principal(request) or "",
                 "workspace": _workspace_authority(request, auth.caller_principal(request) or "", current_tenant_id_strict() or ""),
                 "role": auth.caller_role(request), "suites": sorted(suites) if suites is not None else None,
                 "scopes": sorted(auth.api_key_scopes(request)) if auth.api_key_scopes(request) is not None else None}
        if write and not config.get_chat_message_actions()["enabled"]:
            raise HTTPException(403, "Conversation alternatives are turned off. Your draft and original request are kept; an administrator can manage this in Chat settings.",
                                headers={"X-Lightwork-Feature-Off": "chat_message_actions"})
        return bound


def _caps():
    return api._rest_goal_limits(GoalIn(title="Conversation alternative"))


def _source(request, goal, action, at_turn=None, *, connection=None):
    def authorize(value):
        auth.assert_goal_access(request, value)
        if (value.owner or "") != (auth.caller_principal(request) or ""):
            raise HTTPException(404, "Only your own conversation can be continued here.")
        from maverick.task_handoffs import closure
        if closure(_shared._world(), value.id):
            raise HTTPException(409, "This task was handed off and cannot be copied into new work. Open its handoff to review current responsibilities.")
    try:
        with auth.fresh_configuration():
            return native.source(_shared._world(), goal, action, at_turn=at_turn,
                owner=auth.caller_principal(request) or "", authorize=authorize, connection=connection)
    except (PermissionError, SourceContextUnavailable) as exc:
        raise HTTPException(403, "A copied source is no longer permitted for this account. Private conversation choices must be cleared; open currently permitted work.") from exc
    except (ValueError, OSError) as exc:
        raise HTTPException(409, str(exc) if isinstance(exc, SubmissionConflict) else
            "A retained message, file or source permission is unavailable. Review the current conversation before continuing.") from exc


def source(request, goal, action, expected, at_turn=None):
    before = authority(request, expected, write=True)
    material = _source(request, goal, action, at_turn)
    if before != authority(request, expected, write=True):
        raise HTTPException(409, "Your conversation access changed. Review current messages again.")
    return {"context": before["context"], "goal": goal, "action": action, "turn": at_turn,
            "source": digest(material), "message": "" if action == "branch" else material["question"],
            "history": material["prior"], "files": [{"name": row["filename"], "bytes": row["size_bytes"]} for row in material["files"]],
            "accounts": [{"name": row["name"]} for row in material["connections"]],
            "caps": _caps(), "notice": NOTICE}


def review(request, body):
    with authority_effect_fence():
        before = authority(request, body["context"], write=True)
        material = _source(request, body["goal"], body["action"], body.get("turn"))
        if digest(material) != body["source"]:
            raise HTTPException(409, "A message or file changed. Your edited message is kept; review the current conversation again.")
        if body["action"] == "retry" and body["message"] != material["question"]:
            raise HTTPException(409, "Use Edit and resend to change this saved question.")
        if not body["message"].strip():
            raise HTTPException(422, "Write the message for this separate conversation.")
        now = time.time()
        value = {"purpose": PURPOSE, "operation": secrets.token_hex(16), "authority": before,
                 "reviewed_at": now, "expires": now + TTL, "source": material, "message": body["message"],
                 "answer_only": body["answer_only"], "caps": _caps()}
        token = crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
        if not crypto_at_rest.is_sealed_str(token) or len(token) > 1048576:
            raise HTTPException(413, "This full conversation is too large for a protected review. Nothing was created; start a new conversation with explicitly chosen context.")
        authority(request, before["context"], write=True)
        return {"context": before["context"], "operation": value["operation"], "token": token,
                "action": LABELS[body["action"]], "message": body["message"], "history": material["prior"],
                "files": [{"name": row["filename"], "bytes": row["size_bytes"]} for row in material["files"]],
                "accounts": [{"name": row["name"]} for row in material["connections"]],
                "answer_only": body["answer_only"], "caps": value["caps"], "notice": NOTICE}


def opened(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if value["purpose"] != PURPOSE or not re.fullmatch(r"[a-f0-9]{32}", value["operation"]):
            raise ValueError
        return value
    except Exception as exc:
        raise HTTPException(409, "This protected original request cannot be verified. Keep your draft and review current choices.") from exc


def original(request, token):
    value = opened(token)
    before = authority(request, value["authority"]["context"])
    if before["actor"] != value["authority"]["actor"]:
        raise HTTPException(404, "This original request belongs to another account.")
    receipt = SubmissionStore(_shared._world()).lookup(token=value["operation"], owner=before["actor"])
    if receipt is None:
        return {"context": before["context"], "confirmed": False,
            "message": "This original request has no confirmed admission. It may still be in flight. Nothing was repeated; keep this request and check again."}
    expected = digest({"source": digest(value["source"]), "message": value["message"],
                       "answer_only": value["answer_only"], "caps": value["caps"], "admission": _admission(value)})
    if receipt["fingerprint"] != expected:
        raise HTTPException(409, "This original identity belongs to a different request.")
    goal = _shared._world().get_goal(receipt["goal_id"])
    if goal is None or goal.owner != before["actor"]:
        raise HTTPException(409, "The retained admission's conversation is unavailable. Nothing was repeated.")
    authority(request, before["context"])
    dispatch = {"draft": "AI work has not been confirmed as started; open its draft recovery controls.",
                "admitted": "AI work has not been confirmed as started; open its draft recovery controls.",
                "ready": "AI work has not been confirmed as started; open its draft recovery controls.",
                "dispatching": "The start was reserved, but its dispatch outcome is unconfirmed. Do not repeat this request.",
                "dispatched": "Its dispatch was recorded. Open the conversation to read its current progress.",
                "rejected": "Preparation was refused. Open the conversation to read the actual reason."}
    return {"context": before["context"], "confirmed": True, "state": receipt["state"],
            "goal": goal.id, "href": f"/chat/goal/{goal.id}",
            "message": "Your original request created this separate conversation. No second attempt was started. " + dispatch.get(receipt["state"], "Read its current progress before starting anything else.")}


def _admission(value):
    return {"actor": value["authority"]["actor"], "context": value["authority"]["context"],
            "workspace": current_tenant_id_strict() or "", "operation": value["operation"],
            "reviewed_at": value["reviewed_at"], "review_expires_at": value["expires"]}


def apply(request, token):
    value = opened(token)
    previous = original(request, token)
    if previous["confirmed"]:
        return previous, None
    with authority_effect_fence():
        before = authority(request, value["authority"]["context"], write=True)
        if before != value["authority"] or _caps() != value["caps"]:
            raise HTTPException(409, "Your access or operating limits changed. Your draft is kept; review current choices again.")
        api.require_provider_or_400()
        from .app import check_goal_rate_limit
        check_goal_rate_limit(request)
        def guard(connection):
            if (time.time() >= value["expires"] or authority(request, before["context"], write=True) != before
                    or _caps() != value["caps"]):
                raise HTTPException(409, "This review expired or your access changed while waiting. Nothing was started; review current choices again.")
            current = _source(request, value["source"]["goal_id"], value["source"]["action"],
                              value["source"].get("at_turn"), connection=connection)
            if digest(current) != digest(value["source"]):
                raise HTTPException(409, "A conversation message, file or permission changed after review. Nothing was started; your edited message is kept.")
            if (authority(request, before["context"], write=True) != before or _caps() != value["caps"]
                    or time.time() >= value["expires"]):
                raise HTTPException(409, "This review expired or your access changed while waiting. Nothing was started; review current choices again.")
        try:
            receipt = native.create(_shared._world(), value["source"], token=value["operation"],
                message=value["message"], answer_only=value["answer_only"], caps=value["caps"],
                admission=_admission(value), before_create=guard)
        except SubmissionConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        background = BackgroundTasks()
        if receipt["created"]:
            from maverick.runner import run_goal_in_background_async

            from .attachment_submission import dispatch
            caps = value["caps"]
            background.add_task(dispatch, _shared._world(), receipt, run_goal_in_background_async, receipt["goal_id"],
                **caps, conversation_id=receipt["detail"]["conversation_id"], channel="dashboard",
                user_id=auth.execution_user_id_from_request(request), allowed_suites=auth.caller_suites(request))
        return original(request, token), background
