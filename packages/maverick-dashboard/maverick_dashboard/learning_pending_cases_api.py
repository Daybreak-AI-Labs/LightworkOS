"""Reviewed use or rejection of the existing self-coaching suggestions."""
from __future__ import annotations

import json
import math
import secrets
import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from maverick import crypto_at_rest, self_harness
from maverick import self_harness_eval as corpus
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from pydantic import BaseModel, ConfigDict, Field

from . import learning_ops_api as native
from . import learning_test_cases_api as cases
from .plain_labels import model_label

router = APIRouter(prefix="/learning-pending-cases", tags=["learning-pending-cases"])
PAGE = "/learned#learning-suggested-questions"
PURPOSE = "lightwork.learning-pending-question.v1"
TTL = 600


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    model: str = Field(min_length=1, max_length=200)
    reference: str = Field(pattern=r"^[a-f0-9]{64}$")
    action: Literal["accept", "reject"]


class ReviewIn(DecisionIn):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


def _read(function):
    try:
        return function()
    except (ValueError, OSError, PermissionError, RecursionError) as exc:
        raise HTTPException(409, "The current suggestions or their learning permission could not be read safely. Refresh before continuing; saved information is kept.") from exc


def current(request, model=None, offset=0):
    if not self_harness.settings().get("eval_corpus"):
        return {"context": cases._authority(request), "revision": "", "models": [], "cases": [], "total": 0,
                "blocked": "Set up learning questions above before reviewing suggestions.", "scope": cases.SCOPE}
    scope = cases._scope(request)
    if model is not None and model not in scope["models"]:
        raise HTTPException(409, "Choose a currently available model.")
    state = _read(lambda: corpus.pending_authoring_state(scope["path"], model, offset=offset))
    if cases._scope(request, scope["context"]) != scope:
        raise HTTPException(409, "Your access, models or learning storage changed. Refresh the current suggestions.")
    for row in state.get("cases", []):
        guard = row.pop("_source_guard", None)
        if guard is not None and not corpus.case_current(guard):
            row.update(supported=False, question="Suggestion unavailable for learning", expected="",
                       notice="Learning permission changed. Private details are withheld and the retained suggestion stays in place.")
    blocked = ""
    try:
        native._halt_preflight("self-harness")
    except HTTPException as exc:
        blocked = exc.detail
    return {**state, "context": scope["context"], "model": model, "model_label": model_label(model) if model else "",
            "revision": digest([scope["source"], state["revision"], scope["models"]]),
            "models": [{"value": value, "label": model_label(value), "questions": state["counts"].get(value, 0)} for value in scope["models"]],
            "blocked": blocked, "scope": cases.SCOPE}


def prepare(request, values, *, context=None, revision=None):
    body = DecisionIn.model_validate(values)
    scope = cases._scope(request, context, write=True)
    state = current(request)
    if (body.model not in scope["models"] or revision is not None and revision != state["revision"]
            or state["context"] != scope["context"]):
        raise HTTPException(409, "The suggestions changed. Refresh and choose the current question again.")
    try:
        reviewed = corpus.review_pending_decision(scope["path"], body.model, body.reference, body.action)
    except (ValueError, PermissionError) as exc:
        if str(exc).startswith("This question is already saved."):
            raise HTTPException(409, str(exc)) from exc
        raise HTTPException(409, "The suggestion, saved questions or learning permissions changed. Refresh before reviewing.") from exc
    if (cases._scope(request, scope["context"], write=True) != scope
            or digest([scope["source"], reviewed["revision"], scope["models"]]) != state["revision"]
            or not corpus.case_current(reviewed["source_guard"])):
        raise HTTPException(409, "Learning information changed during review. Refresh before continuing.")
    return {**reviewed, "decision": body.model_dump(), "context": scope["context"], "source": scope["source"],
            "models": scope["models"], "model_label": model_label(body.model), "expires": time.time() + TTL}


def changes(prepared):
    accept = prepared["decision"]["action"] == "accept"
    values = [{"label": "Model", "after": prepared["model_label"]},
              {"label": "Question", "before": prepared["before"]["question"], "after": prepared["before"]["question"] if accept else "Remove this suggestion"},
              {"label": "Expected answer", "before": prepared["before"]["expected"], "after": prepared["before"]["expected"] if accept else "Keep out of future checks"},
              {"label": "Suggested questions remaining", "before": prepared["pending_after"] + 1, "after": prepared["pending_after"]},
              {"label": "Saved questions for this model", "before": prepared["live_after"] - int(accept), "after": prepared["live_after"]},
              {"label": "Effect", "after": "Use the complete suggestion in future self-coaching checks, preserving its original learning permissions. No AI runs now." if accept else "Reject this exact suggestion and remember its question so future searches do not suggest it again. Existing saved questions remain unchanged. No AI runs."},
              {"label": "Shared use", "after": cases.SCOPE}]
    if prepared["forgotten_rejections"]:
        values.append({"label": "Earlier rejection memory", "after": str(prepared["forgotten_rejections"]) + " oldest remembered rejection will be released to retain the latest 500. That earlier question can be suggested again."})
    return values


def _store():
    return GovernedRecordStore("learning-pending-requests", "LPR", "learning_pending_request")


def _id(operation):
    if len(operation) != 32 or any(value not in "0123456789abcdef" for value in operation):
        raise HTTPException(404, "This original suggestion decision is not available.")
    return "LPR-" + operation


def _owned(request, operation):
    context = cases._authority(request)
    row = _store().get(_id(operation))
    if row and (row.get("actor") != native._actor(request) or row.get("context") != context):
        raise HTTPException(404, "This original suggestion decision is not available to this account.")
    cases._authority(request, context)
    return row


def original(request, operation, prepared=None):
    row = _owned(request, operation)
    if row is None:
        return {"operation": operation, "context": cases._authority(request), "confirmed": False,
                "message": "No original decision record is available. Absence does not establish failure. Nothing was repeated."}
    if prepared is not None and row["request_digest"] != digest({"operation": operation, "prepared": prepared, "actor": native._actor(request)}):
        raise HTTPException(409, "This original request belongs to another reviewed decision.")
    value = row["prepared"]
    if not corpus.case_current(value["source_guard"]):
        raise HTTPException(409, "Current permission for this suggestion was withdrawn or cannot be verified. Private question details are withheld; nothing was repeated.")
    confirmed = row["state"] == "saved"
    observation = "The original recorded decision does not promise that today's questions have stayed unchanged."
    try:
        scope = cases._scope(request, row["context"])
        if scope["source"] == value["source"]:
            effect = corpus.authored_corpus_effect(scope["path"], row["binding"])
            expected = {"action": "pending_" + value["decision"]["action"], "model": value["decision"]["model"], "before_digest": value["before_digest"]}
            if effect == expected:
                confirmed = True
                observation = "The exact original decision receipt is retained. No question was added or removed again."
            elif not confirmed:
                observation = "No exact completed decision receipt is available. File storage can retain part of an interrupted decision; check saved questions and current suggestions before a separate decision."
    except (HTTPException, ValueError, OSError):
        observation = "Current learning storage could not be checked. The retained original request remains available; nothing was repeated."
    cases._authority(request, row["context"])
    if not corpus.case_current(value["source_guard"]):
        raise HTTPException(409, "Learning permission changed while reading this original decision. Private details are withheld.")
    return {"operation": operation, "context": row["context"], "confirmed": confirmed,
            "message": ("The original suggestion was saved for future checks." if value["decision"]["action"] == "accept" else "The original suggestion was rejected and remembered.") + " Nothing was repeated and no AI ran." if confirmed else
                       "The original decision is unconfirmed. Read saved questions and current suggestions before a separate decision. Nothing is repeated automatically.",
            "model": value["model_label"], **value["before"], "current": observation}


def apply(request, prepared, operation):
    context = cases._authority(request, prepared["context"], write=True)
    actor = native._actor(request)
    expected_digest = digest({"operation": operation, "prepared": prepared, "actor": actor})
    with authority_effect_fence():
        cases._authority(request, context, write=True)
        previous = _owned(request, operation)
        if previous:
            return original(request, operation, prepared)
        def authorize():
            scope = cases._scope(request, context, write=True)
            if (scope["source"] != prepared["source"] or scope["models"] != prepared["models"]
                    or prepared["decision"]["model"] not in scope["models"]):
                raise HTTPException(409, "Learning storage or models changed. Refresh and review again.")
            if not time.time() < prepared["expires"] <= time.time() + TTL:
                raise HTTPException(409, "This review expired. Review the current suggestion again.")
        authorize()
        binding, store, claim = secrets.token_hex(32), _store(), None
        def claim_request():
            nonlocal claim
            native._record(request, "self_harness_pending_" + prepared["decision"]["action"], phase="prepared",
                           operation=operation, reviewed_revision=prepared["revision"], model_sha256=digest(prepared["decision"]["model"]))
            claim = store.create({"id": _id(operation), "context": context, "actor": actor, "binding": binding,
                                  "request_digest": expected_digest, "prepared": prepared, "state": "writing"},
                                 action="learning.pending.prepare", actor=actor, max_records=10000)
        try:
            scope, choice = cases._scope(request, context, write=True), prepared["decision"]
            corpus.decide_reviewed_pending(scope["path"], choice["model"], choice["reference"], choice["action"],
                expected_revision=prepared["revision"], before_digest=prepared["before_digest"], binding=binding,
                authorize=authorize, before_write=claim_request)
            store.update(claim["id"], lambda value: value.update(state="saved"), expected_revision=claim["revision"],
                         action="learning.pending.saved", actor=actor)
        except Exception as exc:
            retained = _owned(request, operation)
            if retained is not None:
                return original(request, operation, prepared)
            if isinstance(exc, HTTPException):
                raise
            if isinstance(exc, (ValueError, PermissionError)):
                raise HTTPException(409, "The suggestion, collection or learning permission changed. Refresh and review again. Nothing was changed.") from exc
            raise HTTPException(503, "The original decision is unconfirmed. Check its original outcome before another attempt.") from exc
        return original(request, operation, prepared)


@router.get("")
def state(request: Request, model: str | None = Query(None, min_length=1, max_length=200), offset: int = Query(0, ge=0, le=1000000)):
    return cases._response(current(request, model, offset))


@router.get("/context")
def context(request: Request):
    return cases._response({"context": cases._authority(request)})


@router.get("/requests/{operation}")
def receipt(request: Request, operation: str):
    return cases._response(original(request, operation))


@router.post("/review")
def review(request: Request, body: ReviewIn):
    prepared = prepare(request, body.model_dump(exclude={"context", "revision"}), context=body.context, revision=body.revision)
    material = {"purpose": PURPOSE, "prepared": prepared, "operation": secrets.token_hex(16)}
    token = crypto_at_rest.seal_to_str(json.dumps(material, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 262144:
        raise HTTPException(503, "This decision could not be protected. Nothing was changed.")
    return cases._response({"token": token, "operation": material["operation"], "context": prepared["context"], "changes": changes(prepared)})


@router.post("/save")
def save(request: Request, body: cases.SaveIn):
    cases._authority(request, write=True)
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        material = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if (set(material) != {"purpose", "prepared", "operation"} or material["purpose"] != PURPOSE
                or type(material["prepared"]["expires"]) not in (int, float) or not math.isfinite(material["prepared"]["expires"])):
            raise ValueError
        DecisionIn.model_validate(material["prepared"]["decision"])
    except Exception as exc:
        raise HTTPException(409, "This review changed. Review the current suggestion again.") from exc
    return cases._response(apply(request, material["prepared"], material["operation"]))
