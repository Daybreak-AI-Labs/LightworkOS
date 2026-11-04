"""Get two viewpoints: a governed two-sided debate on a question.

People reach ``maverick debate`` here: one side argues for, one argues against,
and an impartial judge weighs them. It is admitted exactly like a task start --
emergency stop, the person's quota and spending limits, the workspace's
allowance -- and runs on a budget built from the configured caps, never above
``MAX_DOLLARS``. Every model call still goes through ``Budget.reserve`` and the
provider, organization and spending-limit admission inside ``LLM``; the spend
is settled to the usage ledger afterwards the way a task's is. The model comes
from the configured ``analyst`` role, never a fixed name. Nothing else is
created or changed; each run is recorded in the activity log.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from ._shared import require_provider_or_400
from .auth import caller_principal, execution_user_id_from_request, require_permission

log = logging.getLogger(__name__)
router = APIRouter(tags=["viewpoints"])

MAX_DOLLARS = 1.0
MAX_TURN_CHARS = 4000
SIDES = (("Proponent", "for", "the answer is YES / the proposal is sound"),
         ("Skeptic", "against", "the answer is NO / the proposal is flawed"))


class ViewpointsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3, max_length=2000)
    rounds: int = Field(default=2, ge=1, le=3)
    # Optional positions each side defends (the command's --for / --against).
    for_side: str | None = Field(default=None, max_length=300)
    against_side: str | None = Field(default=None, max_length=300)


class _Refused(Exception):
    """Not admitted; the message is written for people."""


def _audit(kind: str, actor: str, **data) -> None:
    from maverick.audit import audit_event
    audit_event(kind, agent="dashboard", actor=actor, **data)


def _admit(principal: str, max_dollars: float = MAX_DOLLARS):
    """The checks a task start makes, then a capped budget. Returns the budget."""
    from maverick import killswitch, quotas, spending_limits
    from maverick.budget import budget_from_config, resolve_budget_caps
    from maverick.paths import current_tenant_id
    from maverick.tenant.registry import assert_tenant_active

    try:
        killswitch.check()
    except killswitch.Halted as exc:
        raise _Refused("Lightwork is paused by an emergency stop. An administrator can resume it.") from exc
    try:
        if quotas.quotas_enforced() and quotas.over_quota(principal):
            raise _Refused("You have used your spending allowance for today. Try again tomorrow or ask an administrator.")
        reason = spending_limits.start_refusal(principal)
        assert_tenant_active(current_tenant_id())
    except _Refused:
        raise
    except Exception as exc:
        raise _Refused("Spending limits can't be checked right now, so nothing was started. Try again in a moment.") from exc
    if reason:
        raise _Refused(reason)
    try:
        configured = resolve_budget_caps().get("max_dollars")
        cap = max_dollars if configured is None else min(max_dollars, float(configured))
        budget = budget_from_config(max_dollars=cap)
    except ValueError as exc:
        raise _Refused("The spending caps for AI work can't be read right now, so nothing was started.") from exc
    if getattr(budget, "_tenant_refusal", None):
        raise _Refused("This workspace has used its spending allowance, so nothing was started. An administrator can raise it.")
    return budget


def _plain_turn(text: str) -> str:
    text = (text or "").strip()
    if not text or text.startswith("(turn failed"):
        return "This side could not answer this time."
    return text[:MAX_TURN_CHARS]


def _run(question: str, rounds: int, principal: str, actor: str,
         stances: tuple[str | None, str | None] = (None, None), *, model=None, guard=None) -> dict:
    from maverick.budget import BudgetExceeded
    from maverick.debate import DebateParticipant, run_debate
    from maverick.llm import LLM, model_for_role
    from maverick.orchestrator import _QuotaUsageSettlement
    from maverick.spending_limits import SpendingLimitReached
    from maverick.tenant.provider_admission import run_scope

    budget = _admit(principal)
    settlement = _QuotaUsageSettlement(principal=principal, budget=budget, domain=None)
    try:
        # Recorded before any spend; a deployment that cannot record refuses.
        _audit("viewpoints_run", actor, phase="start", rounds=rounds,
               question_chars=len(question), max_dollars=budget.max_dollars)
    except Exception as exc:
        settlement.record()
        raise _Refused("The activity log couldn't record this request, so nothing was started.") from exc
    llm = LLM(model=model or model_for_role("analyst"))
    def complete(*args, **kwargs):
        if guard is not None:
            guard()
            kwargs.update(dispatch_guard=guard, max_physical_attempts=1, _no_failover=True)
        return llm.complete(*args, **kwargs)
    participants = [DebateParticipant(name=name, persona=(" ".join((chosen or "").split()) or persona),
                                      llm_complete=complete)
                    for (name, _, persona), chosen in zip(SIDES, stances, strict=True)]
    outcome = "failed"
    try:
        with run_scope(budget, principal):
            result = run_debate(question, participants, judge_complete=complete,
                                rounds=rounds, budget=budget)
        outcome = "finished"
    except SpendingLimitReached as exc:
        outcome = "stopped"
        raise _Refused(str(exc)) from exc
    except BudgetExceeded as exc:
        outcome = "stopped"
        raise _Refused(f"This stopped when it reached the limit for one request (at most ${budget.max_dollars:,.2f}). "
                       "Try a shorter question or fewer exchanges.") from exc
    finally:
        settlement.record()
        try:
            _audit("viewpoints_run", actor, phase="end", outcome=outcome,
                   dollars=round(float(budget.dollars), 4))
        except Exception:  # spend already happened; never hide the result
            log.warning("viewpoints: completion audit row not written", exc_info=True)
    side = {name: key for name, key, _ in SIDES}
    reason = (result.judge_reason or "").strip()
    if not reason or reason == "judge JSON parse failed":
        reason = "The judge's answer couldn't be read, so neither side is treated as stronger."
    return {
        "ran": True,
        "rounds": result.rounds_completed,
        "turns": [{"side": side.get(turn.speaker, "for"), "text": _plain_turn(turn.text)}
                  for turn in result.transcript[: rounds * len(SIDES)]],
        "verdict": side.get(result.winner, "draw"),
        "reason": reason[:1000],
        "key_point": (result.key_argument or "").strip()[:1000],
        "cost": round(float(result.total_dollars), 4),
    }


def _prepare(request: Request, body: ViewpointsIn) -> tuple[str, str, str]:
    """The checks every viewpoints request makes. Returns (question, principal, actor)."""
    from maverick.orchestrator import _execution_principal

    from .app import _require_same_origin, check_goal_rate_limit

    require_permission(request, "operate")
    _require_same_origin(request)
    check_goal_rate_limit(request, source="viewpoints")
    question = " ".join(body.question.split())
    if len(question) < 3:
        raise HTTPException(422, "Type a question or decision to weigh up.")
    try:
        require_provider_or_400(role="analyst")
    except HTTPException as exc:
        raise HTTPException(400, "AI isn't connected yet. Finish connecting AI in setup, then try again.") from exc
    principal = _execution_principal(user_id=execution_user_id_from_request(request), capability=None)
    return question, principal, caller_principal(request) or principal


@router.post("/api/v1/viewpoints/jobs", status_code=202)
async def start_viewpoints_job(request: Request, body: ViewpointsIn) -> dict:
    """Start the same debate in the background; the page polls for the result."""
    # Legacy clients use the same durable request custody and current worker
    # guards. The ordinary product adds an explicit complete human review.
    from . import viewpoints_requests as native
    prepared = native.prepare(request, body.model_dump())
    operation = native.operation()
    result = await run_in_threadpool(native.start, request, prepared, operation)
    return {"job": operation, "operation": operation, "original": result}


class ReviewIn(ViewpointsIn):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=262144)
    confirmed: bool


def _response(value):
    return JSONResponse(value, headers={"Cache-Control": "no-store, private"})


@router.get("/api/v1/viewpoints")
def current_viewpoints(request: Request):
    from . import viewpoints_requests as native
    native.authority(request, request.headers.get("X-Lightwork-Viewpoints-Context"))
    return _response(native.listing(request))


@router.get("/api/v1/viewpoints/requests/{operation}")
def original_viewpoints(request: Request, operation: str):
    from . import viewpoints_requests as native
    native.authority(request, request.headers.get("X-Lightwork-Viewpoints-Context"))
    return _response(native.original(request, operation))


@router.post("/api/v1/viewpoints/review")
def review_viewpoints(request: Request, body: ReviewIn):
    from . import viewpoints_requests as native
    prepared = native.prepare(request, body.model_dump(exclude={"context", "revision"}), context=body.context, revision=body.revision)
    operation = native.operation()
    token = native.seal({"purpose": native.PURPOSE, "prepared": prepared, "operation": operation})
    if len(token) > 262144:
        raise HTTPException(422, "This full viewpoints review is too large. Shorten the question or positions and review again.")
    return _response({"context": prepared["state"]["context"], "operation": operation, "token": token, "changes": native.review_rows(prepared)})


@router.post("/api/v1/viewpoints/apply")
async def apply_viewpoints(request: Request, body: ApplyIn):
    from . import viewpoints_requests as native
    native.authority(request, write=True)
    if not body.confirmed:
        raise HTTPException(422, "Review the full question, both positions, connected model and spending before starting.")
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(value) != {"purpose", "prepared", "operation"} or value["purpose"] != native.PURPOSE:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This viewpoints review is unavailable. Read the original request without repeating AI work.") from exc
    return _response(await run_in_threadpool(native.start, request, value["prepared"], value["operation"]))


@router.get("/api/v1/viewpoints/jobs/{job_id}")
async def viewpoints_job(request: Request, job_id: str) -> dict:
    from .ops_jobs import JOBS, identity

    require_permission(request, "operate")
    owner, tenant = identity(request)
    job = JOBS.get(job_id[:64], owner=owner, tenant=tenant, kind="viewpoints")
    if job is None:
        raise HTTPException(404, "no such job")
    return job


@router.post("/api/v1/viewpoints")
async def get_viewpoints(request: Request, body: ViewpointsIn) -> dict:
    """Run one two-sided debate for the signed-in person and return it."""
    require_permission(request, "operate")
    from .app import _require_same_origin
    _require_same_origin(request)
    raise HTTPException(409, "Open Get two viewpoints in Chat to review this AI request and retain its original outcome.")
