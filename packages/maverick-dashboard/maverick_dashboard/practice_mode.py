"""Practice mode in the dashboard: the switch, the marker and the guard.

A person turns practice on for their own browser session. While it is on,
every request they make runs in practice (:mod:`maverick.practice`): tasks,
results and approvals use the separate practice workspace, and anything that
would leave Lightwork is recorded instead. Changes to live settings, agents,
people or connections are refused with the reason (:data:`BLOCKED_CHANGES`)
until they choose Back to live, because those would affect real work. If
practice stops being available while it is on, every screen says so and
changes are refused until Back to live; it never quietly turns into live work.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

COOKIE = "lw_practice"
router = APIRouter(prefix="/api/v1/practice", tags=["practice"])

# What a practising person may change, and why it is safe. Practice tasks,
# their answers, files, approvals, pins, drafts and notes live in the practice
# workspace; the rest are personal, previews that change nothing, or safety
# controls that are never blocked. Order matters: the first match decides.
ALLOWED_CHANGES: tuple[tuple[str, str], ...] = (
    (r"^/api/v1/goals/\d+/share/(?:gist/)?preview$", "Previewing a share changes nothing"),
    (r"^/api/v1/goals/\d+/(?!share|code/)", "Working on your practice tasks"),
    (r"^/api/v1/goals(?:/compose)?$", "Starting practice tasks"),
    (r"^/(?:chat|goals)/|^/api/goal/|^/start$|^/first-outcome/|^/api/v1/first-outcome/run$",
     "Practice conversations and sample tasks"),
    (r"^/api/v1/approvals/|^/approvals/|^/answer-receipts/|^/attachments/",
     "Practice approvals, answers and files"),
    (r"^/api/v1/run-tree/\d+/(?:fork|rewind)$", "Re-running a practice task"),
    (r"^/api/v1/(?:pins/\d+|views/[^/]+)$|^/api/v1/drafts/[^/]+$|^/api/v1/conversations/\d+/organization$"
     r"|^/api/v1/conversation-inbox/", "Pins, saved views, drafts and messages kept with practice"),
    (r"^/api/v1/halt$", "The emergency stop is never blocked"),
    (r"^/api/v1/sessions/|^/auth/", "Signing in and out protects your account"),
    (r"^/api/v1/copilot$|^/api/v1/voice/(?:transcribe|speak)$", "Asking Copilot, dictation and read-aloud"),
    (r"^/api/v1/redact/preview$|^/api/v1/agents/[^/]+/(?:validate|publish-check)$",
     "Checks and previews that change nothing"),
    (r"^/api/v1/practice$|^/api/v1/preferences/display$|^/api/v1/navigation/(?:pins|recent)$"
     r"|^/navigation/areas$|^/api/v1/notifications/personal/seen$",
     "Your display, menu and which notices you have seen"),
)

# What practice refuses, and why, for the 409 and the list on the marker.
BLOCKED_CHANGES: tuple[tuple[str, str, str], ...] = (
    ("Sharing a practice result", r"/share(?:/|$)",
     "Practice results can't be shared: share links and gists are for real results."),
    ("Running code on a practice task", r"/code/sessions",
     "Code sessions run real commands, and practice never runs commands."),
    ("Restoring or changing task files", r"^/api/v1/task-files/",
     "Task files are real files shared with live work."),
    ("Changing settings or spending limits",
     r"^/settings|^/api/v1/(?:settings|features|models|model-cost-tiers|budget|cache)(?:/|$)|^/spending-limits"
     r"|^/styles/|^/api/v1/workspace/",
     "Settings apply to everyone's live work."),
    ("Changing agents, specialists, skills or workflows",
     r"^/api/v1/(?:agents|skills|workflows|templates|flows|flow-teach|generated-tools|roles|plugins|mcp-registry"
     r"|agent-control-plane|governance-agents|customizations|agent-override-changes)(?:/|$)|^/plugins|^/mcp/"
     r"|^/flow/|^/store/|^/projects$|^/api/v1/gallery/",
     "Agents, specialists, skills and workflows are shared with live work."),
    ("Changing people, roles or access",
     r"^/users|^/scim|^/saml|^/api/v1/(?:users|permissions|api-keys|service-accounts|access-requests"
     r"|access-key-requests|departments|employee-[a-z-]+)(?:/|$)",
     "People and access apply to live work."),
    ("Changing connections and channels",
     r"^/channels|^/webhook|^/api/v1/(?:connections|connection-setup|oauth|webhooks|external|external-agents"
     r"|event-triggers|triggers|schedules|governed-connectors|devices|import)(?:/|$)",
     "Connections reach real outside systems."),
    ("Changing your own settings and notifications", r"^/me/|^/api/v1/(?:preferences|notifications)(?:/|$)",
     "Your own settings and notification choices apply to live work too."),
    ("Changing privacy, consent, compliance, security or audit records",
     r"^/api/v1/(?:privacy|consent|compliance|security|audit|third-party|vendors|vendor-[a-z-]+|assess"
     r"|assessments|data-use|data-map|regulatory|breach|records|trust|assurance|my-data)(?:/|$)|^/consent|^/compliance"
     r"|^/rights|^/form/",
     "Privacy, compliance and security records are real records."),
    ("Teaching or changing what agents learn",
     r"^/api/v1/(?:learning[a-z-]*|learned|training-ops|knowledge[a-z-]*|facts|cortex|evolution)(?:/|$)",
     "Learning changes how agents behave in live work."),
)
DEFAULT_BLOCK = ("Anything else that changes Lightwork", "This changes something shared with live work.")
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_ALLOWED = tuple((re.compile(pattern), why) for pattern, why in ALLOWED_CHANGES)
_BLOCKED = tuple((re.compile(pattern), why) for _what, pattern, why in BLOCKED_CHANGES)
_ALWAYS = re.compile(r"^/api/v1/practice$|^/auth/|^/api/v1/sessions/|^/api/v1/halt$")
REFUSED_TAIL = " It can't be done in practice mode. Choose Back to live, then try again."
REFUSED = DEFAULT_BLOCK[1] + REFUSED_TAIL


def wants_practice(request: Request) -> bool:
    return request.cookies.get(COOKIE) == "1"


def rule_for(method: str, path: str) -> tuple[bool, str]:
    """Whether a practising person may make this request, and why."""
    if method.upper() in _SAFE_METHODS:
        return True, "Looking changes nothing"
    for pattern, why in _ALLOWED:
        if pattern.search(path):
            return True, why
    for pattern, why in _BLOCKED:
        if pattern.search(path):
            return False, why
    return False, DEFAULT_BLOCK[1]


def change_allowed(method: str, path: str) -> bool:
    return rule_for(method, path)[0]


def blocked_list() -> list[dict]:
    """What practice refuses, in plain words, for the marker and the docs."""
    return [{"what": what, "why": why} for what, _pattern, why in BLOCKED_CHANGES] + [
        {"what": DEFAULT_BLOCK[0], "why": DEFAULT_BLOCK[1]}]


def _refuse(detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=409, headers={"X-Lightwork-Reason": "practice"})


async def middleware(request: Request, call_next):
    """Run a practising person's requests in practice, and keep live work untouched."""
    if not wants_practice(request):
        return await call_next(request)
    from maverick import practice

    reason = await run_in_threadpool(practice.unavailable_reason)
    if reason:
        # Practice stopped working since the person chose it (turned off, or
        # the workspace moved to a database server or outside workers). They
        # are told on every screen, and nothing changes until Back to live.
        request.state.practice_unavailable = reason
        if request.method.upper() in _SAFE_METHODS or _ALWAYS.search(request.url.path):
            return await call_next(request)
        return _refuse(f"Practice mode stopped: {reason} Nothing was changed. Choose Back to live to "
                       "carry on with real work.")
    allowed, why = rule_for(request.method, request.url.path)
    if not allowed:
        return _refuse(why + REFUSED_TAIL)
    request.state.practice = True
    token = practice.activate(True)
    try:
        return await call_next(request)
    finally:
        practice.reset(token)


def context(request: Request) -> dict:
    """Template flags for the practice marker on every screen and the switch."""
    from maverick import practice

    try:
        reason = practice.unavailable_reason()
        offered = practice.enabled()
    except Exception:  # pragma: no cover -- shell rendering stays fail-soft: no switch offered
        reason, offered = "Practice mode could not be checked.", False
    available = not reason
    on = bool(getattr(request.state, "practice", False))
    spending = None
    if on:
        try:
            from .auth import caller_principal

            spending = practice.spending(caller_principal(request) or "user:local")
        except Exception:  # pragma: no cover -- the marker still renders, without the amount
            spending = None
    return {"practice_mode": on, "practice_available": available, "practice_spending": spending,
            "practice_stopped": getattr(request.state, "practice_unavailable", ""),
            # Offered but impossible here (database server or outside workers): say why.
            "practice_unavailable_reason": reason if offered else ""}


class PracticeSwitch(BaseModel):
    on: bool


def _state(request: Request, on: bool) -> dict:
    from maverick import practice

    reason = practice.unavailable_reason()
    return {"on": on and not reason, "available": not reason, "reason": reason}


@router.get("")
async def practice_state(request: Request) -> dict:
    require_permission(request, "view")
    from maverick import practice

    on = bool(getattr(request.state, "practice", False))
    state = await run_in_threadpool(_state, request, on)
    state["outbox"] = await run_in_threadpool(practice.outbox, 100) if on else []
    if on:
        from .auth import caller_principal

        state["spending"] = await run_in_threadpool(practice.spending, caller_principal(request) or "user:local")
    state["blocked"] = blocked_list()
    return state


@router.post("")
async def switch_practice(request: Request, body: PracticeSwitch) -> JSONResponse:
    """Start or leave practice for this browser session."""
    require_permission(request, "operate")
    state = await run_in_threadpool(_state, request, body.on)
    if body.on and not state["available"]:
        return JSONResponse({"detail": state["reason"]}, status_code=409)
    response = JSONResponse(state)
    if body.on:
        response.set_cookie(COOKIE, "1", httponly=True, samesite="lax", path="/",
                            secure=request.url.scheme == "https")
    else:
        response.delete_cookie(COOKIE, path="/")
    return response


__all__ = ["ALLOWED_CHANGES", "BLOCKED_CHANGES", "COOKIE", "REFUSED", "blocked_list", "change_allowed", "context",
           "middleware", "router", "rule_for", "wants_practice"]
