"""Read-only, current-authority guidance for the ordinary product controls."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from maverick import config
from maverick.governed_operations import digest

from . import auth
from .draft_api import context_for

router = APIRouter(tags=["product-help"])
TourPage = Literal["/start", "/chat", "/goals", "/connections", "/automations", "/learned"]
PAGES = ("/start", "/chat", "/goals", "/connections", "/automations", "/learned")
LABELS = {"/start": "Get started", "/chat": "Give Lightwork work", "/goals": "Follow your work",
          "/connections": "Connect your services", "/automations": "Repeat work", "/learned": "Improve answers"}
# Literal IDs from the current ordinary templates. No caller-supplied selector,
# record, form value or customer content is returned or interpreted here.
STEPS = {
    "/start": (("ready", "Start with the next useful step", "Get started reads your current setup and recorded work. Follow its suggested next step; touring this page does not complete setup.", "content", "", "view"),),
    "/chat": (
        ("request", "Describe the result you need", "Say what you want to achieve, who it is for and anything Lightwork must follow. Your draft stays here while you explore.", "composer-title", "composer-title", "operate"),
        ("files", "Give it the right supporting material", "Attach the documents this task should use. Check the selected files before starting; this tour never uploads a file.", "attach-btn", "attach-btn", "operate"),
        ("format", "Choose what it should create", "Choose an answer, document or other available result. Starting the task is a separate action and uses your workspace's spending limits and approvals.", "authoring-kind", "authoring-kind", "operate"),
        ("help", "Ask for help where you are", "Copilot understands this page and can open its supported controls. Review an action before confirming it; opening help starts nothing.", "mv-copilot-fab", "mv-copilot-fab", "view")),
    "/goals": (
        ("find", "Find work you already asked for", "Search Tasks by its name or request. Open a task to read its current progress, answer and available actions.", "run-search-q", "run-search-q", "view"),
        ("background", "Keep track of background work", "My background work shows the jobs you can see. Check a retained original when a reply is interrupted instead of starting the same action again.", "my-work", "my-work-title", "view")),
    "/connections": (
        ("service", "Choose your business service", "Use the named service choices and the fields shown for that service. Saving a connection and checking its access are separate from giving an agent work.", "cx-form", "cx-preset", "admin"),
        ("accounts", "Review saved accounts", "The list shows the connections currently available to you. Keep access limited to the people who need it; a saved account is not proof that a business action succeeded.", "cx-list", "cx-retry", "view")),
    "/automations": (
        ("schedules", "See what is already scheduled", "Review current schedules before adding another one. Refresh reads their current state; it does not run them.", "auto-sched-section", "auto-sched-retry", "view"),
        ("create", "Set up repeat work", "Create schedule lets you choose the work, timing and time zone. Read its complete review before confirming. If the reply is lost, check the original creation request.", "auto-new-sched", "auto-new-title", "operate")),
    "/learned": (
        ("questions", "Teach it with examples you can judge", "Learning questions pair a real request with the answer you expect. Review the exact question and expected answer before saving. Examples help evaluation; they do not by themselves prove an improvement.", "learning-test-questions", "learning-case-title", "operate"),
        ("check", "Check how answers are judged", "Use the answer check to compare actual checks with your independent labels. An insufficient result stays insufficient; checking an answer does not publish new instructions.", "learning-calibration", "learning-calibration", "operate"),
        ("lessons", "Review what it learned", "Lessons and proposed changes have their own controls. Evaluation, approval and putting a change into use are separate; this tour does none of them.", "harness-guidance", "harness-guidance", "view")),
}


def _enabled():
    try:
        if config.config_source_errors(include_tenant=True):
            raise RuntimeError("configuration unavailable")
        return config.get_features().get("guided_onboarding") is True
    except Exception as exc:
        raise HTTPException(503, "Guided help could not read the current setup. Your work is unchanged.") from exc


def state(request: Request, page: str) -> dict:
    from .app import _switched_off_pages, require_page_visible

    if page not in PAGES:
        raise HTTPException(404, "A product tour is not available for this page.")
    auth.require_page_permission(request, page)
    require_page_visible(request, page)
    context = context_for(request)
    enabled = _enabled()
    try:
        off = _switched_off_pages()
    except Exception as exc:
        raise HTTPException(503, "Guided help could not read current page availability. Your work is unchanged.") from exc
    allowed = []
    for candidate in PAGES:
        if candidate in off:
            continue
        try:
            auth.require_page_permission(request, candidate)
            require_page_visible(request, candidate)
        except HTTPException as exc:
            if exc.status_code in {401, 403, 404}:
                continue
            raise
        allowed.append({"page": candidate, "label": LABELS[candidate]})
    steps = []
    if enabled and page not in off:
        for key, title, body, target, focus, permission in STEPS[page]:
            if auth.has_permission(request, permission):
                steps.append({"id": key, "title": title, "body": body, "target": target, "focus": focus, "page": page})
    result = {"context": context, "page": page, "enabled": enabled, "available": bool(steps), "steps": steps,
              "pages": allowed if enabled else [], "detail": "Viewed steps are remembered in this browser for this account and workspace. This does not mark setup or work as complete." if enabled else
              "Guided help is turned off. An administrator can turn on guided onboarding in Settings. Your work is unchanged."}
    auth.require_page_permission(request, page)
    require_page_visible(request, page)
    if context_for(request) != context or _enabled() != enabled or _switched_off_pages() != off:
        raise HTTPException(409, "Your account, workspace, access or setup changed. Open guided help again.")
    # Include the current action floors after the read, so withdrawal cannot
    # return controls that were admitted only at the beginning of the request.
    for step in steps:
        permission = next(row[5] for row in STEPS[page] if row[0] == step["id"])
        auth.require_permission(request, permission)
    for destination in result["pages"]:
        auth.require_page_permission(request, destination["page"])
        require_page_visible(request, destination["page"])
    result["revision"] = digest(result)
    return result


@router.get("/api/v1/help/product-tour")
def current_tour(request: Request, page: TourPage = Query(...)):
    return JSONResponse(state(request, page), headers={"Cache-Control": "private, no-store"})
