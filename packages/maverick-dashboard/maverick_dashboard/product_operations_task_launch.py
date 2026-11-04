"""Owned task discovery and reviewed launch through native task admission."""
from __future__ import annotations

from dataclasses import asdict

from fastapi import BackgroundTasks, HTTPException, Response
from maverick.governed_operations import dataclass_digest, digest
from maverick.runner import (
    configured_goal_ceiling_dollars,
    configured_goal_ceiling_wall_seconds,
)
from maverick.task_model_selection import EFFORT_LABELS
from pydantic import Field

from . import _shared, api, auth, task_search
from ._shared import require_task_settings_or_400, task_step_readiness
from .api_schemas import GoalIn
from .draft_api import context_for
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class FindInput(StrictInput):
    query: str = Field(min_length=1, max_length=256)
    where: str = Field(default="newest", max_length=1536)


class StartInput(StrictInput):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=12000)
    max_dollars: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    max_wall_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    max_depth: int | None = Field(default=None, ge=1, le=10)
    task_model: str = Field(default="", max_length=128)
    task_effort: str = Field(default="", max_length=8)
    domain: str = Field(default="", max_length=120)


SPECIALIST_NOTICE = (
    "This uses the currently published specialist, including its permitted actions, company reference sources and AI choices. "
    "It is real work: AI spending, source privacy, approvals and the installation's normal learning rules apply. "
    "When work begins, it uses that specialist's published settings. "
    "Unpublished drafts are not used or published by starting a task."
)


def published_specialists(request, *, only=None, revisions=True):
    with auth.fresh_configuration():
        return _published_specialists(request, only=only, revisions=revisions)


def _published_specialists(request, *, only=None, revisions=True):
    """Current named choices only; the complete definition stays native.

    A caller that shows a few choices passes ``only(personal_default)``, the
    names it will show; one that pages through them passes ``revisions=False``
    and gets each choice's ``profile`` to digest for the page it returns. The
    revision of all 2,031 specialists took about 93 ms of every /chat open,
    which showed at most two.
    """
    from maverick.domain import enabled_domains, suites_for_domain

    from .plain_labels import pack_display_name
    from .preferences_api import personal_specialist_default
    from .task_model_selection_api import current_authority

    current_authority(request)
    current = context_for(request)
    allowed = auth.caller_suites(request)
    personal_default = personal_specialist_default(request)
    wanted = None if only is None else only(personal_default)
    choices = []
    for name, profile in sorted(enabled_domains().items()):
        if len(name) > 120 or (wanted is not None and name not in wanted):
            continue
        if allowed is not None and not suites_for_domain(name, profile) <= allowed:
            continue
        choice = {"value": name, "label": pack_display_name(name, profile.persona, profile.description)}
        if revisions:
            choice["revision"] = dataclass_digest(profile)
        else:
            choice["profile"] = profile
        choices.append(choice)
    current_authority(request)
    if current != context_for(request):
        raise HTTPException(409, "Your account or workspace changed. Read the current specialist choices again.")
    return {"context": current, "choices": choices, "personal_default": personal_default}


def published_selection(request, name):
    with auth.fresh_configuration():
        return _published_selection(request, name)


def _published_selection(request, name):
    from maverick.domain import enabled_domains, suites_for_domain

    from .task_model_selection_api import current_authority

    current_authority(request)
    current = context_for(request)
    if not name:
        return {"context": current, "name": "", "definition": None, "revision": ""}
    profile = enabled_domains().get(name)
    if profile is None:
        raise HTTPException(409, "Choose a currently published specialist; unpublished drafts cannot start this work.")
    definition = asdict(profile)
    for suite in suites_for_domain(name, profile):
        auth.require_suite(request, suite)
    current_authority(request)
    if current != context_for(request):
        raise HTTPException(409, "Your account or workspace changed. Review this specialist again.")
    return {"context": current, "name": name, "definition": definition, "revision": digest(definition)}


def published_guard(request, name, context, revision):
    """Compose with native admission guards after attachment/source waits."""
    def guard():
        selected = published_selection(request, name)
        if selected["context"] != context or selected["revision"] != revision:
            raise HTTPException(409, "The selected published specialist or your workspace changed. Review its current version before starting; your message is kept.")
    return guard


def find_snapshot(request, selection):
    current = task_search.context(request)
    filters = selection.get("filters", {})
    query = filters.get("q", "") if selection.get("kind") == "task_filter" and isinstance(filters, dict) else ""
    choices = [{"value": "newest", "label": "Newest work"}]
    selected = selection.get("task_search", {})
    if (isinstance(selected, dict) and set(selected) == {"query", "continuation"}
            and isinstance(selected["query"], str) and isinstance(selected["continuation"], str)):
        try:
            task_search.validate_cursor(request, selected["query"], selected["continuation"])
            choices.append({"value": selected["continuation"], "label": "Older than this search part"})
        except HTTPException as exc:
            if exc.status_code != 409:
                raise
    return Snapshot(digest({"context": current, "choices": choices}),
        "Current task search for this account and workspace",
        task_search.NOTICE,
        fields=[{"name": "query", "label": "Task search", "kind": "text", "required": True,
                 "max_length": 256, "value": query if isinstance(query, str) else ""},
                {"name": "where", "label": "Where to look", "kind": "select", "value": "newest", "choices": choices}])


def find_prepare(request, selection, arguments):
    auth.require_permission(request, "view")
    query = arguments["query"].strip()
    if not query:
        raise HTTPException(422, "Enter words to search your tasks.")
    where = arguments.get("where", "newest")
    if where != "newest":
        selected = selection.get("task_search", {})
        if not isinstance(selected, dict) or selected.get("continuation") != where:
            raise HTTPException(409, "Choose older work from the current task search, or search the newest work.")
    value = task_search.page(request, query, cursor="" if where == "newest" else where, limit=20)
    rows = [{"task": {"label": goal.title, "href": f"/chat/goal/{goal.id}"},
             "status": goal.status}
            for goal in value["goals"]]
    summary = f"Found {len(rows)} matching task{'s' if len(rows) != 1 else ''} in this part. " + (
        "Reached the end of the retained list; later edits need a fresh search." if value["complete"] else
        "Older work remains unchecked. Continue on Tasks to keep looking.")
    details = {"query": query, "tasks": rows, "search_complete": value["complete"],
               "search": {"label": "Open Tasks search", "href": task_search.link(query)}}
    if value["continuation"]:
        details["next_part"] = {"label": "Search older work", "href": task_search.link(query, value["continuation"])}
    return Preview(summary, native=details)


def _policy():
    defaults = api._rest_goal_limits(GoalIn(title="New task"))
    return {"default_max_dollars": defaults["max_dollars"],
            "default_max_wall_seconds": defaults["max_wall_seconds"],
            "default_max_depth": defaults["max_depth"],
            "configured_ceiling_dollars": configured_goal_ceiling_dollars(),
            "configured_ceiling_wall_seconds": configured_goal_ceiling_wall_seconds(),
            "api_ceiling_dollars": api._REST_GOAL_MAX_DOLLARS,
            "api_ceiling_wall_seconds": api._REST_GOAL_MAX_WALL_SECONDS,
            "agent_step_limit": task_step_readiness()}


def start_snapshot(request, selection):
    auth.require_permission(request, "operate")
    from .task_model_selection_api import choices
    models = choices(request)
    specialists = published_specialists(request)
    specialist_choices = [{"value": row["value"], "label": row["label"]} for row in specialists["choices"]]
    if specialists["personal_default"] and specialists["personal_default"] not in {row["value"] for row in specialist_choices}:
        specialist_choices.append({"value": specialists["personal_default"], "label": "Saved specialist — unavailable; choose a current specialist"})
    policy = _policy()
    steps = policy["agent_step_limit"]
    blocked = "" if steps["ready"] else steps["reason"]
    provider_ready = False
    if steps["ready"]:
        try:
            api.require_provider_or_400()
            provider_ready = True
        except HTTPException as exc:
            if exc.status_code not in {400, 503}:
                raise
            blocked = "Set up an available AI provider before starting a task."
    return Snapshot(digest({"context": context_for(request), "policy": policy,
                            "provider_ready": provider_ready, "models": models, "specialists": specialists}),
        "Current task limits and AI connection",
        "Start one new task under current workspace limits. Acceptance starts work; it does not mean the task is complete.",
        {"Most steps for each agent": steps["max_steps"] if steps["ready"] and steps["max_steps"] else
             ("No step limit" if steps["ready"] else steps["reason"]),
         "AI connection": "Ready to start" if provider_ready else
             ("Not checked until the task limit is corrected" if not steps["ready"] else "Setup required"),
         "Task spending limit": f"${policy['default_max_dollars']:g}" if policy["default_max_dollars"] is not None else "No spending limit",
         "Task time limit": f"{policy['default_max_wall_seconds']:g} seconds" if policy["default_max_wall_seconds"] is not None else "No time limit",
         "Levels of helpers": policy["default_max_depth"],
         "Review settings": {"label": "Review task settings" if not steps["ready"] else "Review AI connection",
                             "href": steps["settings"]["href"] if not steps["ready"] else "/start"}},
        [{"name": "title", "label": "Task", "kind": "text", "required": True, "max_length": 200},
         {"name": "description", "label": "Instructions (optional)", "kind": "textarea", "max_length": 12000},
         {"name": "domain", "label": "Published specialist", "kind": "select", "value": specialists["personal_default"],
          "choices": [{"value": "", "label": "Let Lightwork choose the team"},
                      *specialist_choices]},
         {"name": "task_model", "label": "AI model for this task", "kind": "select", "value": "",
          "choices": [{"value": "", "label": "Use workspace settings"}, *models]},
         {"name": "task_effort", "label": "Thinking depth (supported models only)", "kind": "select", "value": "",
          "choices": [{"value": "", "label": "Use the model’s usual thinking depth"},
                      *({"value": value, "label": label} for value, label in EFFORT_LABELS.items())]},
         {"name": "max_dollars", "label": "Maximum dollars (blank uses workspace limit)", "kind": "number"},
         {"name": "max_wall_seconds", "label": "Maximum seconds (blank uses workspace limit)", "kind": "number"},
         {"name": "max_depth", "label": "Levels of helpers", "kind": "select", "value": None,
          "choices": [{"value": None, "label": f"Use workspace limit ({policy['default_max_depth']} levels)"},
                      *({"value": level, "label": f"{level} level{'s' if level != 1 else ''}"}
                        for level in range(1, policy["default_max_depth"] + 1))]}],
        blocked)


def start_prepare(request, selection, arguments):
    require_task_settings_or_400()
    title = arguments["title"].strip()
    if not title:
        raise HTTPException(422, "Enter a task before reviewing its start.")
    # Validate against the native launch schema before sealing the review.
    payload = GoalIn(**{**arguments, "title": title})
    policy = _policy()
    from .task_model_selection_api import choices
    from .task_model_selection_api import selection as model_selection
    model_context = context_for(request)
    chosen = model_selection(request, arguments["task_model"], arguments["task_effort"], model_context)
    model_label = next((row["label"] for row in choices(request) if chosen and row["value"] == chosen["model"]), "Use workspace settings")
    # This reviewed Copilot action enters the same native goal endpoint. Show
    # the limits that endpoint will actually dispatch, including REST safety
    # ceilings on a legacy installation whose general task defaults are off.
    effective = api._rest_goal_limits(payload)
    specialist = published_selection(request, arguments.get("domain", ""))
    specialist_review = []
    if specialist["definition"] is not None:
        from .agent_override_changes import _readable
        specialist_review = [{"label": "Complete published specialist", "after": _readable(specialist["definition"], "definition")},
                             {"label": "Specialist work", "after": SPECIALIST_NOTICE}]
    return Preview("Start one new task. Its accepted receipt confirms admission, not completion or external delivery.",
        [*specialist_review, {"label": "Task", "after": title},
         {"label": "Instructions", "after": arguments["description"]},
         {"label": "AI model", "after": model_label},
         {"label": "Thinking depth", "after": EFFORT_LABELS.get(arguments["task_effort"], "Use the model’s usual thinking depth")},
         {"label": "AI team", "after": "This choice is for this task. Some specialists have their own AI settings. Workspace-approved backups keep their existing rules."},
         {"label": "Maximum dollars", "after": effective["max_dollars"]},
         {"label": "Maximum seconds", "after": effective["max_wall_seconds"]},
         {"label": "Levels of helpers", "after": effective["max_depth"]},
         {"label": "Most steps for each agent", "after": policy["agent_step_limit"]["max_steps"] or "No step limit"},
         {"label": "External effects", "after": "Work may use authorized tools; review task progress and any approvals."}],
        {"policy": policy, "effective": effective, "model_context": model_context,
         "specialist": {key: specialist[key] for key in ("name", "context", "revision")}})


def _receipt_outcome(goal, *, replayed, background=None):
    return Outcome("replayed" if replayed else "queued",
        "The task was already admitted; no second task was started." if replayed else
        "Task admission was recorded. Open progress to see whether execution has started or needs your input.",
        {"goal_id": goal.id, "status": goal.status,
         "task": {"label": "Open task progress", "href": f"/chat/goal/{goal.id}"}},
        background=background)


def start_recover(request, selection, arguments, prepared, operation_id):
    from .goal_submission import lookup_receipt

    auth.require_permission(request, "operate")
    try:
        _receipt, goal = lookup_receipt(_shared._world(), key=operation_id,
            owner=auth.caller_principal(request) or "", kind="api")
    except HTTPException as exc:
        if exc.status_code == 404:
            return None
        raise
    auth.assert_goal_access(request, goal)
    if goal.status == "draft":
        return None  # Native same-key replay may finish the one pending dispatch claim.
    return _receipt_outcome(goal, replayed=True)


def start_execute(request, selection, arguments, prepared, operation_id, *, effect_guard=None):
    if _policy() != prepared["policy"]:
        raise HTTPException(409, "Task limits changed. Review the current limits before starting.")
    background, response = BackgroundTasks(), Response()
    specialist = prepared["specialist"]
    check_specialist = published_guard(request, arguments.get("domain", ""), specialist["context"], specialist["revision"])
    def current_start_guard():
        if effect_guard is not None:
            effect_guard()
        check_specialist()
    current_start_guard()
    goal = api._create_goal(request, GoalIn(**{**arguments, "title": arguments["title"].strip(), "task_model_context": prepared["model_context"]}),
                            background, response, idempotency_key=operation_id, effect_guard=current_start_guard)
    return _receipt_outcome(goal, replayed=response.headers.get("Idempotency-Replayed") == "true",
                            background=background)


def entries():
    pages = ("/chat", "/goals", "/today", "/chat/goal/*", "/goals/*")
    return (
        Adapter("tasks.find", "Find one of my tasks", "tasks", "/goals", pages,
                FindInput, find_snapshot, find_prepare,
                aliases=("find a task", "search my tasks", "find my task")),
        Adapter("tasks.start", "Start a new task", "tasks", "/chat", ("/chat", "/goals", "/today"),
                StartInput, start_snapshot, start_prepare, start_execute, start_recover,
                read_recovery=start_recover,
                aliases=("start a task", "create a task", "new task")),
    )
