"""Personal in-product alerts use current named-account and task authority."""
from __future__ import annotations

import hashlib
import time
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from . import auth

router = APIRouter()


def _app():
    from . import app
    return app


def _identity(request):
    from maverick import experience_preferences
    from maverick.personal_notifications import personal_alerts_enabled

    from .preferences_api import _principal
    principal = _principal(request)
    if not experience_preferences.enabled():
        raise HTTPException(403, "Personal preferences are turned off. An administrator can enable them in All settings.")
    if not personal_alerts_enabled():
        raise HTTPException(403, "Personal alerts are turned off. An administrator can enable them in All settings.")
    return principal


def _goal_pages(world, actor):
    """Unresolved old work survives, independent of recent completed volume."""
    after, since = 0, time.time() - 7 * 86400
    while True:
        batch = world.personal_alert_goals(actor, since=since, after_id=after, limit=250)
        if not batch:
            return
        yield from batch
        after = batch[-1][0].id


def _projection(request, actor: str, *, world=None) -> tuple[list[dict], list[dict], list[dict], bool]:
    world = world if world is not None else _app()._world()
    if request is None:
        from maverick.paths import current_tenant_id_strict
        from maverick.personal_identity import principal_current

        from . import rbac, suite_grants
        if not principal_current(actor):
            raise PermissionError("Personal alert account no longer has access.")
        tenant = current_tenant_id_strict()
        role = rbac.get_tenant_role(tenant, actor) if tenant else auth.global_role_for_principal(actor)
        operate = "operate" in rbac.permissions_for(role)
        admin = "admin" in rbac.permissions_for(role) or auth.is_dashboard_admin(actor)
        suites = None if auth.is_dashboard_admin(actor) else suite_grants.granted_suites(actor)
    else:
        operate = auth.has_permission(request, "operate")
        admin = auth.has_permission(request, "admin")
        suites = auth.caller_suites(request)
    sources, tasks = [], []
    limited = False
    projects = {project["id"]: {"id": project["id"], "name": project["name"]}
                for project in world.list_projects(owner=actor) if project.get("owner") == actor}
    for goal, state_revision, result_revision in _goal_pages(world, actor):
        if goal.owner != actor:
            continue
        # A task the person started but can no longer open (a department grant
        # was removed) is left out; it must not fail every other alert.
        if request is not None and not auth.can_access_goal(request, goal):
            continue
        tasks.append({"id": goal.id, "title": goal.title})
        project_id = getattr(goal, "project_id", None)
        if project_id:
            project = world.get_project(project_id)
            if project is not None and project.get("owner") == actor:
                projects[project_id] = {"id": project_id, "name": project["name"]}
        category = {"blocked": "blocked", "failed": "failed", "done": "completed"}.get(goal.status)
        open_deadline = (float(goal.deadline) if goal.deadline and goal.status not in {"done", "failed", "cancelled"}
                         else None)
        def add(kind, version, label, *, category=category, href=None, goal=goal, project_id=project_id,
                due_at=open_deadline, **extra):
            if not category:
                return
            sources.append({"ref": f"goal:{goal.id}:{kind}", "version": str(version),
                            "category": category, "goal_id": goal.id, "project_id": project_id,
                            "title": goal.title, "label": label, "href": href or f"/chat/goal/{goal.id}",
                            "occurred_at": getattr(goal, "completed_at", None),
                            "reason": "You started this task", "due_at": due_at, **_agent(goal), **extra})
        add("state", f"{goal.status}:{state_revision}", {"blocked": "Needs attention", "failed": "Did not finish", "done": "Finished"}.get(goal.status, ""))
        if goal.status == "done" and goal.result:
            result_digest = hashlib.sha256(str(goal.result).encode()).hexdigest()
            add("result", f"{result_digest}:{result_revision}", "Result changed", category="changed-result")
            sources[-1]["semantic_digest"] = result_digest
            sources[-1]["changed_after_completion"] = result_revision > 0
        for question in world.open_questions(goal.id):
            # Opens the task with the answer box in view; the task waits for the answer.
            add("question:" + str(question.id), question.id, "Needs your answer", category="needs-decision",
                href=f"/chat/goal/{goal.id}#question-panel",
                action="Answer the agent's question so the task can continue",
                no_due="The task waits until you answer", waiting_since=question.asked_at)
        if open_deadline is not None and open_deadline <= time.time() + 3600:
            add("deadline", goal.deadline, "Deadline approaching or overdue", category="deadline")
    if operate:
        for approval in world.pending_approvals():
            if approval.claimed_by != actor:
                continue
            if approval.department and suites is not None and approval.department not in suites:
                continue
            state = world.approval_state(approval.id)
            if not state or state["status"] != "pending" or actor in state["approvers"] or approval.requested_by == actor:
                continue
            sources.append({"ref": f"approval:{approval.id}", "version": str(approval.requested_at),
                            "category": "needs-decision", "title": "Assigned approval", "label": "Needs your decision",
                            "href": f"/approvals#approval-{approval.id}", "goal_id": None, "project_id": None,
                            "reason": "You were assigned to decide this request",
                            "action": "Approve or reject the request", "due_at": _approval_expiry(approval)})
        # Ten minutes without a decision: one reminder for each person who
        # could decide the request in Lightwork.
        from .approval_reminders import reminder_sources

        sources.extend(reminder_sources(world, actor, suites=suites))
        from .flow_approval_inbox import pending_for_observer, pending_for_request

        flow_approvals = (pending_for_observer(actor) if request is None
                          else pending_for_request(request))
        limited = flow_approvals["coverage"] != "current"
        for row in flow_approvals["items"]:
            if row["approval_card_status"] != "current":
                continue
            # Keep personal notification history free of the card and run data.
            # The linked run page performs the current approval checks again.
            card = row.get("approval_card") or {}
            sources.append({
                "ref": f"flow-approval:{row['run_id']}",
                "version": row["approval_binding_sha256"],
                "category": "needs-decision", "title": "Flow approval waiting",
                "label": "Review and decide", "href": row["href"],
                "goal_id": None, "project_id": None,
                "reason": ("You started this flow run" if row.get("owner") == actor
                           else "You are the assigned reviewer for this flow step"),
                "action": "Review the step and decide",
                "due_at": _number(card.get("expires_at")),
            })
    from maverick.budget_guidance import warning_sources
    from maverick.personal_notifications import explain
    sources.extend(warning_sources(actor))
    from maverick.spending_alerts import sources as spending_alert_sources
    sources.extend(spending_alert_sources(actor, admin=admin))
    metric_sources, metric_partial = _metric_sources(request, actor, world)
    sources.extend(metric_sources)
    limited = limited or metric_partial
    # Someone named this person in a comment they can still open (NOT-4).
    from .comments_api import mention_sources
    sources.extend(mention_sources(actor))
    # Every alert says why, what is needed and by when, whatever produced it.
    return [explain(source) for source in sources], tasks, list(projects.values()), limited


def _metric_sources(request, actor, world):
    from maverick.task_metric_alerts import MetricAlertUnavailable, sources

    def readable(goal):
        if request is not None:
            return auth.can_access_goal(request, goal)
        from maverick.domain import suites_for_domain
        from maverick.paths import current_tenant_id_strict
        from maverick.personal_identity import principal_current

        from . import rbac, suite_grants
        if not principal_current(actor):
            raise PermissionError("Personal alert account no longer has access.")
        tenant = current_tenant_id_strict()
        role = rbac.get_tenant_role(tenant, actor) if tenant else auth.global_role_for_principal(actor)
        if "view" not in rbac.permissions_for(role) and not auth.is_dashboard_admin(actor):
            raise PermissionError("Personal alert account no longer has access.")
        suites = None if auth.is_dashboard_admin(actor) else suite_grants.granted_suites(actor)
        return suites is None or all(suite in suites for suite in suites_for_domain(goal.domain))

    try:
        return sources(actor, world, can_read_goal=readable)
    except MetricAlertUnavailable as exc:
        raise HTTPException(503, "Task performance alerts could not be checked. Review All settings or refresh later.") from exc


def _number(value) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _approval_expiry(approval) -> float | None:
    """The card's real expiry; a legacy or unreadable card has none."""
    from maverick.approval_cards import ApprovalCardError, decode_approval_detail
    try:
        card = decode_approval_detail(getattr(approval, "detail", None))
    except ApprovalCardError:
        return None
    return _number((card or {}).get("expires_at"))


def _agent(goal) -> dict:
    """The agent behind a task, when known, so its alerts can be muted."""
    import re

    name = str(getattr(goal, "domain", "") or "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", name):
        return {}
    return {"agent": name, "agent_label": name.replace("_", " ").replace("-", " ")}


def _state(request, *, seen_id=None):
    from maverick.authority_effects import authority_effect_fence
    with authority_effect_fence():
        return _state_locked(request, seen_id=seen_id)


def _state_locked(request, *, seen_id=None):
    from maverick import config
    from maverick import experience_preferences as preferences
    from maverick.personal_notification_delivery import status as delivery_status
    from maverick.personal_notification_recipients import enroll, status
    from maverick.personal_notifications import PersonalInbox, validate_preferences

    from .draft_api import context_for
    actor = _identity(request)
    enroll(actor)
    enrollment = status(actor)
    state = preferences.state(actor)
    choice = validate_preferences(state["values"].get("notification_preferences", {}))
    sources, tasks, projects, limited = _projection(request, actor)
    # Check authority again after reading current sources and before publication.
    if actor != _identity(request):
        raise HTTPException(409, "Your account changed. Reload personal alerts.")
    inbox = PersonalInbox(actor).refresh(sources, choice, seen_id=seen_id,
        allow_critical=(config.load_config().get("notifications") or {}).get("personal_critical_bypass", False) is True,
        enrolled_at=enrollment["enrolled_at"])
    return {**inbox, "preferences": choice, "context": context_for(request), "revision": state["revision"],
            "tasks": tasks, "projects": projects, "partial": limited, "recent_history_days": 7,
            "critical_allowed": (config.load_config().get("notifications") or {}).get("personal_critical_bypass", False) is True,
            "background_enabled": (config.load_config().get("notifications") or {}).get("personal_background") is True,
            "background": enrollment, "private_delivery": delivery_status(actor)}


def page_authority(request):
    """The page's own admission; navigation offers the page only when it passes."""
    auth.require_permission(request, "view")
    if not auth.caller_principal(request):
        raise HTTPException(403, "Sign in with your own account to see personal notifications.")


@router.get("/notifications")
def page(request: Request):
    from maverick import config, experience_preferences
    from maverick.personal_notifications import personal_alerts_on

    page_authority(request)
    if config.config_source_errors(include_tenant=True):
        unavailable = "Notification settings could not be read. Ask an administrator to check All settings."
    elif not experience_preferences.enabled():
        unavailable = "Personal preferences are turned off. An administrator can enable them in All settings."
    elif not personal_alerts_on(config.load_config().get("notifications")):
        unavailable = "Personal task alerts are turned off. An administrator can enable them in All settings."
    else:
        unavailable = ""
    return _app().templates.TemplateResponse(request, "personal_notifications.html",
                                             {"personal_alerts_unavailable": unavailable},
                                             headers={"Cache-Control": "private, no-store"})


@router.get("/api/v1/notifications/personal")
def inbox(request: Request, response: Response):
    response.headers["Cache-Control"] = "private, no-store"
    return _state(request)


@router.get("/api/v1/notifications/personal/summary")
def summary(request: Request, response: Response):
    """A minimal owner-scoped count for the shared navigation bell."""
    response.headers["Cache-Control"] = "private, no-store"
    state = _state(request)
    return {"unseen": sum(item["seen_at"] is None for item in state["items"]),
            "partial": state["partial"], "checked_at": state["checked_at"]}


class PreferencesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(max_length=128)
    expected_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    preferences: dict[str, Any]
    operation_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


def _binding(request, expected):
    from .draft_api import context_for
    _app()._require_same_origin(request)
    auth.require_personal_write(request)
    if not auth.constant_time_equals(expected, context_for(request)):
        raise HTTPException(409, "Your account or workspace changed. Reload personal alerts.")


def validate_current_preferences(request, value):
    """One current authority check shared by direct and reviewed preference edits."""
    from maverick.personal_identity import linked_channels
    from maverick.personal_notifications import validate_preferences
    actor = _identity(request)
    choice = validate_preferences(value)
    if set(choice["external_links"]) - {link["id"] for link in linked_channels(actor)}:
        raise HTTPException(409, "A selected channel identity is no longer verified for your account. Refresh and review your linked identities.")
    world = _app()._world()
    for task_id in choice["muted_tasks"]:
        goal = world.get_goal(int(task_id))
        if goal is None or goal.owner != actor:
            raise HTTPException(409, "A selected task is no longer available. Refresh your preferences.")
        auth.assert_goal_access(request, goal)
    for project_id in choice["projects"]:
        project = world.get_project(project_id)
        if project is None or project.get("owner") != actor:
            raise HTTPException(409, "A selected project is no longer available. Refresh your preferences.")
    return actor, choice


@router.post("/api/v1/notifications/personal/preferences")
def save_preferences(request: Request, response: Response, body: PreferencesIn):
    from maverick import experience_preferences as preferences
    from maverick.authority_effects import authority_effect_fence
    _binding(request, body.context)
    try:
        with authority_effect_fence():
            actor, choice = validate_current_preferences(request, body.preferences)
            preferences.save(actor, scope="personal", changes={"notification_preferences": choice},
                             expected_revision=body.expected_revision, operation_id=body.operation_id)
    except preferences.PreferenceConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    response.headers["Cache-Control"] = "private, no-store"
    return _state(request)


class SeenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(max_length=128)
    item_id: str = Field(pattern=r"^[0-9a-f]{64}$")


@router.post("/api/v1/notifications/personal/seen")
def seen(request: Request, response: Response, body: SeenIn):
    _binding(request, body.context)
    current = _state(request)
    if not any(item["id"] == body.item_id for item in current["items"]):
        raise HTTPException(409, "That alert changed or is no longer available. Refresh the inbox.")
    response.headers["Cache-Control"] = "private, no-store"
    return _state(request, seen_id=body.item_id)


_MUTE_FIELDS = {"task": "muted_tasks", "agent": "muted_agents"}


class MuteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(max_length=128)
    item_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope: Literal["task", "agent"]


class UnmuteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(max_length=128)
    scope: Literal["task", "agent"]
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")


def _change_mutes(request, context: str, change) -> dict:
    """Apply one mute change to the saved preferences at their current revision."""
    from maverick import experience_preferences as preferences
    from maverick.authority_effects import authority_effect_fence
    _binding(request, context)
    try:
        with authority_effect_fence():
            current = _state_locked(request)
            choice, outcome = change(current)
            actor, choice = validate_current_preferences(request, choice)
            preferences.save(actor, scope="personal", changes={"notification_preferences": choice},
                             expected_revision=current["revision"])
    except preferences.PreferenceConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return outcome


@router.post("/api/v1/notifications/personal/mute")
def mute(request: Request, response: Response, body: MuteIn):
    """One click from an alert: mute its task, or every alert from its agent."""
    from maverick.personal_notifications import MUTE_SECONDS

    def change(current):
        item = next((row for row in current["items"] if row["id"] == body.item_id), None)
        if item is None:
            raise HTTPException(409, "That alert changed or is no longer available. Refresh the inbox.")
        if body.scope == "task":
            key = str(item["goal_id"]) if item.get("goal_id") else ""
            label = item.get("title") or "this task"
        else:
            key, label = str(item.get("agent") or ""), item.get("agent_label") or ""
        if not key:
            raise HTTPException(409, "This alert is not about one task, so it can't be muted that way."
                                if body.scope == "task" else
                                "This alert doesn't name an agent, so alerts can't be muted by agent.")
        until = time.time() + MUTE_SECONDS
        field = _MUTE_FIELDS[body.scope]
        choice = {**current["preferences"], field: {**current["preferences"][field], key: until}}
        return choice, {"scope": body.scope, "key": key, "label": label, "until": until}

    muted = _change_mutes(request, body.context, change)
    response.headers["Cache-Control"] = "private, no-store"
    return {**_state(request), "muted": muted}


@router.post("/api/v1/notifications/personal/unmute")
def unmute(request: Request, response: Response, body: UnmuteIn):
    """Undo a mute, from the alert's undo or from notification preferences."""
    def change(current):
        field = _MUTE_FIELDS[body.scope]
        remaining = {key: until for key, until in current["preferences"][field].items() if key != body.key}
        return {**current["preferences"], field: remaining}, {"scope": body.scope, "key": body.key}

    unmuted = _change_mutes(request, body.context, change)
    response.headers["Cache-Control"] = "private, no-store"
    return {**_state(request), "unmuted": unmuted}


# One-action mute and unsubscribe from inside an email, Slack or Telegram
# message (NOT-2). The signed link is the credential, like /share/ and
# /form/: it can only quiet that one person's own notifications, and every
# mute can be undone here. Mail apps press the List-Unsubscribe header with
# one POST (RFC 8058); a person who opens the link presses one button.
_QUIET_WORDS = {
    "task": ("Mute alerts about this task?", "Mute this task",
             "You won't get alerts about this task for 7 days. Everything else stays as it is.",
             "Alerts about this task are muted for 7 days", "Unmuted. Alerts about this task are back on."),
    "agent": ("Mute alerts from this agent?", "Mute this agent",
              "You won't get alerts from this agent for 7 days. Everything else stays as it is.",
              "Alerts from this agent are muted for 7 days", "Unmuted. Alerts from this agent are back on."),
    "summary": ("Stop your daily summary?", "Stop the summary",
                "You won't get the daily summary by email or chat. Turn it back on any time in My work.",
                "Your daily summary is stopped", "Your daily summary is back on."),
}


def _quiet_page(request, status=200, **context):
    return _app().templates.TemplateResponse(
        request, "unsubscribe.html", context, status_code=status,
        headers={"Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer"})


@router.get("/unsubscribe/{token}")
def unsubscribe_page(request: Request, token: str):
    from maverick.notification_unsubscribe import LinkRefused, verify

    try:
        link = verify(token)
    except LinkRefused as exc:
        return _quiet_page(request, 404, problem=str(exc))
    question, button, detail, _done, _undone = _QUIET_WORDS[link["scope"]]
    if link["undo"]:
        return _quiet_page(request, question="Turn these notifications back on?", button="Turn back on",
                           detail="Lightwork will send them to you again.", token=token)
    return _quiet_page(request, question=question, button=button, detail=detail, token=token)


@router.post("/unsubscribe/{token}")
def unsubscribe(request: Request, token: str):
    from maverick.notification_unsubscribe import LinkRefused, apply, sign, verify
    from maverick.paths import reset_tenant, set_tenant

    try:
        link = verify(token)
    except LinkRefused as exc:
        return _quiet_page(request, 404, problem=str(exc))
    pin = set_tenant(link["tenant"])
    try:
        apply(link["principal"], link["scope"], link["key"], undo=link["undo"])
        undo_token = None if link["undo"] else sign(link["principal"], link["scope"], link["key"],
                                                     tenant=link["tenant"], undo=True)
    except (LinkRefused, ValueError) as exc:
        return _quiet_page(request, 409, problem=str(exc))
    finally:
        reset_tenant(pin)
    _question, _button, detail, done, undone = _QUIET_WORDS[link["scope"]]
    if link["undo"]:
        return _quiet_page(request, done=undone, detail="You can change this any time in your notification settings.")
    return _quiet_page(request, done=done + ".", detail=detail, undo_token=undo_token)
