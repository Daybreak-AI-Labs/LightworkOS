"""Use-case guidance backed by current, authorized review records."""
from __future__ import annotations

from .auth import (
    caller_principal,
    caller_role,
    goal_owner_filter,
    has_global_permission,
    has_permission,
    suite_allowed,
)

PLANS = {
    "deliverable": {"label":"Review a completed AI deliverable", "suite":None,
        "prepare":"Choose an agent or specialist whose result requires approval, and describe a small task with clear acceptance criteria.",
        "prepare_href":"/agents", "prepare_label":"Choose an agent or specialist",
        "work":"Run the task, check the output and supporting evidence, and request corrections when needed.",
        "work_href":"/chat", "work_label":"Start the task",
        "review":"Record an explicit approval on the current completed deliverable. A finished task alone does not complete this path.",
        "review_href":"/deliverables", "review_label":"Review deliverables"},
    "vendor": {"label":"Onboard a vendor with reviewed evidence", "suite":"privacy",
        "prepare":"Save the required Jira connection and enroll its project access. Add a Drive connection when using Drive evidence; uploads do not need Drive.",
        "prepare_href":"/third-party/vendor-onboarding", "prepare_label":"Check vendor prerequisites",
        "work":"Create a vendor case, add documents, collect the evidence, and resolve missing or conflicting facts during review.",
        "work_href":"/third-party/vendor-onboarding", "work_label":"Open vendor intake",
        "review":"Review and approve the exact proposed ticket, verify its external result, then record customer acceptance. Sample cases are shown separately.",
        "review_href":"/third-party/vendor-onboarding", "review_label":"Review vendor cases"},
    "privacy": {"label":"Complete a privacy assessment", "suite":"privacy",
        "prepare":"Choose the assessment questionnaire and name the vendor, system, or process. Assign a reviewer and gather supporting evidence.",
        "prepare_href":"/privacy", "prepare_label":"Open privacy worklist",
        "work":"Answer the questions in the app, resolve follow-ups, and review the evidence and findings.",
        "work_href":"/privacy", "work_label":"Continue assessment",
        "review":"Record an explicit approval on the current assessment. An overdue review or unanswered questionnaire does not complete this path.",
        "review_href":"/privacy", "review_label":"Review assessment"},
}


def reviewed_goal(world, *, owner=None, principal=None, domain_allowed=lambda domain: True) -> dict:
    try:
        rows = world.list_goals(status="done", owner=owner, limit=2001, order="desc")
        for goal in rows[:2000]:
            if not domain_allowed(goal.domain):
                continue
            decision = world.signoff_for(goal.id)
            reviewer = (decision or {}).get("decided_by", "")
            human = reviewer.startswith("user:") or (principal is None and reviewer == "operator")
            if decision and decision.get("decision") == "approved" and human:
                return {"complete":True, "status":"reviewed", "title":goal.title,
                        "href":f"/chat/goal/{goal.id}", "reviewed_at":decision.get("created_at"),
                        "detail":"The current completed deliverable has a recorded human approval."}
        return {"complete":False, "status":"partial" if len(rows) > 2000 else "incomplete",
                "detail":"No approved deliverable was found in the latest 2,000 completed tasks accessible to you."}
    except Exception:
        return {"complete":False, "status":"unavailable", "detail":"Reviewed-outcome records could not be checked. Completion has not been assumed."}


def _reviewed_vendor(request):
    from .vendor_onboarding_api import _binding, _call

    rows = _call(_binding(request), "list")
    for row in rows:
        outcome = row.get("outcome") or {}
        if (row.get("stage") == "accepted" and outcome.get("accepted") is True
                and outcome.get("execution_completed") is True
                and outcome.get("validation") == "verified_external_record"
                and str(outcome.get("reviewer", "")).startswith("user:")
                and (row.get("integration_mode") or {}).get("tickets") == "live_unverified"):
            return {"complete":True, "status":"reviewed", "title":row["vendor_name"],
                    "href":"/third-party/vendor-onboarding", "detail":"A permitted vendor case has a recorded verified external result and customer acceptance."}
    return {"complete":False, "status":"incomplete", "detail":"No accepted case with a verified external result was found. Sample cases do not complete this path."}


def _reviewed_assessment(request):
    from maverick.assessment import list_saved, load_saved

    from .app import PRIVACY_ASSESSMENT_TYPES

    principal = caller_principal(request)
    for row in list_saved():
        if row.get("type") not in PRIVACY_ASSESSMENT_TYPES or row.get("status") != "approved" or row.get("review_due"):
            continue
        full = load_saved(row["id"])
        reviewer = str((full or {}).get("decided_by") or "")
        human = reviewer.startswith("user:") or (principal is None and reviewer in {"operator", "local:dashboard"})
        mine = principal is None or reviewer == principal or row.get("assignee") == principal
        if full and human and mine and row.get("answered") == row.get("total") and row.get("total", 0) > 0:
            return {"complete":True, "status":"reviewed", "title":row["subject"], "href":"/privacy",
                    "detail":"Your current, complete assessment has a recorded human approval and is not due for review."}
    return {"complete":False, "status":"incomplete", "detail":"No current approved assessment assigned to or reviewed by you was found."}


def first_outcomes_for(request) -> dict:
    """The eight department first outcomes this caller may run, plus readiness.

    ``ready`` is the offline readiness of the selected model routes; when it is
    false the page says so and links to Settings instead of offering a run
    that would fail quietly. ``selected`` is the department setup recorded.
    """
    from maverick import sample_outcomes
    from maverick.config import get_first_outcome
    from maverick.domain import enabled_domains, suite_for

    from .first_outcome_api import CONNECT_HREF, NOT_READY_DETAIL, provider_ready

    try:
        packs = enabled_domains()
    except Exception:
        packs = {}
    rows = []
    for row in sample_outcomes.departments():
        if row["pack"] in packs and suite_allowed(request, suite_for(row["pack"])):
            rows.append(dict(row, files=list(sample_outcomes.get(row["department"]).files)))
    recorded = get_first_outcome()
    offered = {row["department"] for row in rows}
    selected = recorded["department"] if recorded["department"] in offered else (
        sample_outcomes.DEFAULT_DEPARTMENT if sample_outcomes.DEFAULT_DEPARTMENT in offered else
        (rows[0]["department"] if rows else None))
    ready = provider_ready()
    return {"outcomes": rows, "selected": selected, "ready": ready, "can_operate": has_permission(request, "operate"),
            # Only an administrator can connect an AI service; others are told who can.
            "can_connect": has_global_permission(request, "admin"),
            "connect_href": CONNECT_HREF, "not_ready_detail": NOT_READY_DETAIL if not ready else "",
            "sample_workspace_created": recorded["sample_workspace_created"], "rule": sample_outcomes.SAMPLE_RULE}


def for_request(request, world, selected: str = "deliverable") -> dict:
    from maverick.domain import suites_for_domain

    plans = {key: value for key, value in PLANS.items() if suite_allowed(request, value["suite"])}
    selected = selected if selected in plans else "deliverable"
    plan = dict(plans[selected])

    def admitted(domain):
        try:
            return all(suite_allowed(request, suite) for suite in suites_for_domain(domain))
        except Exception:
            return False

    if not has_permission(request, "operate"):
        outcome = {"complete":False, "status":"permission_required", "detail":"An operator can run and review this workflow. Your access remains read-only."}
    else:
        try:
            if selected == "vendor":
                outcome = _reviewed_vendor(request)
            elif selected == "privacy":
                outcome = _reviewed_assessment(request)
            else:
                outcome = reviewed_goal(world, owner=goal_owner_filter(request), principal=caller_principal(request), domain_allowed=admitted)
        except Exception:
            outcome = {"complete":False, "status":"unavailable", "detail":"This path's prerequisites or review records are unavailable. Open the module to complete setup; success has not been assumed."}
    return {"plans":plans, "selected_plan":selected, "plan":plan, "outcome":outcome,
            "role_label":caller_role(request) or "Administrator on this computer"}
