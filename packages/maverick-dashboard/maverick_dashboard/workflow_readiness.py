"""Customer-facing capability boundaries; enabling a feature is not acceptance."""
from __future__ import annotations

CATALOG = (
    {"name": "Reviewed task delivery", "stage": "available", "feature": "guided_onboarding", "href": "/start", "permission": "operate",
     "scope": "Step-by-step help from first setup to a finished piece of work that a person has approved.",
     "limit": "A finished task is not proof the result is right for your business. Connect an AI provider and review a real result first."},
    {"name": "Action Center", "stage": "available", "feature": "action_center", "href": "/action-center", "permission": "operate",
     "scope": "Everything waiting for you in one place: approvals, assessments and reviews. Mark items read or snooze them.",
     "limit": "Snoozing only hides an item for you. It does not pause the work or move its deadline."},
    {"name": "Editor recovery", "stage": "available", "feature": "draft_recovery", "href": "/workflow-builder", "permission": "operate",
     "scope": "Get back unsaved work in the agent, workflow and guided editors after a browser crash or closed tab.",
     "limit": "Passwords, keys and attachments are not kept. Restoring a draft never runs or publishes it, and it is not a full backup."},
    {"name": "Business record search", "stage": "available", "feature": "record_search", "href": None, "permission": "view",
     "how": "Use the search box at the top of any page.",
     "scope": "Find records you are allowed to see by name or reference from the search box at the top of every page.",
     "limit": "The text inside documents is not searched. The results tell you when a source could not be searched."},
    {"name": "Vendor evidence and renewal", "stage": "live_validation", "feature": None, "href": "/third-party/vendor-onboarding", "permission": "operate", "suite": "privacy",
     "scope": "Read vendor documents (including Google Docs and PDFs), point out missing or conflicting facts, suggest Jira tickets for you to approve, and compare evidence at renewal.",
     "limit": "Try it with your own Google Drive and Jira accounts and a real vendor before relying on it. The built-in examples are made up."},
    {"name": "Privacy discovery setup", "stage": "live_validation", "feature": None, "href": "/privacy/data-discovery", "permission": "operate", "suite": "privacy",
     "scope": "Choose a saved connection for each data source, keep its key up to date, and check that Lightwork can reach it.",
     "limit": "A saved connection does not prove Lightwork can read a private source. Run the access check on each real source."},
    {"name": "Consent publication", "stage": "live_validation", "feature": None, "href": "/consent/publishing", "permission": "operate", "suite": "privacy",
     "scope": "Pick the website and wording to publish, see what changes for visitors, and keep your edits if something needs fixing.",
     "limit": "Publishing still needs its review and a connected website. Check the live site after you publish."},
    {"name": "External delivery reconciliation", "stage": "live_validation", "feature": None, "href": "/security/governance", "permission": "admin", "suite": "security",
     "scope": "When a send to your compliance system is on hold, compare what was sent with what arrived, then confirm it or keep it on hold with a note.",
     "limit": "Comparing never re-sends anything. Lightwork never re-sends automatically after a timeout. Check with your compliance system's owner."},
    {"name": "Project team review", "stage": "available", "feature": "project_reviews", "href": "/project-reviews", "permission": "view",
     "scope": "Share finished task results with named colleagues and keep their comments, decisions and due dates. You can remove a reviewer at any time.",
     "limit": "Reviewers need their own sign-in and a workspace. Reviewing never changes or signs off the task itself."},
    {"name": "Local workspace recovery", "stage": "bounded", "feature": "workspace_recovery", "href": "/workspace/recovery", "permission": "admin",
     "scope": "Save protected copies of this workspace, compare them, test a restore, and restore safely on this computer.",
     "limit": "A restore stops if spending or approval history has changed since the copy was made. Copies kept on other systems need a separate check."},
    {"name": "Workflow pilot measurement", "stage": "preview", "feature": "outcome_measurement", "href": "/outcome-pilots", "permission": "operate",
     "scope": "Plan a trial, record how long work took before and after, the corrections needed and the cost, and see which results were accepted.",
     "limit": "This page does not check your AI provider's bill. Compare against real work you measured before the trial."},
    {"name": "Usage and cost receipts", "stage": "bounded", "feature": None, "href": "/billing", "permission": "view",
     "scope": "Lightwork keeps its own record of what each task used and what it cost, including tasks that were retried.",
     "limit": "This is not your AI provider's bill. Some older usage recorded before a crash may be missing, so compare with your provider's statement."},
    {"name": "Windows desktop application", "stage": "release_candidate", "feature": None, "href": None, "permission": "view",
     "how": "Ask your administrator for the Windows installer.",
     "scope": "A Windows app with built-in setup, updates, repair and recovery.",
     "limit": "It is still being tested on fresh computers before its general release."},
    {"name": "Learning and improvement", "stage": "experimental", "feature": None, "href": "/oversight", "permission": "view",
     "scope": "Lightwork learns from reviewed work, lets you check what it learned, and lets you undo it.",
     "limit": "Good results on practice tests do not guarantee better results on your work. Keep spending limits and reviews in place."},
    {"name": "Watch and spatial companion surfaces", "stage": "prototype", "feature": None, "href": None, "permission": "view",
     "how": "Not available to install yet.",
     "scope": "Early designs for smartwatch and headset views.",
     "limit": "These are not released and cannot be installed yet."},
)

LABELS = {"available": "Ready to use", "live_validation": "Needs a real-world check",
    "bounded": "Ready, with limits", "preview": "Early preview", "release_candidate": "Almost ready",
    "experimental": "Experimental", "prototype": "In design"}


def supplier_setup_readiness(state):
    """Configuration checklist from the caller's sanitized setup snapshot."""
    deployment = state["deployment"]
    actions = []
    if not deployment["supported"]:
        actions.append({"id": "deployment", "label": deployment["next_action"], "href": "#vs-deployment"})
    else:
        if not state["modules_enabled"] or not state["connections_enabled"]:
            actions.append({"id": "enable", "label": "Ask a workspace administrator to enable the vendor workflow below.", "href": "#vs-enable"})
        if not state["binding"].get("resource_owner"):
            actions.append({"id": "owner", "label": "Choose an active workspace member to own vendor reviews.", "href": "#vs-resource-owner"})
        ticket = state["binding"].get("ticket_connection")
        usable = [row for row in state["connections"] if row["connector"] == "jira" and row["has_token"]]
        if not usable:
            actions.append({"id": "jira", "label": "Connect a Jira account with access to the project where approved tasks will be created.", "href": "/connections"})
        elif not any(row["name"] == ticket for row in usable):
            actions.append({"id": "jira", "label": "Select your Jira connection for task delivery.", "href": "#vs-ticket"})
        if not state["revision"]:
            actions.append({"id": "save", "label": "Review the owner and connection choices, confirm, then save workspace setup.", "href": "#vs-confirm"})
    return {"state": "blocked" if not deployment["supported"] else "setup_required" if actions else "configured",
            "configuration_complete": not actions, "actions": actions, "deployment": deployment,
            "live_provider_verified": False}


def for_request(request):
    from maverick import config

    from .auth import has_permission, suite_allowed

    features = config.get_features()
    rows = []
    for record in CATALOG:
        if not suite_allowed(request, record.get("suite")):
            continue
        row = {**record, "stage_label": LABELS[record["stage"]]}
        row["configuration"] = "Turned on" if record["feature"] and features.get(record["feature"]) is True else (
            "Turned off in Settings" if record["feature"] else "Set up inside the page")
        if record["href"] == "/third-party/vendor-onboarding":
            from maverick.vendor_onboarding import deployment_readiness

            profile = deployment_readiness()
            row["configuration"] = "Open the page to choose an owner and connect Jira" if profile["supported"] else profile["message"]
        row["can_open"] = bool(record["href"] and has_permission(request, record["permission"])
                               and (not record["feature"] or features.get(record["feature"]) is True))
        row["can_turn_on"] = bool(record["feature"] and features.get(record["feature"]) is not True
                                  and has_permission(request, "admin"))
        rows.append(row)
    return rows
