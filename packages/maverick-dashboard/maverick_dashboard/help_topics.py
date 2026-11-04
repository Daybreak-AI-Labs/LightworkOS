"""Short step-by-step help for the most common tasks, shown where they happen.

Each topic is one task from the user journeys (new administrator, employee,
approver, privacy officer, executive or auditor). The Help menu on every page
offers "How this works" for the page's topic, which opens the matching
section of the Help page (``/help#how-<slug>``). The steps name the buttons
as the pages show them; a test checks that each named label is still on its
page, so a renamed button fails the build instead of leaving stale help.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Topic:
    slug: str
    title: str
    persona: str
    paths: tuple[str, ...]
    steps: tuple[str, ...]
    # (template, label): labels the steps quote, checked against the page.
    labels: tuple[tuple[str, str], ...] = ()


TOPICS: tuple[Topic, ...] = (
    Topic("connect-ai", "Connect an AI service", "Administrator", ("/settings", "/providers"), (
        "Open Settings and go to Provider keys.",
        "Paste the key for your AI service in its row and save it.",
        "Press Test connection. The row says whether Lightwork could reach the service.",
        "If the test fails, the row says why; fix the key or the network and test again.",
    ), (("settings.html", "Provider keys"),)),
    Topic("first-task", "Run your first task", "Administrator", ("/start", "/get-started"), (
        "Open Get started.",
        "Connect an AI service first: the sample cannot run without one.",
        "Press Run the sample task. It opens the task page so you can watch it work.",
        "The checklist on Get started shows what is left to set up.",
    ), (("get_started.html", "Run the sample task"),)),
    Topic("invite", "Invite a colleague", "Administrator", ("/users",), (
        "Open Users and press Invite someone.",
        "Enter their email address, choose their role, then press Create invite link.",
        "Copy the one-time link and send it to them yourself. Lightwork does not email it.",
        "Pending invitations are listed below; Cancel invitation withdraws one.",
    ), (("users.html", "Invite someone"), ("users.html", "Create invite link"),
        ("users.html", "Cancel invitation"))),
    Topic("spending-limit", "Set a spending limit", "Administrator", ("/spending-limits",), (
        "Open Spending limits and press Set a workspace limit.",
        "Enter the most the workspace may spend and press Save workspace limit.",
        "To limit one person, use Save personal limit instead.",
        "A task that reaches a limit stops and says which limit it reached.",
    ), (("spending_limits.html", "Set a workspace limit"), ("spending_limits.html", "Save workspace limit"),
        ("spending_limits.html", "Save personal limit"))),
    Topic("chat-app", "Connect a chat app", "Administrator", ("/channels",), (
        "Open Channels and choose the chat app.",
        "Enter the details the app gives you; Where do I find these details? explains each one.",
        "Press Test connection, then Send a test message to check it end to end.",
        "People link their own chat account with a link code before they can give work in chat.",
    ), (("channels.html", "Where do I find these details?"), ("channels.html", "Test connection"),
        ("channels.html", "Send a test message"))),
    Topic("start-task", "Ask for work", "Employee", ("/chat",), (
        "Open Chat.",
        "Describe what you need in plain words. Attach files if the work needs them.",
        "Press Start task. The task page shows each step as it happens.",
        "If the agent needs something from you, a question appears above the message box.",
    )),
    Topic("follow-task", "Follow, answer or stop a task", "Employee", ("/chat/goal",), (
        "Open the task from Chat or Tasks.",
        "The status at the top says whether it is working, waiting for you, or done.",
        "If it asks a question, answer in the box that appears; the task waits until you do.",
        "To stop it, press Stop task. It stops after the step it is on and lists what is done and what is left.",
        "Press Resume or Try again to carry on.",
    ), (("chat_goal.html", "Stop task"), ("chat_goal.html", "Try again"))),
    Topic("use-result", "Use a result", "Employee", ("/deliverables",), (
        "Open the finished task.",
        "Use Copy answer, Download Word document or Download Markdown to take the result with you.",
        "Ask for a change in the message box; the task keeps its history.",
        "Results lists every finished result you can see.",
    ), (("chat_goal.html", "Copy answer"), ("chat_goal.html", "Download Word document"),
        ("chat_goal.html", "Download Markdown"))),
    Topic("find-task", "Find a past task", "Employee", ("/goals",), (
        "Open Tasks.",
        "Type part of the task's title in Search tasks.",
        "Open a task to see its steps, result and any problems.",
    )),
    Topic("notifications", "Choose which alerts you get", "Employee", ("/notifications",), (
        "Open the bell at the top of any page.",
        "Each alert says why you got it, what it needs and by when. Open it to go straight to the item.",
        "Use Mute this task or Mute alerts from this agent to quiet one source; Undo puts it back.",
        "Under the alerts, choose quiet hours and which events alert you, then press Save personal notification preferences.",
    ), (("personal_notifications.html", "Save personal notification preferences"),)),
    Topic("daily-summary", "Get a daily summary", "Approver", ("/me",), (
        "Open My work and go to Your daily summary.",
        "Choose the hour and where it goes, then save.",
        "Open Preview today's summary to see exactly what would be sent. Previewing sends nothing.",
        "Send my summary now sends today's summary straight away.",
    ), (("me.html", "Send my summary now"), ("_digest_preview.html", "Preview today's summary"))),
    Topic("approve", "Decide an approval", "Approver", ("/approvals",), (
        "Open Approvals. Each card says what will happen, how risky it is and when it expires.",
        "Read the card, then press Approve or Reject and confirm.",
        "Right after approving you can undo for a short time.",
        "See decisions on your requests shows what happened to the requests you made.",
    ), (("approvals.html", "See decisions on your requests"),)),
    Topic("approval-rules", "Require approval for risky actions", "Administrator", ("/settings/all",), (
        "Open Settings and search for the action, for example \"can't be undone\".",
        "Choose how Lightwork should handle it, for example wait on the Approvals page.",
        "Save, then check the review before it applies.",
    )),
    Topic("data-request", "Handle a data rights request", "Privacy officer", ("/privacy/dsar",), (
        "Open the request from Privacy. Its page shows the law, the due date and the days left.",
        "Press Confirm identity, or Confirm identity another way if you checked it outside Lightwork.",
        "Use Where to search and Start answering to collect and send the answer.",
        "Press Close request when it is answered.",
    ), (("dsar_detail.html", "Confirm identity another way"), ("dsar_detail.html", "Where to search"),
        ("dsar_detail.html", "Start answering"), ("dsar_detail.html", "Close request"))),
    Topic("incident", "Record a privacy incident", "Privacy officer", ("/privacy/incidents", "/incidents"), (
        "Open Privacy and go to incidents.",
        "Record what happened. The clock shows how long is left to decide.",
        "Press Decide: must notify or Decide: no notification needed, and record why.",
    ), (("privacy.html", "Decide: must notify"), ("privacy.html", "Decide: no notification needed"))),
    Topic("vendor", "Review a vendor", "Privacy officer", ("/vendors",), (
        "Open the vendor from Privacy, or press Add a vendor.",
        "Press Send a questionnaire and wait for the replies; View replies shows them.",
        "When the review is done, press Review assessment before activation and confirm the activation, "
        "or press Stop using this vendor.",
    ), (("privacy.html", "Add a vendor"), ("vendor_detail.html", "Send a questionnaire"),
        ("vendor_detail.html", "View replies"), ("vendor_detail.html", "Review assessment before activation"))),
    Topic("privacy-report", "Share the privacy programme report", "Privacy officer", ("/privacy/report",), (
        "Open the privacy report from Privacy.",
        "Print it or save it as a PDF to share it.",
    )),
    Topic("activity-log", "Download the activity log", "Auditor", ("/audit",), (
        "Open the Activity log and pick the dates.",
        "Press Download and choose a format.",
        "Check the log has not been changed proves nothing was edited afterwards.",
    ), (("audit.html", "Download"), ("audit.html", "Check the log has not been changed"))),
    Topic("audit-binder", "Prepare an audit binder", "Auditor", ("/audit/binder",), (
        "Open the audit binder from the Activity log.",
        "Press Print or save as PDF for a readable copy.",
        "Press Download evidence file (for auditors) for the machine-readable copy.",
    ), (("audit.html", "Open the audit binder"), ("audit_binder.html", "Print or save as PDF"),
        ("audit_binder.html", "Download evidence file (for auditors)"))),
    Topic("savings", "See what Lightwork saved", "Executive", ("/savings", "/spend"), (
        "Open Savings and choose the period.",
        "Savings are estimates from the hours each task would have taken; change the assumptions and press Save and recalculate.",
        "Spend shows what the AI work cost over the same period.",
    ), (("savings.html", "Save and recalculate"),)),
)

_BY_SLUG = {topic.slug: topic for topic in TOPICS}


def topic_for(path: str) -> Topic | None:
    """The topic for a page path: the longest whole-segment prefix wins."""
    path = (path or "").rstrip("/") or "/"
    best: tuple[int, Topic] | None = None
    for topic in TOPICS:
        for prefix in topic.paths:
            if (path == prefix or path.startswith(prefix + "/")) and (best is None or len(prefix) > best[0]):
                best = (len(prefix), topic)
    return best[1] if best else None


def by_slug(slug: str) -> Topic | None:
    return _BY_SLUG.get(slug)


__all__ = ["TOPICS", "Topic", "by_slug", "topic_for"]
