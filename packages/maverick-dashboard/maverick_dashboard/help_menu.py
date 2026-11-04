"""What the Help menu and the service banner on every page need.

The Help menu (``_help_menu.html``, both shells) offers Help and diagnostics,
"How this works" for the page's task (:mod:`.help_topics`), "Get help from a
person" (a request prepared on the Help page, never sent automatically) and,
when ``[support] status_page_url`` is set, the public service-status page. The
service banner (``_service_status_banner.html``) appears while an AI service
is paused, a connection can't be used or the database is read-only
(:mod:`maverick.service_status`).
"""
from __future__ import annotations

import logging
import re

log = logging.getLogger(__name__)


def support_settings() -> dict:
    """``[support]`` with every value empty when the config cannot be read."""
    try:
        from maverick.config import get_support

        return get_support()
    except Exception:  # noqa: BLE001 -- a broken config hides the links, never the page
        log.debug("support settings unavailable", exc_info=True)
        return {"status_page_url": "", "contact_email": ""}


def context(request) -> dict:
    from maverick.service_status import safe_current

    from .help_topics import topic_for

    try:
        path = request.url.path
    except Exception:  # pragma: no cover -- shell rendering stays fail-soft
        path = ""
    support = support_settings()
    return {"help_topic": topic_for(path), "support_status_page_url": support["status_page_url"],
            "service_status": safe_current(), "service_notices": service_notices(request)}


def service_notices(request) -> list[dict]:
    """Service banners beside the AI one: connections this person's work can't
    use right now, and a read-only database. Never breaks a page."""
    from maverick.service_status import connector_notice, database_notice

    notices = []
    try:
        from .connection_dependencies import connection_attention

        notices.append(connector_notice(connection_attention(request).get("items") or []))
    except Exception:  # noqa: BLE001 -- the banner is advisory
        log.debug("connection status unavailable", exc_info=True)
    notices.append(database_notice())
    return [notice for notice in notices if notice]


_PAGE = re.compile(r"/[A-Za-z0-9/_.~-]{0,300}")
_TASK = re.compile(r"[1-9][0-9]{0,15}")
_RUN = re.compile(r"[A-Za-z0-9_-]{1,64}")
_FAILURE = re.compile(r"lw-failure-[0-9a-f]{32}")


def _task_visible(request, task: str) -> bool:
    """Name a task in the request only when this person may open it."""
    from fastapi import HTTPException

    from ._shared import _world
    from .auth import assert_goal_access

    goal = _world().get_goal(int(task))
    if goal is None:
        return False
    try:
        assert_goal_access(request, goal)
    except HTTPException:
        return False
    return True


def help_request(request) -> dict:
    """The "Get help from a person" request, filled in from the Help link.

    Only the page address, a task or run number and an error reference are
    carried over, each checked against a strict pattern; never page content,
    task text or results. The person edits it and chooses how to send it.
    """
    query = request.query_params
    page = str(query.get("from") or "")
    page = page if _PAGE.fullmatch(page) and not page.startswith("//") else ""
    task = str(query.get("task") or "")
    try:
        task = task if _TASK.fullmatch(task) and _task_visible(request, task) else ""
    except Exception:  # noqa: BLE001 -- an unreadable task is simply left out
        log.debug("help request task check failed", exc_info=True)
        task = ""
    run = str(query.get("run") or "")
    run = run if _RUN.fullmatch(run) else ""
    failure = str(query.get("failure") or "")
    failure = failure if _FAILURE.fullmatch(failure) else ""
    lines = ["Hello,", "", "I need help with Lightwork.", ""]
    if page:
        lines.append(f"Page: {page}")
    if task:
        lines.append(f"Task: #{task} (/chat/goal/{task})")
    if run:
        lines.append(f"Run: {run}")
    if failure:
        lines.append(f"Error reference: {failure}")
    lines += ["", "What I was trying to do:", "", "What happened instead:", ""]
    email = support_settings()["contact_email"]
    return {"body": "\n".join(lines), "page": page, "task": task, "run": run, "failure": failure,
            "email": email,
            "subject": "Lightwork help request" + (f" about task #{task}" if task else "")}


__all__ = ["context", "help_request", "support_settings"]
