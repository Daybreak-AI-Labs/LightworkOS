"""Schedule proposals on a task's page, each opening the Automations form
filled in for the person to review and create."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlencode


def href(proposal: dict[str, str]) -> str:
    """The Automations page with the create form filled in from ``proposal``."""
    query = {"what": "task", "text": proposal["text"], "title": proposal["title"],
             "cron": proposal["cron"]}
    if proposal.get("zone"):
        query["zone"] = proposal["zone"]
    return "/automations?" + urlencode(query) + "#auto-new-sched"


def context(world, goal) -> dict[str, Any]:
    """Template values for the proposals: never raises."""
    from maverick.schedule_proposals import describe, for_goal

    try:
        proposals = for_goal(world, goal.id)
    except Exception:  # noqa: BLE001 -- the answer still renders without them
        proposals = []
    return {"schedule_proposals": [
        {"title": p["title"], "text": p["text"], "when": describe(p["cron"], p["zone"]), "href": href(p)}
        for p in proposals]}
