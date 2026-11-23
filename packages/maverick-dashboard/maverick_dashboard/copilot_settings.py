"""Settings the Copilot's guide can point to for a question.

Asked "how do I make every command ask for approval again?", the guide had
only the page summary and sent the person to "the Features section"; the
switch is under Settings > Protected work area. The guide now gets the best
matches from the Settings search (the same permission-aware search as the
Settings page) and is told to name a setting only when it answers the
question. A link is offered only when its reply names the top match.
"""
from __future__ import annotations

import json
import logging
import re

log = logging.getLogger(__name__)

MAX_HINTS = 5


def hints(request, question: str) -> list[dict]:
    """The Settings search's best matches for ``question`` that this person
    can open, or ``[]``."""
    from . import settings_experience

    try:
        response = settings_experience.search(request, q=question[:200])
        items = json.loads(response.body).get("items") or []
    except Exception:  # noqa: BLE001 -- the guide answers without hints
        log.debug("settings hints unavailable", exc_info=True)
        return []
    return [{"title": str(item.get("title", "")), "group": str(item.get("group", "")),
             "href": str(item.get("href", ""))}
            for item in items[:MAX_HINTS] if item.get("title") and item.get("href", "").startswith("/")]


def context_line(found: list[dict]) -> str:
    """The guide's context line for ``found``."""
    if not found:
        return ""
    # Names and places only: a setting's value (a folder, a host list) never
    # goes to the model.
    listed = " | ".join(f"{item['title']} (Settings > {item['group']})" for item in found)
    return ("Settings that may answer this question, from the Settings search (name one only when it "
            f"answers the question, as Settings > group > name): {listed}")


# The shapes the Copilot panel opens (LINK_HREF and FOCUS_ID in
# lightwork-copilot.js): a path with at most one simple query value, and the
# element to focus there.
_PANEL_HREF = re.compile(r"/[a-z0-9/-]{0,159}(\?[a-z_]{1,20}=[a-z0-9_-]{1,40})?")
_PANEL_FOCUS = re.compile(r"[a-z][a-z0-9_-]{0,79}")


def _panel_link(href: str) -> tuple[str, str] | None:
    """``(href, focus)`` the panel accepts for a Settings search link: the
    search's /settings/all?group=..&id=..#row-label becomes the group page and
    the row to focus."""
    path, _, anchor = href.partition("#")
    base, _, query = path.partition("?")
    first = query.split("&")[0]
    candidate = f"{base}?{first}" if first else base
    if not _PANEL_HREF.fullmatch(candidate):
        candidate = base
    if not _PANEL_HREF.fullmatch(candidate):
        return None
    return candidate, anchor if _PANEL_FOCUS.fullmatch(anchor) else ""


def link(found: list[dict], reply: str) -> dict | None:
    """A link to the top match when the reply names it."""
    if not found or found[0]["title"].casefold() not in reply.casefold():
        return None
    target = _panel_link(found[0]["href"])
    if target is None:
        return None
    href, focus = target
    result = {"href": href, "label": f"Open the setting: {found[0]['title']}"}
    if focus:
        result["focus"] = focus
    return result


def with_link(result: dict, found: list[dict], reply: str) -> dict:
    """``result`` with a link to the top match when the reply names it."""
    if (target := link(found, reply)) is not None:
        result["action_link"] = target
    return result
