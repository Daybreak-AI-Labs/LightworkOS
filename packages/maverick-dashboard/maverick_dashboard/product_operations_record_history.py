"""Typed historical discovery delegates the same current native source adapters."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException
from maverick.metadata_history import digest
from pydantic import Field

from .plain_labels import day_text
from .product_operations import Adapter, Preview, Snapshot, StrictInput
from .record_history import SOURCES, date_bound, search_history
from .record_search_api import page_context


class HistoryInput(StrictInput):
    source: Literal["tasks", "projects", "workflows", "automations", "connections", "facts", "questionnaires", "vault", "reports", "vendors", "onboarding", "reviews"]
    query: str = Field(default="", max_length=200)
    after: str = Field(default="", pattern=r"^(?:[0-9]{4}-[0-9]{2}-[0-9]{2})?$")
    before: str = Field(default="", pattern=r"^(?:[0-9]{4}-[0-9]{2}-[0-9]{2})?$")
    oldest: bool = False
    cursor: str | None = Field(default=None, max_length=2048)


def snapshot(request, selection):
    context = page_context(request).get("record_search_context")
    if not context:
        raise HTTPException(403, "Record discovery is disabled. An administrator can enable it in Settings.")
    return Snapshot(digest([context, list(SOURCES)]), "Saved record details", "Find older records by name, reference and date. This search excludes private message bodies and document contents.", fields=[
        {"name": "source", "label": "Source", "kind": "select", "required": True,
         "choices": [{"value": code, "label": value[0]} for code, value in SOURCES.items()]},
        {"name": "query", "label": "Name or reference", "kind": "text"},
        {"name": "after", "label": "On or after (YYYY-MM-DD, UTC)", "kind": "text"},
        {"name": "before", "label": "On or before (YYYY-MM-DD, UTC)", "kind": "text"},
        {"name": "oldest", "label": "Oldest first", "kind": "boolean", "value": False}],
        details={"More results": "Narrow the name or dates, or open the full list. Current access is checked for each search."})


def _when(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "Not recorded"
    moment = datetime.fromtimestamp(value, timezone.utc)
    return f"{day_text(moment)}, {moment:%H:%M} UTC"


def readable(result):
    """The page of matches as people read it: names, status and dates only."""
    rows = [{"Name": {"label": row["title"], "href": row["href"]},
             "Status": (row.get("state") or "Not recorded").replace("_", " ").capitalize(),
             "Date": _when(row.get("date"))} for row in result.get("items", [])]
    coverage = (result.get("coverage") or [{}])[0]
    value = {"Records found": rows or "No matching records.",
             "More results": "Yes. Narrow the name or dates, or open the full list." if result.get("next_cursor") else "No"}
    if coverage.get("href"):
        value["Full list"] = {"label": "Open " + coverage.get("source", "the full list"), "href": coverage["href"]}
    if coverage.get("state") in {"partial", "unavailable"} and not rows:
        value["Note"] = "This source could not be searched completely. Choose a narrower date range, or open the full list."
    return value


def prepare(request, selection, arguments):
    """A read: Copilot shows the matches at once. Nothing is reviewed or changed."""
    snapshot(request, selection)
    try:
        date_bound(arguments.get("after", ""))
        date_bound(arguments.get("before", ""), end=True)
        if arguments.get("after") and arguments.get("before") and arguments["after"] > arguments["before"]:
            raise ValueError
    except ValueError as exc:
        raise HTTPException(422, "Choose valid UTC dates in chronological order.") from exc
    try:
        result = search_history(request, **arguments)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return Preview("Saved records found with your current access. This search started no AI work and changed nothing.",
                   native=readable(result))


def entries():
    return (Adapter("knowledge.history", "Find a saved record", "learning", "/goals?find_history=tasks", ("*",), HistoryInput, snapshot, prepare),)
