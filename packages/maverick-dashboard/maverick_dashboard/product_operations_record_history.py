"""Typed historical discovery delegates the same current native source adapters."""
from __future__ import annotations

from typing import Literal

from fastapi import HTTPException
from maverick.metadata_history import digest
from pydantic import Field

from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput
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
        details={"More results": "Continue to another page using the same filters. Current access is checked for each page."})


def prepare(request, selection, arguments):
    snapshot(request, selection)
    try:
        date_bound(arguments.get("after", ""))
        date_bound(arguments.get("before", ""), end=True)
        if arguments.get("after") and arguments.get("before") and arguments["after"] > arguments["before"]:
            raise ValueError
    except ValueError as exc:
        raise HTTPException(422, "Choose valid UTC dates in chronological order.") from exc
    return Preview("Read one page of saved record details using your current access. This search starts no AI work and changes no records.", native=arguments)


def execute(request, selection, arguments, native, operation):
    snapshot(request, selection)
    try:
        result = search_history(request, **native)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return Outcome("confirmed", "Current saved record details returned. Counts describe this page only; continue when another page is available.", result)


def entries():
    return (Adapter("knowledge.history", "Find a saved record", "learning", "/goals?find_history=tasks", ("*",), HistoryInput, snapshot, prepare, execute),)
