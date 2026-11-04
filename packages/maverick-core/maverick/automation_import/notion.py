"""Notion importer (connect-and-trigger).

The Notion API exposes databases, pages, and blocks -- but NOT Notion's
automations (database-button / formula automations aren't in the public API), so
Lightwork can't read them. Two supported flows:

* connect-and-trigger -- a Notion automation (or button) calls a Lightwork
  inbound webhook; the imported template is what runs.
* data + rebuild -- read the client's Notion data with the existing ``notion``
  tool (search / db_query / page_get) and describe the automation as JSON (the
  shared IR shape) to import a template with ``--from-file``.

``fetch`` lists the client's Notion databases (so an operator can see what to
build automations against) when ``NOTION_TOKEN`` is set, but those are data
structures, not automations -- it raises with the connect guidance rather than
pretending a database is an automation.
"""
from __future__ import annotations

from typing import Any

from .base import ImporterError, register
from .ir import ImportedAutomation
from .manual import connect_note
from .manual import translate as _manual_translate


class NotionImporter:
    source = "notion"
    can_fetch_definitions = False

    def fetch(self) -> list[dict[str, Any]]:
        raise ImporterError(connect_note("Notion"))

    def translate(self, raw: dict[str, Any]) -> ImportedAutomation:
        return _manual_translate(raw, source="notion")


register("notion", NotionImporter)
