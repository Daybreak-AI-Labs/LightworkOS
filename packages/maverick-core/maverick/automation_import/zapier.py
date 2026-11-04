"""Zapier importer (connect-and-trigger).

Zapier does NOT expose a user's existing Zaps over its public API (the Platform
API is for building catalog apps; the NLA actions API was retired), so Lightwork
cannot read a client's Zaps. The supported flow is connect-and-trigger: the
client's Zap calls a Lightwork inbound webhook (Zapier's "Webhooks by Zapier ->
POST" action), and the imported template is what that webhook runs. An operator
can also describe a Zap as JSON (the shared IR shape) and import it with
``--from-file`` to scaffold that template.
"""
from __future__ import annotations

from typing import Any

from .base import ImporterError, register
from .ir import ImportedAutomation
from .manual import connect_note
from .manual import translate as _manual_translate


class ZapierImporter:
    source = "zapier"
    can_fetch_definitions = False

    def fetch(self) -> list[dict[str, Any]]:
        raise ImporterError(connect_note("Zapier"))

    def translate(self, raw: dict[str, Any]) -> ImportedAutomation:
        return _manual_translate(raw, source="zapier")


register("zapier", ZapierImporter)
