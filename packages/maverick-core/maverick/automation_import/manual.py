"""Manual / connect-and-trigger translator.

For platforms that don't expose their automation definitions over an API
(Zapier, Notion automations) the source automation can't be fetched, so the
import is driven by a hand-authored (or AI-drafted) description in the shared IR
shape::

    {
      "name": "New lead handler",
      "trigger": {"kind": "webhook", "description": "Zap posts a new lead"},
      "steps": [
        {"name": "Add to CRM", "app": "hubspot", "operation": "create_contact",
         "description": "create the contact", "params": {...}}
      ]
    }

This is the same JSON an operator gets by exporting one of these automations'
*intent* (not its proprietary definition). The Zapier/Notion importers wrap this
with their source name + a "connect" fetch that explains the trigger wiring.
``translate(raw, source=...)`` is shared so all three behave identically.
"""
from __future__ import annotations

from typing import Any

from .base import ImporterError
from .ir import TRIGGER_KINDS, TRIGGER_WEBHOOK, ImportedAutomation, ImportedStep, ImportedTrigger


def _step(raw: dict) -> ImportedStep:
    app = str(raw.get("app") or "").strip()
    op = str(raw.get("operation") or raw.get("action") or "").strip()
    name = str(raw.get("name") or f"{app} {op}".strip() or "step")
    return ImportedStep(
        name=name,
        description=str(raw.get("description") or (f"{op} via {app}." if app else "")),
        app=app,
        operation=op,
        params=raw.get("params") if isinstance(raw.get("params"), dict) else {},
        tools_hint=[app] if app else [],
    )


def translate(raw: dict[str, Any], *, source: str) -> ImportedAutomation:
    """Lower a manual IR-shaped description into an :class:`ImportedAutomation`."""
    if not isinstance(raw, dict):
        raise ImporterError(f"{source} description must be a JSON object")
    name = str(raw.get("name") or "").strip()
    if not name:
        raise ImporterError(f"{source} description needs a 'name'")
    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list):
        raise ImporterError(f"{source} description needs a 'steps' array")

    tr = raw.get("trigger") if isinstance(raw.get("trigger"), dict) else {}
    kind = str(tr.get("kind") or TRIGGER_WEBHOOK).strip()
    if kind not in TRIGGER_KINDS:
        kind = TRIGGER_WEBHOOK
    trigger = ImportedTrigger(
        kind=kind,
        description=str(tr.get("description") or ""),
        app=str(tr.get("app") or ""),
        event=str(tr.get("event") or ""),
        cron=tr.get("cron") if isinstance(tr.get("cron"), str) else None,
        config=tr.get("config") if isinstance(tr.get("config"), dict) else {},
    )
    return ImportedAutomation(
        source=source,
        source_id=str(raw.get("id") or raw.get("source_id") or ""),
        name=name,
        trigger=trigger,
        steps=[_step(s) for s in steps_raw if isinstance(s, dict)],
        description=str(raw.get("description") or ""),
        raw=raw,
    )


def connect_note(source: str) -> str:
    """The standard 'how to connect this platform' guidance."""
    return (
        f"{source} does not expose its automations over an API, so Lightwork "
        f"can't read them directly. Connect it instead: in {source}, add a step "
        "that POSTs to your Lightwork inbound webhook (the imported template is "
        "what that webhook runs), or describe the automation as JSON and import "
        "it with `--from-file`."
    )
