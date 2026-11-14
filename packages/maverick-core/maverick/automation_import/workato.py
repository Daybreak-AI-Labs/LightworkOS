"""Workato importer.

Workato exposes recipes over ``GET /api/recipes``; each recipe carries a
``code`` field that is a JSON *string* of the recipe tree. The root node is the
trigger (``{provider, name, ...}``) and its ``block`` is the ordered list of
action steps (each ``{provider, name, input, block?}``); conditional/loop steps
nest a further ``block`` which we flatten in order. ``provider`` is the app
(``salesforce``, ``slack``, ``clock``), ``name`` the operation.

A ``clock``/``scheduler`` provider trigger is a schedule (Workato uses an
interval/cron schedule stored separately, so we import it as a schedule trigger
without an auto-created cron); a webhook trigger is a webhook; everything else
is a polled app event.

Single-tenant creds (env): ``WORKATO_BASE_URL`` (default
``https://www.workato.com``) and ``WORKATO_TOKEN`` (``Authorization: Bearer``).
"""
from __future__ import annotations

import json
import os
from typing import Any

from .base import ImporterError, register
from .ir import (
    TRIGGER_EVENT,
    TRIGGER_SCHEDULE,
    TRIGGER_WEBHOOK,
    ImportedAutomation,
    ImportedStep,
    ImportedTrigger,
)

_SCHEDULE_PROVIDERS = ("clock", "scheduler", "scheduled")
_WEBHOOK_PROVIDERS = ("webhook", "http", "clock_webhook")


def _parse_code(raw: dict) -> dict:
    """Return the recipe tree, parsing the ``code`` JSON string if present."""
    code = raw.get("code")
    if isinstance(code, str) and code.strip():
        try:
            parsed = json.loads(code)
        except (ValueError, TypeError) as e:
            raise ImporterError(f"Workato recipe 'code' is not valid JSON: {e}") from e
        if isinstance(parsed, dict):
            return parsed
    if isinstance(code, dict):
        return code
    # Some exports embed the tree directly.
    if "provider" in raw and "block" in raw:
        return raw
    raise ImporterError("Workato recipe has no parseable 'code' tree")


def _flatten_block(block: list) -> list[dict]:
    out: list[dict] = []
    for node in block or []:
        if not isinstance(node, dict):
            continue
        out.append(node)
        if isinstance(node.get("block"), list):
            out.extend(_flatten_block(node["block"]))
    return out


def _step(node: dict) -> ImportedStep:
    app = str(node.get("provider") or "").strip()
    op = str(node.get("name") or "").strip()
    label = str(node.get("description") or node.get("as") or f"{app} {op}".strip() or "step")
    return ImportedStep(
        name=label,
        description=f"{op or 'use'} via {app}." if app else "step.",
        app=app,
        operation=op,
        params=node.get("input") if isinstance(node.get("input"), dict) else {},
        tools_hint=[app] if app else [],
    )


def _trigger(root: dict) -> ImportedTrigger:
    app = str(root.get("provider") or "").strip()
    op = str(root.get("name") or "").strip()
    low = app.lower()
    if low in _SCHEDULE_PROVIDERS:
        kind = TRIGGER_SCHEDULE
    elif low in _WEBHOOK_PROVIDERS:
        kind = TRIGGER_WEBHOOK
    else:
        kind = TRIGGER_EVENT
    return ImportedTrigger(
        kind=kind,
        app=app if kind == TRIGGER_EVENT else "",
        event=op or app,
        config=root.get("input") if isinstance(root.get("input"), dict) else {},
    )


def translate(raw: dict[str, Any]) -> ImportedAutomation:
    """Lower one Workato recipe into the shared IR."""
    if not isinstance(raw, dict):
        raise ImporterError("Workato recipe must be a JSON object")
    tree = _parse_code(raw)
    steps = [_step(n) for n in _flatten_block(tree.get("block", []) or [])]
    return ImportedAutomation(
        source="workato",
        source_id=str(raw.get("id") or ""),
        name=str(raw.get("name") or tree.get("name") or "untitled Workato recipe"),
        trigger=_trigger(tree),
        steps=steps,
        enabled=bool(raw.get("running", raw.get("active", True))),
        raw=raw,
    )


class WorkatoImporter:
    source = "workato"
    can_fetch_definitions = True

    def __init__(self, base_url: str | None = None, token: str | None = None, *, request=None):
        self.request = request
        self.base_url = ((base_url or "") if request is not None else (base_url or os.environ.get("WORKATO_BASE_URL", "https://www.workato.com"))).strip().rstrip("/")
        self.token = "" if request is not None else (token or os.environ.get("WORKATO_TOKEN", "")).strip()

    def fetch(self) -> list[dict[str, Any]]:
        if (self.request is None and not self.token) or not self.base_url:
            raise ImporterError("Workato import requires WORKATO_TOKEN")
        try:
            import httpx
        except ImportError as e:  # pragma: no cover - optional dep
            raise ImporterError("httpx is required for live Workato import") from e
        out: list[dict[str, Any]] = []
        page = 1
        with httpx.Client(timeout=30.0) as client:
            for _ in range(100):  # page cap
                if self.request is None:
                    from ..governed_http import admit_client_request
                    admit_client_request(client, f"{self.base_url}/api/recipes")
                r = (self.request or client.get)(
                    f"{self.base_url}/api/recipes",
                    headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
                    params={"page": page, "per_page": 100},
                )
                r.raise_for_status()
                body = r.json() if r.content else {}
                items = body.get("items") if isinstance(body, dict) else body
                items = items or []
                out.extend([w for w in items if isinstance(w, dict)])
                if len(items) < 100:
                    break
                page += 1
            else:
                raise ImporterError("Workato import reached the 10,000 recipe page limit; the inventory may be incomplete")
        return out

    def translate(self, raw: dict[str, Any]) -> ImportedAutomation:
        return translate(raw)


register("workato", WorkatoImporter)
