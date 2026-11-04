"""n8n importer.

n8n exposes workflow definitions over its public REST API
(``GET /api/v1/workflows``), so this is a *true definition import*: we fetch the
node graph and lower it into the shared IR. A workflow is ``{id, name, active,
nodes[], connections{}}``; each node is ``{name, type, parameters}`` and
``connections`` is an adjacency map keyed by node name. We order the actions by
walking the graph from the trigger node so the imported brief matches the real
execution order rather than the (arbitrary) node-array order.

Single-tenant creds (env): ``N8N_BASE_URL`` (e.g. ``https://n8n.example.com``)
and ``N8N_API_KEY`` (sent as the ``X-N8N-API-KEY`` header).
"""
from __future__ import annotations

import os
from typing import Any

from .base import ImporterError, register
from .ir import (
    TRIGGER_EVENT,
    TRIGGER_MANUAL,
    TRIGGER_SCHEDULE,
    TRIGGER_WEBHOOK,
    ImportedAutomation,
    ImportedStep,
    ImportedTrigger,
)

_NODE_PREFIX = "n8n-nodes-base."

# Trigger node types -> normalized trigger kind.
_TRIGGER_TYPES = {
    "webhook": TRIGGER_WEBHOOK,
    "formTrigger": TRIGGER_WEBHOOK,
    "cron": TRIGGER_SCHEDULE,
    "scheduleTrigger": TRIGGER_SCHEDULE,
    "interval": TRIGGER_SCHEDULE,
    "manualTrigger": TRIGGER_MANUAL,
    "start": TRIGGER_MANUAL,
}


def _short_type(node_type: str) -> str:
    """``n8n-nodes-base.slack`` -> ``slack``; ``@scope/pkg.thing`` -> ``thing``."""
    t = str(node_type or "")
    t = t.removeprefix(_NODE_PREFIX)
    return t.rsplit(".", 1)[-1]


def _is_trigger_node(node: dict) -> bool:
    short = _short_type(node.get("type", ""))
    return short in _TRIGGER_TYPES or short.endswith("Trigger")


def _trigger_kind(short: str) -> str:
    if short in _TRIGGER_TYPES:
        return _TRIGGER_TYPES[short]
    # "*Trigger" node from a community/app package -> a polled app event.
    return TRIGGER_EVENT


def _cron_from_interval(interval: dict) -> str | None:
    """Synthesize a 5-field cron from one modern ``scheduleTrigger`` interval
    rule (``{field, <field>Interval, triggerAtHour, triggerAtMinute, ...}``).

    Covers minutes/hours/days/weeks/months -- the encodings n8n uses instead of
    a raw cron. Returns ``None`` for sub-minute (``seconds``) or unknown fields,
    which a 5-field cron can't express (the trigger still imports, just without
    an auto-created schedule)."""
    field = str(interval.get("field") or "").strip()

    def _int(key: str, default: int) -> int:
        try:
            return int(interval.get(key, default))
        except (TypeError, ValueError):
            return default

    minute = _int("triggerAtMinute", 0)
    hour = _int("triggerAtHour", 0)
    if field == "minutes":
        n = max(1, _int("minutesInterval", 1))
        return f"*/{n} * * * *"
    if field == "hours":
        n = max(1, _int("hoursInterval", 1))
        return f"{minute} {'*' if n == 1 else f'*/{n}'} * * *"
    if field == "days":
        n = max(1, _int("daysInterval", 1))
        return f"{minute} {hour} {'*' if n == 1 else f'*/{n}'} * *"
    if field == "weeks":
        days = interval.get("triggerAtDay")
        dow = "*"
        if isinstance(days, list) and days:
            picked = [str(int(d)) for d in days if str(d).lstrip("-").isdigit()]
            dow = ",".join(picked) or "*"
        return f"{minute} {hour} * * {dow}"
    if field == "months":
        n = max(1, _int("monthsInterval", 1))
        dom = max(1, _int("triggerAtDayOfMonth", 1))
        return f"{minute} {hour} {dom} {'*' if n == 1 else f'*/{n}'} *"
    return None  # seconds / unknown -> not representable in 5 fields


def _extract_cron(params: dict) -> str | None:
    """Best-effort 5-field cron from a scheduleTrigger/cron node's parameters.

    Recovers an explicit cron expression, and (new) synthesizes one from the
    modern ``scheduleTrigger`` interval rules. Leaves ``None`` only for
    sub-minute or otherwise un-expressible schedules -- the trigger still
    imports, just without an auto-created schedule."""
    # Classic cron node: parameters.cronExpression, or triggerTimes.item[].mode.
    expr = params.get("cronExpression")
    if isinstance(expr, str) and expr.strip():
        return expr.strip()
    rule = params.get("rule")
    if isinstance(rule, dict):
        for interval in rule.get("interval", []) or []:
            if not isinstance(interval, dict):
                continue
            ce = interval.get("cronExpression") or interval.get("expression")
            if isinstance(ce, str) and ce.strip():
                return ce.strip()
            synthesized = _cron_from_interval(interval)
            if synthesized:
                return synthesized
    return None


def _ordered_action_nodes(nodes: list[dict], connections: dict, trigger_name: str | None) -> list[dict]:
    """Action nodes in execution order via a BFS over ``connections`` from the
    trigger; falls back to node-array order for anything unreachable."""
    by_name = {n.get("name"): n for n in nodes if n.get("name")}
    ordered: list[str] = []
    seen: set[str] = set()
    queue: list[str] = [trigger_name] if trigger_name else []
    while queue:
        cur = queue.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        if cur != trigger_name:
            ordered.append(cur)
        for group in (connections.get(cur, {}) or {}).get("main", []) or []:
            for edge in group or []:
                nxt = edge.get("node") if isinstance(edge, dict) else None
                if nxt and nxt not in seen:
                    queue.append(nxt)
    # Append any node the graph walk missed (disconnected branches), in file order.
    for n in nodes:
        nm = n.get("name")
        if nm and nm not in seen and not _is_trigger_node(n):
            ordered.append(nm)
    return [by_name[nm] for nm in ordered if nm in by_name]


def _step_from_node(node: dict) -> ImportedStep:
    params = node.get("parameters") if isinstance(node.get("parameters"), dict) else {}
    app = _short_type(node.get("type", ""))
    operation = ""
    if isinstance(params, dict):
        operation = str(params.get("operation") or params.get("resource") or "").strip()
    name = str(node.get("name") or app or "step")
    desc_op = f"{operation} via {app}" if operation else f"use {app}"
    return ImportedStep(
        name=name,
        description=f"{desc_op}.",
        app=app,
        operation=operation,
        params=params if isinstance(params, dict) else {},
        tools_hint=[app] if app else [],
    )


def translate(raw: dict[str, Any]) -> ImportedAutomation:
    """Lower one n8n workflow definition into the shared IR."""
    if not isinstance(raw, dict):
        raise ImporterError("n8n workflow must be a JSON object")
    nodes = raw.get("nodes")
    if not isinstance(nodes, list):
        raise ImporterError("n8n workflow has no 'nodes' array")
    connections = raw.get("connections") if isinstance(raw.get("connections"), dict) else {}

    trigger_node = next((n for n in nodes if isinstance(n, dict) and _is_trigger_node(n)), None)
    if trigger_node is not None:
        short = _short_type(trigger_node.get("type", ""))
        tparams = trigger_node.get("parameters") if isinstance(trigger_node.get("parameters"), dict) else {}
        kind = _trigger_kind(short)
        trigger = ImportedTrigger(
            kind=kind,
            app=short.replace("Trigger", "") if kind == TRIGGER_EVENT else "",
            event=short,
            cron=_extract_cron(tparams) if kind == TRIGGER_SCHEDULE else None,
            config=tparams,
        )
    else:
        trigger = ImportedTrigger(kind=TRIGGER_MANUAL)

    action_nodes = _ordered_action_nodes(
        [n for n in nodes if isinstance(n, dict)],
        connections,
        trigger_node.get("name") if trigger_node else None,
    )
    steps = [_step_from_node(n) for n in action_nodes]

    return ImportedAutomation(
        source="n8n",
        source_id=str(raw.get("id") or ""),
        name=str(raw.get("name") or "untitled n8n workflow"),
        trigger=trigger,
        steps=steps,
        enabled=bool(raw.get("active", True)),
        raw=raw,
    )


class N8nImporter:
    source = "n8n"
    can_fetch_definitions = True

    def __init__(self, base_url: str | None = None, api_key: str | None = None, *, request=None):
        self.request = request
        self.base_url = ((base_url or "") if request is not None else (base_url or os.environ.get("N8N_BASE_URL", ""))).strip().rstrip("/")
        self.api_key = "" if request is not None else (api_key or os.environ.get("N8N_API_KEY", "")).strip()

    def fetch(self) -> list[dict[str, Any]]:
        if not self.base_url or (self.request is None and not self.api_key):
            raise ImporterError("n8n import requires N8N_BASE_URL + N8N_API_KEY")
        try:
            import httpx
        except ImportError as e:  # pragma: no cover - optional dep
            raise ImporterError("httpx is required for live n8n import") from e
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        with httpx.Client(timeout=30.0) as client:
            for _ in range(100):  # hard page cap (defensive)
                params = {"limit": 100}
                if cursor:
                    params["cursor"] = cursor
                if self.request is None:
                    from ..governed_http import admit_client_request
                    admit_client_request(client, f"{self.base_url}/api/v1/workflows")
                r = (self.request or client.get)(
                    f"{self.base_url}/api/v1/workflows",
                    headers={"X-N8N-API-KEY": self.api_key, "Accept": "application/json"},
                    params=params,
                )
                r.raise_for_status()
                body = r.json() if r.content else {}
                out.extend([w for w in (body.get("data") or []) if isinstance(w, dict)])
                cursor = body.get("nextCursor")
                if not cursor:
                    break
            else:
                raise ImporterError(
                    "n8n import exceeded the 100-page (10,000 workflow) "
                    "safety limit; narrow the source account or use an export "
                    "instead of accepting a silently truncated import"
                )
        return out

    def translate(self, raw: dict[str, Any]) -> ImportedAutomation:
        return translate(raw)


register("n8n", N8nImporter)
