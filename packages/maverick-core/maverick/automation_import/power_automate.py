"""Microsoft Power Automate importer.

A cloud flow's logic is the Logic Apps Workflow Definition Language (WDL):
``{properties: {definition: {triggers: {...}, actions: {...}}}}``. ``triggers``
and ``actions`` are name-keyed dicts; action order is the dependency graph in
each action's ``runAfter`` (a topological sort, NOT dict order). An action of
type ``OpenApiConnection`` names its connector + operation under
``inputs.host`` (``apiId``/``connectionName`` + ``operationId``). A ``Request``
trigger is a webhook; ``Recurrence`` is a schedule (frequency/interval, not
cron); an ``OpenApiConnection`` trigger is a polled app event.

Single-tenant creds (env): ``POWER_AUTOMATE_TOKEN`` (a bearer token for the
Flow/Graph API). Live fetch is environment-specific, so definition import via
``--from-file`` (an exported flow definition) is the primary path.
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


def _definition(raw: dict) -> dict:
    """Find the WDL ``definition`` inside the several envelopes Power Automate /
    the Flow API wrap it in."""
    if "triggers" in raw or "actions" in raw:
        return raw
    props = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
    d = props.get("definition") if isinstance(props.get("definition"), dict) else None
    if isinstance(d, dict):
        return d
    if isinstance(raw.get("definition"), dict):
        return raw["definition"]
    return raw


def _connector_app(inputs: dict) -> tuple[str, str]:
    """Best-effort (app, operation) from an OpenApiConnection action's inputs."""
    host = inputs.get("host") if isinstance(inputs.get("host"), dict) else {}
    op = str(host.get("operationId") or "").strip()
    conn = host.get("connection") if isinstance(host.get("connection"), dict) else {}
    app = str(
        host.get("apiId") or host.get("connectionName")
        or conn.get("name") or conn.get("referenceName") or ""
    ).strip()
    # apiId looks like ".../providers/Microsoft.PowerApps/apis/shared_slack".
    if "/" in app:
        app = app.rsplit("/", 1)[-1]
    app = app.removeprefix("shared_")
    return app, op


def _toposort_actions(actions: dict) -> list[str]:
    """Action names ordered so each follows everything in its ``runAfter``."""
    ordered: list[str] = []
    placed: set[str] = set()
    remaining = dict(actions)
    # Iterate to a fixpoint; any cycle/dangling dep is appended at the end.
    progress = True
    while remaining and progress:
        progress = False
        for name in list(remaining):
            spec = remaining[name] or {}
            deps = spec.get("runAfter") or {}
            if not isinstance(deps, dict) or all(d in placed for d in deps):
                ordered.append(name)
                placed.add(name)
                del remaining[name]
                progress = True
    ordered.extend(remaining)  # leftovers (cycles / external deps), stable order
    return ordered


def _step(name: str, spec: dict) -> ImportedStep:
    spec = spec if isinstance(spec, dict) else {}  # an action value can be null
    inputs = spec.get("inputs") if isinstance(spec.get("inputs"), dict) else {}
    atype = str(spec.get("type") or "")
    app, op = ("", "")
    if atype == "OpenApiConnection":
        app, op = _connector_app(inputs)
    label = name.replace("_", " ").strip()
    return ImportedStep(
        name=label or "step",
        description=(f"{op or atype} via {app}." if app else f"{atype or 'action'}."),
        app=app,
        operation=op or atype,
        params=inputs.get("parameters") if isinstance(inputs.get("parameters"), dict) else {},
        tools_hint=[app] if app else [],
    )


def _trigger(triggers: dict) -> ImportedTrigger:
    if not triggers:
        return ImportedTrigger(kind=TRIGGER_MANUAL)
    name, spec = next(iter(triggers.items()))
    spec = spec or {}
    ttype = str(spec.get("type") or "")
    if ttype in ("Request", "ApiConnectionWebhook", "HttpWebhook"):
        return ImportedTrigger(kind=TRIGGER_WEBHOOK, description=name.replace("_", " "))
    if ttype == "Recurrence":
        rec = spec.get("recurrence") if isinstance(spec.get("recurrence"), dict) else {}
        freq = rec.get("frequency")
        interval = rec.get("interval")
        return ImportedTrigger(
            kind=TRIGGER_SCHEDULE,
            description=f"every {interval} {freq}".strip() if freq else "on a schedule",
            config=rec,
        )
    app, op = _connector_app(spec.get("inputs") if isinstance(spec.get("inputs"), dict) else {})
    return ImportedTrigger(kind=TRIGGER_EVENT, app=app, event=op or name)


def translate(raw: dict[str, Any]) -> ImportedAutomation:
    """Lower one Power Automate flow definition into the shared IR."""
    if not isinstance(raw, dict):
        raise ImporterError("Power Automate flow must be a JSON object")
    d = _definition(raw)
    triggers = d.get("triggers") if isinstance(d.get("triggers"), dict) else {}
    actions = d.get("actions") if isinstance(d.get("actions"), dict) else {}
    if not triggers and not actions:
        raise ImporterError("Power Automate definition has no triggers/actions")

    steps = [_step(n, actions[n]) for n in _toposort_actions(actions)]
    name = (
        raw.get("properties", {}).get("displayName")
        if isinstance(raw.get("properties"), dict) else None
    ) or raw.get("name") or raw.get("displayName") or "untitled Power Automate flow"

    return ImportedAutomation(
        source="power_automate",
        source_id=str(raw.get("name") or raw.get("id") or ""),
        name=str(name),
        trigger=_trigger(triggers),
        steps=steps,
        raw=raw,
    )


class PowerAutomateImporter:
    source = "power_automate"
    can_fetch_definitions = False

    def __init__(self, token: str | None = None):
        self.token = (token or os.environ.get("POWER_AUTOMATE_TOKEN", "")).strip()

    def fetch(self) -> list[dict[str, Any]]:
        # Live enumeration is environment/region specific (which Dataverse env,
        # which API host). Definition import via --from-file (an exported flow)
        # is the supported path; surface that rather than guessing an endpoint.
        raise ImporterError(
            "Power Automate live fetch is environment-specific; export the flow "
            "definition and import with `--from-file` (a flow's WDL definition)"
        )

    def translate(self, raw: dict[str, Any]) -> ImportedAutomation:
        return translate(raw)


register("power_automate", PowerAutomateImporter)
