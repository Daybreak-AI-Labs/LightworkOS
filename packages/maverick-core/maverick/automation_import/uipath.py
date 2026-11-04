"""UiPath (Orchestrator) importer.

UiPath's automation *logic* lives in compiled packages (.nupkg/.xaml), not in a
JSON the API returns -- so a "definition import" here is necessarily coarser
than n8n/Make: the Orchestrator API exposes deployed **Releases** (a process:
``{Name, ProcessKey, ProcessVersion, Arguments}``) and **ProcessSchedules**
(time triggers: ``{Name, ReleaseName, StartProcessCron, Enabled}``). We import a
Release as a one-step automation ("run the UiPath process X") and a schedule as
the same with a schedule trigger. UiPath cron is Quartz (6-7 fields), which the
Lightwork scheduler (5-field) can't run directly, so we capture it in the
trigger for the operator to translate rather than auto-creating a schedule.

Single-tenant creds (env): ``UIPATH_BASE_URL`` (Orchestrator URL incl. tenant
path) and ``UIPATH_TOKEN`` (bearer). ``translate`` also accepts an exported
Release/Schedule object via ``--from-file``.
"""
from __future__ import annotations

import os
from typing import Any

from .base import ImporterError, register
from .ir import (
    TRIGGER_MANUAL,
    TRIGGER_SCHEDULE,
    ImportedAutomation,
    ImportedStep,
    ImportedTrigger,
)


def _is_schedule(raw: dict) -> bool:
    return bool(raw.get("StartProcessCron") or raw.get("ReleaseName"))


def translate(raw: dict[str, Any]) -> ImportedAutomation:
    """Lower one UiPath Release or ProcessSchedule into the shared IR."""
    if not isinstance(raw, dict):
        raise ImporterError("UiPath object must be a JSON object")

    if _is_schedule(raw):
        process = str(raw.get("ReleaseName") or raw.get("Name") or "UiPath process")
        quartz = str(raw.get("StartProcessCron") or "").strip()
        trigger = ImportedTrigger(
            kind=TRIGGER_SCHEDULE,
            description=f"on the UiPath schedule '{raw.get('Name', '')}'"
                        + (f" (Quartz cron {quartz})" if quartz else ""),
            cron=None,  # Quartz != 5-field cron; don't auto-create a schedule
            config={"quartz_cron": quartz} if quartz else {},
        )
        name = str(raw.get("Name") or f"Schedule for {process}")
        source_id = str(raw.get("Id") or raw.get("Key") or "")
    else:
        process = str(raw.get("Name") or raw.get("ProcessKey") or "UiPath process")
        trigger = ImportedTrigger(kind=TRIGGER_MANUAL,
                                  description="on demand (UiPath process)")
        name = process
        source_id = str(raw.get("Key") or raw.get("Id") or raw.get("ProcessKey") or "")

    args = raw.get("Arguments") if isinstance(raw.get("Arguments"), dict) else {}
    step = ImportedStep(
        name=f"Run UiPath process: {process}",
        description=f"invoke the UiPath RPA process '{process}' via the UiPath "
                    "Orchestrator connector (start a job on a robot).",
        app="uipath",
        operation="start_job",
        params={"process": process, **({"arguments": args} if args else {})},
        tools_hint=["uipath"],
    )

    return ImportedAutomation(
        source="uipath",
        source_id=source_id,
        name=name,
        trigger=trigger,
        steps=[step],
        enabled=bool(raw.get("Enabled", True)),
        raw=raw,
    )


class UiPathImporter:
    source = "uipath"
    can_fetch_definitions = True

    def __init__(self, base_url: str | None = None, token: str | None = None, *, request=None):
        self.request = request
        self.base_url = ((base_url or "") if request is not None else (base_url or os.environ.get("UIPATH_BASE_URL", ""))).strip().rstrip("/")
        self.token = "" if request is not None else (token or os.environ.get("UIPATH_TOKEN", "")).strip()

    def _get(self, client, path: str):
        if self.request is None:
            from ..governed_http import admit_client_request
            admit_client_request(client, f"{self.base_url}{path}")
        return (self.request or client.get)(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
        )

    def fetch(self) -> list[dict[str, Any]]:
        if not self.base_url or (self.request is None and not self.token):
            raise ImporterError("UiPath import requires UIPATH_BASE_URL + UIPATH_TOKEN")
        try:
            import httpx
        except ImportError as e:  # pragma: no cover - optional dep
            raise ImporterError("httpx is required for live UiPath import") from e
        out: list[dict[str, Any]] = []
        with httpx.Client(timeout=30.0) as client:
            # Schedules carry the trigger + the release they run; releases cover
            # the on-demand processes. Both lower into one-step automations.
            for path in ("/odata/ProcessSchedules", "/odata/Releases"):
                r = self._get(client, path)
                r.raise_for_status()
                body = r.json() if r.content else {}
                out.extend([x for x in (body.get("value") or []) if isinstance(x, dict)])
        return out

    def translate(self, raw: dict[str, Any]) -> ImportedAutomation:
        return translate(raw)


register("uipath", UiPathImporter)
