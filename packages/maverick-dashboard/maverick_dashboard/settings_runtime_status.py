"""Honest saved-versus-startup status for the existing global Settings surface."""
from __future__ import annotations

import time

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from maverick import config, runtime_configuration

from . import auth
from . import settings_all_page as page
from . import settings_catalog as catalog

router = APIRouter()
IMMEDIATE = ("dashboard.", "personalization.", "copilot.", "features.")


def impact(setting):
    if setting.restart:
        return {"activation": "restart", "timing": "After the owning service restarts and acknowledges this revision"}
    if setting.id.startswith(IMMEDIATE):
        return {"activation": "immediate", "timing": "On the next page request or policy check; existing drafts are retained"}
    return {"activation": "next_task", "timing": "On the next configuration read for new work; running work keeps its captured settings"}


def projection(ids=()):
    if not runtime_configuration.enabled():
        return {"enabled": False, "checked_at": time.time(), "items": [],
                "message": "Configuration startup acknowledgements are disabled or their configuration is unavailable."}
    current = config.load_global_config()
    desired = runtime_configuration.snapshot(current)
    observed, unavailable = runtime_configuration.records()
    layers = page._sources()
    selected = [catalog.BY_ID[key] for key in ids if key in catalog.BY_ID] if ids else [
        setting for setting in catalog.SETTINGS if setting.restart and page._resolve(setting, layers)["source"] == "here"]
    items = []
    for setting in selected:
        timing = impact(setting)
        if setting.restart:
            value = runtime_configuration.setting_status(setting, desired, observed, unavailable=unavailable)
        else:
            value = {"state": timing["activation"], "message": timing["timing"], "processes": []}
        items.append({"id": setting.id, "label": setting.label, "module": setting.group, "area": setting.group,
                      "scope": "Organization / installation; authorized workspaces inherit unless policy specifies otherwise",
                      **timing, **value})
    return {"enabled": True, "checked_at": time.time(), "saved_revision": page._revision(layers),
            "configuration_revision": desired["revision"], "items": items,
            "coverage": "Only observed processes sharing this configuration data folder are included. A startup acknowledgement does not prove connector health, model availability or the success of running work."}


@router.get("/api/v1/settings/runtime-status")
def runtime_status(request: Request, ids: list[str] = Query(default=[])):
    auth.require_global_permission(request, "admin")
    if len(ids) > 100:
        from fastapi import HTTPException
        raise HTTPException(422, "Review at most 100 settings at a time.")
    return JSONResponse(projection(ids), headers={"Cache-Control": "private, no-store"})
