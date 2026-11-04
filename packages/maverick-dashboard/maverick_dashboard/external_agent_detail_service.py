"""Authorized, read-only outside-agent detail shared with the page and Copilot."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from maverick import external_agents

from .auth import require_page_permission

_STATUS = {"executed": ("Request completed", "active"), "failed": ("Request failed", "failure"),
    "denied": ("Not approved", "failure"), "expired": ("Approval expired", "idle"),
    "executing": ("Request in progress", "idle"), "pending": ("Waiting for approval", "idle"),
    "indeterminate": ("Result unknown — check connected service", "failure"),
    "accepted": ("Accepted; completion unconfirmed", "idle")}
_ACTIONS = {"get": "Read", "post": "Create", "put": "Replace", "patch": "Update", "delete": "Delete"}


def _human(value):
    return re.sub(r"[_:.-]+", " ", str(value or "Unavailable")).strip().capitalize()


def detail_for(request: Request, agent_id: str):
    require_page_permission(request, "/external-agents")
    try:
        detail = external_agents.agent_detail(agent_id)
    except external_agents.ExternalAgentsDependencyError as exc:
        raise HTTPException(503, "Saved agent status is unavailable. Reload before deciding what to do next.") from exc
    except external_agents.ExternalAgentsError as exc:
        raise HTTPException(404, "This outside agent is no longer available. Open Outside agents to choose a current agent.") from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "Saved agent status is unavailable. Reload before deciding what to do next.") from exc
    rows = []
    for entry in detail.get("executions", []):
        label, tone = _STATUS.get(entry["status"], ("Status unavailable", "idle"))
        if entry["status"] == "pending":
            approval = entry.get("approval_status")
            if approval == "approved":
                label = "Approved; awaiting agent"
            elif approval == "denied":
                label, tone = "Not approved", "failure"
            elif approval == "unknown":
                label = "Approval needs checking"
        rows.append({"execution_id": entry["execution_id"], "status": label, "tone": tone,
            "connector": _human(entry.get("connector")),
            "action": _ACTIONS.get(str(entry.get("op", "")).lower(), _human(entry.get("op"))),
            **{key: entry[key] for key in ("created_at", "claimed_at", "finished_at") if key in entry},
            "notice": ("The change may already have happened. Check the connected service before submitting another request; this execution will not run again."
                       if entry["status"] == "indeterminate" else
                       "The connected service accepted this request for processing. Completion has not been confirmed. Check that service; this execution will not run again."
                       if entry["status"] == "accepted" else
                       "Lightwork received a completed response. Check the connected service for the business result."
                       if entry["status"] == "executed" else "")})
    detail["execution_readback"] = rows
    return detail


def readback_details(detail):
    coverage = detail.get("execution_coverage", {})
    return {"agent": detail.get("description") or _human(detail["id"]),
        "recorded_changes": [{"execution_reference": entry["execution_id"],
            "status": entry["status"], "connector": entry["connector"], "action": entry["action"],
            **{label: datetime.fromtimestamp(entry[key], timezone.utc).strftime("%d %b %Y at %H:%M UTC")
               for key, label in (("created_at", "requested"), ("claimed_at", "started"), ("finished_at", "recorded")) if key in entry},
            **({"next_step": entry["notice"]} if entry["notice"] else {})}
            for entry in detail.get("execution_readback", [])],
        "displayed_records": coverage.get("displayed_count", 0),
        "retained_records": coverage.get("retained_count", 0),
        "coverage": "Latest 20 retained local execution records; this is not a complete activity archive.",
        "record_retention_hours": coverage.get("retention_seconds", 0) / 3600,
        "source_notice": "Saved Lightwork status only. No connected service was contacted and no change or retry was sent."}
