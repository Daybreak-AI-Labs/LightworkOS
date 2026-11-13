"""Small privacy actions that had no button: Microsoft 365 collection for a
data request (``maverick dsar-fulfill collect-graph``).

Same permission (operate) as the other data-request routes, and both module
gates: the privacy register and answering data requests must be on;
the kernel keeps its own checks (subject must be a Microsoft 365 account,
the fulfillment revision must match, nothing but counts is collected).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from .auth import require_permission
from .privacy_access import privacy_ops_or_403

router = APIRouter(prefix="/api/v1/privacy", tags=["privacy-actions"])

#: Plain names for the sources the kernel records.
SOURCE_LABELS = {
    "graph:outlook_mail": "Outlook mailbox",
    "graph:onedrive_files": "OneDrive files",
}


class CollectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: int = Field(..., ge=1)


@router.post("/dsar/{request_id}/collect-microsoft365")
async def collect_microsoft365(request: Request, request_id: str, body: CollectIn) -> dict:
    """Count the requester's Outlook mail and OneDrive files (no content)."""
    require_permission(request, "operate")
    privacy_ops_or_403()
    from maverick import dsar_fulfillment as df
    from maverick.privacy_ops import RecordConflict

    from .request_identity import request_actor as _request_actor

    if not df.enabled():
        from .feature_gate import feature_off

        raise feature_off("dsar_fulfillment", "Answering data requests")
    try:
        result = await run_in_threadpool(
            df.collect_graph_sources,
            request_id[:64],
            actor=_request_actor(request),
            expected_revision=body.revision,
        )
    except df.DsarFulfillmentConfigError as exc:
        raise HTTPException(status_code=503, detail="Microsoft 365 is not connected.") from exc
    except RecordConflict as exc:
        raise HTTPException(status_code=409, detail="This request changed. Refresh the page.") from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="That request no longer exists.") from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="This person is not a Microsoft 365 account, so their data must be collected another way.",
        ) from exc
    except df.DsarFulfillmentError as exc:
        raise HTTPException(status_code=502, detail="Microsoft 365 did not answer as expected.") from exc
    found = []
    for probe in result.get("probes") or []:
        label = SOURCE_LABELS.get(str(probe.get("source")), "Microsoft 365")
        if probe.get("collected"):
            more = " (more exist)" if probe.get("more") else ""
            found.append(f"{label}: {probe.get('items', 0)} item(s){more}")
        else:
            found.append(f"{label}: could not be checked")
    complete = bool(found) and all(probe.get("collected") for probe in result.get("probes") or [])
    heading = "Microsoft 365 checked." if complete else "Microsoft 365 check is incomplete."
    return {"message": heading + (" " + "; ".join(found) + "." if found else ""),
            "complete": complete, "revision": (result.get("record") or {}).get("revision", body.revision)}


__all__ = ["SOURCE_LABELS", "router"]
