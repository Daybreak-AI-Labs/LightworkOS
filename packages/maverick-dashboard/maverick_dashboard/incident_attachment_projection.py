"""Fail-closed response integration for governed incident attachments."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import HTTPException, Request


def project_incident_records(
    request: Request,
    records: Sequence[Mapping[str, Any]],
    incident_kind: str,
) -> list[dict[str, Any]]:
    """Add metadata-only attachments when the tenant capability is enabled.

    Disabled tenants retain the legacy response exactly.  Once enabled, a
    missing dependency or stale incident authority is an explicit 503/409
    rather than silently omitting attachments from a response that an operator
    may mistake for complete.
    """

    if incident_kind not in {"privacy", "security"}:
        raise TypeError("incident kind must be privacy or security")
    if not isinstance(request, Request):
        raise TypeError("request authority is required")
    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
        raise TypeError("incident records must be a sequence")
    normalized: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, Mapping):
            raise HTTPException(status_code=503, detail="incident authority is unavailable")
        normalized.append(dict(record))

    from maverick.paths import current_tenant_id_strict

    tenant_id = current_tenant_id_strict()
    if tenant_id is None:
        # Existing single-root incident APIs predate this tenant-only add-on.
        # The metadata composition cannot be enabled without a canonical tenant,
        # so preserve the legacy response instead of breaking the base register.
        return normalized
    state = request.app.state
    enabled_probe = getattr(state, "incident_attachment_metadata_enabled_probe", None)
    readiness_probe = getattr(state, "incident_attachment_metadata_readiness_probe", None)
    projection_factory = getattr(
        state, "incident_attachment_metadata_projection_factory", None
    )
    if not callable(enabled_probe):
        return normalized
    try:
        enabled = enabled_probe(tenant_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="incident attachment configuration is unavailable",
        ) from exc
    if type(enabled) is not bool:
        raise HTTPException(
            status_code=503,
            detail="incident attachment configuration is unavailable",
        )
    if enabled is not True:
        return normalized
    if not callable(readiness_probe) or not callable(projection_factory):
        raise HTTPException(
            status_code=503,
            detail="incident attachment authority is not configured",
        )
    try:
        ready = readiness_probe(tenant_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="incident attachment authority is unavailable",
        ) from exc
    if ready is not True:
        raise HTTPException(
            status_code=503,
            detail="incident attachment authority is not ready",
        )
    try:
        from .incident_attachment_metadata_composition import (
            principal_ref_from_request,
        )

        principal_ref = principal_ref_from_request(request, tenant_id)
        projector = projection_factory(
            tenant_id=tenant_id,
            principal_ref=principal_ref,
            request=request,
        )
        if not callable(projector):
            raise TypeError("projection factory returned no projector")
        return [projector(record, incident_kind) for record in normalized]
    except HTTPException:
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        name = type(exc).__name__.casefold()
        status = 409 if "conflict" in name else 503
        detail = (
            "incident attachment authority changed"
            if status == 409
            else "incident attachment authority is unavailable"
        )
        raise HTTPException(status_code=status, detail=detail) from exc


def project_incident_record(
    request: Request,
    record: Mapping[str, Any],
    incident_kind: str,
) -> dict[str, Any]:
    """Single-record convenience wrapper used by incident mutations."""

    return project_incident_records(request, [record], incident_kind)[0]


__all__ = ["project_incident_record", "project_incident_records"]
