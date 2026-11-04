"""Explicit connection impact review, staged keys, and exact source rebinding."""
from __future__ import annotations

import hmac

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import (
    has_global_permission,
    has_permission,
    require_global_permission,
    require_permission,
)
from .connection_dependencies import impact, owned_connections, require_review
from .draft_api import context_for

router = APIRouter(tags=["connection-review"])


class ReviewedIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_revision: str = Field(min_length=1, max_length=128)
    impact_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    replacement: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    replacement_revision: str = Field(min_length=1, max_length=128)
    confirm: bool = False


class RebindIn(ReviewedIn):
    source_id: str = Field(min_length=1, max_length=200)
    source_revision: int = Field(ge=1, strict=True)
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")


def _authority(request, body=None):
    from .connection_dependencies import require_connections as _require_connections

    require_permission(request, "admin" if body is not None else "operate")
    _require_connections()
    if body is not None:
        from .app import _require_same_origin

        _require_same_origin(request)
        if not body.confirm or not hmac.compare_digest(body.context, context_for(request)):
            raise HTTPException(409, "Review this change in the current account and workspace.")


@router.get("/api/v1/connections/{name}/impact")
async def connection_impact(request: Request, name: str):
    from maverick.connection_capabilities import choices

    _authority(request)
    value = await run_in_threadpool(impact, request, name)
    records = owned_connections(request)
    selected = next((row for row in records if row["name"] == name), None)
    if selected is None or selected["revision"] != value["revision"]:
        raise HTTPException(409, "Connection changed while its dependencies were being reviewed.")
    value["replacements"] = [row for row in records if row["name"] != name]
    value["can_manage"] = has_permission(request, "admin")
    value["can_rebind"] = has_global_permission(request, "admin")
    value["capabilities"] = choices(selected["connector"])
    value["capability_receipts"] = selected.get("capability_receipts", [])
    value["provider_revocation"] = {"google": "https://myaccount.google.com/connections",
        "atlassian": "https://id.atlassian.com/manage-profile/apps"}
    return value


class CapabilityIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_revision: str = Field(min_length=1, max_length=128)
    capability: str = Field(min_length=1, max_length=80)
    resource: str = Field(min_length=1, max_length=256)
    confirm: bool = False


@router.post("/api/v1/connections/{name}/capability-check")
async def check_capability(request: Request, name: str, body: CapabilityIn):
    from maverick import connections
    from maverick.connection_capabilities import probe

    from .app import _require_same_origin
    from .request_identity import request_identity as _request_identity

    def authorize():
        _authority(request)
        if not body.confirm or not hmac.compare_digest(body.context, context_for(request)):
            raise HTTPException(409, "Review this read-only check in the current account and workspace.")
    authorize()
    _require_same_origin(request)
    try:
        return await run_in_threadpool(probe, name, body.capability, body.resource,
            actor=_request_identity(request), expected_revision=body.expected_revision, authorize=authorize)
    except connections.ConnectionVersionConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except (PermissionError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/api/v1/connections/qualification")
def qualification_matrix(request: Request):
    from maverick.connection_oauth import PROFILES

    require_permission(request, "operate")
    return {"context": context_for(request), "schema": 1, "rows": [
        {"profile": key, "label": value["label"], "surface": surface,
         "qualification": "not qualified", "synthetic": "tests authored; not executed for this audit",
         "native": "not observed", "live_provider": "not observed", "installed_build": None,
         "recovery": "Review provider app registration, permitted callback, and allowed provider hosts in Connections. Start a new consent only after the original attempt is cancelled or expired."}
        for key, value in PROFILES.items() for surface in ("browser return", "installed Windows return")],
        "note": "Designed support is not qualification. No installed Windows build or live-provider combination has observed acceptance evidence in this audit. Qualification requires separately observed native and provider acceptance evidence."}


@router.post("/api/v1/connections/{name}/replace-staged")
async def replace_staged(request: Request, name: str, body: ReviewedIn):
    from maverick import connections

    from .request_identity import request_identity as _request_identity

    _authority(request, body)
    def mutate():
        with connections._mutation_lock():
            require_review(request, name, body.expected_revision, body.impact_version, expected_context=body.context, rotation=True)
            return connections.replace_from_staged(name, body.replacement, owner=_request_identity(request),
                expected_revision=body.expected_revision, replacement_revision=body.replacement_revision)
    try:
        record = await run_in_threadpool(mutate)
    except connections.ConnectionVersionConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except (ValueError, PermissionError) as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"connection": record, "external_outcome": "unknown", "historical_actions_replayed": False,
            "next_action": "Review pinned sources and pending approvals before continuing. The staged record remains saved separately."}


@router.post("/api/v1/connections/{name}/rebind-source")
async def rebind_source(request: Request, name: str, body: RebindIn):
    from maverick import connections, privacy_discovery_credentials

    from .privacy_data_discovery_api import _actor_ref
    from .privacy_data_discovery_api import _authority as discovery_authority
    from .request_identity import request_identity as _request_identity

    _authority(request, body)
    require_global_permission(request, "admin")
    ops, tenant, store = discovery_authority(request)
    def mutate():
        with connections._mutation_lock(), connections.bind_principal(_request_identity(request)):
            review = require_review(request, name, body.expected_revision, body.impact_version, expected_context=body.context)
            if not any(item["kind"] == "discovery_source" and item["id"] == body.source_id and item["revision"] == body.source_revision for item in review["items"]):
                raise HTTPException(409, "This source changed. Review its current connection before rebinding.")
            if not any(row["name"] == body.replacement and row["revision"] == body.replacement_revision for row in owned_connections(request)):
                raise HTTPException(409, "Replacement account changed or is unavailable to its owner.")
            source = store.get_source(tenant, body.source_id)
            if source is None:
                raise HTTPException(404, "Source is unavailable.")
            reference = "connection:" + body.replacement + ":" + body.replacement_revision
            # Exact origin/provider and current caller grant are checked by the
            # same resolver used at source admission. No resource is scanned.
            privacy_discovery_credentials.resolve_connection(reference, provider=source.provider, origin=source.origin)
            return store.enroll_source(tenant, source_id=source.source_id, kind=source.kind,
                provider=source.provider, origin=source.origin, resource_ref=source.resource_ref,
                credential_env=reference, evidence_key_env=source.evidence_key_env,
                actor_ref=_actor_ref(request, tenant), expected_revision=body.source_revision,
                idempotency_key=body.operation_id)
    try:
        source = await run_in_threadpool(mutate)
    except (connections.ConnectionVersionConflict, ops.PrivacyDataDiscoveryConflict) as exc:
        raise HTTPException(409, "Source or connection changed. Review the repair again.") from exc
    except (ValueError, PermissionError) as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"source_id": source.source_id, "revision": source.revision, "rebound": True,
            "scan_started": False, "historical_actions_replayed": False,
            "next_action": "Review this source's schedules and run a source access check in Privacy scanning."}
