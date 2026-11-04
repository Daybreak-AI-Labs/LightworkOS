"""Current request batches with private, authority-bound positions."""
from __future__ import annotations

import base64
import json
import math
import re
import time

from fastapi import HTTPException, Response
from maverick.crypto_at_rest import seal_bound, unseal_bound
from maverick.governed_operations import digest
from maverick.paths import data_dir, tenant_scope

from . import knowledge_access_api as native

VIEWS = {"active": "Active requests", "archive": "Finished archive", "ready": "Ready to archive"}
TTL = 600
MAX_TOKEN = 2048
_STALE = "This request page expired or its account, workspace or view changed. Start this view again."


def _purpose(tenant, actor, context, view, service, can_review=True):
    with tenant_scope(tenant=tenant):
        source = [str(data_dir()), service.request_store.namespace,
                  service.request_store.backend_kind, service.archive_store.namespace,
                  service.archive_store.backend_kind]
        # Backend resolution above revalidates each native persistence pin.
        # Include its non-secret DSN identity so a page from another database
        # cannot resume under otherwise equal account/workspace settings.
        for store in (service.request_store, service.archive_store):
            source.append(getattr(store._authority_token, "dsn_sha256", ""))
    return "lightwork.knowledge-request-page.v1:" + digest([tenant, actor, context, view, source, can_review])


def _position(token, purpose):
    if not token:
        return ""
    try:
        if (not isinstance(token, str) or len(token) > MAX_TOKEN
                or re.fullmatch(r"[A-Za-z0-9_-]+", token) is None):
            raise ValueError("invalid page")
        encoded = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(encoded).decode().rstrip("=") != token:
            raise ValueError("noncanonical page")
        value = json.loads(unseal_bound(encoded, context=purpose))
        if (not isinstance(value, dict) or set(value) != {"position", "expires_at"}
                or not isinstance(value["position"], str) or not 1 <= len(value["position"]) <= 128
                or isinstance(value["expires_at"], bool)
                or not isinstance(value["expires_at"], (int, float))
                or not math.isfinite(value["expires_at"])
                or not time.time() < value["expires_at"] <= time.time() + TTL + 1):
            raise ValueError("expired page")
        return value["position"]
    except Exception as exc:  # noqa: BLE001 - private positions and key failures are never disclosed
        raise HTTPException(409, _STALE) from exc


def _token(position, purpose):
    if position is None:
        return None
    material = json.dumps({"position": position, "expires_at": time.time() + TTL}, allow_nan=False).encode()
    try:
        return base64.urlsafe_b64encode(seal_bound(material, context=purpose)).decode().rstrip("=")
    except Exception as exc:  # noqa: BLE001 - never fall back to a plaintext position
        raise HTTPException(503, "Request pages could not be protected. Refresh this view later.") from exc


def browse(request, *, view="active", cursor="", limit=100):
    if view not in VIEWS or isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 250:
        raise HTTPException(422, "Choose a request view and a smaller batch.")
    can_review = native.has_global_permission(request, "admin")
    if view == "ready" and not can_review:
        raise HTTPException(403, "Administrator access is required for this view")
    tenant, actor, context = native._binding(request, Response(), administrator=can_review)
    service = native.call_native(native._service, request)
    purpose = native.call_native(_purpose, tenant, actor, context, view, service, can_review)
    position = _position(cursor, purpose)
    page = native.call_native(service.browse_requests, tenant, view=view, cursor=position, limit=limit,
                             actor=None if can_review else actor)
    capacity = native.call_native(service.request_capacity, tenant) if can_review else None
    # A slow source/hold projection must not escape an account or authority change.
    current_review = native.has_global_permission(request, "admin")
    current = native._binding(request, Response(), administrator=current_review)
    if (current_review != can_review or current != (tenant, actor, context)
            or native.call_native(_purpose, *current, view, service, current_review) != purpose):
        raise HTTPException(409, _STALE)
    return {"schema": "lightwork.knowledge-rights-requests.v1", "context": context,
            "items": page["items"], "count": len(page["items"]), "can_review": can_review,
            "archived": view == "archive", "ready_to_archive": view == "ready",
            "capacity": capacity, "next_cursor": _token(page["next_cursor"], purpose),
            "complete": page["complete"], "scanned": page["scanned"] if can_review else len(page["items"]), "view": view,
            "notice": "Batches follow the retained record order. Start over to include new requests before this batch. " +
                      ("Source restrictions and legal holds are checked again when each batch opens." if can_review else
                       "Only your own submissions and status are shown. Other employees' requests and administrative evidence are withheld.")}
