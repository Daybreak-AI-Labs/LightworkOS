"""Reviewed banner withdrawal and exact native accepted-request readback."""
from __future__ import annotations

import json
import math
import re
import secrets
import time

from fastapi import HTTPException
from maverick import config, consent_publishing, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.paths import current_tenant_id_strict

from . import auth
from . import consent_publishing_api as native
from .api_flow_operator_review import _workspace_authority
from .draft_api import context_for
from .tools_ops_api import actor, same_origin

PAGE = "/consent/publishing#cpp-withdrawal-original"
TTL = 600
NOTICE = "Stop serving this website or app's current banner from Lightwork. Its publishing history and people's recorded choices remain. Cached or separately hosted copies are not recalled, and this does not stop the site's own data collection. Restoring an older banner stays a separate reviewed action; versions from an earlier website or app configuration cannot be restored directly."


def context(request):
    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(409, "Choose a workspace before managing consent banners.")
    suites, scopes = auth.caller_suites(request), auth.api_key_scopes(request)
    return digest([context_for(request), _workspace_authority(request, actor(request), tenant), auth.caller_role(request),
                   sorted(suites) if suites is not None else None, sorted(scopes) if scopes is not None else None])


def authority(request, expected=None, *, write=False):
    auth.require_global_permission(request, "admin")
    current = context(request)
    if expected is not None and expected != current:
        raise HTTPException(409, "Your account, workspace or access changed. Refresh before reviewing private banner choices.")
    if write:
        same_origin(request)
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Current settings are unavailable. Nothing was withdrawn.")
        native._ops()
    return current


def _store():
    return GovernedRecordStore("consent-withdrawal-requests", "CWR", "consent_withdrawal_request")


def _publishing():
    return native._store(consent_publishing, current_tenant_id_strict())


def _call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except (consent_publishing.PublishingConflict, consent_publishing.PublishingIdempotencyConflict) as exc:
        raise HTTPException(409, "This banner or website changed. Review the current version; nothing was repeated.") from exc
    except consent_publishing.PublishingNotFound as exc:
        raise HTTPException(404, "This website or app is no longer available in the workspace.") from exc
    except (consent_publishing.ConsentPublishingError, OSError) as exc:
        raise HTTPException(503, "The native banner record could not be verified. Keep the original request and check it before a new decision.") from exc


def prepare(request, property_id, expected=None):
    current = authority(request, expected, write=True)
    source = _call(_publishing().withdrawal_preview, current_tenant_id_strict(), property_id)
    authority(request, current, write=True)
    return {"actor": actor(request), "owner": context_for(request), "context": current, "nonce": secrets.token_hex(16),
            "source": source, "expires": time.time() + TTL}


def changes(prepared):
    prop, head = prepared["source"]["property"], prepared["source"]["head"]
    return [{"label": "Website or app", "after": prop["property_id"].replace("-", " ").replace("_", " ")},
            {"label": "Current website or app configuration", "after": "Version " + str(prop["revision"])},
            {"label": "Complete current website addresses", "after": prop["web_domains"] or ["Not a website"]},
            {"label": "Complete permitted website origins", "after": prop["origin_allowlist"] or ["None"]},
            {"label": "Complete current app identities", "after": prop["mobile_bundle_ids"] or ["Not a mobile app"]},
            {"label": "Current banner", "after": "Already withdrawn" if head["action"] == "withdraw" else "Published version " + str(head["publication_revision"])},
            {"label": "Configuration used by this banner", "after": "Version " + str(head["property_revision"])},
            {"label": "What this changes", "after": NOTICE}]


def review(request, property_id, expected):
    prepared = prepare(request, property_id, expected)
    token = crypto_at_rest.seal_to_str(json.dumps({"purpose": "consent-withdrawal-review.v1", "value": prepared}, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(409, "Enable stored-data protection before reviewing this private banner change.")
    return {"context": prepared["context"], "operation": secrets.token_hex(16), "token": token, "changes": changes(prepared), "notice": NOTICE}


def opened(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if value["purpose"] != "consent-withdrawal-review.v1":
            raise ValueError
        return value["value"]
    except Exception as exc:
        raise HTTPException(409, "This private review cannot be verified. Review the current banner again.") from exc


def owned(request, operation, prepared=None):
    current = authority(request)
    if not isinstance(operation, str) or re.fullmatch(r"[a-f0-9]{32}", operation) is None:
        raise HTTPException(404, "This original banner request is unavailable.")
    row = _store().get("CWR-" + operation)
    if row and (row["actor"], row["owner"]) != (actor(request), context_for(request)):
        raise HTTPException(404, "This original banner request is unavailable to this account and workspace.")
    if row and prepared is not None and row["binding"] != digest(prepared):
        raise HTTPException(409, "This original request belongs to another complete banner review.")
    if row and row.get("_audit_pending"):
        row = _store()._flush(row)
    authority(request, current)
    return row


def _arguments(prepared, operation):
    source = prepared["source"]
    return {"expected_property_revision": source["property"]["revision"], "expected_publication_revision": source["head"]["publication_revision"],
            "idempotency_key": "CWR-" + operation, "receipt_owner": digest([prepared["actor"], prepared["owner"], operation, digest(prepared)])}


def original(request, operation, *, prepared=None):
    current = authority(request)
    row = owned(request, operation, prepared)
    result = {"context": current, "operation": operation, "confirmed": False,
              "message": "The original withdrawal is unconfirmed and will not repeat. Current absence or another person's withdrawal cannot confirm this request.", "notice": NOTICE}
    if row:
        value = opened(row["sealed_review"])
        accepted = _call(_publishing().withdrawal_original, current_tenant_id_strict(), value["source"]["property"]["property_id"], **_arguments(value, operation))
        confirmed = accepted is not None and not row.get("_audit_pending")
        result.update(confirmed=confirmed, website=row["website"], recorded_at=row["created_at"])
        if accepted is not None:
            receipt = accepted["withdrawal_receipt"]
            result.update(changed=receipt["changed"], accepted_at=receipt["recorded_at"], version=accepted["publication_revision"])
            result["message"] = ("Your exact original request withdrew the reviewed banner. Nothing was repeated." if receipt["changed"] else
                                 "Your exact original request recorded that the banner was already withdrawn. It did not withdraw another version.") if confirmed else "The native decision exists, but its activity record is still unconfirmed. Nothing was repeated."
        try:
            now = _call(_publishing().withdrawal_preview, current_tenant_id_strict(), value["source"]["property"]["property_id"])
            result["current"] = "Currently withdrawn" if now["head"]["action"] == "withdraw" else "A banner is currently published; this does not change the original decision."
        except HTTPException:
            result["current"] = "Current banner state is unavailable; it does not establish the original outcome."
    authority(request, current)
    return result


def catalog(request):
    current = authority(request)
    items, offset = [], 0
    while offset is not None:
        page = _call(_publishing().catalog, current_tenant_id_strict(), kind="property", offset=offset, limit=50)
        if page["total"] > 1000:
            raise HTTPException(409, "This complete selector supports up to one thousand websites and apps. No entries were omitted.")
        items.extend(page["items"])
        offset = page["next_offset"]
    rows = _store().list(limit=10001)
    if len(rows) > 10000:
        raise HTTPException(409, "The retained request limit was exceeded. No original entries were omitted.")
    rows = [row for row in rows if (row["actor"], row["owner"]) == (actor(request), context_for(request))]
    rows.sort(key=lambda row: (row["created_at"], row["id"]), reverse=True)
    authority(request, current)
    return {"context": current, "websites": [{"value": item["property_id"], "label": item["property_id"].replace("-", " ").replace("_", " ")} for item in items if item["publication_revision"]],
            "requests": [{"value": row["id"][4:], "label": row["website"] + " · " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))} for row in rows], "notice": NOTICE}


def apply(request, prepared, operation):
    # Read an existing original before fresh-review checks; never dispatch it again.
    if owned(request, operation, prepared):
        return original(request, operation, prepared=prepared)
    current = authority(request, prepared["context"], write=True)
    with authority_effect_fence():
        if owned(request, operation, prepared):
            return original(request, operation, prepared=prepared)

        def guard(prop, head):
            authority(request, current, write=True)
            expiry = prepared["expires"]
            if prepared["actor"] != actor(request) or prepared["owner"] != context_for(request) or type(expiry) not in {int, float} or not math.isfinite(expiry) or not time.time() < expiry <= time.time() + TTL:
                raise HTTPException(409, "This review expired or its owner changed. Review the current banner; nothing was withdrawn.")
            if prepared["source"] != {"property": prop, "head": {key: value for key, value in head.items() if key not in {"signature", "withdrawal_receipt"}}}:
                raise HTTPException(409, "The exact website settings or published banner changed. Review it again; nothing was withdrawn.")

        def reserve(prop, head):
            guard(prop, head)
            token = crypto_at_rest.seal_to_str(json.dumps({"purpose": "consent-withdrawal-review.v1", "value": prepared}, allow_nan=False, separators=(",", ":")))
            if not crypto_at_rest.is_sealed_str(token):
                raise HTTPException(409, "Stored-data protection is unavailable. Nothing was withdrawn.")
            saved = _store().create({"id": "CWR-" + operation, "actor": prepared["actor"], "owner": prepared["owner"],
                "binding": digest(prepared), "website": prepared["source"]["property"]["property_id"].replace("-", " ").replace("_", " "),
                "sealed_review": token}, action="consent.banner.withdraw.reviewed", actor=prepared["actor"], max_records=10000)
            if saved.get("_audit_pending"):
                raise HTTPException(503, "The reviewed activity record is unconfirmed. The original will not repeat; no banner was withdrawn.")
            guard(prop, head)

        _call(_publishing().withdraw, current_tenant_id_strict(), prepared["source"]["property"]["property_id"], before_write=reserve, **_arguments(prepared, operation))
        return original(request, operation, prepared=prepared)


def legacy(request, property_id, arguments):
    current = authority(request, write=True)
    with authority_effect_fence():
        return _call(_publishing().withdraw, current_tenant_id_strict(), property_id,
                     before_write=lambda _prop, _head: authority(request, current, write=True), **arguments)
