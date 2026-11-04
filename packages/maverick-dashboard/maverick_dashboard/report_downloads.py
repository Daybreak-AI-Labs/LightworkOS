"""Current-account file offers through the existing native report readers."""
from __future__ import annotations

import hmac
import re

from fastapi import HTTPException

from . import auth
from ._request_memo import fresh_configuration
from .draft_api import context_for

HEADER = "X-Lightwork-Report-Context"
KEY_HEADER = "X-Lightwork-Public-Key-Revision"
MAX_BYTES = 8 * 1024 * 1024
REPORTS = {
    "soc2": ("SOC 2 snapshot", "admin", "/compliance#cmp-reports", "lightwork-soc2-snapshot.json", "application/json"),
    "ai_inventory": ("AI inventory list", "admin", "/compliance#cmp-reports", "lightwork-ai-inventory.cdx.json", "application/json"),
    "oscal": ("Assessment results", "operate", "/compliance#cmp-reports", "lightwork-assessment-results.oscal.json", "application/json"),
    "soa": ("Statement of Applicability", "operate", "/compliance#cmp-reports", "lightwork-statement-of-applicability.md", "text/markdown"),
    "public_key": ("Public consent signing key", "operate", "/consent/publishing#cpp-signing", "lightwork-consent-public-key.json", "application/json"),
}


def capture(request, kind, expected=None):
    """Legacy callers stay compatible; protected controls bind their account."""
    if kind not in REPORTS:
        raise HTTPException(422, "Choose a report from the download controls.")
    with fresh_configuration():
        auth.require_permission(request, REPORTS[kind][1])
        current = context_for(request)
    expected = request.headers.get(HEADER) if expected is None else expected
    if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected) or not hmac.compare_digest(current, expected)):
        raise HTTPException(409, "Your account or workspace changed. Reload this page before downloading private information.")
    return current


def finish(request, kind, context, response):
    """Recheck authority after native collection, before releasing the bytes."""
    capture(request, kind, context)
    if len(response.body) > MAX_BYTES:
        raise HTTPException(413, "This report is too large for the protected browser download. Narrow its source before trying again; no file was offered.")
    response.headers[HEADER] = context
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"
    return response


def public_key_revision(key):
    from maverick.governed_operations import digest

    return digest(key) if key is not None else ""


def current_public_key():
    from .consent_publication_signing_api import _tenant_id, key_state

    with fresh_configuration():
        return key_state(_tenant_id())["key"]


def catalog(request):
    from maverick.paths import current_tenant_id_strict

    auth.require_permission(request, "view")
    context = context_for(request)
    choices = [{"value": key, "label": row[0], "href": row[2], "filename": row[3], "type": row[4]}
               for key, row in REPORTS.items() if auth.has_permission(request, row[1])
               and (key != "public_key" or current_tenant_id_strict() is not None)]
    for row in choices:
        if row["value"] == "public_key":
            row["revision"] = public_key_revision(current_public_key())
    with fresh_configuration():
        auth.require_permission(request, "view")
        if context_for(request) != context:
            raise HTTPException(409, "Your account or workspace changed. Reload before choosing a report.")
    return {"context": context, "choices": choices, "max_bytes": MAX_BYTES}
