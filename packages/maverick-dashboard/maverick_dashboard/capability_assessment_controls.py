"""Current native specialist/workflow assessments for protected form handoffs."""
from __future__ import annotations

import json
import re

from fastapi import HTTPException
from maverick import assessments
from maverick.governed_operations import digest

from . import auth
from .draft_api import context_for

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BYTES = 262144


def authority(request, *, review=False):
    with auth.fresh_configuration():
        auth.require_permission(request, "audit")
        if review:
            auth.require_permission(request, "admin")
        return {"context": context_for(request), "role": auth.caller_role(request),
                "audit": auth.has_permission(request, "audit"),
                "admin": auth.has_permission(request, "admin")}


def selected(selection):
    if (not isinstance(selection, dict)
            or set(selection) != {"kind", "subject_kind", "subject"}
            or selection.get("kind") != "capability_assessment"
            or selection.get("subject_kind") not in {"agent", "flow"}
            or not isinstance(selection.get("subject"), str)
            or not 1 <= len(selection["subject"]) <= 256):
        raise HTTPException(422, "Choose an assessment from the current register first.")
    return selection["subject_kind"], selection["subject"]


def _record(kind, subject):
    try:
        value = assessments.get_assessment(kind, subject)
        if value is None:
            raise HTTPException(404, "This assessment is no longer in the current register.")
        revision = value.get("revision", 0)
        if (value.get("kind") != kind or value.get("subject") != subject
                or type(revision) is not int or not 0 <= revision <= 2**53 - 1
                or not isinstance(value.get("lenses"), dict)):
            raise ValueError("invalid current assessment")
        material = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(material.encode("utf-8")) > _MAX_BYTES:
            raise HTTPException(413, "This assessment is too large for the protected handoff. Open its full native register instead.")
        return value, digest(value)
    except HTTPException:
        raise
    except (ValueError, OSError, assessments.AssessmentRegisterError) as exc:
        raise HTTPException(503, "The current assessment could not be read. Your existing review is kept; try the native register again.") from exc


def current(request, kind, subject, *, review=False):
    selected({"kind": "capability_assessment", "subject_kind": kind, "subject": subject})
    before = authority(request, review=review)
    value, source = _record(kind, subject)
    _again, checked = _record(kind, subject)
    if source != checked or before != authority(request, review=review):
        raise HTTPException(409, "Your account, access or assessment changed while it was read. Check the current register again.")
    return {"context": before["context"], "kind": kind, "subject": subject,
            "revision": value.get("revision", 0), "source": source,
            "review_allowed": before["admin"], "record": value}


def read_selection(request, kind, subject, *, expected_context, expected_revision, expected_source, review=False):
    if not isinstance(expected_context, str) or not _HEX.fullmatch(expected_context):
        raise HTTPException(409, "Your account or workspace changed. Reopen the current assessment.")
    if authority(request, review=review)["context"] != expected_context:
        raise HTTPException(409, "Your account or workspace changed. Reopen the current assessment.")
    value = current(request, kind, subject, review=review)
    if (value["context"] != expected_context or value["revision"] != expected_revision
            or value["source"] != expected_source):
        raise HTTPException(409, "This assessment changed after you chose it. Your current work is kept; review its latest version.")
    return value
