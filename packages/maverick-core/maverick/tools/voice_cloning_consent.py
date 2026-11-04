"""Voice-cloning consent gate.

Decide whether a voice-clone operation is permitted for a given subject. A
clone is only allowed when the subject has *granted* consent, the requested
scope is covered by the granted scope, and the consent has not expired.
Deterministic and offline: the caller supplies the recorded consent, the scope
being requested, and today's date; this returns ALLOW / DENY. Deny by default —
a missing, ungranted, mis-scoped, or expired consent never authorises a clone.

ops:
  - check(consent, requested_scope, today_iso)

``consent`` is ``{"subject", "granted": bool, "scope", "expires_iso"?}`` where
``scope`` is a single scope string or a list of scope strings. ``"*"`` (or
``"all"``) in the granted scope matches any requested scope.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Any

from . import Tool


def _parse_date(value: Any) -> date | None:
    """Parse an ISO date / datetime string into a date; None if unparseable."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        return date.fromisoformat(text)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _granted_scopes(scope: Any) -> set[str]:
    if isinstance(scope, str):
        items = [scope]
    elif isinstance(scope, list):
        items = scope
    else:
        items = []
    return {str(s).strip().lower() for s in items if str(s).strip()}


def _check(args: dict[str, Any]) -> str:
    consent = args.get("consent")
    if not isinstance(consent, dict):
        return "ERROR: consent (object) is required"
    requested = str(args.get("requested_scope") or "").strip().lower()
    if not requested:
        return "ERROR: requested_scope is required"
    today = _parse_date(args.get("today_iso"))
    if today is None:
        return "ERROR: today_iso (YYYY-MM-DD) is required"

    subject = str(consent.get("subject") or "").strip() or "<unknown>"

    # Deny by default: only a real boolean True grants. A stringy "false" is
    # truthy in Python, so anything that isn't True fails closed.
    if consent.get("granted") is not True:
        return f"DENY {subject}: consent not granted"

    granted = _granted_scopes(consent.get("scope"))
    if not (requested in granted or "*" in granted or "all" in granted):
        return f"DENY {subject}: requested scope {requested!r} not in granted scope"

    expires_raw = consent.get("expires_iso")
    if expires_raw not in (None, ""):
        expires = _parse_date(expires_raw)
        if expires is None:
            return f"DENY {subject}: unparseable expires_iso {expires_raw!r}"
        if today > expires:
            return f"DENY {subject}: consent expired on {expires.isoformat()}"

    return f"ALLOW {subject}: scope {requested!r} granted and current"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    return _check(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "consent": {
            "type": "object",
            "description": "recorded consent for the subject's voice",
            "properties": {
                "subject": {"type": "string"},
                "granted": {"type": "boolean"},
                "scope": {
                    "description": "granted scope string or list of strings",
                    "type": ["string", "array"],
                    "items": {"type": "string"},
                },
                "expires_iso": {"type": "string", "description": "YYYY-MM-DD"},
            },
            "required": ["subject", "granted", "scope"],
        },
        "requested_scope": {"type": "string"},
        "today_iso": {"type": "string", "description": "YYYY-MM-DD"},
    },
    "required": ["consent", "requested_scope", "today_iso"],
}


def voice_cloning_consent() -> Tool:
    return Tool(
        name="voice_cloning_consent",
        description=(
            "Gate a voice-clone operation on recorded consent. op=check with "
            "'consent' ({subject, granted, scope, expires_iso?}), "
            "'requested_scope', and 'today_iso'. Returns ALLOW only when consent "
            "is granted, the requested scope is covered (or scope is '*'/'all'), "
            "and it has not expired; otherwise DENY. Deny by default; offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
