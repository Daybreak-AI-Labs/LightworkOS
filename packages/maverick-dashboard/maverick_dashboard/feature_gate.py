"""Tell "this feature is turned off" apart from "you may not do this".

Both arrive as a 403, and a page that cannot tell them apart tells an
administrator they lack permission when the feature is simply off. A refusal
because a feature is off carries response headers that say so:

* ``X-Lightwork-Reason: feature-off`` -- the stable machine-readable reason;
* ``X-Lightwork-Feature`` -- the feature's settings section, when known;
* ``X-Lightwork-Feature-Label`` -- its name for people (percent-encoded);
* ``X-Lightwork-Feature-Switch: module`` -- it can be turned on in the app
  (``POST /api/v1/features/modules``), so a page may offer "Turn on".

New gates raise :func:`feature_off`. Older gates raise a plain 403 whose text
says the feature is disabled; :func:`refusal_headers` recognises those in the
app's error handler, so every gated module answers the same way. The body is
never changed.
"""
from __future__ import annotations

import re
from urllib.parse import quote

from fastapi import HTTPException

REASON_HEADER = "X-Lightwork-Reason"
FEATURE_HEADER = "X-Lightwork-Feature"
LABEL_HEADER = "X-Lightwork-Feature-Label"
SWITCH_HEADER = "X-Lightwork-Feature-Switch"
FEATURE_OFF = "feature-off"

_OFF_TEXT = re.compile(
    r"\b(?:is|are) (?:turned off|disabled|off|not enabled)\b|\bisn't enabled\b|"
    r"\baren't enabled\b|\bdisabled in Settings\b|\b[a-z0-9]+(?:_[a-z0-9]+)*_disabled\Z|\Adisabled\Z",
    re.IGNORECASE,
)
# Refusals that mention a switch but are about the person, not the feature.
_NOT_A_SWITCH = re.compile(r"\bfor your role\b|\bnot allowed for you\b", re.IGNORECASE)
_SECTION_IN_TEXT = re.compile(r"\(\[([a-z0-9_.]+)\] enable\)")
_SECTION_CODE = re.compile(r"\A([a-z0-9_]+)_disabled\Z")
_SECTION_SUBJECT = re.compile(r"\A([a-z0-9_.]+) is not enabled\Z")


def _switches() -> dict:
    from .module_activation import _MODULE_SWITCHES

    return _MODULE_SWITCHES


def headers_for(section: str = "", label: str = "") -> dict[str, str]:
    """The response headers for a refusal because ``section`` is off."""
    meta = _switches().get(section) if section else None
    label = label or (meta or {}).get("label", "")
    headers = {REASON_HEADER: FEATURE_OFF}
    if section:
        headers[FEATURE_HEADER] = section
    if label:
        headers[LABEL_HEADER] = quote(label, safe=" ")
    if meta is not None:
        headers[SWITCH_HEADER] = "module"
    return headers


def feature_off(section: str, label: str = "", *, detail: str = "") -> HTTPException:
    """A 403 saying ``section`` is turned off, never "no permission"."""
    headers = headers_for(section, label)
    name = label or (_switches().get(section) or {}).get("label", "") or "This feature"
    return HTTPException(status_code=403, detail=detail or f"{name} is turned off.",
                         headers=headers)


def refusal_headers(detail: object) -> dict[str, str]:
    """Headers for an older 403 whose text says a feature is off; ``{}``
    when the text is about the person (role, sign-in, ownership)."""
    if isinstance(detail, dict):
        detail = detail.get("code") or ""
    if not isinstance(detail, str) or not detail or _NOT_A_SWITCH.search(detail):
        return {}
    if not _OFF_TEXT.search(detail):
        return {}
    for pattern in (_SECTION_IN_TEXT, _SECTION_CODE, _SECTION_SUBJECT):
        match = pattern.search(detail)
        if match:
            return headers_for(match.group(1))
    return headers_for()


__all__ = [
    "FEATURE_HEADER", "FEATURE_OFF", "LABEL_HEADER", "REASON_HEADER", "SWITCH_HEADER",
    "feature_off", "headers_for", "refusal_headers",
]
