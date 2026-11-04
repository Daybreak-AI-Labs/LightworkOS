"""Business errors shared by direct controls and governed operation adapters.

Messages must be authored customer copy, never ``str(exc)`` or provider text.
Callers validate access before including any record-specific recovery location.
The renderer treats all copy as text and permits only same-origin app links.
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from fastapi import HTTPException

SCHEMA = "lightwork.error.v1"


def _text(value: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError("Business error copy must be nonempty, bounded text")
    if any(ord(char) < 32 for char in value):
        raise ValueError("Business error copy cannot contain control characters")
    return value.strip()


def _validated_action(label: str, href: str) -> dict[str, str]:
    """Build a local recovery link after its caller has checked destination access."""
    label = _text(label, 120)
    href = _text(href, 1024)
    decoded = unquote(href)
    parsed = urlsplit(href)
    if (not href.startswith("/") or decoded.startswith("//") or "\\" in decoded
            or parsed.scheme or parsed.netloc or any(ord(char) < 32 for char in decoded)):
        raise ValueError("Recovery links must be same-origin application paths")
    return {"label": label, "href": href}


next_action = _validated_action


def error_detail(code: str, message: str, *, next_action: dict | None = None,
                 field_errors: dict[str, str] | None = None, retryable: bool = False) -> dict:
    """Stable wire envelope. Retryable never authorizes an automatic mutation retry."""
    if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", code):
        raise ValueError("Business error code is invalid")
    fields = {}
    for name, copy in (field_errors or {}).items():
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,79}", name):
            raise ValueError("Business error field name is invalid")
        fields[name] = _text(copy, 400)
    action = None
    if next_action is not None:
        action = _validated_action(next_action["label"], next_action["href"])
    return {"schema": SCHEMA, "code": code, "message": _text(message, 1200),
            "next_action": action, "field_errors": fields, "retryable": bool(retryable)}


def product_error(status_code: int, code: str, message: str, *,
                  next_action: dict | None = None, field_errors: dict[str, str] | None = None,
                  retryable: bool = False) -> HTTPException:
    return HTTPException(status_code=status_code, detail=error_detail(
        code, message, next_action=next_action, field_errors=field_errors, retryable=retryable))


def background_save(request) -> bool:
    """A page script saving a form in the background (``data-mv-save="background"``
    asks for ``Accept: application/json``): a refused value then comes back as
    a business error the script shows beside its field, instead of a page to
    load. A plain form post (or any other client) keeps its redirect."""
    accept = (request.headers.get("accept") or "").lower()
    return "application/json" in accept and "text/html" not in accept
