"""Bound and validate untrusted JSON for the local Model Risk Officer."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from request_boundary import PayloadError as PayloadError
from request_boundary import _declared_length as _declared_length
from request_boundary import read_bounded_object as _read_bounded_object

MAX_REQUEST_BYTES = 768 * 1024
MAX_DEPTH = 14
MAX_OBJECT_KEYS = 4_096
MAX_ARRAY_ITEMS = 8_192
MAX_TOTAL_VALUES = 60_000
MAX_STRING_BYTES = 64 * 1024
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|access[_-]?token|authorization|credential|api[_-]?key|"
    r"private[_-]?key|cookie|secret|prompt|messages?|completion|tool[_-]?(?:argument|"
    r"result|call)|request[_-]?body|response[_-]?body|raw(?:_|$)|payload|content)",
    re.IGNORECASE,
)


def _port(scheme: str, value: int | None) -> int | None:
    if value is not None:
        return value
    return 443 if scheme == "https" else 80 if scheme == "http" else None


def _validate_boundary(request) -> None:
    media_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
    if media_type != "application/json":
        raise PayloadError("Content-Type must be application/json", 415)
    origin = request.headers.get("origin")
    if origin is None:
        return
    parsed = urlsplit(origin)
    try:
        origin_port = parsed.port
        request_port = request.url.port
    except ValueError as exc:
        raise PayloadError("browser Origin has an invalid port", 403) from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.scheme != request.url.scheme
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (parsed.hostname or "").lower() not in _LOOPBACK_HOSTS
        or (request.url.hostname or "").lower() not in _LOOPBACK_HOSTS
        or _port(parsed.scheme, origin_port) != _port(request.url.scheme, request_port)
    ):
        raise PayloadError("browser requests must use the same loopback origin", 403)


def _validate_shape(value, depth: int = 0, counter: list[int] | None = None) -> None:
    if depth > MAX_DEPTH:
        raise PayloadError(f"JSON nesting exceeds {MAX_DEPTH} levels")
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_TOTAL_VALUES:
        raise PayloadError("JSON body contains too many values")
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_KEYS:
            raise PayloadError(f"JSON objects may contain at most {MAX_OBJECT_KEYS} keys")
        for key, item in value.items():
            if not isinstance(key, str) or len(key.encode("utf-8")) > 512:
                raise PayloadError("JSON object keys must be bounded strings")
            _validate_shape(item, depth + 1, counter)
    elif isinstance(value, list):
        if len(value) > MAX_ARRAY_ITEMS:
            raise PayloadError(f"JSON arrays may contain at most {MAX_ARRAY_ITEMS} items")
        for item in value:
            _validate_shape(item, depth + 1, counter)
    elif isinstance(value, str) and len(value.encode("utf-8")) > MAX_STRING_BYTES:
        raise PayloadError(f"JSON strings may not exceed {MAX_STRING_BYTES} bytes")


def reject_sensitive_fields(value) -> None:
    """Reject key shapes that invite secrets or raw model/tool content."""
    if isinstance(value, dict):
        for key, item in value.items():
            if _SENSITIVE_KEY.search(str(key)):
                raise PayloadError(f"sensitive or raw field is not accepted: {key}")
            reject_sensitive_fields(item)
    elif isinstance(value, list):
        for item in value:
            reject_sensitive_fields(item)


async def read_bounded_json(request) -> dict:
    return await _read_bounded_object(
        request, max_bytes=MAX_REQUEST_BYTES, validate_boundary=_validate_boundary,
        validate_shape=_validate_shape, declared_length=_declared_length,
    )


def require_expected_revision(value: dict) -> int:
    revision = value.get("expected_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise PayloadError("expected_revision must be a non-negative integer")
    return revision


__all__ = [
    "MAX_REQUEST_BYTES",
    "PayloadError",
    "read_bounded_json",
    "reject_sensitive_fields",
    "require_expected_revision",
]
