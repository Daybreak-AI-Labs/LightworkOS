"""Shared request-boundary primitives for standalone demos.

Edit this source, then regenerate independently packaged copies with
scripts/sync_standalone_support.py.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlsplit

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


@dataclass
class PayloadError(ValueError):
    detail: str
    status_code: int = 422

    def __str__(self) -> str:
        return self.detail


def _declared_length(request) -> int | None:
    value = request.headers.get("content-length")
    if value is None:
        return None
    try:
        length = int(value)
    except ValueError as exc:
        raise PayloadError("invalid Content-Length header") from exc
    if length < 0:
        raise PayloadError("invalid Content-Length header")
    return length


def _effective_port(scheme: str, port: int | None) -> int | None:
    if port is not None:
        return port
    return 443 if scheme == "https" else 80 if scheme == "http" else None


def _validate_json_boundary(request) -> None:
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise PayloadError("Content-Type must be application/json", status_code=415)
    origin = request.headers.get("origin")
    if origin is None:
        return
    parsed = urlsplit(origin)
    request_host = (request.url.hostname or "").lower()
    origin_host = (parsed.hostname or "").lower()
    try:
        origin_port = parsed.port
        request_port = request.url.port
    except ValueError as exc:
        raise PayloadError("browser Origin has an invalid port", status_code=403) from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.scheme != request.url.scheme
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or bool(parsed.query or parsed.fragment)
        or request_host not in _LOOPBACK_HOSTS
        or origin_host not in _LOOPBACK_HOSTS
        or _effective_port(parsed.scheme, origin_port)
        != _effective_port(request.url.scheme, request_port)
    ):
        raise PayloadError("browser requests must use the same loopback origin", status_code=403)


async def read_bounded_object(request, *, max_bytes, validate_boundary, validate_shape, declared_length=_declared_length):
    """Validate the origin and stream a bounded JSON object, without buffering excess."""
    validate_boundary(request)
    declared = declared_length(request)
    if declared is not None and declared > max_bytes:
        raise PayloadError(f"request body exceeds {max_bytes} bytes", status_code=413)
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > max_bytes:
            raise PayloadError(f"request body exceeds {max_bytes} bytes", status_code=413)
        raw.extend(chunk)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PayloadError("request body must be valid JSON") from exc
    validate_shape(value)
    if not isinstance(value, dict):
        raise PayloadError("request body must be a JSON object")
    return value
