"""Small, dependency-free JSON request limits for the standalone app."""
from __future__ import annotations

from request_boundary import PayloadError as PayloadError
from request_boundary import _declared_length as _declared_length
from request_boundary import _effective_port as _effective_port
from request_boundary import _validate_json_boundary as _validate_json_boundary
from request_boundary import read_bounded_object as _read_bounded_object

MAX_REQUEST_BYTES = 512 * 1024
MAX_DEPTH = 8
MAX_OBJECT_KEYS = 64
MAX_ARRAY_ITEMS = 512
MAX_STRING_BYTES = 256 * 1024
MAX_TOTAL_KEYS = 4096


def _validate_shape(value, *, depth: int = 0, counter: list[int] | None = None) -> None:
    if depth > MAX_DEPTH:
        raise PayloadError(f"JSON nesting exceeds {MAX_DEPTH} levels")
    if counter is None:
        counter = [0]
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_KEYS:
            raise PayloadError(f"JSON objects may contain at most {MAX_OBJECT_KEYS} keys")
        counter[0] += len(value)
        if counter[0] > MAX_TOTAL_KEYS:
            raise PayloadError(f"JSON payload may contain at most {MAX_TOTAL_KEYS} keys")
        for key, item in value.items():
            if len(str(key).encode("utf-8")) > 256:
                raise PayloadError("JSON object keys may not exceed 256 bytes")
            _validate_shape(item, depth=depth + 1, counter=counter)
    elif isinstance(value, list):
        if len(value) > MAX_ARRAY_ITEMS:
            raise PayloadError(f"JSON arrays may contain at most {MAX_ARRAY_ITEMS} items")
        for item in value:
            _validate_shape(item, depth=depth + 1, counter=counter)
    elif isinstance(value, str) and len(value.encode("utf-8")) > MAX_STRING_BYTES:
        raise PayloadError(f"JSON strings may not exceed {MAX_STRING_BYTES} bytes")


async def read_bounded_json(request):
    return await _read_bounded_object(
        request, max_bytes=MAX_REQUEST_BYTES, validate_boundary=_validate_json_boundary,
        validate_shape=_validate_shape, declared_length=_declared_length,
    )


def require_expected_revision(value: dict) -> int:
    if "expected_revision" not in value:
        raise PayloadError("expected_revision is required")
    revision = value["expected_revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise PayloadError("expected_revision must be a non-negative integer")
    return revision


__all__ = ["PayloadError", "read_bounded_json", "require_expected_revision"]
