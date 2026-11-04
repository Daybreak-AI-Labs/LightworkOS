"""Bound and validate untrusted JSON before standalone threat detection."""
from __future__ import annotations

import json
import math

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
MAX_EVENTS = 256
MAX_EVENT_BYTES = 32 * 1024
MAX_EVENT_KEYS = 256
FORBIDDEN_RAW_KEYS = frozenset(
    {"raw", "raw_event", "raw_events", "raw_payload", "raw_telemetry"}
)


def _validate_shape(
    value,
    *,
    depth: int = 0,
    counter: list[int] | None = None,
    max_total_keys: int = MAX_TOTAL_KEYS,
) -> None:
    if depth > MAX_DEPTH:
        raise PayloadError(f"JSON nesting exceeds {MAX_DEPTH} levels")
    if counter is None:
        counter = [0]
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_KEYS:
            raise PayloadError(f"JSON objects may contain at most {MAX_OBJECT_KEYS} keys")
        counter[0] += len(value)
        if counter[0] > max_total_keys:
            raise PayloadError(f"JSON value may contain at most {max_total_keys} keys")
        for key, item in value.items():
            if len(str(key).encode("utf-8")) > 256:
                raise PayloadError("JSON object keys may not exceed 256 bytes")
            _validate_shape(
                item,
                depth=depth + 1,
                counter=counter,
                max_total_keys=max_total_keys,
            )
    elif isinstance(value, list):
        if len(value) > MAX_ARRAY_ITEMS:
            raise PayloadError(f"JSON arrays may contain at most {MAX_ARRAY_ITEMS} items")
        for item in value:
            _validate_shape(
                item,
                depth=depth + 1,
                counter=counter,
                max_total_keys=max_total_keys,
            )
    elif isinstance(value, str) and len(value.encode("utf-8")) > MAX_STRING_BYTES:
        raise PayloadError(f"JSON strings may not exceed {MAX_STRING_BYTES} bytes")


def reject_raw_fields(value) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).strip().lower() in FORBIDDEN_RAW_KEYS:
                raise PayloadError(f"field {key!r} is not accepted at this boundary")
            reject_raw_fields(item)
    elif isinstance(value, list):
        for item in value:
            reject_raw_fields(item)


def validate_events(events) -> list[dict]:
    if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
        raise PayloadError("events must be a list of objects")
    if len(events) > MAX_EVENTS:
        raise PayloadError(f"events may contain at most {MAX_EVENTS} items")
    for event in events:
        encoded = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_EVENT_BYTES:
            raise PayloadError(f"each event may contain at most {MAX_EVENT_BYTES} bytes")
        _validate_shape(event, counter=[0], max_total_keys=MAX_EVENT_KEYS)
        for field in ("budget_spend", "tool_novelty"):
            if field not in event:
                continue
            number = event[field]
            if (
                not isinstance(number, (int, float))
                or isinstance(number, bool)
                or not math.isfinite(float(number))
            ):
                raise PayloadError(f"event field {field!r} must be a finite JSON number")
        if "chain_valid" in event and not isinstance(event["chain_valid"], bool):
            raise PayloadError("event field 'chain_valid' must be a boolean")
    return events


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


__all__ = [
    "PayloadError",
    "read_bounded_json",
    "reject_raw_fields",
    "require_expected_revision",
    "validate_events",
]
