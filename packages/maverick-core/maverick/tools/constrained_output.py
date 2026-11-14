"""Constrained-generation guard tool.

The pragmatic, model-agnostic half of "constrained generation": validate (and
where safe, coerce) a candidate value against a compact constraint spec before
it's accepted. Use it to gate an LLM's free-text answer down to a typed,
enum'd, ranged, or regex-shaped value — failing closed with a precise reason
the model can act on, instead of silently passing malformed output downstream.

ops:
  - check(value, schema)  — validate/coerce. schema keys: type (string|integer|
                            number|boolean), enum, pattern (regex), minimum,
                            maximum, min_length, max_length.

Returns ``PASS <coerced-value>`` or ``FAIL: <reason>``, or ``ERROR: schema ...``
when the pattern is invalid, longer than 1,000 characters, or takes more than
a second to evaluate (it runs in a separate, killable process). Deterministic;
no LLM.
"""
from __future__ import annotations

import math
from typing import Any

from . import Tool
from ._regex_guard import PatternInvalid, PatternTimeout, RegexGuardError, guarded_search

_TRUE = {"true", "1", "yes", "on"}
# The pattern and the value both come from the model, and ``re`` has no time
# limit. A pattern with a quantifier is evaluated in a separate interpreter
# that is killed after _PATTERN_TIMEOUT_S (see _regex_guard), and the value is
# bounded.
_PATTERN_MAX_VALUE_LEN = 1000
_PATTERN_TIMEOUT_S = 1.0
_FALSE = {"false", "0", "no", "off"}


def _coerce(value: Any, typ: str) -> tuple[bool, Any, str]:
    """Return (ok, coerced, reason). Strings are coerced toward the target type."""
    if typ == "string":
        return True, value if isinstance(value, str) else str(value), ""
    if typ == "boolean":
        if isinstance(value, bool):
            return True, value, ""
        s = str(value).strip().lower()
        if s in _TRUE:
            return True, True, ""
        if s in _FALSE:
            return True, False, ""
        return False, None, f"{value!r} is not a boolean"
    if typ in ("integer", "number"):
        if isinstance(value, bool):
            return False, None, "boolean is not a number"
        what = "an integer" if typ == "integer" else "a number"
        try:
            num = float(value) if typ == "number" or isinstance(value, float) else int(value)
        except (TypeError, ValueError, OverflowError):
            return False, None, f"{value!r} is not {what}"
        if isinstance(num, float) and not math.isfinite(num):
            return False, None, f"{value!r} is not {'an integer' if typ == 'integer' else 'a finite number'}"
        if typ == "integer" and isinstance(num, float):
            if not num.is_integer():
                return False, None, f"{value!r} is not {what}"
            num = int(num)
        return True, num, ""
    return False, None, f"unknown type {typ!r}"


def _check_pattern(pat: Any, value: str) -> str | None:
    if not isinstance(pat, str):
        return "ERROR: schema pattern must be a string"
    if len(value) > _PATTERN_MAX_VALUE_LEN:
        return (f"FAIL: value longer than {_PATTERN_MAX_VALUE_LEN} characters "
                "cannot be checked against a pattern")
    try:
        matched = guarded_search(pat, value, timeout_s=_PATTERN_TIMEOUT_S)
    except PatternInvalid as e:
        return f"ERROR: schema pattern {pat!r} is invalid: {e}"
    except PatternTimeout:
        return (f"ERROR: schema pattern {pat!r} took too long to evaluate "
                f"(over {_PATTERN_TIMEOUT_S:g}s); rewrite it")
    except RegexGuardError as e:
        return f"ERROR: schema pattern {pat!r} could not be evaluated: {e}"
    if not matched:
        return f"FAIL: {value!r} does not match pattern {pat!r}"
    return None


def _check(value: Any, schema: dict) -> str:
    typ = schema.get("type")
    if typ:
        ok, value, reason = _coerce(value, typ)
        if not ok:
            return f"FAIL: {reason}"

    if "enum" in schema:
        allowed = schema["enum"]
        if not isinstance(allowed, list):
            return "FAIL: enum must be a list"
        if value not in allowed:
            return f"FAIL: {value!r} not in enum {allowed}"

    if isinstance(value, str):
        pat = schema.get("pattern")
        if pat:
            failure = _check_pattern(pat, value)
            if failure:
                return failure
        if "min_length" in schema and len(value) < schema["min_length"]:
            return f"FAIL: length {len(value)} < min_length {schema['min_length']}"
        if "max_length" in schema and len(value) > schema["max_length"]:
            return f"FAIL: length {len(value)} > max_length {schema['max_length']}"

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            return f"FAIL: {value} < minimum {schema['minimum']}"
        if "maximum" in schema and value > schema["maximum"]:
            return f"FAIL: {value} > maximum {schema['maximum']}"

    return f"PASS {value!r}"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    if "value" not in args:
        return "ERROR: value is required"
    schema = args.get("schema")
    if not isinstance(schema, dict) or not schema:
        return "ERROR: schema (object) is required"
    try:
        return _check(args.get("value"), schema)
    except Exception as e:  # pragma: no cover - defensive
        return f"FAIL: validation error: {type(e).__name__}: {e}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "value": {"description": "the candidate value to validate/coerce"},
        "schema": {
            "type": "object",
            "description": "constraints: type, enum, pattern, minimum, maximum, "
                           "min_length, max_length",
        },
    },
    "required": ["value", "schema"],
}


def constrained_output() -> Tool:
    return Tool(
        name="constrained_output",
        description=(
            "Constrain a candidate value to a typed/enum'd/ranged/regex shape "
            "before accepting it (the guard half of constrained generation). "
            "op=check with a 'value' and a 'schema' (type, enum, pattern, "
            "minimum, maximum, min_length, max_length). Coerces strings toward "
            "the target type; returns 'PASS <value>' or 'FAIL: <reason>', or "
            "'ERROR: schema pattern ...' when the pattern is invalid, over "
            "1,000 characters, or takes over 1s to evaluate. Pattern checks "
            "apply to values up to 1,000 characters."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
