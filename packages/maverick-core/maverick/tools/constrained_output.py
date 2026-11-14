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

Returns ``PASS <coerced-value>`` or ``FAIL: <reason>``. Deterministic; no LLM.
"""
from __future__ import annotations

import math
import re
from typing import Any

from . import Tool

_TRUE = {"true", "1", "yes", "on"}
# The pattern and the value both come from the model, and ``re`` has no time
# limit: bound the text and refuse the pattern shapes that backtrack
# exponentially (a repeated group that itself contains a quantifier or an
# alternation, such as ``(a+)+$`` or ``(a|a)*$``).
_PATTERN_MAX_VALUE_LEN = 1000
_REPEAT_RE = re.compile(r"[*+]|\{\d*,?\d*\}")
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


def _skip_class(pat: str, i: int) -> int:
    """Index just past the character class that starts at ``pat[i] == '['``."""
    i += 1
    if i < len(pat) and pat[i] == "^":
        i += 1
    if i < len(pat) and pat[i] == "]":
        i += 1
    while i < len(pat) and pat[i] != "]":
        i += 2 if pat[i] == "\\" else 1
    return i + 1


def _backtracks_exponentially(pat: str) -> bool:
    """True if a repeated group contains a quantifier or an alternation."""
    stack: list[list[bool]] = []  # per open group: [has_quantifier, has_alternation]
    i = 0
    while i < len(pat):
        ch = pat[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            i = _skip_class(pat, i)
            continue
        if ch == "(":
            stack.append([False, False])
        elif ch == "|" and stack:
            stack[-1][1] = True
        elif ch == ")" and stack:
            has_q, has_alt = stack.pop()
            repeated = _REPEAT_RE.match(pat, i + 1) is not None
            if repeated and (has_q or has_alt):
                return True
            if stack and (has_q or repeated):
                stack[-1][0] = True
        elif stack and _REPEAT_RE.match(pat, i):
            stack[-1][0] = True
        i += 1
    return False


def _check_pattern(pat: Any, value: str) -> str | None:
    if not isinstance(pat, str):
        return "FAIL: pattern must be a string"
    if len(value) > _PATTERN_MAX_VALUE_LEN:
        return (f"FAIL: value longer than {_PATTERN_MAX_VALUE_LEN} characters "
                "cannot be checked against a pattern")
    if _backtracks_exponentially(pat):
        return (f"FAIL: pattern {pat!r} repeats a group that contains a "
                "quantifier or alternation; rewrite it without nesting")
    try:
        matched = re.search(pat, value)
    except re.error as e:
        return f"FAIL: invalid pattern {pat!r}: {e}"
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
            "the target type; returns 'PASS <value>' or 'FAIL: <reason>'."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
