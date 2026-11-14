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
when the pattern is invalid or is refused because it could backtrack
exponentially. Deterministic; no LLM.
"""
from __future__ import annotations

import math
import re
from typing import Any

from . import Tool

_TRUE = {"true", "1", "yes", "on"}
# The pattern and the value both come from the model, and ``re`` has no time
# limit: bound the text and refuse the pattern shapes that backtrack
# exponentially. Those are a group repeated without bound (``*``, ``+``,
# ``{n,}``) whose body contains a quantifier and has no delimiter that ends
# each repetition (``(a+)+$``), or whose alternatives can start with the same
# character (``(a|a)*$``); and a group repeated many times whose body is
# optional or quantified (``(a?){25}``). Delimited and bounded shapes such as
# ``(\d+\.){2}`` or ``([\w-]+\.)+`` are linear and allowed.
_PATTERN_MAX_VALUE_LEN = 1000
_QUANT_RE = re.compile(r"([*+?])|\{(\d*)(,?)(\d*)\}")
_MAX_BOUNDED_REPEAT = 10
_DELIM_END_RE = re.compile(r"(?:\\([^A-Za-z0-9])|([^\\\w.^$|()\[\]{}*+?]))$")
_WIDE_ATOM_RE = re.compile(r"(?<!\\)\.|\\[WSD]|\[\^")  # can match punctuation
_CLASS_RE = re.compile(r"\[(?:\\.|[^\]])*\]")
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


def _quantifier_at(pat: str, i: int) -> tuple[bool, int | None, int] | None:
    """(can_repeat_zero_times, max_count or None if unbounded, end index) for
    a quantifier starting at ``pat[i]``, or None. A lazy/possessive suffix is
    consumed with it."""
    m = _QUANT_RE.match(pat, i)
    if not m:
        return None
    end = m.end()
    if end < len(pat) and pat[end] in "?+":
        end += 1
    sym, lo, comma, hi = m.groups()
    if sym:
        return sym != "+", (1 if sym == "?" else None), end
    if not lo and not hi:
        return None  # a literal '{'
    low = int(lo or 0)
    if not comma:
        return low == 0, low, end
    return low == 0, (int(hi) if hi else None), end


def _strip_group_prefix(body: str) -> str:
    if body.startswith("?:"):
        return body[2:]
    if body.startswith("?P<") and ">" in body:
        return body[body.index(">") + 1:]
    return body


def _branches(body: str) -> list[str]:
    """Split a group body at its top-level '|'."""
    out, depth, i, last = [], 0, 0, 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            i = _skip_class(body, i)
            continue
        depth += (ch == "(") - (ch == ")")
        if ch == "|" and depth == 0:
            out.append(body[last:i])
            last = i + 1
        i += 1
    out.append(body[last:])
    return out


def _branches_overlap(body: str) -> bool:
    """True if two alternatives could start with the same character (or one
    starts with a class, wildcard, group or nothing, which we cannot tell)."""
    branches = _branches(body)
    if len(branches) < 2:
        return False
    firsts: set[str] = set()
    for b in branches:
        if not b or b[0] in ".[(" or (b[0] == "\\" and b[1:2].isalnum()):
            return True
        key = b[1:2] if b[0] == "\\" else b[0]
        if key in firsts:
            return True
        firsts.add(key)
    return False


def _delimited(body: str) -> bool:
    """True if the body ends with a literal punctuation character that nothing
    else in the body can match, so each repetition is unambiguous."""
    m = _DELIM_END_RE.search(body)
    if not m:
        return False
    delim = m.group(1) or m.group(2)
    head = body[: m.start()]
    if _WIDE_ATOM_RE.search(head):
        return False
    if delim.isspace() and "\\s" in head:
        return False
    return not any(delim in c for c in _CLASS_RE.findall(head))


def _group_problem(group: dict, body: str, rep: tuple | None) -> str | None:
    if rep is None:
        return None
    body = _strip_group_prefix(body)
    risky_body = group["quant"] or group["optional"]
    if rep[1] is None:
        if group["quant"] and not _delimited(body):
            return "repeats without bound a group that contains a quantifier"
        if _branches_overlap(body):
            return "repeats without bound an alternation whose branches can match the same text"
    elif rep[1] > _MAX_BOUNDED_REPEAT and risky_body and not _delimited(body):
        return "repeats many times a group that is optional or quantified"
    return None


def _pattern_problem(pat: str) -> str | None:
    """Why ``pat`` can backtrack exponentially, or None."""
    stack: list[dict] = []  # per open group: start index, has quantifier, has optional
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
            stack.append({"start": i, "quant": False, "optional": False})
            i += 2 if pat.startswith("(?", i) else 1
            continue
        rep = _quantifier_at(pat, i + 1 if ch == ")" else i)
        if ch == ")" and stack:
            group = stack.pop()
            problem = _group_problem(group, pat[group["start"] + 1:i], rep)
            if problem:
                return problem
            if stack:
                stack[-1]["quant"] |= group["quant"] or rep is not None
                stack[-1]["optional"] |= group["optional"] or bool(rep and rep[0])
            i = rep[2] if rep else i + 1
            continue
        if rep is not None:
            if stack:
                stack[-1]["quant"] = True
                stack[-1]["optional"] |= rep[0]
            i = rep[2]
            continue
        if ch == "|" and stack and (pat[i - 1] in "(|" or pat[i + 1:i + 2] in ("|", ")")):
            stack[-1]["optional"] = True  # an empty alternative matches nothing
        i += 1
    return None


def _check_pattern(pat: Any, value: str) -> str | None:
    if not isinstance(pat, str):
        return "ERROR: schema pattern must be a string"
    if len(value) > _PATTERN_MAX_VALUE_LEN:
        return (f"FAIL: value longer than {_PATTERN_MAX_VALUE_LEN} characters "
                "cannot be checked against a pattern")
    problem = _pattern_problem(pat)
    if problem:
        return (f"ERROR: schema pattern {pat!r} refused: it {problem}, which "
                "can backtrack exponentially; rewrite it")
    try:
        matched = re.search(pat, value)
    except re.error as e:
        return f"ERROR: schema pattern {pat!r} is invalid: {e}"
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
