"""Semantic-version constraint checker.

Decides whether a semver version satisfies a constraint expression — the check
behind a dependency-pinning or upgrade-gating policy. Supports comparator sets
(``>=1.2.0,<2.0.0``), caret (``^1.2.3``) and tilde (``~1.2.3``) ranges, exact
pins, and ``*`` (any). Comparisons follow semver precedence, including
prerelease ordering, while excluding prereleases at a final-release upper
bound unless the bound explicitly names a prerelease. Pure parsing/comparison —
deterministic and offline.

ops:
  - check(version, constraint)  — reports SATISFIED or UNSATISFIED (with the
    failing comparator).
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

# Numeric components are bounded to 18 digits: a real semver number never
# approaches this, and an unbounded \d+ lets a multi-thousand-digit string reach
# int() and trip CPython's int_max_str_digits ValueError (DoS on model input).
_CORE = re.compile(
    r"^(\d{1,18})(?:\.(\d{1,18}))?(?:\.(\d{1,18}))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


def _parse(v: str):
    """Return (major, minor, patch, prerelease_ids) or None if unparseable."""
    m = _CORE.match(v.strip())
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) is not None else 0
    patch = int(m.group(3)) if m.group(3) is not None else 0
    pre = tuple(m.group(4).split(".")) if m.group(4) else ()
    return (major, minor, patch, pre)


def _cmp_pre(a: tuple, b: tuple) -> int:
    # No prerelease ranks higher than any prerelease.
    if not a and not b:
        return 0
    if not a:
        return 1
    if not b:
        return -1
    for x, y in zip(a, b, strict=False):
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            # Compare numerically without int() — an unbounded prerelease digit
            # run would trip CPython's int_max_str_digits limit. Strip leading
            # zeros, then longer = larger; equal length compares lexically.
            xs, ys = x.lstrip("0") or "0", y.lstrip("0") or "0"
            if len(xs) != len(ys):
                return -1 if len(xs) < len(ys) else 1
            if xs != ys:
                return -1 if xs < ys else 1
        elif xn != yn:
            return -1 if xn else 1  # numeric identifiers are lower than alphanumeric
        elif x != y:
            return -1 if x < y else 1
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    return 0


def _cmp(a: tuple, b: tuple) -> int:
    for x, y in zip(a[:3], b[:3], strict=False):
        if x != y:
            return -1 if x < y else 1
    return _cmp_pre(a[3], b[3])


def _expand(token: str) -> list[tuple[str, tuple]] | str:
    """Expand one constraint token into [(op, version), ...] or an error string."""
    token = token.strip()
    if token in ("", "*", "x", "X"):
        return []  # matches anything

    for prefix in ("^", "~"):
        if token.startswith(prefix):
            base = _parse(token[1:])
            if base is None:
                return f"ERROR: bad version in {token!r}"
            major, minor, patch, _ = base
            lower = (major, minor, patch, ())
            if prefix == "^":
                if major > 0:
                    upper = (major + 1, 0, 0, ())
                elif minor > 0:
                    upper = (0, minor + 1, 0, ())
                else:
                    upper = (0, 0, patch + 1, ())
            else:  # tilde: allow patch-level changes
                upper = (major, minor + 1, 0, ())
            return [(">=", lower), ("<", upper)]

    m = re.match(r"^(>=|<=|>|<|==|=|!=)?\s*(.+)$", token)
    if not m:
        return f"ERROR: bad comparator {token!r}"
    op = m.group(1) or "=="
    if op == "=":
        op = "=="
    ver = _parse(m.group(2))
    if ver is None:
        return f"ERROR: bad version in {token!r}"
    return [(op, ver)]


def _is_prerelease_at_final_upper_bound(version: tuple, target: tuple) -> bool:
    return bool(version[3]) and not target[3] and version[:3] == target[:3]


def _satisfies(version: tuple, op: str, target: tuple) -> bool:
    if op == "<" and _is_prerelease_at_final_upper_bound(version, target):
        return False
    c = _cmp(version, target)
    return {
        ">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0,
        "==": c == 0, "!=": c != 0,
    }[op]


def _check(version_str: str, constraint: str) -> str:
    version = _parse(version_str)
    if version is None:
        return f"ERROR: version is not valid semver: {version_str!r}"

    tokens = [t for t in re.split(r"[,\s]+", constraint.strip()) if t]
    comparators: list[tuple[str, tuple]] = []
    for tok in tokens:
        expanded = _expand(tok)
        if isinstance(expanded, str):
            return expanded
        comparators.extend(expanded)

    for op, target in comparators:
        if not _satisfies(version, op, target):
            tv = ".".join(map(str, target[:3])) + ("-" + ".".join(target[3]) if target[3] else "")
            return f"UNSATISFIED: {version_str} fails {op}{tv} (in {constraint!r})"
    return f"SATISFIED: {version_str} matches {constraint!r}"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    version = args.get("version")
    if not isinstance(version, str) or not version:
        return "ERROR: version must be a non-empty string"
    constraint = args.get("constraint")
    if not isinstance(constraint, str):
        return "ERROR: constraint must be a string"
    return _check(version, constraint)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "version": {"type": "string", "description": "the semver version, e.g. 1.4.2 or 2.0.0-rc.1"},
        "constraint": {"type": "string", "description": "constraint, e.g. '>=1.2,<2', '^1.4.0', '~1.4', '*'"},
    },
    "required": ["version", "constraint"],
}


def semver_check() -> Tool:
    return Tool(
        name="semver_check",
        description=(
            "Check whether a semver version satisfies a constraint. op=check with "
            "'version' and 'constraint'. Supports comparator sets ('>=1.2,<2'), "
            "caret ('^1.2.3'), tilde ('~1.2.3'), exact pins, and '*'; follows "
            "semver precedence but excludes prereleases at final-release upper "
            "bounds unless explicitly named. Reports SATISFIED or UNSATISFIED "
            "with the failing comparator. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
