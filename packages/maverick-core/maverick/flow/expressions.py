"""Bounded, non-evaluating expressions for workflow data and routing."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from .run_events import FlowCredentialRefused

_COND = re.compile(r"^\s*(\S+)\s*(==|!=|>=|<=|>|<|contains)\s*(.+?)\s*$")
_FN_CALL = re.compile(r"^([a-zA-Z_]\w*)\s*\((.*)\)$")


def render(text: str, data: dict, *, allow_secrets: bool = False) -> str:
    """Substitute ``{{expr}}`` from ``data``. ``expr`` is a dotted key
    (``{{a.b}}``) or a transform call over keys/literals (``{{upper(name)}}``,
    ``{{default(x, "n/a")}}``, ``{{concat(first, " ", last)}}``). An unfilled bare
    key stays literal (unchanged); a function always resolves (missing args are
    empty).

    ``allow_secrets`` is retained for caller compatibility, but never grants
    deployment-secret access. Legacy secret expressions in action parameters
    are refused. Native connectors resolve their own scoped credentials after
    authorization, without putting raw credentials in arbitrary parameters.
    """
    src = str(text)
    out: list[str] = []
    pos = 0
    while True:
        start = src.find("{{", pos)
        if start < 0:
            out.append(src[pos:])
            break
        end = src.find("}}", start + 2)
        if end < 0:
            out.append(src[pos:])
            break
        out.append(src[pos:start])
        raw = src[start:end + 2]
        expr = src[start + 2:end].strip()
        v = _eval_expr(expr, data, allow_secrets=allow_secrets)
        out.append(raw if v is None else _as_text(v))
        pos = end + 2
    return "".join(out)


def _as_text(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))          # render add(2,3) as "5", not "5.0"
    return str(v)


def _num(x: Any) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def _fn_slice(a: list) -> Any:
    """slice(value, start[, end]) -- substring or sublist. Missing end = to the
    end. Works on a string or a list; out-of-range indices clamp like Python."""
    if not a:
        return ""
    seq = a[0]
    if not isinstance(seq, (str, list, tuple)):
        seq = _as_text(seq)
    start = int(_num(a[1])) if len(a) > 1 else 0
    end = int(_num(a[2])) if len(a) > 2 else len(seq)
    return seq[start:end]


# Python's backtracking ``re`` engine has no match timeout. Keep flow regexes
# intentionally small and conservative: permit literal/character-class searches
# and simple capture groups used for extraction. Allow at most one simple
# quantifier and no counted repetitions: adjacent or nested repetitions can
# otherwise make even a short pattern catastrophically expensive.
_REGEX_MAX_PATTERN = 200
_REGEX_MAX_SUBJECT = 2000
_GROUP_QUANTIFIERS = frozenset("*+?")


class FlowRegexRefused(ValueError):
    """A pattern cannot be evaluated within the flow's safe regex subset."""


# A run's whole checkpoint is capped at 16 MiB, but only when it is saved; a
# text function must not build a larger value in memory first.
_MAX_TEXT_CHARS = 16 * 1024 * 1024


class FlowTextLimitRefused(FlowRegexRefused):
    """A text function would build a value larger than a run may hold.

    It shares the regex refusal's handling: the step fails instead of the
    expression quietly rendering empty.
    """


def _bounded_text(length: int) -> None:
    if length > _MAX_TEXT_CHARS:
        raise FlowTextLimitRefused("flow text function result exceeds 16 MiB")


def _fn_concat(a: list) -> str:
    parts = [_as_text(x) for x in a]
    _bounded_text(sum(len(part) for part in parts))
    return "".join(parts)


def _fn_replace(a: list) -> str:
    if len(a) < 3:
        return str(a[0]) if a else ""
    text, old, new = str(a[0]), str(a[1]), str(a[2])
    hits = text.count(old)
    _bounded_text(len(text) + hits * (len(new) - len(old)))
    return text.replace(old, new)


def _fn_join(a: list) -> str:
    if len(a) >= 2 and isinstance(a[0], (list, tuple)):
        parts = [_as_text(x) for x in a[0]]
        sep = str(a[1])
        _bounded_text(sum(len(part) for part in parts) + len(sep) * max(0, len(parts) - 1))
        return sep.join(parts)
    return _as_text(a[0]) if a else ""


def _regex_is_safe(pattern: str) -> bool:
    """Return whether ``pattern`` stays within the flow-safe regex subset."""
    in_class = False
    escaped = False
    groups: list[dict[str, bool]] = []
    last_group_had_quantifier = False
    quantifiers = 0

    for i, ch in enumerate(pattern):
        if escaped:
            if ch.isdigit() or ch in {"g", "k"}:
                return False
            escaped = False
            last_group_had_quantifier = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_class:
            if ch == "]":
                in_class = False
            continue
        if ch == "[":
            in_class = True
            last_group_had_quantifier = False
            continue
        if ch == "|":
            return False
        if ch == "(":
            if groups:
                return False
            if pattern[i + 1:i + 2] == "?":
                return False
            groups.append({"has_quantifier": False})
            last_group_had_quantifier = False
            continue
        if ch == ")":
            if not groups:
                return False
            last_group_had_quantifier = groups.pop()["has_quantifier"]
            continue
        if ch in "{}":
            return False
        if ch in _GROUP_QUANTIFIERS:
            quantifiers += 1
            if quantifiers > 1:
                return False
            if groups:
                groups[-1]["has_quantifier"] = True
            elif last_group_had_quantifier:
                return False
            last_group_had_quantifier = False
            continue
        last_group_had_quantifier = False

    return not escaped and not in_class and not groups


def _fn_regex(a: list) -> str:
    """regex(value, pattern) -- the first match; group 1 if the pattern has a
    capture group, else the whole match. Empty on no match or invalid syntax;
    unsupported patterns fail the flow instead of changing its branch result.
    Guarded against ReDoS: the pattern is length-capped and rejected
    if it has more than one quantifier or counted repetition, and the subject
    is length-capped. Existing flows with more complex patterns must be revised."""
    if len(a) < 2:
        return ""
    pattern = str(a[1])
    if len(pattern) > _REGEX_MAX_PATTERN or not _regex_is_safe(pattern):
        raise FlowRegexRefused("flow regex pattern exceeds the supported safe subset")
    subject = _as_text(a[0])[:_REGEX_MAX_SUBJECT]
    try:
        m = re.search(pattern, subject)
    except re.error:
        return ""
    if not m:
        return ""
    return m.group(1) if m.groups() else m.group(0)


def _fn_datefmt(a: list) -> str:
    """datefmt(value, fmt) -- format an epoch-seconds number or an ISO-8601
    string with a strftime pattern (UTC). Bad input yields ''. Default fmt is
    ISO date. E.g. datefmt(now(), "%Y-%m-%d")."""
    if not a:
        return ""
    import datetime as _dt
    fmt = str(a[1]) if len(a) > 1 else "%Y-%m-%d"
    val = a[0]
    try:
        if isinstance(val, (int, float)) or (isinstance(val, str) and val.strip().replace(".", "", 1).isdigit()):
            dt = _dt.datetime.fromtimestamp(_num(val), tz=_dt.timezone.utc)
        else:
            dt = _dt.datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        return dt.strftime(fmt)
    except (ValueError, OverflowError, OSError):
        return ""


def _now_utc():
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc)


def _add_days(value: Any, n: Any) -> str:
    """``value`` (an ISO date/datetime, or '' for today) plus ``n`` days, as an ISO
    date (YYYY-MM-DD) -- so "due in 3 days" is ``{{add_days('', 3)}}`` and it
    orders correctly against other ISO dates. A bad date -> ''."""
    import datetime as _dt
    s = str(value or "").strip()
    try:
        base = _dt.date.fromisoformat(s[:10]) if s else _now_utc().date()
        return (base + _dt.timedelta(days=int(_num(n)))).isoformat()
    except (TypeError, ValueError):
        return ""


_CREDENTIAL_REPAIR = (
    "This flow uses legacy secret expressions. No action was authorized by this expression. "
    "Open Connections to review an account for the intended service, then replace the step "
    "with its authorized connector action and review a new flow version. "
    "Server secrets cannot be used as flow parameters; no credential or grant was migrated."
)


def _resolve_secret(name: Any) -> str:
    # This is the shared sink for literal, computed, nested and direct render
    # callers. Never consult the deployment provider, even for missing names.
    del name
    raise FlowCredentialRefused(_CREDENTIAL_REPAIR)


# Safe transform functions usable inside {{ }} -- no eval, pure string/collection/
# arithmetic helpers. Each takes the evaluated arg list.
_FUNCS: dict[str, Callable[[list], Any]] = {
    "upper": lambda a: str(a[0]).upper() if a else "",
    "lower": lambda a: str(a[0]).lower() if a else "",
    "trim": lambda a: str(a[0]).strip() if a else "",
    "title": lambda a: str(a[0]).title() if a else "",
    "length": lambda a: (len(a[0]) if a and hasattr(a[0], "__len__") else 0),
    "concat": _fn_concat,
    "replace": _fn_replace,
    "default": lambda a: (a[0] if (a and a[0] not in (None, "", [], {})) else (a[1] if len(a) > 1 else "")),
    "json": lambda a: (__import__("json").dumps(a[0]) if a else ""),
    # date/time (UTC): enable "due in N days" / "older than a week" workflows,
    # ISO-formatted so they order correctly with the lexical comparison above.
    "now": lambda a: _now_utc().isoformat(timespec="seconds"),
    "today": lambda a: _now_utc().date().isoformat(),
    "add_days": lambda a: _add_days(a[0], a[1]) if len(a) >= 2 else "",
    "first": lambda a: (a[0][0] if a and isinstance(a[0], (list, tuple)) and a[0] else ""),
    "last": lambda a: (a[0][-1] if a and isinstance(a[0], (list, tuple)) and a[0] else ""),
    # string / collection transforms
    "split": lambda a: (str(a[0]).split(str(a[1])) if len(a) >= 2 else str(a[0]).split() if a else []),
    "join": _fn_join,
    "slice": _fn_slice,
    "index": lambda a: (a[0][int(_num(a[1]))] if a and isinstance(a[0], (list, tuple)) and -len(a[0]) <= int(_num(a[1])) < len(a[0]) else ""),
    "regex": _fn_regex,
    "keys": lambda a: (list(a[0].keys()) if a and isinstance(a[0], dict) else []),
    # arithmetic
    "add": lambda a: sum(_num(x) for x in a),
    "sub": lambda a: (_num(a[0]) - _num(a[1])) if len(a) >= 2 else _num(a[0] if a else 0),
    "mul": lambda a: (_num(a[0]) * _num(a[1])) if len(a) >= 2 else _num(a[0] if a else 0),
    "div": lambda a: (_num(a[0]) / _num(a[1])) if (len(a) >= 2 and _num(a[1])) else 0,
    "round": lambda a: round(_num(a[0]), int(_num(a[1])) if len(a) > 1 else 0) if a else 0,
    "abs": lambda a: abs(_num(a[0])) if a else 0,
    "int": lambda a: int(_num(a[0])) if a else 0,
    "datefmt": _fn_datefmt,
}


def _split_args(s: str) -> list[str]:
    """Comma-split respecting quotes AND nested parens, so a literal comma or a
    nested call's arguments (``default(x, "y")``) survive as one argument."""
    out, cur, q, depth = [], "", None, 0
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
            cur += ch
        elif ch == "(":
            depth += 1
            cur += ch
        elif ch == ")":
            depth = max(0, depth - 1)
            cur += ch
        elif ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if s.strip():
        out.append(cur)
    return [a.strip() for a in out]


def _arg_value(tok: str, data: dict, *, allow_secrets: bool = False) -> Any:
    """A function argument: a quoted/number/bool literal, a NESTED transform call
    (evaluated recursively), else a data key (missing -> '')."""
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] in "'\"" and tok[-1] == tok[0]:
        return tok[1:-1]
    low = tok.lower()
    if low in ("true", "false"):
        return low == "true"
    for cast in (int, float):
        try:
            return cast(tok)
        except ValueError:
            pass
    m = _FN_CALL.match(tok)
    funcs = _funcs(allow_secrets=allow_secrets)
    if m and m.group(1) in funcs:          # nested call: {{upper(default(x,"y"))}}
        return _eval_expr(tok, data, allow_secrets=allow_secrets)
    return _dig(data, tok, "")


def _funcs(*, allow_secrets: bool = False) -> dict[str, Callable[[list], Any]]:
    if not allow_secrets:
        return _FUNCS
    return {**_FUNCS, "secret": lambda a: _resolve_secret(a[0] if a else None)}


def _eval_expr(expr: str, data: dict, *, allow_secrets: bool = False) -> Any:
    """Evaluate a ``{{ }}`` expression: a transform call (args may themselves be
    transform calls), else a dotted-key dig (``None`` for a missing bare key so
    render keeps it literal)."""
    m = _FN_CALL.match(expr.strip())
    funcs = _funcs(allow_secrets=allow_secrets)
    if m and m.group(1) in funcs:
        args = [_arg_value(a, data, allow_secrets=allow_secrets) for a in _split_args(m.group(2))]
        try:
            return funcs[m.group(1)](args)
        except (FlowCredentialRefused, FlowRegexRefused):
            raise
        except Exception:  # a bad transform never breaks rendering
            return ""
    return _dig(data, expr.strip())


def _dig(data: dict, dotted: str, default: Any = None) -> Any:
    cur: Any = data
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _coerce(token: str) -> Any:
    token = token.strip()
    if len(token) >= 2 and token[0] in "'\"" and token[-1] == token[0]:
        return token[1:-1]
    low = token.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        return token


def _eval_predicate(expr: str, data: dict) -> bool:
    """One ``<key> <op> <value>`` comparison (or a bare truthiness test)."""
    m = _COND.match(str(expr or ""))
    if not m:
        return bool(_dig(data, str(expr).strip()))
    key, op, rhs = m.group(1), m.group(2), _coerce(m.group(3))
    lhs = _dig(data, key)
    try:
        if op == "==":
            return lhs == rhs
        if op == "!=":
            return lhs != rhs
        if op == "contains":
            return str(rhs) in str(lhs) if lhs is not None else False
        # Ordering: numeric when BOTH sides are numbers, else lexical -- so an ISO
        # date/string comparison (`created >= '2026-01-01'`) is honoured instead of
        # silently false. A None lhs (missing key) is never ordered-true.
        if lhs is None:
            return False
        lo, ro = _order_operands(lhs, rhs)
        return {">": lo > ro, "<": lo < ro, ">=": lo >= ro, "<=": lo <= ro}[op]
    except (TypeError, ValueError):
        return False


def _order_operands(lhs: Any, rhs: Any) -> tuple[Any, Any]:
    """Coerce a pair for an ordering comparison: floats when both parse as numbers
    (so `10 > 9` isn't the string-wise `'10' > '9'` == False), else strings (so
    dates and other text order lexically instead of raising / being dropped)."""
    try:
        return float(lhs), float(rhs)
    except (TypeError, ValueError):
        return str(lhs), str(rhs)


def _split_bool_ops(expr: str, op: str) -> list[str]:
    """Split on a boolean operator only when it appears outside quotes."""
    out: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    i = 0
    op_len = len(op)
    while i < len(expr):
        ch = expr[i]
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            cur.append(ch)
            i += 1
            continue
        if (
            expr[i : i + op_len].lower() == op
            and (i == 0 or expr[i - 1].isspace())
            and (i + op_len == len(expr) or expr[i + op_len].isspace())
        ):
            out.append("".join(cur).strip())
            cur = []
            i += op_len
            continue
        cur.append(ch)
        i += 1
    out.append("".join(cur).strip())
    return out


def eval_condition(expr: str, data: dict) -> bool:
    """A safe boolean predicate over flow data (no eval).

    A predicate is ``<key> <op> <value>`` (``<value>`` a number / 'quoted' /
    bareword / true|false), or a bare key (truthiness). Predicates compose with
    ``and`` / ``or`` (``or`` of ``and`` groups, standard precedence), e.g.
    ``amount > 100 and region == 'EU'``. Unparsable predicates are falsey."""
    s = str(expr or "").strip()
    for or_part in _split_bool_ops(s, "or"):
        parts = [p for p in _split_bool_ops(or_part, "and") if p.strip()]
        if parts and all(_eval_predicate(p, data) for p in parts):
            return True
    return False
