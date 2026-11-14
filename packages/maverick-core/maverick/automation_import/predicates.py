"""Supported import predicates, or an explicit repair requirement.

Boolean trees become branch graphs. No clause is discarded and NOT swaps
destinations, including when an operand is missing, rather than guessing an
inverse comparison. Source expressions are data; they are never evaluated.
WDL ``contains`` uses the runtime's string-substring comparison, including for
arrays and objects; its fidelity must be reported as approximated.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from ..flow.ir import NODE_BRANCH, FlowNode
from .ir import _complete_text

_PATH = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\Z")
_N8N_OPS = {
    "gt": ">", "larger": ">", "gte": ">=", "largerEqual": ">=",
    "lt": "<", "smaller": "<", "lte": "<=", "smallerEqual": "<=",
    "equal": "==", "equals": "==", "notEqual": "!=", "notEquals": "!=",
    "contains": "contains",
}
_WDL_OPS = {
    "equals": "==", "notEquals": "!=", "greater": ">", "greaterOrEquals": ">=",
    "less": "<", "lessOrEquals": "<=", "contains": "contains",
}
_MAKE_OPS = {
    "equal": "==", "notequal": "!=", "greater": ">", "greaterorequal": ">=",
    "less": "<", "lessorequal": "<=", "contain": "contains", "contains": "contains",
}


def repair(reason: str) -> ValueError:
    # Never echo external expressions: they can contain credentials.
    return ValueError(f"Imported condition requires repair before execution: {reason}")


def _checked_operand(value):
    if isinstance(value, str) and _complete_text(value) != value:
        raise repair("credential-bearing operand needs an explicit data binding")
    return value


@dataclass(frozen=True)
class Predicate:
    kind: str
    text: str = ""
    children: tuple[Predicate, ...] = ()
    approximated: bool = False

    @property
    def has_approximation(self) -> bool:
        return self.approximated or any(child.has_approximation for child in self.children)


# The flow runtime splits conditions on these words, so a field with this
# exact name would compile to a condition that can never match.
_RESERVED_PATHS = frozenset({"or", "and"})


def _path(value: str) -> str:
    if len(value) > 512 or not _PATH.fullmatch(value) or value.lower() in _RESERVED_PATHS:
        raise repair("unsupported data reference")
    return value


def n8n_key(value: Any) -> str:
    if not isinstance(value, str):
        raise repair("left operand must name a data field")
    value = value.strip()
    if len(value) > 1024:  # no data reference is this long; bounds all work below
        raise repair("unsupported data reference")
    # Linear delimiter parse (a lazy regex here was cubic on "{{" + spaces).
    body = value.removeprefix("=")
    if body.startswith("{{") and body.endswith("}}") and len(body) >= 4:
        value = body[2:-2].strip()
    if value.startswith("$json"):
        suffix = value[5:]
        suffix = re.sub(r"\[['\"]([A-Za-z_]\w*)['\"]\]", r".\1", suffix)
        if not suffix.startswith("."):
            raise repair("unsupported n8n data reference")
        value = suffix[1:]
    return _path(value)


def wdl_key(value: Any) -> str:
    if not isinstance(value, str):
        raise repair("left operand must name a data field")
    value = value.strip()
    match = re.fullmatch(r"@?triggerBody\(\)((?:\??\['[^']+'\])+)", value)
    if match:
        fields = re.findall(r"\['([^']+)'\]", match[1])
        if any(not re.fullmatch(r"[A-Za-z_]\w*", field) for field in fields):
            raise repair("WDL property cannot be represented as a flow data path")
        return _path(".".join(fields))
    raise repair("left operand is not a supported trigger data reference")


def _literal(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            raise repair("non-finite comparison value")
        return str(value)
    if not isinstance(value, str):
        raise repair("only scalar comparison values are supported")
    if len(value) > 4096 or any(ord(ch) < 32 for ch in value):
        raise repair("comparison value cannot be represented without truncation")
    if value.startswith("@") or "{{" in value or "$json" in value:
        raise repair("dynamic right operand must be bound explicitly")
    # The runtime intentionally has no expression evaluator or escape decoder.
    # Select a quote absent from the actual value instead of changing its bytes.
    quote = "'" if "'" not in value else '"'
    if quote in value:
        raise repair("comparison text contains both quote styles")
    return f"{quote}{value}{quote}"


def n8n_predicate(node: dict) -> Predicate:
    params = node.get("parameters") or {}
    if not isinstance(params, dict):
        raise repair("malformed n8n parameters")
    conditions = params.get("conditions")
    if not isinstance(conditions, dict):
        raise repair("n8n condition is missing")
    options = conditions.get("options") or {}
    if not isinstance(options, dict):
        raise repair("malformed n8n comparison options")
    if options.get("caseSensitive") is False or options.get("typeValidation") == "loose":
        raise repair("case-insensitive or loose type comparisons need an explicit mapping")
    clauses = conditions.get("conditions")
    v2 = isinstance(clauses, list)
    if not v2:
        unknown = set(conditions) - {"number", "string", "boolean", "combineOperation"}
        if unknown:
            raise repair("unsupported n8n condition group")
        clauses = []
        for kind in ("number", "string", "boolean"):
            group = conditions.get(kind, [])
            if not isinstance(group, list):
                raise repair("malformed n8n condition group")
            clauses.extend(group)
    if not clauses or len(clauses) > 128:
        raise repair("condition must contain between 1 and 128 clauses")
    result = []
    for clause in clauses:
        if not isinstance(clause, dict):
            raise repair("malformed n8n comparison")
        op = clause.get("operator") if v2 else clause.get("operation")
        op = op.get("operation") if isinstance(op, dict) else op
        if not isinstance(op, str) or op not in _N8N_OPS:
            raise repair("unsupported n8n comparison operator")
        left = n8n_key(clause.get("leftValue" if v2 else "value1"))
        right = _literal(clause.get("rightValue" if v2 else "value2"))
        result.append(Predicate("atom", f"{left} {_N8N_OPS[op]} {right}"))
    combination = conditions.get("combinator", params.get("combineOperation", "all"))
    combination = conditions.get("combineOperation", combination)
    if combination not in ("and", "or", "all", "any"):
        raise repair("unsupported n8n boolean combination")
    return Predicate("and" if combination in ("and", "all") else "or", children=tuple(result))


def make_predicate(route: dict) -> Predicate | None:
    """Retain a Make module or route's OR-of-AND filter using native branches."""
    if "filter" not in route:
        return None  # An explicitly unfiltered route runs unconditionally.
    filt = route["filter"]
    if not isinstance(filt, dict) or set(filt) - {"name", "conditions"}:
        raise repair("malformed or unsupported Make filter")
    groups = filt.get("conditions")
    if not isinstance(groups, list) or not 1 <= len(groups) <= 128:
        raise repair("Make filter needs between 1 and 128 condition groups")
    result, count = [], 0
    for group in groups:
        if not isinstance(group, list) or not group:
            raise repair("Make condition group is empty or malformed")
        count += len(group)
        if count > 256:
            raise repair("Make filter exceeds 256 comparisons")
        clauses = []
        for clause in group:
            if not isinstance(clause, dict) or set(clause) != {"a", "o", "b"}:
                raise repair("malformed or unsupported Make comparison")
            left, operator, right = clause["a"], clause["o"], clause["b"]
            if not isinstance(left, str) or not isinstance(operator, str):
                raise repair("Make comparison needs a data field and supported operator")
            left = _path(_checked_operand(left).strip())
            right = _checked_operand(right)
            family, separator, op = operator.lower().partition(":")
            if not separator or op not in _MAKE_OPS:
                raise repair("unsupported Make comparison operator")
            if family == "number" and op not in {"contain", "contains"}:
                if isinstance(right, str):
                    right = right.strip()
                    if (len(right) > 512 or not re.fullmatch(r"[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?", right)
                            or not math.isfinite(float(right))):
                        raise repair("Make number must be a finite literal")
                    literal = right
                elif type(right) in {int, float}:
                    literal = _literal(right)
                else:
                    raise repair("Make number must be a finite literal")
            elif family == "text" and op in {"equal", "notequal", "contain", "contains"} and isinstance(right, str):
                literal = _literal(right)
            elif family == "boolean" and op in {"equal", "notequal"}:
                if isinstance(right, str) and right.lower() in {"true", "false"}:
                    right = right.lower() == "true"
                if type(right) is not bool:
                    raise repair("Make boolean must be true or false")
                literal = _literal(right)
            else:
                raise repair("unsupported Make comparison type or operator")
            clauses.append(Predicate("atom", f"{left} {_MAKE_OPS[op]} {literal}"))
        result.append(Predicate("and", children=tuple(clauses)))
    return Predicate("or", children=tuple(result))


def _split_args(text: str) -> list[str]:
    parts, start, depth, quoted, index = [], 0, 0, False, 0
    while index < len(text):
        char = text[index]
        if char == "'":
            if quoted and text[index:index + 2] == "''":
                index += 2
                continue
            quoted = not quoted
        elif not quoted:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth < 0:
                    raise repair("malformed WDL expression")
            elif char == "," and depth == 0:
                parts.append(text[start:index].strip())
                start = index + 1
        index += 1
    if quoted or depth:
        raise repair("malformed WDL expression")
    parts.append(text[start:].strip())
    return parts


def _wdl_value(text: str) -> Any:
    if len(text) >= 2 and text[0] == text[-1] == "'":
        inner = text[1:-1]
        if "'" in inner.replace("''", ""):
            raise repair("malformed WDL string")
        return inner.replace("''", "'")
    if text in ("true", "false"):
        return text == "true"
    if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        return float(text) if "." in text else int(text)
    raise repair("WDL right operand is not a supported literal")


def wdl_predicate(expr: Any, _depth: int = 0, _remaining: list[int] | None = None) -> Predicate:
    if _remaining is None:
        _remaining = [256]
    _remaining[0] -= 1
    if _remaining[0] < 0:
        raise repair("condition exceeds 256 terms")
    if _depth > 16:
        raise repair("boolean nesting exceeds 16 levels")
    from_string = isinstance(expr, str)
    if from_string:
        if len(expr) > 8192:
            raise repair("condition exceeds the supported size")
        match = re.fullmatch(r"@?(\w+)\((.*)\)", expr.strip(), re.DOTALL)
        if not match:
            raise repair("unsupported WDL expression")
        op, args = match[1], _split_args(match[2])
    elif isinstance(expr, dict) and len(expr) == 1:
        op, args = next(iter(expr.items()))
    else:
        raise repair("malformed WDL condition")
    if op == "not":
        if isinstance(args, dict):
            args = [args]
        if not isinstance(args, list) or len(args) != 1:
            raise repair("NOT requires exactly one condition")
        return Predicate("not", children=(wdl_predicate(args[0], _depth + 1, _remaining),))
    if op in ("and", "or"):
        if not isinstance(args, list) or not 1 <= len(args) <= 128:
            raise repair("boolean combination requires between 1 and 128 conditions")
        return Predicate(op, children=tuple(wdl_predicate(a, _depth + 1, _remaining) for a in args))
    if op not in _WDL_OPS or not isinstance(args, list) or len(args) != 2:
        raise repair("unsupported WDL comparison")
    right = _wdl_value(args[1]) if from_string else args[1]
    return Predicate("atom", f"{wdl_key(args[0])} {_WDL_OPS[op]} {_literal(right)}",
                     approximated=op == "contains")


def branches(predicate: Predicate, node_id: str, yes: str | None, no: str | None,
             label: str, successor: str | None = None) -> dict[str, FlowNode]:
    """Compile short-circuit boolean logic using only existing branch nodes."""
    nodes: dict[str, FlowNode] = {}
    serial = 0

    def emit(item: Predicate, nid: str, true: str | None, false: str | None) -> None:
        nonlocal serial
        if item.kind == "not":
            emit(item.children[0], nid, false, true)
        elif item.kind == "atom":
            if len(nodes) >= 256:
                raise repair("condition exceeds 256 comparisons")
            nodes[nid] = FlowNode(id=nid, kind=NODE_BRANCH, condition=item.text,
                                  if_true=true, if_false=false, next=successor, label=label)
        else:
            ids = [nid]
            for _ in item.children[1:]:
                serial += 1
                ids.append(f"{node_id}p{serial}")
            for index, child in enumerate(item.children):
                tail = index == len(item.children) - 1
                emit(child, ids[index],
                     true if tail or item.kind == "or" else ids[index + 1],
                     false if tail or item.kind == "and" else ids[index + 1])

    emit(predicate, node_id, yes, no)
    return nodes
