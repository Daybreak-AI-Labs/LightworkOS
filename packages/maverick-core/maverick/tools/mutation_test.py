"""Mutation-testing planner tool.

Generates the *mutants* of a piece of Python source — small semantic changes a
good test suite should catch (a surviving mutant = a coverage gap). It produces
the mutation plan (operator swaps with line numbers and the rewritten line) via
``ast``; actually running the suite against each mutant is a separate,
sandbox-mediated step, so this stays deterministic and side-effect-free.

ops:
  - mutants(source[, max])  — list the mutants (default cap 50).

Operators: arithmetic (+/-/*//), comparison (</<=, >/>=, ==/!=), boolean
(and/or), boolean constants (True/False), and numeric-constant bump (n -> n+1).
"""
from __future__ import annotations

import ast
from typing import Any

from . import Tool

_BINOP = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.Div, ast.Div: ast.Mult}
_BINOP_SYM = {ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/"}
_CMP = {
    ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
}
_CMP_SYM = {
    ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=", ast.Eq: "==", ast.NotEq: "!=",
}
_BOOL = {ast.And: ast.Or, ast.Or: ast.And}


def _line(source_lines: list[str], lineno: int) -> str:
    return source_lines[lineno - 1].strip() if 1 <= lineno <= len(source_lines) else ""


def _mutants(source: str, cap: int) -> list[tuple[int, str, str]]:
    """(lineno, description, original_line) for each mutant, deterministic order."""
    tree = ast.parse(source)
    lines = source.splitlines()
    out: list[tuple[int, str, str]] = []

    for node in ast.walk(tree):
        ln = getattr(node, "lineno", None)
        if ln is None:
            continue
        if isinstance(node, ast.BinOp) and type(node.op) in _BINOP:
            a, b = _BINOP_SYM[type(node.op)], _BINOP_SYM[_BINOP[type(node.op)]]
            out.append((ln, f"arithmetic: '{a}' -> '{b}'", _line(lines, ln)))
        elif isinstance(node, ast.Compare) and node.ops and type(node.ops[0]) in _CMP:
            a, b = _CMP_SYM[type(node.ops[0])], _CMP_SYM[_CMP[type(node.ops[0])]]
            out.append((ln, f"comparison: '{a}' -> '{b}'", _line(lines, ln)))
        elif isinstance(node, ast.BoolOp) and type(node.op) in _BOOL:
            a = "and" if isinstance(node.op, ast.And) else "or"
            b = "or" if isinstance(node.op, ast.And) else "and"
            out.append((ln, f"boolean: '{a}' -> '{b}'", _line(lines, ln)))
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                out.append((ln, f"constant: {node.value} -> {not node.value}", _line(lines, ln)))
            elif isinstance(node.value, (int, float)):
                out.append((ln, f"number: {node.value} -> {node.value + 1}", _line(lines, ln)))

    out.sort(key=lambda t: (t[0], t[1]))
    return out[:cap]


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "mutants"):
        return f"ERROR: unknown op {args.get('op')!r}"
    source = str(args.get("source") or "")
    if not source.strip():
        return "ERROR: source is required"
    try:
        cap = int(args.get("max", 50))
    except (TypeError, ValueError, OverflowError):
        cap = 50
    cap = max(1, min(cap, 500))
    try:
        muts = _mutants(source, cap)
    except SyntaxError as e:
        return f"ERROR: source does not parse: {e}"
    if not muts:
        return "no mutants (no mutable operators/constants found)"
    rows = [f"L{ln}: {desc}   | {orig}" for ln, desc, orig in muts]
    return f"{len(muts)} mutant(s):\n" + "\n".join(rows)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["mutants"]},
        "source": {"type": "string", "description": "Python source to mutate"},
        "max": {"type": "integer", "description": "cap on mutants returned (default 50)"},
    },
    "required": ["source"],
}


def mutation_test() -> Tool:
    return Tool(
        name="mutation_test",
        description=(
            "Plan mutation tests for Python source: list the mutants (operator "
            "swaps + constant bumps with line numbers) a strong suite should "
            "catch — a surviving mutant flags a coverage gap. op=mutants. "
            "Generates the plan via ast (no execution); run it against the "
            "suite as a separate sandboxed step."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
