"""Comparative replay tool.

Diff two run traces step-by-step to answer "where did these two runs diverge?".
Aligns the traces by their ``step`` field, reports the first step whose action
or result differs, prints a per-step match/mismatch table, and scores overall
similarity. Deterministic and offline: similarity is ``difflib.SequenceMatcher``
over the two action sequences.

ops:
  - compare(run_a, run_b)  — each a list of {step, action, result}.
"""
from __future__ import annotations

import difflib
from typing import Any

from . import Tool


def _by_step(trace: list) -> dict[Any, dict]:
    out: dict[Any, dict] = {}
    for entry in trace:
        if isinstance(entry, dict):
            out[entry.get("step")] = entry
    return out


def _actions(trace: list) -> list[str]:
    return [
        str(e.get("action", "")) for e in trace if isinstance(e, dict)
    ]


def _compare(run_a: list, run_b: list) -> str:
    a_by = _by_step(run_a)
    b_by = _by_step(run_b)
    steps = sorted(
        set(a_by) | set(b_by),
        key=lambda s: (s is None, str(s)),
    )

    table: list[str] = []
    first_divergence: str | None = None
    matches = 0
    for s in steps:
        a = a_by.get(s)
        b = b_by.get(s)
        if a is None:
            verdict = "MISMATCH (only in B)"
        elif b is None:
            verdict = "MISMATCH (only in A)"
        elif a.get("action") != b.get("action"):
            verdict = (
                f"MISMATCH action {a.get('action')!r} != {b.get('action')!r}"
            )
        elif a.get("result") != b.get("result"):
            verdict = (
                f"MISMATCH result {a.get('result')!r} != {b.get('result')!r}"
            )
        else:
            verdict = "MATCH"
            matches += 1
        if verdict != "MATCH" and first_divergence is None:
            first_divergence = f"step {s}: {verdict}"
        table.append(f"  step {s}: {verdict}")

    ratio = difflib.SequenceMatcher(
        None, _actions(run_a), _actions(run_b)
    ).ratio()
    similarity = round(ratio * 100, 1)

    head = (
        "IDENTICAL" if first_divergence is None
        else f"DIVERGES at {first_divergence}"
    )
    summary = (
        f"{head}\nsimilarity={similarity}%  "
        f"matched {matches}/{len(steps)} step(s)"
    )
    return summary + "\n" + "\n".join(table)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "compare"):
        return f"ERROR: unknown op {args.get('op')!r}"
    run_a = args.get("run_a")
    run_b = args.get("run_b")
    if not isinstance(run_a, list) or not isinstance(run_b, list):
        return "ERROR: compare needs 'run_a' and 'run_b' lists of {step, action, result}"
    if not run_a and not run_b:
        return "ERROR: both traces are empty"
    return _compare(run_a, run_b)


_ENTRY = {
    "type": "object",
    "properties": {
        "step": {"description": "step identifier used to align the traces"},
        "action": {"type": "string"},
        "result": {"type": "string"},
    },
}

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["compare"]},
        "run_a": {"type": "array", "description": "first trace", "items": _ENTRY},
        "run_b": {"type": "array", "description": "second trace", "items": _ENTRY},
    },
    "required": ["run_a", "run_b"],
}


def comparative_replay() -> Tool:
    return Tool(
        name="comparative_replay",
        description=(
            "Comparative replay of two run traces. op=compare with 'run_a' and "
            "'run_b' (each a list of {step, action, result}). Aligns by step, "
            "reports the first divergence, a per-step match/mismatch table, and "
            "an overall similarity % (difflib over the action sequences). "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
