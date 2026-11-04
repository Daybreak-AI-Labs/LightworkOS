"""Reliability harness.

Summarise repeated test runs into a per-test reliability report and an overall
reliability score. Deterministic and offline: the caller supplies the test runs
(each ``{name, outcomes: [bool, ...]}`` where each bool is one pass/fail); this
resolves the classification.

Per-test classification over its outcomes:
  - STABLE-PASS: every run passed.
  - ALWAYS-FAIL: every run failed.
  - FLAKY: mixed pass and fail.

Overall reliability % is the total passes across every outcome of every test
divided by the total number of outcomes.

ops:
  - report(runs)  — per-test pass-rate + status + overall reliability %.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _classify(passes: int, total: int) -> str:
    if passes == total:
        return "STABLE-PASS"
    if passes == 0:
        return "ALWAYS-FAIL"
    return "FLAKY"


def _report(runs: list) -> str:
    lines: list[str] = []
    total_pass = 0
    total_runs = 0
    flaky = 0

    for i, run in enumerate(runs):
        if not isinstance(run, dict):
            return f"ERROR: run #{i} must be an object"
        name = run.get("name")
        if not isinstance(name, str) or not name.strip():
            return f"ERROR: run #{i} needs a non-empty name"
        outcomes = run.get("outcomes")
        if not isinstance(outcomes, list) or not outcomes:
            return f"ERROR: test {name!r} needs a non-empty outcomes list"
        if not all(isinstance(o, bool) for o in outcomes):
            return f"ERROR: test {name!r} outcomes must all be booleans"

        n = len(outcomes)
        passes = sum(1 for o in outcomes if o)
        status = _classify(passes, n)
        if status == "FLAKY":
            flaky += 1
        rate = passes / n * 100.0
        lines.append(f"  {name}: {status} pass_rate={rate:.1f}% ({passes}/{n})")

        total_pass += passes
        total_runs += n

    overall = total_pass / total_runs * 100.0
    header = (
        f"RELIABILITY overall={overall:.1f}% "
        f"({total_pass}/{total_runs} outcomes; {len(runs)} tests, {flaky} flaky)"
    )
    return header + "\n" + "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "report"):
        return f"ERROR: unknown op {args.get('op')!r}"
    runs = args.get("runs")
    if not isinstance(runs, list) or not runs:
        return "ERROR: runs (non-empty list of {name, outcomes:[bool,...]}) is required"
    return _report(runs)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["report"]},
        "runs": {
            "type": "array",
            "description": "Test runs: {name, outcomes:[bool,...]} (one bool per run)",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "outcomes": {
                        "type": "array",
                        "items": {"type": "boolean"},
                        "description": "Pass/fail per repeated run",
                    },
                },
                "required": ["name", "outcomes"],
            },
        },
    },
    "required": ["runs"],
}


def reliability_harness() -> Tool:
    return Tool(
        name="reliability_harness",
        description=(
            "Reliability harness. op=report with 'runs' (each {name, "
            "outcomes:[bool,...]}). Computes each test's pass rate and flags it "
            "STABLE-PASS (all passed), ALWAYS-FAIL (all failed) or FLAKY (mixed), "
            "plus an overall reliability % across every outcome. Deterministic, "
            "offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
