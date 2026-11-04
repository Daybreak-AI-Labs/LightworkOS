"""Agent simulator harness tool.

Replays a scripted plan against a fixed set of "world responses" and checks
each step's outcome against its expectation — a pure, deterministic simulation
for regression-testing an agent's expected behavior without a live model or
real side effects.

ops:
  - run(script, world)  — replay the script, returning PASS/FAIL per step and a
    summary of how many steps matched their ``expect``.

``script``: list of {step?, action, expect}. ``world``: list of {action,
result}; the first unconsumed response whose ``action`` matches is used (each
response is consumed once, so repeated actions map to successive responses).
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _norm(v: Any) -> str:
    return " ".join(str(v if v is not None else "").split()).strip()


def _run_sim(script: list[Any], world: list[Any]) -> str:
    # Build a list of (action, result, consumed?) so repeated actions resolve to
    # successive responses deterministically.
    responses: list[dict[str, Any]] = []
    for r in world:
        if isinstance(r, dict):
            responses.append({"action": _norm(r.get("action")),
                              "result": _norm(r.get("result")),
                              "used": False})

    lines: list[str] = []
    passed = 0
    for i, raw in enumerate(script, 1):
        if not isinstance(raw, dict):
            lines.append(f"step {i}: FAIL (not an object)")
            continue
        step_id = raw.get("step", i)
        action = _norm(raw.get("action"))
        expect = _norm(raw.get("expect"))
        # Find the first unconsumed world response for this action.
        actual = None
        for resp in responses:
            if not resp["used"] and resp["action"] == action:
                resp["used"] = True
                actual = resp["result"]
                break
        if actual is None:
            lines.append(
                f"step {step_id}: FAIL action={action!r} "
                f"(no world response)"
            )
            continue
        if actual == expect:
            passed += 1
            lines.append(
                f"step {step_id}: PASS action={action!r} -> {actual!r}"
            )
        else:
            lines.append(
                f"step {step_id}: FAIL action={action!r} "
                f"expected={expect!r} got={actual!r}"
            )
    total = len(script)
    header = (
        f"{'PASS' if passed == total and total else 'FAIL'}: "
        f"{passed}/{total} step(s) matched expect"
    )
    return "\n".join([header, *lines])


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "run"):
        return f"ERROR: unknown op {args.get('op')!r} (expected run)"
    script = args.get("script")
    world = args.get("world")
    if not isinstance(script, list):
        return "ERROR: script (array of {action, expect}) is required"
    if not isinstance(world, list):
        return "ERROR: world (array of {action, result}) is required"
    return _run_sim(script, world)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["run"]},
        "script": {
            "type": "array",
            "description": "scripted steps; each {step?, action, expect}",
            "items": {
                "type": "object",
                "properties": {
                    "step": {"type": ["string", "integer"]},
                    "action": {"type": "string"},
                    "expect": {"type": "string"},
                },
                "required": ["action", "expect"],
            },
        },
        "world": {
            "type": "array",
            "description": "scripted world responses; each {action, result}",
            "items": {
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "result": {"type": "string"},
                },
                "required": ["action", "result"],
            },
        },
    },
    "required": ["script", "world"],
}


def agent_simulator() -> Tool:
    return Tool(
        name="agent_simulator",
        description=(
            "Agent simulator harness: deterministically replay a scripted plan "
            "against fixed world responses. op=run with 'script' (each {step?, "
            "action, expect}) and 'world' (each {action, result}; matched "
            "first-unconsumed by action). Returns PASS/FAIL per step plus a "
            "summary of how many matched expect. Pure simulation, no model."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
