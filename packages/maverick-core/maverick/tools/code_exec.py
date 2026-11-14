"""code_exec: programmatic tool calling (the run-to-completion slice).

Anthropic's programmatic-tool-calling pattern, scoped to today's run-to-completion
sandbox (no interactive sessions yet): the model declares a set of tool calls plus
a Python script. The host runs the tool calls FIRST (through the agent's shielded
tool path), injects their outputs into the script as a ``tools`` dict, runs the
script in the sandbox, and returns ONLY the script's stdout. The raw tool outputs
-- and the data-flow between them -- stay in the sandbox, out of the model's
context, so the model can fetch/query many things and return just a filtered or
aggregated summary in a single turn.

What this slice does NOT do: dynamic mid-execution tool calls (the script cannot
issue NEW tool calls based on intermediate results). That needs interactive
sandbox sessions -- a separate effort. Here the tool calls are resolved up front.

Safety:
  - Declared tool calls go through ``agent._run_tool``, so the shield, PreToolUse
    / PostToolUse hooks, secret redaction, the complete-result byte quota, and the tool
    ACL all apply exactly as for a normal call; each is budget-accounted.
  - The script runs in the sandbox (CLAUDE.md rule #4) -- same isolation as the
    ``shell`` tool -- never in-process.
  - Opt-in: ``[capabilities] code_exec`` or ``MAVERICK_CODE_EXEC=1``.
"""
from __future__ import annotations

import asyncio
import json

from ..approval_cards import ApprovalCardError
from ..safety import ConsentDenied, consume_operation_consent
from ..safety.secret_detector import redact
from . import Tool, sandbox_run
from .execution_consent import execution_target, request_execution_consent

# Bound the up-front fan-out; each declared call is budget-accounted besides.
_MAX_DECLARED_CALLS = 24
_CODE_TIMEOUT = 120.0


def _declared_call_error(declared: list) -> str | None:
    for i, call in enumerate(declared):
        if not isinstance(call, dict) or not call.get("name"):
            return f"ERROR: tool_calls[{i}] needs a name and arguments."
        cargs = call.get("arguments")
        if cargs is None:
            cargs = call.get("input") or {}
        if not isinstance(cargs, dict):
            return f"ERROR: tool_calls[{i}].arguments must be an object."
    return None


async def _request_code_permit(agent, code: str, declared: list):
    parameters = {"code": code, "tool_calls": declared, "timeout_seconds": _CODE_TIMEOUT}
    preview, _ = redact(" | ".join(code.strip().splitlines()[:2])[:180])
    call_names, _ = redact(", ".join(str(call["name"]) for call in declared)[:180] or "none")
    return await asyncio.to_thread(
        request_execution_consent,
        "code_exec",
        target_provider=lambda: execution_target(agent.ctx.sandbox),
        parameters=parameters,
        detail="Run one Python script and its declared tool calls.",
        effect="Runs declared tools, then Python code in the reviewed environment.",
        review_items=[f"Script start (truncated, redacted): {preview}",
                      f"Declared tool calls ({len(declared)}): {call_names}"],
        timeout=_CODE_TIMEOUT,
    )


def _stop_reason(agent) -> str | None:
    """Why the run must stop now (a halt or a cancelled goal), else ``None``.

    The agent's serial tool loop checks both between tools; the declared
    fan-out below is several tool calls inside one, so it checks them too.
    """
    from .. import killswitch

    try:
        killswitch.check()
    except killswitch.Halted as e:
        return str(e)
    cancelled = getattr(agent, "_goal_cancelled", None)
    if callable(cancelled) and cancelled():
        return "goal cancelled"
    return None


def _stopped(reason: str, ran: int) -> str:
    if ran == 0:
        return f"ERROR: {reason}; no tool or script was run"
    return (
        f"INDETERMINATE: {reason} after {ran} declared tool call(s). Script withheld; "
        "reconcile prior tool calls and do not repeat them blindly."
    )


def _admit_declared_call(agent, name, ran: int) -> str | None:
    """Refusal for the next declared call (halt, cancel or budget), else ``None``."""
    from ..budget import BudgetExceeded

    if reason := _stop_reason(agent):
        return _stopped(reason, ran)
    try:
        agent.ctx.budget.record_tool_call()
    except BudgetExceeded as e:
        return f"ERROR: budget exhausted before running {name!r}: {e}"
    return None


def _build_script(agent, code: str, declared: list, tool_outputs: dict[str, str]) -> str:
    """The script to run, or an ``ERROR:``/``INDETERMINATE:`` refusal."""
    from ..tool_result_stream import ToolOutputLimit, result_bytes

    if reason := _stop_reason(agent):
        return _stopped(reason, len(declared))
    # The complete screened outputs as a dict, then the model's code.
    # json.dumps of a str->str dict is valid Python only without ASCII
    # escaping: "\ud83d\ude00" would become two lone surrogates in a Python
    # literal, not the original character.
    preamble = (
        "# Injected by code_exec: outputs of the tool_calls you declared,\n"
        "# keyed by your `as` (or '<name>_<index>'). Read them via tools[...].\n"
        "tools = " + json.dumps(tool_outputs, ensure_ascii=False) + "\n\n"
    )
    script = preamble + code
    try:
        result_bytes(script)
    except ToolOutputLimit:
        return (
            "INDETERMINATE: encoded script and complete inputs exceed the 16 MiB byte quota. "
            "Script withheld; prior calls may have executed, so do not retry blindly."
        )
    return script


def _run_approved_script(agent, permit, script: str):
    with consume_operation_consent(permit):
        return sandbox_run(agent.ctx.sandbox, ["python3", "-"],
                           timeout=_CODE_TIMEOUT, stdin=script)


def code_exec_tool(agent) -> Tool:
    """Build the code_exec tool bound to ``agent`` (for its shielded _run_tool,
    sandbox, and budget)."""

    async def fn(args: dict) -> str:
        code = str(args.get("code") or "")
        if not code.strip():
            return "ERROR: `code` is required (a Python script to run)."
        declared = args.get("tool_calls") or []
        if not isinstance(declared, list):
            return "ERROR: `tool_calls` must be a list of {name, arguments}."
        if len(declared) > _MAX_DECLARED_CALLS:
            return (f"ERROR: too many tool_calls ({len(declared)}; max "
                    f"{_MAX_DECLARED_CALLS}). Batch fewer, or loop inside the script "
                    "over data a single call returns.")

        from ..agent import unframe_tool_output
        from ..tool_result_stream import (
            MAX_RESULT_BYTES,
            ToolOutputLimit,
            execution_output_scope,
            result_bytes,
        )

        try:
            result_bytes(code)
        except ToolOutputLimit:
            return "ERROR: script exceeds the complete-result byte quota; no tool was dispatched"

        if error := _declared_call_error(declared):
            return error
        # Review before *any* declared call. Such calls still pass through the
        # agent's own shield and per-tool consent; this permit covers the
        # model's script and the exact declared fan-out together.
        try:
            permit = await _request_code_permit(agent, code, declared)
        except ConsentDenied:
            return "ERROR: code execution was not approved; no tool or script was run"
        except ApprovalCardError:
            return "ERROR: code, execution target, or approval authority changed; review it again"

        # 1. Run the declared tool calls FIRST, through the shielded path.
        tool_outputs: dict[str, str] = {}
        retained_bytes = 0
        for i, call in enumerate(declared):
            name = call.get("name")
            cargs = call.get("arguments")
            if cargs is None:
                cargs = call.get("input") or {}
            var = str(call.get("as") or f"{name}_{i}")
            if refusal := _admit_declared_call(agent, name, i):
                return refusal
            with execution_output_scope():
                framed = await agent._run_tool(str(name), cargs)
            value = unframe_tool_output(framed)
            from ..tool_results import ToolResultState, ToolResultText, classify_tool_result

            unknown = (classify_tool_result(framed) is ToolResultState.INDETERMINATE
                       if isinstance(framed, ToolResultText)
                       else value.startswith("INDETERMINATE:"))
            if not framed.startswith("<tool_output ") or unknown:
                return (
                    "INDETERMINATE: a declared tool did not provide a complete screened value. "
                    "Script withheld; reconcile prior tool calls and do not repeat them blindly."
                )
            try:
                retained_bytes += result_bytes(value)
                if retained_bytes > MAX_RESULT_BYTES:
                    raise ToolOutputLimit("combined inputs exceed quota")
            except ToolOutputLimit:
                return (
                    "INDETERMINATE: complete declared results exceed the combined 16 MiB input quota. "
                    "Script withheld; prior calls may have executed, so do not retry blindly."
                )
            tool_outputs[var] = value

        # 2. Build the script (complete screened outputs, then the model's code).
        script = _build_script(agent, code, declared, tool_outputs)
        if script.startswith(("ERROR:", "INDETERMINATE:")):
            return script

        # 3. Run the script in the sandbox (off the event loop). stdin carries
        # the script to `python3 -`; only its stdout returns to the model.
        try:
            rc, out, err = await asyncio.to_thread(_run_approved_script, agent, permit, script)
        except ApprovalCardError:
            if declared:
                return (
                    "INDETERMINATE: execution approval changed after declared tools were called; "
                    "the script was withheld. Earlier tools may have run; inspect their effects "
                    "before retrying."
                )
            return "ERROR: code, execution target, or approval authority changed; review it again"
        except Exception as e:  # noqa: BLE001 -- surface as a tool error, don't crash the turn
            return f"ERROR: could not run the script: {type(e).__name__}: {e}"
        if rc != 0:
            return (
                f"ERROR: script exited {rc}.\n"
                f"--- stderr (tail) ---\n{(err or '').strip()[-2000:]}\n"
                f"--- stdout (tail) ---\n{(out or '').strip()[-2000:]}"
            )
        out = (out or "").strip()
        return out or "(script produced no stdout; print() the result you want returned)"

    return Tool(
        name="code_exec",
        description=(
            "Run a Python script in the sandbox to orchestrate work over tool "
            "outputs WITHOUT each raw output entering the conversation. Declare "
            "`tool_calls` (a list of {name, arguments[, as]}); they run first "
            "through the normal safety path and their outputs are injected into "
            "your script as a `tools` dict keyed by your `as` (or '<name>_<i>'). "
            "Your `code` filters/aggregates/computes over them and print()s the "
            "ONLY thing returned to you. Ideal for 'fetch/query N things, then "
            "summarize' so large intermediate data stays out of context. Note: "
            "the script can't issue NEW tool calls mid-run -- declare them up front."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Python to run. Reads `tools[...]`; print() the result.",
                },
                "tool_calls": {
                    "type": "array",
                    "description": "Tool calls to run first; their outputs become `tools`.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "arguments": {"type": "object"},
                            "as": {
                                "type": "string",
                                "description": "Key for this result in `tools` (default '<name>_<i>').",
                            },
                        },
                        "required": ["name"],
                    },
                },
            },
            "required": ["code"],
        },
        fn=fn,
    )


__all__ = ["code_exec_tool"]
