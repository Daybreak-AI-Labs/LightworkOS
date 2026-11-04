"""Tool-use checks for saved answer checks, run against recording stubs only.

A check with ``with_tools`` says which tools the specialist must call, which it must
not call, and text a call must include. It may also give a fixed result per tool.
The model is offered stub tools only: each call is recorded (name and bounded
arguments) and answered with the check's fixed result, or with a fixed "not
available in a test" result. Nothing here reaches the real tool registry, a
sandbox, the network, a file or a shell.
"""
from __future__ import annotations

import json
import re
from typing import Any

# Model turns and tool calls one tool check may use. Calls also count against the run's budget.
MAX_TOOL_STEPS = 4
MAX_TOOL_CALLS = 4
MAX_TOOL_NAMES = 10      # tool names one check names, across its expectations and results
MAX_TOOLS_OFFERED = 30   # stub tools offered to the model in one check
MAX_RESULT_CHARS = 500

_RECORD_LIMIT = 1000     # characters of arguments kept in a run record
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_NOT_AVAILABLE = "This tool is not available in a test. Nothing was run."
_LIMIT_REACHED = "This test allowed no more tool calls. Nothing was run."
_STUB_DESCRIPTION = "Test stub: this call is recorded and answered with a fixed result. Nothing runs."


def _bounded(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit]


def _match_text(value: Any) -> str:
    """Every key and value in a call's arguments as plain text, untruncated, for "must include" checks."""
    if isinstance(value, dict):
        return "\n".join(part for key, item in value.items() for part in (str(key), _match_text(item)))
    if isinstance(value, list):
        return "\n".join(_match_text(item) for item in value)
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)


def _clean_name(value: Any) -> str:
    name = " ".join(str(value or "").split())
    if not _NAME.match(name):
        raise ValueError("Each tool name must start with a letter and use only letters, numbers, dots, dashes or underscores.")
    return name


def normalized(*, enabled: bool, with_tools: bool, called: list[dict], not_called: list[str],
               results: list[dict]) -> dict:
    """The stored tool fields for one check. Raises ``ValueError`` with a plain reason."""
    if not with_tools:
        if called or not_called or results:
            raise ValueError("Turn on tool checks to name tools, or remove the tool lines.")
        return {"with_tools": False, "tools_called": [], "tools_not_called": [], "tool_results": []}
    if not enabled:
        raise ValueError("Tool checks are turned off. An administrator can turn them on in All settings "
                         "under Saved answer checks.")
    expect_called = [{"name": _clean_name(row.get("name")), "contains": " ".join(str(row.get("contains") or "").split())}
                     for row in called]
    expect_absent = [_clean_name(name) for name in not_called]
    if not expect_called and not expect_absent:
        raise ValueError("Name at least one tool the specialist must call or must not call.")
    if {row["name"] for row in expect_called} & set(expect_absent):
        raise ValueError("A tool cannot be both required and forbidden in the same check.")
    if any(len(row["contains"]) > 100 for row in expect_called):
        raise ValueError("The text a call must include can be at most 100 characters.")
    canned = []
    for row in results:
        name = _clean_name(row.get("name"))
        text = str(row.get("text") or "").strip()
        if not text or len(text) > MAX_RESULT_CHARS:
            raise ValueError(f"The canned result for {name} must have between 1 and {MAX_RESULT_CHARS} characters.")
        canned.append({"name": name, "text": text})
    if len({row["name"] for row in canned}) != len(canned):
        raise ValueError("Give each tool one canned result at most.")
    names = {row["name"] for row in expect_called} | set(expect_absent) | {row["name"] for row in canned}
    if len(names) > MAX_TOOL_NAMES:
        raise ValueError(f"One check can name at most {MAX_TOOL_NAMES} tools.")
    return {"with_tools": True, "tools_called": expect_called, "tools_not_called": expect_absent,
            "tool_results": canned}


def named_tools(case: dict) -> list[str]:
    """Every tool the check names, in a stable order."""
    names = [row["name"] for row in case.get("tools_called") or []]
    names += list(case.get("tools_not_called") or [])
    names += [row["name"] for row in case.get("tool_results") or []]
    return list(dict.fromkeys(names))


def offered_tools(case: dict, *, allow: list[str], deny: list[str]) -> list[str]:
    """The stub tools offered to the model: the named ones, then the pack's allowed ones it does not deny."""
    extra = [name for name in allow if name not in set(deny)]
    return list(dict.fromkeys([*named_tools(case), *extra]))[:MAX_TOOLS_OFFERED]


def budget_questions(cases: list[dict], *, enabled: bool) -> int:
    """How many questions the run's spending allowance is sized for: a tool check counts as several."""
    return sum(MAX_TOOL_STEPS if enabled and case.get("with_tools") else 1 for case in cases)


def tool_call_ceiling(cases: list[dict], *, enabled: bool) -> int:
    """The run's tool-call allowance: a few calls for each tool check, none when there are none."""
    return MAX_TOOL_CALLS * sum(1 for case in cases if enabled and case.get("with_tools"))


def tool_step_tokens(output_ceiling: int | None) -> int:
    """Output tokens for one tool-using model turn: an equal share of the run's output allowance, 32 to 256."""
    if output_ceiling is None:
        return 256
    return max(32, min(256, output_ceiling // MAX_TOOL_STEPS))


def tool_check_results(case: dict, calls: list[dict]) -> list[dict]:
    """One plain-words line per expectation, each passed or not."""
    results = []
    for expect in case.get("tools_called") or []:
        name, contains = expect["name"], expect.get("contains") or ""
        suffix = f' with "{contains}" in the call' if contains else ""
        named = [call for call in calls if call["name"] == name]
        if not named:
            outcome, passed = f"Did not call {name}.", False
        elif contains and not any(contains.casefold() in call.get("match", call["arguments"]).casefold() for call in named):
            outcome, passed = f'Called {name}, but no call included "{contains}".', False
        else:
            outcome, passed = f"Called {name}{suffix}.", True
        results.append({"check": f"Must call {name}{suffix}", "passed": passed, "result": outcome})
    for name in case.get("tools_not_called") or []:
        if any(call["name"] == name for call in calls):
            results.append({"check": f"Must not call {name}", "passed": False,
                            "result": f"Called {name}, which it must not call."})
        else:
            results.append({"check": f"Must not call {name}", "passed": True, "result": f"Did not call {name}."})
    return results


class ToolStubs:
    """Records each call and answers it. It never reaches a real tool."""

    def __init__(self, names: list[str], canned: dict[str, str]):
        self._names = set(names)
        self._canned = canned
        self.calls: list[dict] = []

    def answer(self, name: str, arguments: Any, *, allowed: bool = True) -> str:
        text = _bounded(json.dumps(arguments, ensure_ascii=False, sort_keys=True, default=str), _RECORD_LIMIT)
        if not allowed:
            kind, reply = "limit", _LIMIT_REACHED
        elif name in self._names and name in self._canned:
            kind, reply = "canned", self._canned[name]
        elif name in self._names:
            kind, reply = "not_available", _NOT_AVAILABLE
        else:
            kind, reply = "not_offered", _NOT_AVAILABLE
        # "match" holds the untruncated text for grading only; it is never stored in a run record.
        self.calls.append({"name": _bounded(str(name), 64), "arguments": text, "answer": kind,
                           "match": _match_text(arguments)})
        return reply


def stub_schemas(names: list[str]) -> list[dict]:
    return [{"name": name, "description": _STUB_DESCRIPTION,
             "input_schema": {"type": "object", "additionalProperties": True}} for name in names]


def run_tool_check(llm: Any, *, system: str, task: str, case: dict, names: list[str], budget: Any,
                   before_call, max_tokens: int) -> tuple[str, list[dict]]:
    """One bounded tool-using answer through ``llm``. Returns the final text and the recorded calls.

    ``before_call`` runs before every provider call and must raise to refuse. A budget
    refusal from ``budget.record_tool_call`` propagates to the caller.
    """
    stubs = ToolStubs(names, {row["name"]: row["text"] for row in case.get("tool_results") or []})
    schemas = stub_schemas(names)
    messages: list[dict] = [{"role": "user", "content": task}]
    text = ""
    for _ in range(MAX_TOOL_STEPS):
        before_call()
        response = llm.complete(system, messages, tools=schemas, budget=budget, max_tokens=max_tokens,
                                _no_failover=True)
        text = response.text or ""
        if not response.tool_calls:
            break
        content: list[dict] = [{"type": "text", "text": response.text}] if response.text else []
        content += [{"type": "tool_use", "id": call.id, "name": call.name, "input": call.input}
                    for call in response.tool_calls]
        messages.append({"role": "assistant", "content": content})
        blocks, exhausted = [], False
        for call in response.tool_calls:
            allowed = sum(1 for row in stubs.calls if row["answer"] != "limit") < MAX_TOOL_CALLS
            if allowed:
                budget.record_tool_call()
            exhausted = exhausted or not allowed
            blocks.append({"type": "tool_result", "tool_use_id": call.id,
                           "content": stubs.answer(call.name, call.input, allowed=allowed)})
        messages.append({"role": "user", "content": blocks})
        if exhausted:
            break
    return text, stubs.calls
