"""Expose the governed session kernel to the agent as a tool.

:mod:`maverick.governed_repl` is the governed substrate; this is the seam
that lets the AGENT reach it. Without this the kernel is a library with no
caller — the capability exists but nothing can use it.

Registration is config-gated (``[repl] enable``, off by default) so the tool
does not even appear in the catalog the model sees unless an operator has
admitted arbitrary code execution. That matters beyond safety: an absent
tool costs no prompt tokens and cannot be hallucinated into a call.

One session is opened per goal on first use and reused for the rest of the
run, which is what makes the kernel worth having — state accumulated in
statement N is still there at statement N+1, so the agent can build up a
working context instead of re-deriving it in every call.
"""
from __future__ import annotations

from typing import Any

from . import Tool

#: Session ids, keyed by goal, for the life of this registry. A goal-less
#: run (CLI one-shot, benchmark) shares the ``None`` slot.
_SESSIONS: dict[int | None, str] = {}


def _session_for(goal_id: int | None, principal: str) -> str:
    from .. import governed_repl
    session_id = _SESSIONS.get(goal_id)
    if session_id is not None:
        # A session whose directory was cleaned up underneath us (operator
        # wipe, tmpdir reaper) must not wedge the tool for the whole run.
        try:
            governed_repl.transcript(session_id)
            return session_id
        except governed_repl.ReplError:
            _SESSIONS.pop(goal_id, None)
    session_id = governed_repl.open_session(goal_id, principal=principal)
    _SESSIONS[goal_id] = session_id
    return session_id


def repl_exec(*, goal_id: int | None = None, principal: str = "") -> Tool:
    """The ``repl_exec`` tool: run one Python statement in the goal's kernel."""

    def fn(args: dict[str, Any]) -> str:
        from .. import governed_repl
        code = str(args.get("code") or "")
        if not code.strip():
            return "ERROR: code is required"
        try:
            session_id = _session_for(goal_id, principal)
            result = governed_repl.execute(
                session_id, code, goal_id=goal_id, principal=principal)
        except governed_repl.ReplError as e:
            # A governance refusal is a RESULT the model should read and
            # adapt to, not an exception that kills the turn.
            return f"ERROR: {e}"
        out = result.get("stdout") or ""
        if result.get("stderr"):
            out += f"\n[stderr]\n{result['stderr']}"
        if result.get("truncated"):
            out += "\n[output truncated]"
        dropped = result.get("dropped") or []
        if dropped:
            # Silence here would be a debugging trap: the value looks set
            # but is gone on the next statement.
            out += ("\n[not carried to the next statement (not "
                    f"JSON-serializable): {', '.join(sorted(dropped))}]")
        if not result.get("ok"):
            out += f"\n[exit {result.get('exit_code')}]"
        return out or "[no output]"

    return Tool(
        name="repl_exec",
        description=(
            "Run Python in a persistent session kernel and return its "
            "output. Variables, imports, and function definitions PERSIST "
            "across calls within this goal, so you can build up state "
            "instead of re-deriving it every time.\n\n"
            "Use it to compute, parse, filter, and reshape data — "
            "especially when the alternative is pushing a large "
            "intermediate result through the transcript. Print what you "
            "want to see; the return value of the last expression is not "
            "echoed automatically.\n\n"
            "Limits worth knowing:\n"
            "  • only JSON-serializable globals survive to the next call "
            "(no open files, connections, classes, or arrays) — anything "
            "dropped is named back to you\n"
            "  • no access to Lightwork tools or the world model from "
            "inside the kernel; call those as tools instead\n"
            "  • every statement is bounded, screened, and recorded"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": (
                        "Python source to execute in the session "
                        "namespace. Use print() to surface values."
                    ),
                },
            },
            "required": ["code"],
        },
        fn=fn,
    )
