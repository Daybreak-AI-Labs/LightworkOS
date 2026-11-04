"""A task's recorded steps, narrated in plain words.

Each goal event becomes one short line a person can follow ("Read a file",
"Asked the Researcher for help", "Checked the answer against your request: it
passed"). The narration is built only from the event's kind, its agent's role
and the tool it used; the recorded text itself (prompts, briefs, tool output,
raw markdown) never becomes the narration. That text stays available behind
"Technical details" on the pages that show steps.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

_AGENT_NAME = re.compile(r"^(?P<role>[A-Za-z0-9_.:]+(?:-[A-Za-z0-9_.:]+)*?)-(?P<depth>\d{1,3})-[0-9a-f]{6}$")
_TOOL_LINE = re.compile(r"^tool=(?P<tool>[\w.:-]+)(?P<rest>[\s\S]*)$")
_FAILED_OUTPUT = ("ERROR", "Error:", "error:", "⚠")
_INTERNAL_KINDS = frozenset({"trace_meta", "tool_signal", "prm"})

# Tool name -> (what it did, the same as "to ..."). Unknown tools still read as
# "Used <action>" from the factory's own action labels.
_TOOLS: dict[str, tuple[str, str]] = {
    "read_file": ("Read a file", "read a file"),
    "write_file": ("Saved a file", "save a file"),
    "apply_patch": ("Changed a file", "change a file"),
    "str_replace_editor": ("Changed a file", "change a file"),
    "ast_edit": ("Changed a file", "change a file"),
    "list_files": ("Looked through the files", "look through the files"),
    "glob": ("Looked through the files", "look through the files"),
    "grep": ("Searched the files", "search the files"),
    "search_files": ("Searched the files", "search the files"),
    "web_search": ("Searched the web", "search the web"),
    "http_fetch": ("Opened a web page", "open a web page"),
    "web_fetch": ("Opened a web page", "open a web page"),
    "browser": ("Used the browser", "use the browser"),
    "knowledge_search": ("Searched company knowledge", "search company knowledge"),
    "shell": ("Ran a command", "run a command"),
    "code_exec": ("Ran a calculation", "run a calculation"),
    "compute": ("Ran a calculation", "run a calculation"),
    "notebook_exec": ("Ran code", "run code"),
    "repl_exec": ("Ran code", "run code"),
    "spawn_subagent": ("Asked a helper to take on part of the work",
                       "ask a helper to take on part of the work"),
    "spawn_swarm": ("Asked several helpers to work on parts of it at once",
                    "ask several helpers to work on parts of it"),
    # The roster it spawns from includes customer-built agents (owner glossary).
    "spawn_specialist": ("Asked an agent or specialist for help", "ask an agent or specialist for help"),
    "delegate_to_agent": ("Handed part of the work to another agent",
                          "hand part of the work to another agent"),
    "send_to_agent": ("Sent a message to another agent", "send a message to another agent"),
    "recv_from_agent": ("Read a message from another agent", "read a message from another agent"),
    "memory": ("Checked what it remembers", "check what it remembers"),
    "email": ("Used email", "use email"),
    "attachments": ("Read the attached files", "read the attached files"),
    "read_tool_result": ("Reread an earlier result", "reread an earlier result"),
}
# A run of the same successful step reads as one line in the live work log.
_PLURALS = {
    "read_file": "Read {count} files",
    "write_file": "Saved {count} files",
    "apply_patch": "Changed files {count} times",
    "web_search": "Searched the web {count} times",
    "http_fetch": "Opened {count} web pages",
    "web_fetch": "Opened {count} web pages",
    "knowledge_search": "Searched company knowledge {count} times",
    "shell": "Ran {count} commands",
    "grep": "Searched the files {count} times",
    "search_files": "Searched the files {count} times",
    "spawn_subagent": "Asked {count} helpers to take on parts of the work",
}

_VERIFY = (
    ("verifier accepted", "Checked the answer against your request: it passed"),
    ("verifier rejected after retry",
     "Checked the answer again: concerns remained, so the revised answer was kept"),
    ("verifier rejected", "Checked the answer and asked for a revision"),
    ("verification skipped (conversational",
     "Skipped the extra check: a short conversational answer that used no tools or files"),
    ("verification skipped (risk-proportional",
     "Skipped the extra check: a low-risk answer that used no tools or code"),
    ("verifier did not complete",
     "Started the extra check, but it could not finish within the spending limit"),
    ("test-driven verifier", "Ran the required tests"),
    ("defensive warnings", "Checked the proposed code change and noted warnings"),
    ("search/replace apply failed", "The proposed code change did not apply, so it is being revised"),
    ("no valid", "The proposed code change did not apply, so it is being revised"),
    ("patch rejected", "The proposed code change did not pass a check, so it is being revised"),
    ("patch failed to apply", "The proposed code change did not apply, so it is being revised"),
)
_ERRORS = (
    ("cancelled via dashboard", "Stopped because someone pressed Stop"),
    ("halted:", "Stopped because work was halted"),
    ("verifier failed", "The extra check could not run"),
    ("budget exceeded", "Stopped at a spending or time limit"),
    ("organization spending limit", "Stopped at the organization's spending limit"),
    ("unpriced model", "Stopped: the selected AI model has no price, so it was not used"),
    ("provider usage accounting", "Stopped: the AI service reported usage Lightwork could not check"),
    ("conversation guidance could not be verified",
     "Paused: your latest guidance could not be confirmed"),
)
_SUPERVISION = {
    "paused by operator": "Paused by a person",
    "resumed by operator": "Resumed by a person",
    "cancelled by operator": "Stopped by a person",
    "prioritized by operator": "Marked as a priority by a person",
}
_PLAIN_KINDS = {
    "artifact": "Produced a file",
    "status": "Updated the task status",
    "progress": "Made progress",
    "denial": "Was not allowed to do a step",
    "model_fallback": "Switched to the backup AI model because the main one was unavailable",
    "skill": "Saved what it learned as a reusable skill",
    "budget_summary": "Added up what the task cost",
    "sample_data": "Ran on made-up sample files",
    "question": "Asked you a question",
    "answer": "Received your answer",
    "thinking": "Thought it through",
    "thought": "Thought it through",
    "handoff": "Handed the work over",
    "result": "Recorded a result",
    "info": "Recorded an update",
    "decision": "Recorded a decision",
    "evidence": "Recorded evidence",
    "supervision": "A person changed how the task runs",
}
GENERIC = "Worked on a step"


@dataclass(frozen=True)
class Step:
    text: str
    group: str = ""
    plural: str = ""
    hidden: bool = False

    def as_dict(self) -> dict:
        return asdict(self)


def agent_parts(agent: object) -> tuple[str, int | None]:
    """``"researcher-1-ab12cd"`` -> ``("researcher", 1)``; other names keep depth None."""
    text = str(agent or "")
    match = _AGENT_NAME.match(text)
    if match is None:
        return text, None
    return match.group("role"), int(match.group("depth"))


def role_title(role: object) -> str:
    """A role or specialist pack, as people know it ("Researcher", "Procurement Specialist")."""
    from .plain_labels import AGENT_ROLES, pack_display_name

    key = str(role or "").strip()
    if not key:
        return "Lightwork"
    if key in AGENT_ROLES:
        return AGENT_ROLES[key][0]
    try:
        from maverick.domain import available_domains

        profile = available_domains().get(key)
    except Exception:  # a missing catalog still reads as words
        profile = None
    if profile is not None:
        return pack_display_name(key, getattr(profile, "persona", ""), getattr(profile, "description", ""))
    return pack_display_name(key)


def who(agent: object) -> str:
    """The agent behind a step, in words: the planner, a helper, or a person."""
    role, depth = agent_parts(agent)
    if depth is None:
        lowered = role.casefold()
        if lowered in {"supervisor", "operator", "dashboard"}:
            return "A person"
        if lowered in {"lightwork", "system", ""}:
            return "Lightwork"
    return role_title(role)


def _tool_label(name: str) -> tuple[str, str]:
    if name in _TOOLS:
        return _TOOLS[name]
    try:
        from maverick.domain_edit import _action_label

        action = _action_label(name)
    except Exception:  # pragma: no cover -- labels are best effort
        action = name.replace("_", " ")
    lowered = action[:1].lower() + action[1:]
    return f"Used a tool: {lowered}", f"use a tool ({lowered})"


def _tool_step(kind: str, tool: str, rest: str) -> Step:
    done, base = _tool_label(tool)
    output = rest.split("->", 1)[1].strip() if "->" in rest else ""
    head = rest.strip().upper()
    if kind == "error" or head.startswith(("DENIED", "BLOCKED", "GATED")) or " DENIED" in head[:120]:
        return Step(f"Was not allowed to {base}", group=f"denied:{tool}")
    if tool == "ask_user":
        return Step("Asked you a question", group="ask_user")
    if output.startswith(_FAILED_OUTPUT):
        return Step(f"Tried to {base}, but it did not work", group=f"failed:{tool}")
    return Step(done, group=f"tool:{tool}", plural=_PLURALS.get(tool, ""))


def _matched(content: str, table) -> str:
    lowered = content.strip().casefold()
    for prefix, text in table:
        if lowered.startswith(prefix):
            return text
    return ""


def _by_depth(depth: int | None, title: str, root: str, helper: str, other: str) -> Step:
    if depth == 0:
        return Step(root)
    return Step(helper.format(title=title) if title else other)


def _plan(content: str, depth: int | None, title: str) -> Step:
    if content.strip().casefold().startswith("resumed from checkpoint"):
        return Step("Picked up where it left off")
    return _by_depth(depth, title, "Started working on your request",
                     "{title} started on its part of the work", "Planned the next steps")


def _note(content: str, depth: int | None, title: str) -> Step:
    lowered = content.strip().casefold()
    if lowered.startswith("review checkpoint"):
        return Step("Paused at a review checkpoint")
    if lowered.startswith("stopping at $"):
        return Step("Stopped early to keep enough budget for the final answer")
    return Step("Made a note")


_BY_KIND = {
    "plan": _plan,
    "observation": lambda content, depth, title: _by_depth(
        depth, title, "Worked out the next step", "{title} worked out its next step",
        "Worked out the next step"),
    "finding": lambda content, depth, title: _by_depth(
        depth, title, "Wrote the answer", "{title} reported back", "Shared what it found"),
    "verify": lambda content, depth, title: Step(_matched(content, _VERIFY) or "Checked the work"),
    "error": lambda content, depth, title: Step(_matched(content, _ERRORS) or "Ran into a problem"),
    "note": _note,
    "supervision": lambda content, depth, title: Step(
        _SUPERVISION.get(content.strip().casefold(), _PLAIN_KINDS["supervision"])),
}


def narrate(kind: object, agent: object, content: object) -> Step:
    """One plain line for a recorded step; internal bookkeeping is hidden."""
    kind = str(kind or "").strip().lower()
    content = str(content or "")
    if kind in _INTERNAL_KINDS:
        return Step("", hidden=True)
    tool = _TOOL_LINE.match(content.strip())
    if tool and kind in {"observation", "error", "tool", "tool_call"}:
        return _tool_step(kind, tool.group("tool"), tool.group("rest"))
    handler = _BY_KIND.get(kind)
    if handler is None:
        return Step(_PLAIN_KINDS.get(kind, GENERIC))
    role, depth = agent_parts(agent)
    return handler(content, depth, role_title(role) if depth is not None else "")


def event_payload(event) -> dict:
    """The live-stream shape of one event, with its plain narration."""
    return {"id": event.id, "agent": event.agent, "kind": event.kind,
            "content": event.content, "ts": event.ts,
            "step": narrate(event.kind, event.agent, event.content).as_dict(),
            "who": who(event.agent)}


__all__ = ["GENERIC", "Step", "agent_parts", "event_payload", "narrate", "role_title", "who"]
