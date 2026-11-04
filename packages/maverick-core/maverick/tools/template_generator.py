"""Skill + channel template generators.

Scaffold a valid starting point so contributors don't hand-copy boilerplate:
  - a ``SKILL.md`` with the right frontmatter (name / triggers / tools_needed),
  - a channel adapter module that subclasses the channels ``base.Channel`` and
    stubs the three abstract methods (``start`` / ``send`` / ``stop``).

Deterministic string generation — it emits the file *contents* (the caller
writes them where they belong). Names are validated/slugified so the output is
always importable / parseable.
"""
from __future__ import annotations

import json
import re
from typing import Any

from . import Tool

_SLUG = re.compile(r"[^a-z0-9_]+")


def _slug(name: str, *, dashes: bool = True) -> str:
    s = name.strip().lower()
    s = re.sub(r"[\s-]+", "-" if dashes else "_", s)
    s = re.sub(r"[^a-z0-9_-]+", "", s)
    return s.strip("-_")


def _skill(name: str, triggers: list[str], tools: list[str]) -> str:
    slug = _slug(name)
    if not slug:
        return "ERROR: name must contain at least one alphanumeric character"
    trig = triggers or [f"use {slug}"]
    # YAML frontmatter accepts JSON-style flow sequences. Serialize the
    # user-provided strings instead of interpolating them so embedded quotes,
    # backslashes, newlines, and frontmatter delimiters cannot reshape the
    # generated SKILL.md or inject body content.
    trig_arr = json.dumps(trig, ensure_ascii=False)
    tools_arr = json.dumps(tools, ensure_ascii=False)
    title = name.strip().title()
    return (
        "---\n"
        f"name: {slug}\n"
        f"triggers: {trig_arr}\n"
        f"tools_needed: {tools_arr}\n"
        "---\n"
        f"# {title}\n\n"
        f"Describe, step by step, how the agent should accomplish "
        f"\"{name.strip()}\". Reference each tool in tools_needed and end with "
        "the concrete deliverable.\n"
    )


def _channel(name: str) -> str:
    mod = _slug(name, dashes=False)
    if not mod:
        return "ERROR: name must contain at least one alphanumeric character"
    cls = "".join(p.capitalize() for p in mod.split("_")) + "Channel"
    return (
        '"""' f"{mod} channel adapter (scaffold).\n\n"
        f"Wire this into packages/maverick-channels and add a [channels.{mod}] "
        'config knob + an installer-wizard step (CLAUDE.md #5/#6).\n"""\n'
        "from __future__ import annotations\n\n"
        "from .base import Channel\n\n\n"
        f"class {cls}(Channel):\n"
        f'    """Adapter for {mod}. Fill in the transport calls."""\n\n'
        "    def __init__(self, config: dict) -> None:\n"
        "        self.config = config\n\n"
        "    async def start(self) -> None:\n"
        "        # Connect / begin receiving inbound messages.\n"
        "        raise NotImplementedError\n\n"
        "    async def send(self, user_id: str, text: str) -> None:\n"
        "        # Deliver an outbound message to user_id.\n"
        "        raise NotImplementedError\n\n"
        "    async def stop(self) -> None:\n"
        "        # Disconnect / clean up.\n"
        "        raise NotImplementedError\n"
    )


def _run(args: dict[str, Any]) -> str:
    kind = args.get("kind")
    name = args.get("name")
    if not isinstance(name, str) or not name.strip():
        return "ERROR: name is required"
    if kind == "skill":
        triggers = [str(t) for t in (args.get("triggers") or []) if str(t).strip()]
        tools = [str(t) for t in (args.get("tools_needed") or []) if str(t).strip()]
        return _skill(name, triggers, tools)
    if kind == "channel":
        return _channel(name)
    return "ERROR: kind must be 'skill' or 'channel'"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "kind": {"type": "string", "enum": ["skill", "channel"]},
        "name": {"type": "string", "description": "Human name of the skill/channel"},
        "triggers": {"type": "array", "items": {"type": "string"},
                     "description": "Trigger phrases (skill only)"},
        "tools_needed": {"type": "array", "items": {"type": "string"},
                         "description": "Tool names the skill uses (skill only)"},
    },
    "required": ["kind", "name"],
}


def template_generator() -> Tool:
    return Tool(
        name="template_generator",
        description=(
            "Scaffold a new skill or channel. kind=skill with 'name' "
            "(+ optional triggers/tools_needed) emits a valid SKILL.md; "
            "kind=channel emits a channels/base.Channel subclass stubbing "
            "start/send/stop. Returns the file contents; names are slugified."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
