"""Retain a complete human-readable suggestion without executing its tool."""
from __future__ import annotations

import json
import re


def _label(value):
    words = re.sub(r"([a-z])([A-Z])", r"\1 \2", value).replace("_", " ").strip()
    return words[:1].upper() + words[1:]


def _rows(value, *, path="", schema=None, depth=0, rows=None):
    rows = [] if rows is None else rows
    if depth > 8 or len(rows) >= 512:
        raise ValueError("The complete suggestion exceeds the supported review size")
    if isinstance(value, dict):
        if not value:
            rows.append([path or "Details", "No details entered"])
        properties = (schema or {}).get("properties", {})
        for key, child in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise ValueError("The suggestion has an unsupported detail name")
            child_schema = properties.get(key, {})
            name = child_schema.get("title") or _label(key)
            _rows(child, path=f"{path} · {name}" if path else name,
                  schema=child_schema, depth=depth + 1, rows=rows)
    elif isinstance(value, list):
        if not value:
            rows.append([path or "Details", "No items entered"])
        for index, child in enumerate(value):
            _rows(child, path=f"{path} · Item {index + 1}", schema=(schema or {}).get("items", {}),
                  depth=depth + 1, rows=rows)
    elif value is None or isinstance(value, str | bool | int | float):
        rendered = ("Not set" if value is None else "Yes" if value is True else "No"
                    if value is False else "Empty text" if value == "" else str(value))
        rows.append([path or "Details", rendered])
    else:
        raise ValueError("The suggestion has an unsupported detail value")
    return rows


def stage(agent, name, arguments):
    """Existing task artifacts provide encrypted custody, versions and UI controls."""
    from .audit import audit_event
    from .governed_operations import digest
    from .safety.secret_detector import redact

    agent.ctx.budget.check()
    raw = json.dumps(arguments, ensure_ascii=False, allow_nan=False)
    if len(raw.encode()) > 64000:
        raise ValueError("The complete suggestion is too large to save for review")
    safe, _ = redact(raw)
    if safe != raw:
        raise ValueError("Confidential values must be removed before this suggestion can be reviewed")
    tool = agent.tools.get(name)
    rows = [["Execution", "Suggested only. A person must carry out this action; the specialist has not performed it."],
            ["Proposed action", tool.description]] + _rows(arguments, schema=tool.input_schema)
    content = json.dumps({"columns": ["Detail", "Proposed value"], "rows": rows}, ensure_ascii=False, allow_nan=False)
    if len(content.encode()) > 128000:
        raise ValueError("The complete suggestion exceeds the supported review size")
    goal = agent.ctx.world.get_goal(agent.ctx.goal_id)
    if goal is None:
        raise ValueError("The task is no longer available; no action was performed")
    # This is an intent event, never a tool-call/completion or a human approval.
    if not audit_event("human_action_suggested", agent=agent.name, goal_id=goal.id,
                       tool=name, principal=goal.owner, intent_sha256=digest({"tool": name, "arguments": arguments}),
                       suggestion_sha256=digest(json.loads(content))):
        raise ValueError("The suggestion could not be recorded; no action was performed")
    agent.ctx.world.add_artifact(goal.id, "table", "Suggested action for a person", content)
    return ("The complete suggested action is saved in this task’s results. No tool ran and no approval to run it was requested. "
            "Show the person the complete saved suggestion. A person must carry out the action; "
            "do not claim it was executed or retry it to obtain a completion result.")
