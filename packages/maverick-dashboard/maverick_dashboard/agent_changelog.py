"""A short record of changes to each agent, so people can see when the AI changed.

Every saved change to what an agent is told (its instructions, workflow,
allowed actions) or which AI model it uses adds one entry: who changed it,
when, and what changed in plain words. Changes made in the agent editor are
recorded against that agent; changes to workspace-wide model routing or core
roles are recorded against :data:`EVERY_AGENT` because they change every
agent's answers.

Append-only NDJSON in the current workspace's data directory (0600,
best-effort, bounded tail), the same shape as the feedback store. Entries
never contain task content.
"""
from __future__ import annotations

import time

from maverick.ndjson_log import append_row, tail_rows
from maverick.paths import data_dir

EVERY_AGENT = "*"
_MAX_ROWS = 2000
_MAX_CHANGES = 8

# Pack fields people would recognise, in the order a change is reported.
_INSTRUCTION_FIELDS = ("persona", "description")
_FIELD_WORDS = (
    (("allow_tools", "deny_tools"), "Changed what it is allowed to do"),
    (("max_risk",), "Changed the riskiest kind of action it may take"),
    (("knowledge_sources",), "Changed the company knowledge it can search"),
    (("output",), "Changed what it hands back"),
    (("compartment",), "Changed its safety compartment"),
    (("effort",), "Changed how much effort it puts into answers"),
)


def _path():
    return data_dir("dashboard", "agent-changelog.ndjson")


def record(agent: str, changes: list[str], *, by: str = "") -> dict | None:
    """Add one entry for ``agent`` (or :data:`EVERY_AGENT`). Never raises."""
    changes = [str(change) for change in changes if str(change or "").strip()][:_MAX_CHANGES]
    if not changes or not str(agent or ""):
        return None
    row = {"ts": time.time(), "agent": str(agent), "by": str(by or ""), "changes": changes}
    return row if append_row(_path(), row) else None


def entries(agent: str | None = None, *, limit: int = 10, include_workspace: bool = True) -> list[dict]:
    """Newest-first entries for ``agent``; workspace-wide entries are included
    unless ``include_workspace`` is false. ``agent=None`` returns every entry."""
    wanted = {str(agent)} if agent is not None else None
    if wanted is not None and include_workspace:
        wanted.add(EVERY_AGENT)
    rows = [row for row in tail_rows(_path(), _MAX_ROWS)
            if isinstance(row.get("changes"), list) and isinstance(row.get("ts"), (int, float))
            and (wanted is None or str(row.get("agent", "")) in wanted)]
    # The file is oldest first. Reversing it before the stable sort keeps the
    # later record first when two share a clock reading (a coarse clock can
    # give equal stamps). A clock stepped back still orders by its stamp, so
    # this covers equal readings only.
    rows.reverse()
    rows.sort(key=lambda row: row["ts"], reverse=True)
    return rows[:max(0, int(limit))]


def _role_words(role: str) -> str:
    from .plain_labels import agent_role_title

    return agent_role_title(role)


def _model_words(spec: object) -> str:
    from .plain_labels import model_label

    return model_label(spec) or "the default model"


def _model_changes(before: dict, after: dict) -> list[str]:
    old, new = dict(before or {}), dict(after or {})
    return [f"Changed the AI model it uses for the {_role_words(role)}: "
            f"{_model_words(old.get(role))} to {_model_words(new.get(role))}"
            for role in sorted(set(old) | set(new)) if old.get(role) != new.get(role)]


def describe_agent_change(before: dict | None, after: dict | None) -> list[str]:
    """What changed between two editor views of one agent, in plain words."""
    if before is None and after is None:
        return []
    if before is None:
        return ["Created this agent"]
    if after is None:
        return ["Removed this agent"]
    changes: list[str] = []
    if any(before.get(field) != after.get(field) for field in _INSTRUCTION_FIELDS):
        changes.append("Changed its instructions")
    if before.get("workflow") != after.get("workflow"):
        changes.append("Changed its workflow steps")
    changes.extend(text for fields, text in _FIELD_WORDS
                   if any(before.get(field) != after.get(field) for field in fields))
    changes.extend(_model_changes(before.get("models"), after.get("models")))
    return changes


def describe_role_change(role: str, before: dict | None, after: dict | None) -> list[str]:
    """A core role's instructions, model or effort changed for every agent."""
    before, after = dict(before or {}), dict(after or {})
    title = _role_words(role)
    changes = []
    if before.get("system_addendum", "") != after.get("system_addendum", ""):
        changes.append(f"Changed the instructions the {title} follows for every agent and specialist")
    if before.get("model") != after.get("model"):
        changes.append(f"Changed the AI model the {title} uses for every agent and specialist: "
                       f"{_model_words(before.get('model'))} to {_model_words(after.get('model'))}")
    if before.get("effort") != after.get("effort"):
        changes.append(f"Changed how much effort the {title} puts into answers for every agent and specialist")
    return changes


def describe_default_model(before: object, after: object) -> list[str]:
    if before == after:
        return []
    return [f"Changed the default AI model for every agent and specialist: {_model_words(before)} to {_model_words(after)}"]


def describe_role_models(before: dict, after: dict) -> list[str]:
    old, new = dict(before or {}), dict(after or {})
    return [f"Changed the AI model the {_role_words(role)} uses for every agent and specialist: "
            f"{_model_words(old.get(role))} to {_model_words(new.get(role))}"
            for role in sorted(set(old) | set(new)) if old.get(role) != new.get(role)]


def agent_kind(agent: str) -> str:
    """``"specialist"`` for one of Lightwork's built-in packs (a customized copy
    included), ``"agent"`` for everything else: customer-built agents and the
    general assistant. Copy uses the word this returns."""
    if not agent or agent == EVERY_AGENT:
        return "agent"
    try:
        from maverick.domain import builtin_domains

        return "specialist" if str(agent) in builtin_domains() else "agent"
    except Exception:  # an unreadable catalog never promotes an agent to specialist
        return "agent"


def agent_title(agent: str) -> str:
    """The name people know an agent by; the general assistant is Lightwork."""
    if not agent:
        return "Lightwork"
    from .step_narration import role_title

    return role_title(agent)


def version_label(agent: str, *, answered_at: float | None) -> dict:
    """Which version of the agent answered, and what changed after the answer.

    ``updated_at`` is the newest change made before the answer (``None`` when
    the agent has not changed since it was installed, or for changes this
    record does not cover). ``changed_since`` lists the changes made after it.
    """
    rows = entries(agent or EVERY_AGENT, limit=50)
    if answered_at is None:
        before, after = rows, []
    else:
        before = [row for row in rows if row["ts"] <= answered_at]
        after = [row for row in rows if row["ts"] > answered_at]
    return {"agent": agent_title(agent), "kind": agent_kind(agent), "updated_at": before[0]["ts"] if before else None,
            "changes": before[:3], "changed_since": after[:3]}


__all__ = [
    "EVERY_AGENT", "agent_kind", "agent_title", "describe_agent_change", "describe_default_model",
    "describe_role_change", "describe_role_models", "entries", "record", "version_label",
]
