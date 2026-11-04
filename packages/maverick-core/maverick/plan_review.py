"""The plan a person checks before a task's first outside action.

With ``[autonomy] confirm_plan`` on, :meth:`maverick.agent.Agent._plan_denial`
asks once per task run. This module writes what the person reads, in plain
words: the plan's steps, the first action with what it reaches, every other
outside action the agent can take later, the task's spending cap, and what
approving or rejecting does. Nothing here decides anything.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

# Everyday tools: (plain phrase, phrase with the argument, argument name).
_PHRASES: dict[str, tuple[str, str, str]] = {
    "send_email": ("send an email", "send an email to {}", "to"),
    "email_send": ("send an email", "send an email to {}", "to"),
    "http_fetch": ("open a web page", "open the web page {}", "url"),
    "http_request": ("call an outside web service", "call the web service at {}", "url"),
    "web_search": ("search the web", "search the web for “{}”", "query"),
    "write_file": ("change a file in the workspace", "change the file {}", "path"),
    "apply_patch": ("change files in the workspace", "change files in the workspace", ""),
    "delete_file": ("delete a file", "delete the file {}", "path"),
    "shell": ("run a command", "run a command", ""),
    "python_exec": ("run a program", "run a program", ""),
    "send_message": ("send a chat message", "send a chat message to {}", "channel"),
    "slack_post": ("post in Slack", "post in the Slack channel {}", "channel"),
    "send_payment": ("make a payment", "make a payment of {}", "amount"),
    "browser_click": ("click on a web page", "click on a web page", ""),
    "browser_type": ("type into a web page", "type into a web page", ""),
}
_MAX_LISTED = 12


def plain_action(name: str, args: Mapping | None = None) -> str:
    """One tool call in plain words, lower case, with its main target."""
    plain, with_arg, key = _PHRASES.get(name, ("", "", ""))
    if not plain:
        return "use " + " ".join(w for w in re.split(r"[_\-.\s]+", str(name)) if w).lower()
    value = (args or {}).get(key) if key else None
    if key and value not in (None, ""):
        return with_arg.format(" ".join(str(value).split())[:120])
    return with_arg if not key else plain


# Everything else the agent can do, grouped in plain words by the words in
# each tool's name (first match wins); the rest are counted and named.
_GROUPS: tuple[tuple[str, frozenset[str]], ...] = (
    ("send messages or email", frozenset({"email", "mail", "slack", "teams", "message", "notify", "sms", "post",
                                          "tweet", "discord", "send"})),
    ("make payments or refunds", frozenset({"pay", "payment", "refund", "transfer", "charge", "payout"})),
    ("change files in the workspace", frozenset({"file", "files", "patch", "editor", "edit"})),
    ("run commands or programs", frozenset({"shell", "exec", "bash", "terminal", "command", "python", "code"})),
    ("open web pages or call outside services", frozenset({"http", "fetch", "browser", "web", "url", "scrape",
                                                           "request"})),
    ("save notes to its memory", frozenset({"memory", "remember", "kv", "note", "notes"})),
    ("change records in connected systems", frozenset({"create", "update", "delete", "upsert", "crm", "ticket"})),
)
_NAMED_OTHERS = 4


def _words(name: str) -> list[str]:
    return [w for w in re.split(r"[_\-.\s]+", str(name).lower()) if w]


def outside_actions(tool_names: Iterable[str], first: str) -> list[str]:
    """Plain words for every other tool that would leave Lightwork or change
    something, grouped; tools no group fits are counted and named."""
    from .practice import tool_allowed

    groups: list[str] = []
    others: list[str] = []
    for name in dict.fromkeys(tool_names):
        if name == first or tool_allowed(name):
            continue
        words = set(_words(name))
        group = next((label for label, keys in _GROUPS if words & keys), None)
        if group is None:
            others.append(" ".join(_words(name)))
        elif group not in groups:
            groups.append(group)
    groups.sort(key=[label for label, _keys in _GROUPS].index)
    if len(others) > _NAMED_OTHERS:  # a long list of tool names helps nobody decide
        groups.append(f"use {len(others):,} other tools it has been given")
    elif others:
        groups.append(f"use {len(others)} other tool{'s' if len(others) != 1 else ''}: {', '.join(others)}")
    return groups


def summary_text(steps: list[str], name: str, args: Mapping, cap: float | None) -> str:
    """The same review as one paragraph, for channels without the card."""
    plan = "; ".join(f"{i}. {step}" for i, step in enumerate(steps, 1)) or "No written plan was recorded."
    return (f"Lightwork wants to start acting on this task. Plan so far: {plan} "
            f"First action: {plain_action(name, args)}. "
            + (f"Spending cap for this task: ${cap:.2f}. " if cap is not None else "")
            + "Approve to let it carry on, reject to stop before anything runs, or send it back "
              "with what to change.")


def plan_card(goal_id: int, steps: list[str], name: str, args: Mapping,
              tool_names: Iterable[str], cap: float | None) -> dict:
    """The approval card: the plan's steps and the outside actions, in plain words."""
    from .safety.consent import described_approval_card

    first = plain_action(name, args)
    later = outside_actions(tool_names, name)
    effects = []
    if later:
        listed = ", ".join(later[:_MAX_LISTED]) + (", and more" if len(later) > _MAX_LISTED else "")
        effects.append(f"Later in this task it can also: {listed}.")
    effects.append("Each later step that your rules send for approval still asks first.")
    if cap is not None:
        effects.append(f"Spending cap for this task: ${cap:.2f} (a cap, not an estimate).")
    effects.append("If you reject, nothing runs and the task stops so the request can be changed.")
    return described_approval_card(
        "Check the plan before this task acts",
        scope=f"task {goal_id}",
        summary="Lightwork wants to start acting on this task. Check its plan and what it will do outside Lightwork.",
        target_label=f"Task {goal_id}",
        request={"goal_id": goal_id, "steps": steps[:20], "first_action": name,
                 "outside_tools": sorted(set(tool_names))[:200]},
        what_it_will_do=[*(f"Step {i}: {step}" for i, step in enumerate(steps[:20], 1)),
                         f"First outside action: {first}"],
        known_effects=effects,
        open_questions=[] if steps else ["The task wrote no plan before this first action."],
        before="Nothing has run outside Lightwork for this task yet.",
        after="The task carries on with this plan.",
        irreversible=False,
    )


__all__ = ["outside_actions", "plain_action", "plan_card", "summary_text"]
