"""Task-centric Copilot help: what people come to a page to do, and where the control is.

Each page lists the few tasks people most often come to it for. A task is
offered as a suggestion; asking for it (or naming it in a question) answers
with plain steps and a link that opens the page and focuses the exact control
("Open Spending limits" puts the cursor in the amount field). These are
navigation actions only: they open a page, focus a control or filter a list,
and never change anything. The person still makes every change with the page's
own controls and confirmations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_FOCUS = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_HREF = re.compile(r"/[a-z0-9/-]{0,159}(?:\?[a-z_]{1,20}=[a-z0-9_-]{1,40}){0,1}\Z")


@dataclass(frozen=True)
class CopilotTask:
    label: str              # the suggestion: what the person wants to do
    answer: str             # plain steps, true to the page
    href: str               # the page to open (a closed in-app path, optional filter)
    link: str               # the link's words
    focus: str = ""         # the element id to focus on that page
    phrases: tuple[str, ...] = ()  # wordings that ask for this task
    floor: str = "view"     # the permission the task needs ("view", "operate" or "admin")

    def target(self) -> dict:
        target = {"href": self.href, "label": self.link}
        if self.focus:
            target["focus"] = self.focus
        return target


TASKS: dict[str, tuple[CopilotTask, ...]] = {
    "/users": (
        CopilotTask("Invite a colleague",
                    "Under Invite someone by email, enter their email address, pick a role and press "
                    "Create invite link, then send them the link. Viewer is the safe start; you can change it later.",
                    "/users", "Open Invite someone", "invite-email",
                    ("invite", "add a colleague", "add someone", "add a user", "new user"), "admin"),
        CopilotTask("Change someone's role",
                    "Find the person under People, choose a new role next to their name and save it. "
                    "The change applies the next time they open a page.",
                    "/users", "Open People", "people",
                    ("change someone's role", "change a role", "change their role", "make someone an admin"), "admin"),
        CopilotTask("See who is signed in",
                    "The Sessions page lists where people are signed in and lets you sign a device out.",
                    "/sessions", "Open Sessions", "",
                    ("signed in", "sign out a device", "sessions"), "admin"),
    ),
    "/settings": (
        CopilotTask("Set a spending limit",
                    "Under Stop tasks that go over a limit, choose Stop a task when it has spent, enter the "
                    "amount per task and press Save task limit. Tasks stop when they reach it.",
                    "/settings", "Open Spending limits", "settings-task-budget",
                    ("spending limit", "task limit", "budget", "spend limit", "cost limit"), "admin"),
        CopilotTask("Connect an AI service",
                    "Under Provider keys, paste a key from your AI provider's account page, save it, then "
                    "press Test connection to confirm it works.",
                    "/settings", "Open Provider keys", "settings-integrations",
                    ("api key", "provider key", "connect an ai", "ai service", "ai provider"), "admin"),
        CopilotTask("Choose the AI model",
                    "Pick a model in Default model and save. Leave it on Lightwork's recommended model "
                    "if you are not sure.",
                    "/settings", "Open Default model", "settings-model-default",
                    ("which model", "ai model", "default model", "choose a model", "change the model"), "admin"),
    ),
    "/goals": (
        CopilotTask("Show my running tasks",
                    "This filters your tasks to the ones still working, queued or waiting.",
                    "/goals?status=running", "Show running tasks", "",
                    ("running tasks", "tasks that are running", "what is running", "in progress")),
        CopilotTask("Show tasks that failed",
                    "This filters your tasks to the ones that stopped with a problem. Open one to see why "
                    "and try it again.",
                    "/goals?status=failed", "Show failed tasks", "",
                    ("failed tasks", "tasks that failed", "which tasks failed", "show failed")),
        CopilotTask("Find a task by name",
                    "Type part of the task's name in Search tasks; the list narrows as you type.",
                    "/goals", "Search tasks", "run-search-q",
                    ("find a task", "search tasks", "search for a task", "look up a task")),
    ),
    "/chat": (
        CopilotTask("Start a task",
                    "Describe what you need in the message box and press Start task. You can add details "
                    "or attach files first.",
                    "/chat", "Write your request", "composer-title",
                    ("start a task", "new task", "start a chat"), "operate"),
        CopilotTask("Check my task limits",
                    "The line under the message box says how much one task may spend and for how long.",
                    "/chat", "Show task limits", "goal-task-limits",
                    ("task limits", "how much can a task spend", "time limit"), "operate"),
        CopilotTask("Get two viewpoints on a decision",
                    "Open Weighing up a decision?, type the question and press Get two viewpoints. One side "
                    "argues for, one against, and a neutral judge weighs them up.",
                    "/chat", "Open two viewpoints", "viewpoints",
                    ("two viewpoints", "both sides", "weigh up a decision", "decide between"), "operate"),
    ),
    "/approvals": (
        CopilotTask("See decisions on my requests",
                    "Decisions on your requests lists what was approved, refused or sent back, and by whom.",
                    "/approvals", "Open decisions on your requests", "request-decision-history",
                    ("decisions on my requests", "my requests", "decision history", "was it approved")),
    ),
    "/learning": (
        CopilotTask("See what people said about each agent and specialist",
                    "What people said about each agent and specialist counts thumbs up and down for each one "
                    "and the reasons people picked. Written comments stay with each person's task.",
                    "/learning", "Open answer feedback", "agent-feedback",
                    ("feedback", "what people said", "ratings", "thumbs"), "admin"),
    ),
    "/agents": (
        CopilotTask("Change what an agent or specialist may do",
                    "Pick the agent or specialist, change its allowed actions or instructions, then press Save. "
                    "Its change history records who changed it and when.",
                    "/agents", "Open Agent Factory", "",
                    ("allowed actions", "what a specialist may do", "what an agent may do", "agent tools",
                     "change a specialist", "change an agent"), "admin"),
        CopilotTask("Create a custom agent",
                    "Give the agent a name and describe the job in plain words, choose what it may do, then "
                    "press Create custom agent.",
                    "/agents?new=1", "Start a custom agent", "agent-form",
                    ("custom agent", "new agent", "create an agent"), "admin"),
        CopilotTask("See what changed in an agent or specialist",
                    "Open an agent or specialist; Change history lists who changed it, when, and what changed.",
                    "/agents", "Open Agent Factory", "",
                    ("change history", "who changed", "what changed"), "view"),
    ),
}


def _allowed(task: CopilotTask, permissions: frozenset[str] | None) -> bool:
    return permissions is None or task.floor in permissions


def tasks_for(path: str, permissions: frozenset[str] | None = None) -> list[CopilotTask]:
    """The page's tasks this person can carry out, most common first."""
    return [task for task in TASKS.get(path, ()) if _allowed(task, permissions)]


def match(path: str, message: str, permissions: frozenset[str] | None = None) -> CopilotTask | None:
    """The task a question asks for: its exact label, or one of its wordings."""
    text = " ".join(str(message or "").casefold().replace("’", "'").split()).rstrip(".?!")
    if not text:
        return None
    candidates = tasks_for(path, permissions)
    for task in candidates:
        if text == task.label.casefold():
            return task
    scored = [(sum(phrase in text for phrase in task.phrases), index, task)
              for index, task in enumerate(candidates)]
    scored = [item for item in scored if item[0] > 0]
    return min(scored, key=lambda item: (-item[0], item[1]))[2] if scored else None


def reply(task: CopilotTask) -> dict:
    """The deterministic answer: plain steps plus a link that focuses the control."""
    return {"reply": task.answer, "mode": "built_in", "action_link": task.target(),
            "warning": "Nothing was changed. The link opens the page so you can do it yourself."}


def _valid(task: CopilotTask) -> bool:
    return bool(_HREF.fullmatch(task.href)) and (not task.focus or bool(_FOCUS.fullmatch(task.focus)))


if not all(_valid(task) for tasks in TASKS.values() for task in tasks):  # pragma: no cover - import invariant
    raise RuntimeError("invalid Copilot task target")


__all__ = ["TASKS", "CopilotTask", "match", "reply", "tasks_for"]
