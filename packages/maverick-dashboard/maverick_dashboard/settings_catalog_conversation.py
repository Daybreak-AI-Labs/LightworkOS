"""Administrator ceilings for durable conversation admission."""
from __future__ import annotations


def entries(setting):
    group, reader = "Chat channels", "maverick.conversation_inbox"
    return (
        setting("chat_message_actions", "enabled", "Allow alternative conversation answers",
                "Let people try an answer again, edit and resend their message, or branch from an earlier answer. The original conversation is kept. Alternatives use current access and spending limits; connected actions require a separate review.",
                "toggle", group, True, "maverick.config"),
        setting("conversation_inbox", "enabled", "Keep conversation responsive during tasks",
                "Let people send messages while a task runs: guidance the task reads at its next safe point, the next task in the conversation, or a separate task. On by default. Separate tasks remain subject to current permissions, task ownership and spending limits.",
                "toggle", group, True, reader),
        setting("conversation_inbox", "guidance", "Allow reviewed guidance during a task",
                "Task owners review additional instructions before delivery at a safe checkpoint. Guidance never starts a separate task.",
                "toggle", group, True, reader),
        setting("conversation_inbox", "queue", "Allow queued conversation messages",
                "Save the next message and selected files until earlier conversation work finishes. Current access and spending limits are checked before execution.",
                "toggle", group, True, reader),
        setting("conversation_inbox", "independent", "Allow explicitly separate conversation tasks",
                "Let an owner choose a new task with no context or an explicitly selected read-only snapshot. The new task has its own execution owner and existing concurrency limits.",
                "toggle", group, True, reader),
        setting("conversation_inbox", "max_pending", "Pending messages per conversation",
                "Maximum messages awaiting review, safe delivery or task admission. Lower workspace limits can narrow this organization ceiling.",
                "number", group, 20, reader, minimum=1, maximum=100, integer=True),
    )
