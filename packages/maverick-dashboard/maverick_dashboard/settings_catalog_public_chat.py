"""Administrator switches for the public website chat widget."""
from __future__ import annotations


def entries(setting):
    group, reader = "Chat channels", "maverick_dashboard.public_chat_api"
    return (
        setting("public_chat", "enabled", "Chat box on your public website",
                "Let anonymous visitors on a listed website ask one published specialist's questions. "
                "Off by default. Each website is listed exactly and has a daily spending limit. "
                "Visitors cannot use tools or see records. Administrators add, rotate and stop websites on the Channels page, under Chat on your public website.",
                "toggle", group, False, reader),
        setting("public_chat", "allow_localhost_origins", "Allow a local test address for the chat",
                "For development only: lets a website at http://localhost use the chat. "
                "Off by default; never turn this on for a public website.",
                "toggle", group, False, reader),
    )
