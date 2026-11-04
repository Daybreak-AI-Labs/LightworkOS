"""MCP prompt catalog and argument-to-message projection."""
from __future__ import annotations

from .protocol import ProtocolError as _ProtocolError


def list_prompts(params: dict) -> dict:
    return {"prompts": [
        {
            "name": "research_topic",
            "description": "Spawn a research swarm to investigate a topic.",
            "arguments": [
                {"name": "topic", "description": "What to research",
                 "required": True},
                {"name": "depth", "description": "shallow / medium / deep",
                 "required": False},
            ],
        },
        {
            "name": "draft_message",
            "description": "Draft an email / message in a given tone.",
            "arguments": [
                {"name": "recipient", "required": True},
                {"name": "intent", "required": True},
                {"name": "tone", "required": False},
            ],
        },
        {
            "name": "compare_options",
            "description": "Compare 2-N options against a criterion list.",
            "arguments": [
                {"name": "options", "required": True},
                {"name": "criteria", "required": True},
            ],
        },
    ]}

def get_prompt(params: dict) -> dict:
    name = params.get("name", "")
    if not isinstance(name, str):
        raise _ProtocolError(-32602, "name must be a string")
    args = params.get("arguments", {})
    if args is None:  # a client that sends an omitted optional as null (as tools/call allows)
        args = {}
    if not isinstance(args, dict):
        raise _ProtocolError(-32602, "arguments must be an object")
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in args.items()):
        raise _ProtocolError(-32602, "prompt arguments must have string names and values")
    templates = {
        "research_topic": (
            "Spawn a research swarm to investigate: {topic}. "
            "Depth: {depth}. Verify findings before FINAL."
        ),
        "draft_message": (
            "Draft a message to {recipient} with intent: {intent}. "
            "Tone: {tone}. Keep it concise."
        ),
        "compare_options": (
            "Compare these options: {options}. Use criteria: {criteria}. "
            "Build a table; recommend one."
        ),
    }
    if name not in templates:
        raise _ProtocolError(-32602, f"unknown prompt: {name}")
    try:
        text = templates[name].format(**{
            "topic": args.get("topic", ""),
            "depth": args.get("depth", "medium"),
            "recipient": args.get("recipient", ""),
            "intent": args.get("intent", ""),
            "tone": args.get("tone", "professional"),
            "options": args.get("options", ""),
            "criteria": args.get("criteria", ""),
        })
    except KeyError as e:
        raise _ProtocolError(-32602, f"missing argument: {e}") from e
    return {
        "description": f"Lightwork prompt: {name}",
        "messages": [{
            "role": "user",
            "content": {"type": "text", "text": text},
        }],
    }
