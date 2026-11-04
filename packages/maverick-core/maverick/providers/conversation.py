"""Provider-neutral conversation records and lossless Anthropic adapters.

Content is kept in order. Unknown blocks and extension fields are retained so
signed reasoning, future provider blocks, and metadata can round-trip without
being rewritten by the kernel. Provider adapters decide which kinds they can
actually send and must reject or explicitly omit unsupported kinds.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import Enum
from typing import Any


class PartKind(str, Enum):
    TEXT = "text"
    IMAGE = "image"
    DOCUMENT = "document"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    REASONING = "reasoning"
    REDACTED_REASONING = "redacted_reasoning"
    UNKNOWN = "unknown"


_ANTHROPIC_KINDS = {
    "text": PartKind.TEXT,
    "image": PartKind.IMAGE,
    "document": PartKind.DOCUMENT,
    "tool_use": PartKind.TOOL_CALL,
    "tool_result": PartKind.TOOL_RESULT,
    "thinking": PartKind.REASONING,
    "redacted_thinking": PartKind.REDACTED_REASONING,
}


@dataclass(frozen=True, init=False)
class ContentPart:
    """One ordered content part, retaining its original provider payload."""

    kind: PartKind
    _payload: dict[str, Any]

    def __init__(self, kind: PartKind, payload: dict[str, Any]) -> None:
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "_payload", copy.deepcopy(payload))

    @property
    def payload(self) -> dict[str, Any]:
        """Return a copy so inspecting a part cannot change the stored turn."""
        return copy.deepcopy(self._payload)

    @classmethod
    def from_anthropic(cls, payload: dict[str, Any]) -> ContentPart:
        kind = payload.get("type")
        part_kind = _ANTHROPIC_KINDS.get(kind, PartKind.UNKNOWN) if isinstance(kind, str) else PartKind.UNKNOWN
        return cls(part_kind, payload)

    def to_anthropic(self) -> dict[str, Any]:
        return copy.deepcopy(self._payload)


@dataclass(frozen=True, init=False)
class ConversationMessage:
    """A conversation turn with typed parts and lossless extension fields."""

    _role: Any
    _content: Any
    _extensions: dict[str, Any]
    role_present: bool
    content_present: bool
    content_is_parts: bool

    def __init__(self, role: Any, content: Any, extensions: dict[str, Any],
                 role_present: bool = True, content_present: bool = True,
                 content_is_parts: bool = False) -> None:
        object.__setattr__(self, "_role", copy.deepcopy(role))
        object.__setattr__(self, "_content", copy.deepcopy(content))
        object.__setattr__(self, "_extensions", copy.deepcopy(extensions))
        object.__setattr__(self, "role_present", role_present)
        object.__setattr__(self, "content_present", content_present)
        object.__setattr__(self, "content_is_parts", content_is_parts)

    @property
    def role(self) -> Any:
        return copy.deepcopy(self._role)

    @property
    def content(self) -> Any:
        """Return an independent snapshot, including nested unknown parts."""
        return copy.deepcopy(self._content)

    @property
    def extensions(self) -> dict[str, Any]:
        return copy.deepcopy(self._extensions)

    @classmethod
    def from_anthropic(cls, message: dict[str, Any]) -> ConversationMessage:
        content = message.get("content")
        content_is_parts = isinstance(content, list)
        if content_is_parts:
            content = tuple(
                ContentPart.from_anthropic(part) if isinstance(part, dict) else copy.deepcopy(part)
                for part in content
            )
        else:
            content = copy.deepcopy(content)
        return cls(
            message.get("role"), content,
            {key: value for key, value in message.items() if key not in {"role", "content"}},
            "role" in message, "content" in message, content_is_parts,
        )

    def to_anthropic(self) -> dict[str, Any]:
        message = copy.deepcopy(self._extensions)
        if self.role_present:
            message["role"] = copy.deepcopy(self._role)
        if self.content_present:
            if self.content_is_parts:
                message["content"] = [
                    part.to_anthropic() if isinstance(part, ContentPart) else copy.deepcopy(part)
                    for part in self._content
                ]
            else:
                message["content"] = copy.deepcopy(self._content)
        return message


def anthropic_messages(messages: list[dict | ConversationMessage]) -> list[dict]:
    """Adapt canonical records at the legacy provider boundary.

    Existing dictionaries are passed through for compatibility; records are
    emitted as independent data so later redaction cannot mutate the caller's
    preserved provider signatures or content.
    """
    return [message.to_anthropic() if isinstance(message, ConversationMessage) else message
            for message in messages]


def assistant_content_from_response(response: Any, *, final_dropped_tools: bool = False) -> list[dict]:
    """Reconstruct an assistant turn without altering signed reasoning order.

    When a final answer suppresses tool calls, return only the final text: a
    partial replay of interleaved signed blocks would be rejected by Anthropic
    and orphan the suppressed calls. Otherwise retain ordered provider blocks
    exactly, falling back to the legacy bucketed fields for older providers.
    """
    if final_dropped_tools:
        return [{"type": "text", "text": response.text}]
    ordered = getattr(response, "content_blocks", None)
    if ordered:
        return [dict(block) for block in ordered]
    parts: list[dict] = []
    thinking_blocks = getattr(response, "thinking_blocks", None) or []
    if thinking_blocks:
        for text, signature in thinking_blocks:
            if not text and not signature:
                continue
            block = {"type": "thinking", "thinking": text}
            if signature:
                block["signature"] = signature
            parts.append(block)
    elif response.thinking or getattr(response, "thinking_signature", None):
        block = {"type": "thinking", "thinking": response.thinking or ""}
        signature = getattr(response, "thinking_signature", None)
        if signature:
            block["signature"] = signature
        parts.append(block)
    if response.text:
        parts.append({"type": "text", "text": response.text})
    for call in response.tool_calls:
        parts.append({"type": "tool_use", "id": call.id, "name": call.name, "input": call.input})
    return parts
