"""One typed interpretation of the string-based tool result protocol.

Tool functions historically return strings, so execution surfaces had grown
independent ``startswith('ERROR')`` checks.  That made a governed refusal or an
indeterminate external effect look successful in agents and workflows.  Keep
the wire-compatible string contract while centralizing its semantic state.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ToolResultState(str, Enum):
    """Execution meaning of a tool result."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUSED = "refused"
    PREVIEW = "preview"
    INDETERMINATE = "indeterminate"


class ToolResultText(str):
    """String-compatible result carrying an explicitly declared state.

    This is an in-process boundary, not a serialization format. It keeps the
    state intact through existing string consumers until the provider wire
    result is constructed.
    """

    __slots__ = ("_state",)
    _state: ToolResultState

    def __new__(cls, content: str, state: ToolResultState) -> ToolResultText:
        if not isinstance(content, str):
            raise TypeError("content must be a string")
        if not isinstance(state, ToolResultState):
            raise TypeError("state must be a ToolResultState")
        obj = super().__new__(cls, content)
        object.__setattr__(obj, "_state", state)
        return obj

    @property
    def state(self) -> ToolResultState:
        return self._state

    @property
    def tool_execution_unknown(self) -> bool:
        return self._state is ToolResultState.INDETERMINATE

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("tool result state is immutable")

    def __reduce__(self) -> tuple[Any, tuple[str, ToolResultState]]:
        return ToolResultText, (str(self), self._state)


@dataclass(frozen=True)
class ToolOutcome:
    """Explicit state and content at a tool-result boundary.

    Legacy strings still use the reserved-prefix protocol. A producer that
    returns this type explicitly supplies the state independently of its text.
    """

    state: ToolResultState
    content: str

    def __post_init__(self) -> None:
        if not isinstance(self.state, ToolResultState):
            raise TypeError("state must be a ToolResultState")
        if not isinstance(self.content, str):
            raise TypeError("content must be a string")

    @classmethod
    def from_legacy(cls, value: Any) -> ToolOutcome:
        """Adapt a legacy return value without changing its classification."""
        if isinstance(value, cls):
            return value
        return cls(classify_tool_result(value), str(value))

    def as_text(self) -> ToolResultText:
        """Expose the result to legacy string consumers without losing state."""
        return ToolResultText(self.content, self.state)


def unframe_tool_result(value: Any) -> str:
    """Return raw content from the optional untrusted-output frame."""
    if isinstance(value, ToolOutcome):
        value = value.content
    text = value if isinstance(value, str) else str(value or "")
    if text.startswith("<tool_output "):
        newline = text.find("\n")
        if newline != -1:
            text = text[newline + 1:]
    return text.lstrip()


def classify_tool_result(value: Any) -> ToolResultState:
    """Classify reserved failure/refusal/ambiguity prefixes consistently."""
    if isinstance(value, (ToolOutcome, ToolResultText)):
        return value.state
    from .connector_attempts import ConnectorResult

    if isinstance(value, ConnectorResult):
        attempt = value.attempt
        if attempt.outcome_unknown:
            return ToolResultState.INDETERMINATE
        if (attempt.error_class is None and attempt.status_code is not None
                and 200 <= attempt.status_code < 300):
            return ToolResultState.SUCCEEDED
    text = unframe_tool_result(value)
    if text.startswith("INDETERMINATE"):
        return ToolResultState.INDETERMINATE
    if text.startswith("DRY RUN"):
        return ToolResultState.PREVIEW
    if text.startswith(("REFUSED", "BLOCKED by Shield", "⚠")):
        return ToolResultState.REFUSED
    if text.startswith("ERROR"):
        return ToolResultState.FAILED
    return ToolResultState.SUCCEEDED


def tool_result_failed(value: Any) -> bool:
    """Whether the caller must not treat this result as successful output.

    A dry-run preview is intentionally included: it describes an effect that
    did not happen and must never advance a live workflow or become cached as a
    successful connector response.
    """
    return classify_tool_result(value) is not ToolResultState.SUCCEEDED


def confirmed_success_text(value: str) -> str:
    """Preserve successful content that begins with a legacy error marker.

    Ordinary text remains an exact built-in string for legacy callers.
    Call only at a boundary that has independently established success.
    """
    if not isinstance(value, str):
        raise TypeError("successful tool content must be a string")
    if classify_tool_result(str(value)) is not ToolResultState.SUCCEEDED:
        return ToolResultText(str(value), ToolResultState.SUCCEEDED)
    return str(value)


__all__ = [
    "ToolOutcome",
    "ToolResultText",
    "ToolResultState",
    "classify_tool_result",
    "confirmed_success_text",
    "tool_result_failed",
    "unframe_tool_result",
]
