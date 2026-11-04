"""Typed internal workflow control signals and safe failure reporting."""
from __future__ import annotations

from typing import Any

from ..approval_cards import ApprovalCardError
from ..budget import BudgetExceeded
from .ir import FlowNode


class FlowCredentialRefused(ValueError):
    """Legacy credential interpolation needs an explicit reviewed migration."""


class FlowBudgetExceeded(BudgetExceeded):
    """A flow allowance refused an invocation before it dispatched any work."""


class FlowApprovalStale(ApprovalCardError):
    """The authority behind a paused approval changed before an effect."""


def _safe_error_text(value: Any, *, limit: int = 500) -> str:
    """Redact untrusted executor text before persistence or catch routing."""
    try:
        from .redact import redact

        safe = str(redact(str(value)))
    except Exception:  # pragma: no cover - error reporting must fail closed
        safe = "execution failed (details redacted)"
    return safe[:limit]


class _Pause(Exception):
    def __init__(self, kind: str, node: FlowNode, data: dict, resume_at: float | None = None):
        self.kind, self.node, self.data, self.resume_at = kind, node, data, resume_at


class _Reject(Exception):
    def __init__(self, node: FlowNode, data: dict, *, error: str = ""):
        self.node, self.data, self.error = node, data, error


class _NodeError(Exception):
    """An executor raised inside a specific node -- carries the node id so a
    failed run records WHERE it failed (the retry-from-failure entry point)."""

    def __init__(self, node_id: str, cause: Exception):
        super().__init__(f"node {node_id!r}: {_safe_error_text(cause)}")
        self.node_id = node_id
        self.cause = cause


class _Indeterminate(Exception):
    """A work boundary may have committed an effect without proving its state."""

    def __init__(self, node_id: str, detail: str, *, boundary: str = "high-risk action"):
        super().__init__(
            f"{boundary} {node_id!r} is indeterminate: {_safe_error_text(detail)}"
        )
        self.node_id = node_id
