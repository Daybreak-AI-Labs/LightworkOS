"""Flows -- a deterministic control-flow skeleton over agentic + tool steps.

A :class:`~.ir.Flow` generalises a template: a single ``agent`` node IS today's
template, and adding branch / foreach / parallel / approval / delay nodes lets a
migrated workflow keep its structure (fidelity + auditability) while any node can
still be a full agentic goal. OFF by default -- ``[flows] enable`` /
``MAVERICK_FLOWS`` -- so a default deployment is unaffected (kernel rule 1).
"""
from __future__ import annotations

from .expressions import eval_condition, render
from .ir import (
    NODE_ACTION,
    NODE_AGENT,
    NODE_APPROVAL,
    NODE_BRANCH,
    NODE_DELAY,
    NODE_FOREACH,
    NODE_PARALLEL,
    NODE_SUBFLOW,
    Flow,
    FlowNode,
    single_agent_flow,
)
from .run_state import FlowRunResult
from .runner import run_flow


def enabled() -> bool:
    """Whether the flow engine is on. OFF by default; never raises."""
    from ..config import env_flag
    v = env_flag("MAVERICK_FLOWS")
    if v is not None:
        return v
    try:
        from ..config import get_flows
        return bool(get_flows().get("enable", False))
    except Exception:  # pragma: no cover -- config must never block
        return False


def auto_evolve_enabled() -> bool:
    """Whether the flow engine may AUTONOMOUSLY revert a regressed self-rewrite.
    Requires the engine on AND ``[flows] auto_evolve`` (or ``MAVERICK_FLOWS_AUTO``).
    OFF by default -- surfacing proposals + human apply never needs it. Never
    raises."""
    if not enabled():
        return False
    from ..config import env_flag
    v = env_flag("MAVERICK_FLOWS_AUTO")
    if v is not None:
        return v
    try:
        from ..config import get_flows
        return bool(get_flows().get("auto_evolve", False))
    except Exception:  # pragma: no cover -- config must never block
        return False


def auto_apply_enabled() -> bool:
    """Whether the loop may AUTONOMOUSLY APPLY a self-rewrite proposal forward
    (not just revert). Strictly opt-in: requires auto_evolve on (so a bad apply
    is auto-reverted) AND ``[flows] auto_apply``. OFF by default -- the forward
    step is human-gated unless an operator explicitly enables full autonomy.
    Never raises."""
    if not auto_evolve_enabled():
        return False
    try:
        from ..config import get_flows
        return bool(get_flows().get("auto_apply", False))
    except Exception:  # pragma: no cover
        return False


__all__ = [
    "enabled", "auto_evolve_enabled", "auto_apply_enabled",
    "Flow", "FlowNode", "single_agent_flow",
    "run_flow", "FlowRunResult", "render", "eval_condition",
    "NODE_ACTION", "NODE_AGENT", "NODE_BRANCH", "NODE_FOREACH",
    "NODE_PARALLEL", "NODE_APPROVAL", "NODE_DELAY", "NODE_SUBFLOW",
]
