"""LangChain / LangGraph interop.

Two directions, both behind the ``[langchain]`` extra:

  - **Lightwork as a LangChain tool** — :func:`maverick_langchain_tool` returns a
    LangChain ``StructuredTool`` that delegates a goal to the Lightwork swarm and
    returns its result, so a LangChain/LangGraph agent can call Lightwork as one
    of its tools.
  - **A LangChain tool as a Lightwork tool** — :func:`wrap_langchain_tool` adapts
    any LangChain ``BaseTool`` into a Lightwork :class:`~maverick.tools.Tool`, so
    the swarm can use the LangChain ecosystem's tools.

The delegation core (:func:`run_maverick_goal`) is transport-agnostic and
unit-tested with injected fakes; the LangChain wrappers lazy-import
``langchain_core`` and raise a clear install hint when the extra is absent.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .tools import Tool


def _default_world():  # pragma: no cover -- exercised only against a real DB
    from .world_model import open_world
    return open_world()  # client/tenant-floored canonical world


def _default_dispatch(goal_id: int, **kw):  # pragma: no cover -- real run
    from .runner import run_goal_in_background
    return run_goal_in_background(goal_id, **kw)


def run_maverick_goal(
    goal: str,
    description: str = "",
    *,
    max_dollars: float | None = None,
    channel: str | None = None,
    user_id: str | None = None,
    capability: Any | None = None,
    world_factory: Callable[[], Any] | None = None,
    dispatch: Callable[..., Any] | None = None,
) -> str:
    """Delegate a goal to the Lightwork swarm and return its result text.

    Creates the goal, runs it to completion, and returns its result (or a short
    status line if it produced none). ``channel``, ``user_id``, and
    ``capability`` are forwarded to the runner so host integrations can bind
    Lightwork execution to the authenticated caller's policy context.
    Dependencies are injected for testing."""
    if not (goal or "").strip():
        raise ValueError("goal is required")
    world = (world_factory or _default_world)()
    try:
        goal_id = int(world.create_goal(goal.strip(), description or ""))
    finally:
        _close(world)
    status = (dispatch or _default_dispatch)(
        goal_id,
        max_dollars=max_dollars,
        channel=channel,
        user_id=user_id,
        capability=capability,
    )
    world = (world_factory or _default_world)()
    try:
        g = world.get_goal(goal_id)
        result = (getattr(g, "result", None) if g else None) or ""
    finally:
        _close(world)
    return result or f"(goal #{goal_id} ended {status or 'unknown'})"


def _close(world: Any) -> None:
    from .world_model import close_world_if_owned

    try:
        close_world_if_owned(world)
    except Exception:  # pragma: no cover
        pass


def maverick_langchain_tool(
    *,
    max_dollars: float | None = None,
    channel: str | None = None,
    user_id: str | None = None,
    capability: Any | None = None,
):
    """A LangChain ``StructuredTool`` that delegates a goal to Lightwork.

    Pass ``channel``, ``user_id``, and/or ``capability`` from the trusted host
    application when constructing this tool for an authenticated request. Those
    values are not exposed as model-controlled tool inputs; they are forwarded
    with each Lightwork goal dispatch for ACLs, quotas, and capability checks.
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as e:
        raise ImportError(
            "LangChain adapter needs langchain-core "
            "(python -m pip install -e './packages/maverick-core[langchain]')") from e

    def _run(goal: str, description: str = "") -> str:
        return run_maverick_goal(
            goal,
            description,
            max_dollars=max_dollars,
            channel=channel,
            user_id=user_id,
            capability=capability,
        )

    return StructuredTool.from_function(
        _run,
        name="maverick",
        description=(
            "Delegate a complex, long-horizon goal to the Lightwork multi-agent "
            "swarm and return its result. Use for tasks needing research, coding, "
            "verification, or multi-step planning."),
    )


def wrap_langchain_tool(lc_tool: Any) -> Tool:
    """Adapt a LangChain ``BaseTool`` into a Lightwork :class:`~maverick.tools.Tool`.

    The wrapped tool takes a single ``input`` string (the common LangChain tool
    shape) and returns the LangChain tool's string output."""
    name = getattr(lc_tool, "name", None) or "langchain_tool"
    description = getattr(lc_tool, "description", "") or f"LangChain tool {name}"

    def _fn(args: dict) -> str:
        value = args.get("input", "")
        # LangChain tools expose .invoke (>=0.1) or the legacy .run.
        invoke = getattr(lc_tool, "invoke", None) or getattr(lc_tool, "run", None)
        if invoke is None:
            raise TypeError(f"{name!r} is not a runnable LangChain tool")
        return str(invoke(value))

    return Tool(
        name=str(name),
        description=str(description),
        input_schema={
            "type": "object",
            "properties": {"input": {"type": "string", "description": "Tool input."}},
            "required": ["input"],
        },
        fn=_fn,
    )


__all__ = ["run_maverick_goal", "maverick_langchain_tool", "wrap_langchain_tool"]
