"""Explicit dependencies for workflow routes.

The dashboard composition root supplies these services before mounting the
workflow router. The workflow package does not import the API facade.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from fastapi import Request


@dataclass(frozen=True)
class FlowDependencies:
    """Application services shared by workflow endpoints."""
    _dashboard_token_authenticated: Callable[..., Any]
    _event_trigger_allowed_owners: Callable[..., Any]
    _live_tool_index: Callable[..., Any]
    _live_tool_schemas: Callable[..., Any]
    _supervisor: Callable[..., Any]
    auth_genuinely_off: Callable[..., Any]
    caller_principal: Callable[..., Any]
    caller_suites: Callable[..., Any]
    configured_goal_ceiling_dollars: Callable[..., Any]
    execution_user_id_from_request: Callable[..., Any]
    goal_owner_filter: Callable[..., Any]
    require_permission: Callable[..., Any]
    run_in_threadpool: Callable[..., Any]


_dependencies: FlowDependencies | None = None
_request_dependencies: ContextVar[FlowDependencies | None] = ContextVar(
    "workflow_request_dependencies", default=None,
)


def configure(dependencies: FlowDependencies) -> None:
    """Bind the workflow router to the application services."""
    global _dependencies
    _dependencies = dependencies


def _services() -> FlowDependencies:
    dependencies = _request_dependencies.get() or _dependencies
    if dependencies is None:
        raise RuntimeError("Workflow services must be configured before use")
    return dependencies


async def bind_request_services(request: Request) -> AsyncIterator[None]:
    """Use the current app's services for this request, including worker threads."""
    dependencies = getattr(request.app.state, "flow_dependencies", None) or _dependencies
    if dependencies is None:
        raise RuntimeError("Workflow services must be configured before use")
    token = _request_dependencies.set(dependencies)
    try:
        yield
    finally:
        _request_dependencies.reset(token)


def _dashboard_token_authenticated(*args: Any, **kwargs: Any) -> Any:
    return _services()._dashboard_token_authenticated(*args, **kwargs)


def _event_trigger_allowed_owners(*args: Any, **kwargs: Any) -> Any:
    return _services()._event_trigger_allowed_owners(*args, **kwargs)


def _live_tool_index(*args: Any, **kwargs: Any) -> Any:
    return _services()._live_tool_index(*args, **kwargs)


def _live_tool_schemas(*args: Any, **kwargs: Any) -> Any:
    return _services()._live_tool_schemas(*args, **kwargs)


def _supervisor(*args: Any, **kwargs: Any) -> Any:
    return _services()._supervisor(*args, **kwargs)


def auth_genuinely_off(*args: Any, **kwargs: Any) -> Any:
    return _services().auth_genuinely_off(*args, **kwargs)


def caller_principal(*args: Any, **kwargs: Any) -> Any:
    return _services().caller_principal(*args, **kwargs)


def caller_suites(*args: Any, **kwargs: Any) -> Any:
    return _services().caller_suites(*args, **kwargs)


def configured_goal_ceiling_dollars(*args: Any, **kwargs: Any) -> Any:
    return _services().configured_goal_ceiling_dollars(*args, **kwargs)


def execution_user_id_from_request(*args: Any, **kwargs: Any) -> Any:
    return _services().execution_user_id_from_request(*args, **kwargs)


def goal_owner_filter(*args: Any, **kwargs: Any) -> Any:
    return _services().goal_owner_filter(*args, **kwargs)


def require_permission(*args: Any, **kwargs: Any) -> Any:
    return _services().require_permission(*args, **kwargs)


def run_in_threadpool(*args: Any, **kwargs: Any) -> Any:
    return _services().run_in_threadpool(*args, **kwargs)
