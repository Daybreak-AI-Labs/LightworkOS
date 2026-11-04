"""AutoGen + CrewAI + OpenAI interop.

The LangChain adapter's two directions, extended to the other frameworks
people actually run multi-agent stacks on. The delegation core is shared —
:func:`maverick.langchain_adapter.run_maverick_goal` (transport-agnostic,
already unit-tested) — so this module is wrappers only:

  - **Lightwork as an AutoGen tool** — :func:`maverick_autogen_tool` returns a
    plain typed function (AutoGen 0.4 ``FunctionTool``-compatible; AutoGen
    registers ordinary callables with docstrings), optionally wrapped in
    ``autogen_core.tools.FunctionTool`` when the package is installed.
  - **Lightwork as a CrewAI tool** — :func:`maverick_crewai_tool` returns a
    CrewAI ``BaseTool`` subclass instance (lazy import, clear install hint).
  - **Lightwork as an OpenAI function tool** — :func:`maverick_openai_tool`
    returns the ``(tool_def, executor)`` pair for OpenAI's function-calling
    wire format (plain dicts; no SDK dependency at all).
  - **Their tools as Lightwork tools** — :func:`wrap_autogen_tool` /
    :func:`wrap_crewai_tool` / :func:`wrap_openai_tool` adapt an AutoGen
    ``FunctionTool`` / CrewAI ``BaseTool`` / OpenAI function-tool definition
    into a Lightwork :class:`~maverick.tools.Tool`, so the swarm can call
    into any of these ecosystems' tools.

Nothing here imports ``autogen``/``crewai``/``openai`` at module import time;
each wrapper lazy-imports and raises an actionable hint when the package is
absent (mirrors the ``[langchain]`` extra discipline). The OpenAI pair is
dict-only and needs no package.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import re
import sys
from typing import Any

from .langchain_adapter import run_maverick_goal
from .tools import Tool

log = logging.getLogger(__name__)

_GOAL_DESCRIPTION = (
    "Delegate a goal to the Lightwork agent swarm (planning, tools, "
    "verification) and return its result text. Use for multi-step work "
    "that needs real tools rather than a single completion."
)
_VALID_EXTERNAL_TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_MAX_SCHEMA_SCAN_DEPTH = 64
_DEFAULT_SCHEMA = {
    "type": "object",
    "properties": {"input": {"type": "string"}},
    "required": ["input"],
}


# ---- Lightwork as an AutoGen tool -------------------------------------------

def maverick_autogen_callable(*, max_dollars: float | None = None, **binds: Any):
    """The plain typed callable AutoGen registers as a tool.

    AutoGen (0.4's ``FunctionTool``, and 0.2's ``register_function``) wraps
    ordinary Python callables whose signature + docstring become the schema —
    so the core adapter is dependency-free and the FunctionTool wrapper below
    is optional sugar."""
    def run_maverick(goal: str, description: str = "") -> str:
        """Delegate a goal to the Lightwork agent swarm and return its result."""
        return run_maverick_goal(goal, description, max_dollars=max_dollars, **binds)

    return run_maverick


def maverick_autogen_tool(*, max_dollars: float | None = None, **binds: Any):
    """Lightwork as an AutoGen ``FunctionTool`` (needs ``autogen-core``)."""
    try:
        from autogen_core.tools import FunctionTool
    except ImportError as e:
        raise ImportError(
            "autogen-core not installed. Run: pip install autogen-core "
            "(or use maverick_autogen_callable(), which has no dependency)"
        ) from e
    return FunctionTool(
        maverick_autogen_callable(max_dollars=max_dollars, **binds),
        description=_GOAL_DESCRIPTION,
        name="run_maverick",
    )


# ---- Lightwork as a CrewAI tool ----------------------------------------------

def maverick_crewai_tool(*, max_dollars: float | None = None, **binds: Any):
    """Lightwork as a CrewAI tool (needs ``crewai``).

    Returns an instance of a ``crewai.tools.BaseTool`` subclass whose ``_run``
    delegates to the swarm."""
    try:
        from crewai.tools import BaseTool  # type: ignore[import-not-found]
    except ImportError as e:
        raise ImportError(
            "crewai not installed. Run: pip install crewai"
        ) from e

    class MaverickTool(BaseTool):  # type: ignore[misc,valid-type]
        name: str = "run_maverick"
        description: str = _GOAL_DESCRIPTION

        def _run(self, goal: str, description: str = "") -> str:
            return run_maverick_goal(goal, description,
                                     max_dollars=max_dollars, **binds)

    return MaverickTool()


# ---- Lightwork as an OpenAI function tool ------------------------------------

def maverick_openai_tool(*, max_dollars: float | None = None, **binds: Any):
    """Lightwork as an OpenAI function tool (dependency-free).

    OpenAI's function calling is a plain JSON wire format, so this returns the
    ``(tool_def, executor)`` pair directly — pass ``tool_def`` in the request's
    ``tools`` list and call ``executor`` with the model's parsed tool-call
    arguments (``executor(**json.loads(call.function.arguments))``). The
    factory ``max_dollars`` is a ceiling: a model-supplied ``max_dollars`` may
    lower the budget for one call, never raise it."""
    ceiling = max_dollars

    def run_maverick(prompt: str, max_dollars: float | None = None) -> str:
        """Delegate a goal to the Lightwork agent swarm and return its result."""
        from .runner import clamp_task_limit

        dollars = clamp_task_limit(max_dollars, ceiling)
        return run_maverick_goal(prompt, "", max_dollars=dollars, **binds)

    tool_def = {
        "type": "function",
        "function": {
            "name": "maverick_run_goal",
            "description": _GOAL_DESCRIPTION,
            "parameters": {
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "The goal to delegate to the swarm.",
                    },
                    "max_dollars": {
                        "type": "number",
                        "description": "Optional per-call budget cap in USD "
                                       "(never raises the configured ceiling).",
                    },
                },
                "required": ["prompt"],
            },
        },
    }
    return tool_def, run_maverick


# ---- Their tools as Lightwork tools ------------------------------------------

def _schema_or_default(obj: Any) -> dict:
    """Best-effort JSON schema from a framework tool's args model."""
    model = getattr(obj, "args_type", None)
    if callable(model):
        try:
            model = model()
        except Exception:
            model = None
    if model is None:
        model = getattr(obj, "args_schema", None)
    if model is None:
        return dict(_DEFAULT_SCHEMA)

    dump = getattr(model, "model_json_schema", None)
    if not callable(dump):
        return dict(_DEFAULT_SCHEMA)
    try:
        schema = dump()
    except Exception as e:
        raise ValueError("external tool args schema could not be extracted") from e
    _validate_schema(schema)
    return schema


def _try_shield():
    if (
        "maverick_shield" not in sys.modules
        and importlib.util.find_spec("maverick_shield") is None
    ):
        return None
    from maverick_shield import Shield  # type: ignore

    return Shield.from_config()


def _validate_schema(schema: Any) -> None:
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ValueError("external tool schema must be a JSON object schema")
    leaves: list[str] = []
    if not _collect_schema_strings(schema, leaves):
        raise ValueError(
            "external tool schema exceeds maximum metadata scan depth "
            f"{_MAX_SCHEMA_SCAN_DEPTH}"
        )


def _collect_schema_strings(node: Any, out: list[str], _depth: int = 0) -> bool:
    """Collect every string leaf from JSON-schema metadata, failing on bad data."""
    if _depth > _MAX_SCHEMA_SCAN_DEPTH:
        return False
    if isinstance(node, dict):
        for value in node.values():
            if isinstance(value, str):
                out.append(value)
            elif isinstance(value, (dict, list)):
                if not _collect_schema_strings(value, out, _depth + 1):
                    return False
            elif value is not None and not isinstance(value, (bool, int, float)):
                raise ValueError("external tool schema contains non-JSON metadata")
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, (dict, list)):
                if not _collect_schema_strings(item, out, _depth + 1):
                    return False
            elif item is not None and not isinstance(item, (bool, int, float)):
                raise ValueError("external tool schema contains non-JSON metadata")
    else:
        raise ValueError("external tool schema contains non-JSON metadata")
    return True


def _secure_tool_metadata(
    *,
    framework: str,
    namespace: str,
    raw_name: Any,
    raw_description: Any,
    schema: dict,
) -> tuple[str, str, dict]:
    original_name = str(raw_name or f"{framework}_tool")
    if (
        not _VALID_EXTERNAL_TOOL_NAME.fullmatch(original_name)
        or "__" in original_name
    ):
        raise ValueError(
            f"{framework} tool has invalid name {original_name!r} "
            "(must match [A-Za-z0-9_.-], <=128 chars, no '__')"
        )

    description = str(raw_description or original_name)
    leaves: list[str] = []
    if not _collect_schema_strings(schema, leaves):
        raise ValueError(
            f"{framework} tool {original_name!r} schema exceeds maximum "
            f"metadata scan depth {_MAX_SCHEMA_SCAN_DEPTH}"
        )

    shield = _try_shield()
    if shield is not None:
        payload = "\n".join(
            [f"tool: {original_name}", f"description: {description}"]
            + [f"schema_text: {leaf}" for leaf in leaves]
        )
        try:
            verdict = shield.scan_input(payload)
            allowed = bool(verdict.allowed)
        except Exception as e:  # pragma: no cover
            log.warning(
                "%s tool %r shield scan errored (fail-open): %s",
                framework,
                original_name,
                e,
            )
            allowed = True
        if not allowed:
            raise ValueError(f"{framework} tool {original_name!r} rejected by Shield")

    return (
        f"{namespace}__{original_name}",
        f"[{framework}:{original_name}] {description}",
        schema,
    )


def _result_text(out: Any) -> str:
    if isinstance(out, str):
        return out
    try:
        return json.dumps(out, default=str)
    except (TypeError, ValueError):
        return str(out)


def wrap_autogen_tool(autogen_tool: Any) -> Tool:
    """Adapt an AutoGen ``FunctionTool``-shaped object into a Lightwork Tool.

    Duck-typed: needs ``name``, ``description``, and either ``run`` (async,
    AutoGen 0.4: ``run(args, cancellation_token)``) or a plain callable
    ``func``/``fn``. The 0.4 ``run`` path builds the args object from the
    tool's ``args_type`` when available, else passes the dict through.
    """
    schema = _schema_or_default(autogen_tool)
    name, description, schema = _secure_tool_metadata(
        framework="autogen",
        namespace="autogen",
        raw_name=getattr(autogen_tool, "name", "") or "autogen_tool",
        raw_description=getattr(autogen_tool, "description", ""),
        schema=schema,
    )

    def fn(args: dict[str, Any]) -> str:
        runner = getattr(autogen_tool, "run", None)
        if callable(runner):
            payload: Any = args
            args_type = getattr(autogen_tool, "args_type", None)
            if callable(args_type):
                try:
                    payload = args_type()(**args)
                except Exception:
                    payload = args
            try:
                out = asyncio.run(runner(payload, None))
            except TypeError:
                out = asyncio.run(runner(payload))
            return _result_text(out)
        call = getattr(autogen_tool, "func", None) or getattr(autogen_tool, "fn", None)
        if callable(call):
            return _result_text(call(**args))
        return "ERROR: AutoGen tool exposes neither run() nor func"

    return Tool(name=name, description=description, input_schema=schema, fn=fn)


def wrap_crewai_tool(crewai_tool: Any) -> Tool:
    """Adapt a CrewAI ``BaseTool``-shaped object into a Lightwork Tool.

    Duck-typed: needs ``name``, ``description``, and ``_run`` (CrewAI's
    execution method) or ``run``.
    """
    schema = _schema_or_default(crewai_tool)
    name, description, schema = _secure_tool_metadata(
        framework="crewai",
        namespace="crewai",
        raw_name=getattr(crewai_tool, "name", "") or "crewai_tool",
        raw_description=getattr(crewai_tool, "description", ""),
        schema=schema,
    )

    def fn(args: dict[str, Any]) -> str:
        call = getattr(crewai_tool, "_run", None) or getattr(crewai_tool, "run", None)
        if not callable(call):
            return "ERROR: CrewAI tool exposes neither _run() nor run()"
        return _result_text(call(**args))

    return Tool(name=name, description=description, input_schema=schema, fn=fn)


def wrap_openai_tool(tool_def: Any, executor: Any) -> Tool:
    """Adapt an OpenAI function-tool definition + executor into a Lightwork Tool.

    ``tool_def`` is the plain function-calling dict
    (``{"type": "function", "function": {name, description, parameters}}``;
    the flat Responses-API shape with ``name`` beside ``type`` is also
    accepted) and ``executor`` is the callable your tool-loop would run for
    it — called with the model's arguments as keywords.
    """
    if not isinstance(tool_def, dict):
        raise ValueError("openai tool definition must be a dict")
    if tool_def.get("type", "function") != "function":
        raise ValueError("openai tool definition must have type 'function'")
    fn_def = tool_def.get("function", tool_def)
    if not isinstance(fn_def, dict):
        raise ValueError("openai tool definition must have a 'function' object")
    if not callable(executor):
        raise ValueError("openai tool executor must be callable")

    schema = fn_def.get("parameters")
    if schema is None:
        schema = dict(_DEFAULT_SCHEMA)
    else:
        _validate_schema(schema)
    name, description, schema = _secure_tool_metadata(
        framework="openai",
        namespace="openai",
        raw_name=fn_def.get("name", "") or "openai_tool",
        raw_description=fn_def.get("description", ""),
        schema=schema,
    )

    def fn(args: dict[str, Any]) -> str:
        return _result_text(executor(**args))

    return Tool(name=name, description=description, input_schema=schema, fn=fn)


__all__ = [
    "maverick_autogen_callable", "maverick_autogen_tool",
    "maverick_crewai_tool", "maverick_openai_tool",
    "wrap_autogen_tool", "wrap_crewai_tool", "wrap_openai_tool",
]
