"""Zero-config BYO tool: turn a plain function into a Tool with ``@tool``.

Instead of hand-writing a JSON Schema + a dict-dispatch ``_run``, decorate a
typed function and the schema is derived from its signature + type hints:

    from maverick.tools.decorator import tool

    @tool
    def add(a: int, b: int) -> int:
        \"\"\"Add two integers.\"\"\"
        return a + b

The decorated object stays callable (``add(1, 2) == 3``) and carries a built
``.tool`` (a real ``Tool``). Decorated tools are also collected into a module
registry so ``base_registry`` can pick up any that were imported. Params without
a default are required; params without a type hint accept anything. The registry
calls tools with a single dict, so the adapter bridges ``fn(args_dict)`` →
``f(**args)`` and converts a missing-arg ``TypeError`` into a clean tool error.
"""
from __future__ import annotations

import inspect
from typing import Any, get_type_hints

from . import Tool

_PY_TO_JSON = {
    str: "string", int: "integer", float: "number", bool: "boolean",
    list: "array", dict: "object",
}

# Tools created via @tool, in definition order. base_registry pulls these in.
_REGISTERED: list[Tool] = []


def _json_type(annotation: Any) -> str | None:
    if annotation is inspect.Parameter.empty:
        return None
    origin = getattr(annotation, "__origin__", None)
    if origin in (list, tuple, set):
        return "array"
    if origin is dict:
        return "object"
    return _PY_TO_JSON.get(annotation)


def schema_from_signature(fn) -> dict:
    """Build a JSON Schema (object) from ``fn``'s parameters + type hints."""
    sig = inspect.signature(fn)
    try:
        hints = get_type_hints(fn)
    except Exception:  # pragma: no cover -- exotic annotations
        hints = {}
    props: dict[str, dict] = {}
    required: list[str] = []
    for pname, param in sig.parameters.items():
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        ann = hints.get(pname, param.annotation)
        jtype = _json_type(ann)
        prop: dict = {} if jtype is None else {"type": jtype}
        props[pname] = prop
        if param.default is inspect.Parameter.empty:
            required.append(pname)
    schema: dict = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def _adapt(fn):
    sig = inspect.signature(fn)
    accepted = {p.name for p in sig.parameters.values()
                if p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)}
    has_kwargs = any(p.kind == p.VAR_KEYWORD for p in sig.parameters.values())

    def _run(args: dict[str, Any]) -> str:
        args = args or {}
        kwargs = args if has_kwargs else {k: v for k, v in args.items() if k in accepted}
        try:
            result = fn(**kwargs)
        except TypeError as e:
            return f"ERROR: bad arguments for {fn.__name__}: {e}"
        except Exception as e:
            return f"ERROR: {type(e).__name__}: {e}"
        return result if isinstance(result, str) else repr(result)

    return _run


def tool(_fn=None, *, name: str | None = None, description: str | None = None,
         parallel_safe: bool = False):
    """Decorator that builds a ``Tool`` from a typed function.

    Usable bare (``@tool``) or with options (``@tool(name=..., parallel_safe=True)``).
    """
    def wrap(fn):
        built = Tool(
            name=name or fn.__name__,
            description=(description or inspect.getdoc(fn) or fn.__name__).strip(),
            input_schema=schema_from_signature(fn),
            fn=_adapt(fn),
            parallel_safe=parallel_safe,
        )
        fn.tool = built  # type: ignore[attr-defined]
        _REGISTERED.append(built)
        return fn

    return wrap(_fn) if callable(_fn) else wrap


def registered_tools() -> list[Tool]:
    """Tools created via ``@tool`` so far (base_registry registers these)."""
    return list(_REGISTERED)


def clear_registered() -> None:
    """Drop all decorator-registered tools (tests)."""
    _REGISTERED.clear()


__all__ = ["tool", "registered_tools", "clear_registered", "schema_from_signature"]
