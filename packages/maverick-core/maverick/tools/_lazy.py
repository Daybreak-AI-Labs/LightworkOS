"""Immutable tool descriptions with registry-owned, first-use executors.

Only trusted built-in descriptors belong here. Discovery never imports a factory
module, resolves credentials or invokes an executor. No resolved tool is global.
"""
from __future__ import annotations

import copy
import importlib
import re
import threading
from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Any

from . import Tool

_TOKEN = re.compile(r"[a-z0-9]+")
GOVERNED_DESCRIPTION_NOTE = " [governed: writes simulated, human-gated, and transaction-receipted]"
_GOVERNED_TOKENS = frozenset(_TOKEN.findall(GOVERNED_DESCRIPTION_NOTE))


@lru_cache(maxsize=8192)
def search_tokens(name: str, description: str) -> tuple[frozenset[str], frozenset[str]]:
    """Cache immutable lexical inputs, not query results or authorization."""
    if description.endswith(GOVERNED_DESCRIPTION_NOTE):
        body, name_tokens = search_tokens(name, description[:-len(GOVERNED_DESCRIPTION_NOTE)])
        return body | _GOVERNED_TOKENS, name_tokens
    return (frozenset(_TOKEN.findall(f"{name} {description}".lower())),
            frozenset(_TOKEN.findall(name.lower())))


def _immutable(*_args, **_kwargs):
    raise TypeError("tool descriptor metadata is immutable; copy it before editing")


class _FrozenDict(dict):
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _immutable

    def __deepcopy__(self, memo):
        return {copy.deepcopy(k, memo): copy.deepcopy(v, memo) for k, v in self.items()}


class _FrozenList(list):
    __setitem__ = __delitem__ = append = clear = extend = insert = pop = remove = _immutable
    reverse = sort = __iadd__ = __imul__ = _immutable

    def __deepcopy__(self, memo):
        return [copy.deepcopy(item, memo) for item in self]


def freeze(value):
    """Keep JSON-compatible dict/list types while refusing accidental mutation."""
    if isinstance(value, (_FrozenDict, _FrozenList)):
        return value
    if isinstance(value, dict):
        return _FrozenDict((k, freeze(v)) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return _FrozenList(freeze(v) for v in value)
    return value


@dataclass(frozen=True, eq=False)
class ToolDescriptor:
    name: str
    description: str
    input_schema: dict[str, Any]
    factory_module: str
    factory_name: str
    factory_kwargs: dict[str, Any]
    parallel_safe: bool = False
    strict: bool = False

    def __post_init__(self):
        object.__setattr__(self, "input_schema", freeze(self.input_schema))
        object.__setattr__(self, "factory_kwargs", freeze(self.factory_kwargs))
        search_tokens(self.name, self.description)

    def construct(self) -> Tool:
        module = importlib.import_module(self.factory_module)
        factory = getattr(module, self.factory_name)
        return factory(**copy.deepcopy(self.factory_kwargs))


@lru_cache(maxsize=8192)
def _wrapped_descriptor(descriptor: ToolDescriptor, description: str,
                        parallel_safe: bool, strict: bool) -> ToolDescriptor:
    """Share only immutable wrapper metadata, never its bound factory."""
    return replace(descriptor, description=description, parallel_safe=parallel_safe, strict=strict)


class LazyToolConstructionError(RuntimeError):
    """A trusted factory failed or returned metadata different from discovery."""


class _Executor:
    def __init__(self, descriptor: ToolDescriptor, factory):
        self.descriptor = descriptor
        self._factory = factory
        self._lock = threading.Lock()
        self._tool: Tool | None = None
        self._failure: str | None = None
        # Introspection must preserve connector provenance without forcing an
        # executor. Governed receipts inspect the real Tool after resolution.
        self.__module__ = descriptor.factory_module
        self.__qualname__ = descriptor.factory_name + ".<locals>._run"

    def resolve(self) -> Tool:
        with self._lock:
            if self._failure is not None:
                raise LazyToolConstructionError(self._failure)
            if self._tool is None:
                try:
                    tool = self._factory()
                    d = self.descriptor
                    if (not isinstance(tool, Tool) or tool.name != d.name
                            or tool.description != d.description
                            or tool.input_schema != d.input_schema
                            or tool.parallel_safe != d.parallel_safe or tool.strict != d.strict):
                        raise ValueError("factory metadata differs from descriptor")
                    self._tool = tool
                except Exception as exc:
                    from .. import killswitch
                    from ..budget import BudgetExceeded
                    if isinstance(exc, (BudgetExceeded, killswitch.Halted)):
                        raise
                    # Construction may fail with credential-bearing exception
                    # text. Cache a safe failure, never raw messages or traces.
                    self._failure = (
                        f"tool {self.descriptor.name!r} could not be constructed "
                        f"({type(exc).__name__})"
                    )
                    raise LazyToolConstructionError(self._failure) from None
            return self._tool

    def __call__(self, args):
        return self.resolve().fn(args)


class LazyTool(Tool):
    """A normal Tool for introspection; its executor belongs to this instance."""

    def __init__(self, descriptor: ToolDescriptor, *, factory=None):
        self.descriptor = descriptor
        self._executor = _Executor(descriptor, factory or descriptor.construct)
        super().__init__(name=descriptor.name, description=descriptor.description,
                         input_schema=descriptor.input_schema, fn=self._executor,
                         parallel_safe=descriptor.parallel_safe, strict=descriptor.strict)

    def with_wrapper(self, wrapper, *, description: str,
                     parallel_safe: bool = False, strict: bool = False) -> LazyTool:
        """Defer an existing trusted wrapper, retaining this registry's binding."""
        descriptor = _wrapped_descriptor(self.descriptor, description, parallel_safe, strict)
        executor = self._executor
        return LazyTool(descriptor, factory=lambda: wrapper(executor.resolve()))
