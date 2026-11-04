"""Declarative registration metadata for the built-in connector catalog."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ToolDescriptor:
    """A factory and its stable public name, before the factory is invoked."""

    name: str
    factory: Callable[[], Any]
    deferred: bool = False


def register_descriptors(registry: Any, descriptors: Iterable[ToolDescriptor]) -> None:
    """Construct and register tools in declaration order with their metadata.

    Factories run at the same point in registry assembly as before; this helper
    does not change ACLs, credential identity, or invocation-time authority.
    """
    for descriptor in descriptors:
        tool = descriptor.factory()
        if tool.name != descriptor.name:
            raise ValueError(
                f"tool factory {descriptor.factory.__name__} returned {tool.name!r}; "
                f"catalog declares {descriptor.name!r}"
            )
        registry.register(tool)
        if descriptor.deferred:
            registry.deferrable_names.add(tool.name)


def declared_names(descriptors: Iterable[ToolDescriptor]) -> tuple[str, ...]:
    """Inspect declared names without constructing tools or loading credentials."""
    return tuple(descriptor.name for descriptor in descriptors)
