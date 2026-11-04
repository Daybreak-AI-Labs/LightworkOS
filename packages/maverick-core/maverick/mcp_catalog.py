"""Bounded, atomic MCP tool catalogs shared by both client transports.

Catalogs are untrusted descriptions, never grants. A refresh publishes only a
complete validated generation; existing registry bindings retain their exact
metadata identity and new names require normal registry assembly.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import re
from collections.abc import Awaitable, Callable, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from types import MappingProxyType

log = logging.getLogger(__name__)
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_TYPES = {"null", "boolean", "object", "array", "number", "string", "integer"}
_call_guard: ContextVar[Callable[[], bool] | None] = ContextVar("mcp_call_guard", default=None)


class CatalogError(ValueError):
    """A safe fixed diagnostic; never contains remote metadata or cursors."""


@dataclass(frozen=True)
class CatalogLimits:
    pages: int = 32
    tools: int = 2048
    bytes: int = 4 * 1024 * 1024
    nodes: int = 100_000
    depth: int = 64
    seconds: float = 30.0


def _bounded_json(value: object, limits: CatalogLimits) -> str:
    # Check before serialization: no recursive serializer overflow, NaN, giant
    # string copy, non-JSON values or unbounded container walk.
    stack = [(value, 0)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > limits.nodes or depth > limits.depth:
            raise CatalogError("catalog exceeds structural limits")
        if isinstance(node, str):
            if len(node) > limits.bytes:
                raise CatalogError("catalog exceeds byte limit")
        elif isinstance(node, dict):
            if len(node) + nodes + len(stack) > limits.nodes:
                raise CatalogError("catalog exceeds structural limits")
            if any(not isinstance(key, str) for key in node):
                raise CatalogError("catalog contains invalid object keys")
            stack.extend((key, depth + 1) for key in node)
            stack.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, list):
            if len(node) + nodes + len(stack) > limits.nodes:
                raise CatalogError("catalog exceeds structural limits")
            stack.extend((item, depth + 1) for item in node)
        elif node is not None and not isinstance(node, (bool, int, float)):
            raise CatalogError("catalog contains non-JSON data")
        elif isinstance(node, float) and not math.isfinite(node):
            raise CatalogError("catalog contains non-finite numbers")
    parts = []
    size = 0
    for part in json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False).iterencode(value):
        size += len(part.encode("utf-8"))
        if size > limits.bytes:
            raise CatalogError("catalog exceeds byte limit")
        parts.append(part)
    return "".join(parts)


def _validate_schema(root: object) -> None:
    """Validate the object-schema envelope and standard structural keywords.

    No reference retrieval or schema execution. Extension keywords remain data.
    Resource bounds have already been checked across the entire page.
    """
    if not isinstance(root, dict) or root.get("type") != "object":
        raise CatalogError("tool inputSchema must be an object schema")
    stack = [root]
    while stack:
        node = stack.pop()
        if isinstance(node, bool):
            continue
        if not isinstance(node, dict):
            raise CatalogError("invalid nested input schema")
        if "type" in node:
            types = node["type"] if isinstance(node["type"], list) else [node["type"]]
            if not types or any(not isinstance(t, str) or t not in _TYPES for t in types):
                raise CatalogError("invalid schema type")
        for key in ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas"):
            if key in node:
                if not isinstance(node[key], dict):
                    raise CatalogError("invalid schema property map")
                stack.extend(node[key].values())
        for key in ("items", "additionalProperties", "unevaluatedProperties", "propertyNames", "contains", "not", "if", "then", "else"):
            if key in node:
                stack.extend(node[key] if key == "items" and isinstance(node[key], list) else [node[key]])
        for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
            if key in node:
                if not isinstance(node[key], list) or not node[key]:
                    raise CatalogError("invalid schema alternatives")
                stack.extend(node[key])
        if "required" in node:
            required = node["required"]
            if not isinstance(required, list) or any(not isinstance(k, str) for k in required):
                raise CatalogError("invalid required properties")
            if len(set(required)) != len(required):
                raise CatalogError("duplicate required property")
        for key in ("$ref", "$schema", "$id", "description", "title"):
            if key in node and not isinstance(node[key], str):
                raise CatalogError("invalid schema text field")


@dataclass(frozen=True)
class CatalogGeneration:
    number: int = 0
    # Serialized immutable metadata prevents callers mutating the accepted view.
    entries: tuple[tuple[str, str, str], ...] = ()
    identities: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))


class ToolCatalog:
    def __init__(self, request: Callable[[str, dict], Awaitable[dict]], *, limits: CatalogLimits | None = None):
        self._request = request
        self.limits = limits or CatalogLimits()
        self.generation = CatalogGeneration()
        self.stale = True
        self.error: str | None = "catalog has not been loaded"
        self._revision = 0
        self._refresh: asyncio.Task | None = None
        self._closed = False
        self._last_notification_refresh = 0.0

    @property
    def tools(self) -> list[dict]:
        return [json.loads(encoded) for _, encoded, _ in self.generation.entries]

    @property
    def status(self) -> dict:
        return {"generation": self.generation.number, "stale": self.stale,
                "error": self.error, "tool_count": len(self.generation.entries),
                "new_tools_require_registry_rebuild": True}

    def identity(self, name: str) -> str | None:
        if self.stale or self._closed:
            return None
        return self.generation.identities.get(name)

    def changed(self) -> None:
        if self._closed:
            return
        self._revision += 1
        self.stale = True
        self.error = "catalog refresh pending"
        self._ensure_refresh(notification=True)

    def _ensure_refresh(self, *, notification: bool = False) -> asyncio.Task:
        if self._refresh is None or self._refresh.done():
            self._refresh = asyncio.create_task(self._refresh_once(notification=notification))
        return self._refresh

    async def refresh(self) -> None:
        if self._closed:
            raise CatalogError("catalog is closed")
        await asyncio.shield(self._ensure_refresh())
        if self.stale:
            raise CatalogError(self.error or "catalog is stale")

    async def _refresh_once(self, *, notification: bool = False) -> None:
        self.stale = True
        try:
            if notification:
                loop = asyncio.get_running_loop()
                await asyncio.sleep(max(0.0, 1.0 - (loop.time() - self._last_notification_refresh)))
                self._last_notification_refresh = loop.time()
            revision = self._revision
            # A notification flood cannot produce an unbounded reload loop.
            # At most one extra pass, sharing the same total deadline.
            entries, loaded_revision = await asyncio.wait_for(self._load_stable(revision), self.limits.seconds)
            if loaded_revision != self._revision:
                raise CatalogError("catalog changed before publication; retry explicitly")
            self.generation = CatalogGeneration(
                self.generation.number + 1, entries,
                MappingProxyType({name: digest for name, _, digest in entries}),
            )
            self.stale = False
            self.error = None
        except asyncio.CancelledError:
            self.error = "catalog refresh cancelled"
            raise
        except Exception as exc:
            self.error = str(exc) if isinstance(exc, CatalogError) else f"catalog refresh failed ({type(exc).__name__})"
            log.warning("MCP %s; previous generation retained but unavailable", self.error)

    async def _load_stable(self, revision: int) -> tuple[tuple[tuple[str, str, str], ...], int]:
        budget = {"pages": self.limits.pages, "bytes": self.limits.bytes}
        for _ in range(2):
            entries = await self._load(budget)
            if revision == self._revision:
                return entries, revision
            revision = self._revision
        raise CatalogError("catalog changed repeatedly during refresh; retry explicitly")

    async def _load(self, budget: dict[str, int]) -> tuple[tuple[str, str, str], ...]:
        cursor = None
        seen = set()
        entries = []
        names = set()
        while budget["pages"] > 0:
            budget["pages"] -= 1
            page = await self._request("tools/list", {"cursor": cursor} if cursor is not None else {})
            encoded = _bounded_json(page, self.limits)
            budget["bytes"] -= len(encoded.encode("utf-8"))
            if budget["bytes"] < 0:
                raise CatalogError("catalog exceeds total byte limit")
            if not isinstance(page, dict) or not isinstance(page.get("tools"), list):
                raise CatalogError("invalid tools/list page")
            for spec in page["tools"]:
                if not isinstance(spec, dict):
                    raise CatalogError("invalid tool descriptor")
                name = spec.get("name")
                if not isinstance(name, str) or not _NAME.fullmatch(name) or "__" in name:
                    raise CatalogError("invalid tool name")
                if name in names:
                    raise CatalogError("duplicate tool name across catalog")
                names.add(name)
                if len(names) > self.limits.tools:
                    raise CatalogError("catalog exceeds tool limit")
                if not isinstance(spec.get("description", ""), str):
                    raise CatalogError("invalid tool description")
                _validate_schema(spec.get("inputSchema"))
                encoded = _bounded_json(spec, self.limits)
                entries.append((name, encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()))
            cursor = page.get("nextCursor")
            if cursor is None:
                return tuple(entries)
            if not isinstance(cursor, str) or not cursor or len(cursor) > 4096 or cursor in seen:
                raise CatalogError("invalid or repeated catalog cursor")
            seen.add(cursor)
        raise CatalogError("catalog exceeds page limit")

    async def close(self) -> None:
        self._closed = True
        self.stale = True
        self.error = "catalog is closed"
        if self._refresh is not None and not self._refresh.done():
            self._refresh.cancel()
            try:
                await self._refresh
            except asyncio.CancelledError:
                pass


@contextmanager
def bind_call_guard(guard: Callable[[], bool]):
    token = _call_guard.set(guard)
    try:
        check_call_guard()
        yield
    finally:
        _call_guard.reset(token)


def check_call_guard() -> None:
    guard = _call_guard.get()
    if guard is not None and not guard():
        raise CatalogError("MCP binding is stale or no longer authorized; rebuild the registry")
