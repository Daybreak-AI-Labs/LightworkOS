"""Stable route identities for reverse routing and request observability.

FastAPI defaults a route's name to its endpoint function name.  That is useful
inside a small router, but this dashboard composes many routers whose handlers
share deliberately generic names such as ``status``, ``history``, and
``workbench``.  FastAPI 0.141 keeps included routers lazy, so inspecting only
``app.routes`` also misses nearly all of those collisions.

This module qualifies only colliding names.  Existing names that are already
unique remain unchanged, preserving intentional reverse-routing contracts.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, FastAPI
from starlette.routing import BaseRoute

_DASHBOARD_MODULE_PREFIX = "maverick_dashboard."


@dataclass(frozen=True)
class _EffectiveRoute:
    original_route: BaseRoute
    owner: APIRouter
    name: str
    path: str
    methods: tuple[str, ...]
    endpoint_module: str
    endpoint_qualname: str


def iter_compatible_route_contexts(
    routes: Sequence[BaseRoute | Any],
) -> Iterator[Any]:
    """Yield effective leaf routes without FastAPI-version coupling.

    FastAPI 0.141 added the public ``fastapi.routing.iter_route_contexts``
    helper together with lazy included routers, but the dashboard's supported
    baseline starts at 0.110.  Newer lazy wrappers expose their own
    ``effective_route_contexts`` method; older releases already expose flat
    leaf routes.  The recursive ``original_router`` fallback also covers an
    included-router wrapper without importing any non-baseline FastAPI symbol.
    """
    for route in routes:
        effective_route_contexts = getattr(route, "effective_route_contexts", None)
        if callable(effective_route_contexts):
            yield from effective_route_contexts()
            continue
        included = getattr(route, "original_router", None)
        if isinstance(included, APIRouter):
            yield from iter_compatible_route_contexts(included.routes)
            continue
        yield route


def _include_prefix(route: Any) -> str:
    """The path prefix a lazy include wrapper adds to its router's routes."""
    context = getattr(route, "include_context", None)
    prefix = getattr(context, "prefix", "")
    return prefix if isinstance(prefix, str) else ""


def _endpoint_identity(route: BaseRoute) -> tuple[str, str]:
    endpoint = getattr(route, "endpoint", None)
    if endpoint is None:
        endpoint = route
    module = getattr(endpoint, "__module__", type(endpoint).__module__)
    qualname = getattr(endpoint, "__qualname__", type(endpoint).__qualname__)
    if module.startswith(_DASHBOARD_MODULE_PREFIX):
        module = module.removeprefix(_DASHBOARD_MODULE_PREFIX)
    return module, qualname


def _effective_routes(app: FastAPI) -> list[_EffectiveRoute]:
    """Every effective leaf route, read from the include tree by plain
    attribute access.

    FastAPI 0.141 materialises an included router's effective contexts on
    first traversal (``effective_route_contexts``), which rebuilds every
    route's dependant and pydantic adapters; on this dashboard that is
    thousands of routes and seconds of import time.  A route's effective
    identity (name, methods, endpoint, prefixed path) is fully determined by
    the original route object and the prefixes of the includes above it, so
    it is computed here without touching those lazy caches.  Older FastAPI
    releases flatten includes into ``router.routes`` with the prefix already
    applied, which this walk reads identically.
    """
    effective: list[_EffectiveRoute] = []
    pending: list[tuple[APIRouter, str]] = [(app.router, "")]
    while pending:
        router, prefix = pending.pop()
        for route in reversed(router.routes):
            included = getattr(route, "original_router", None)
            if isinstance(included, APIRouter):
                pending.append((included, prefix + _include_prefix(route)))
                continue
            name = getattr(route, "name", None)
            if not isinstance(name, str):
                continue
            path = prefix + str(getattr(route, "path", "") or "")
            methods = tuple(sorted(getattr(route, "methods", None) or ()))
            endpoint_module, endpoint_qualname = _endpoint_identity(route)
            effective.append(
                _EffectiveRoute(
                    original_route=route,
                    owner=router,
                    name=name or "route",
                    path=path,
                    methods=methods,
                    endpoint_module=endpoint_module,
                    endpoint_qualname=endpoint_qualname,
                )
            )
    return effective


def _qualified_name(route: _EffectiveRoute) -> str:
    return f"{route.endpoint_module}.{route.name}"


def _signature_name(route: _EffectiveRoute) -> str:
    methods = "_".join(method.lower() for method in route.methods) or "any"
    signature = "\0".join(
        (
            route.endpoint_module,
            route.endpoint_qualname,
            route.name,
            methods,
            route.path,
        )
    )
    digest = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:12]
    return f"{_qualified_name(route)}__{methods}__{digest}"


def _target_names(routes: list[_EffectiveRoute]) -> list[str]:
    original_counts = Counter(route.name for route in routes)
    targets = [
        _qualified_name(route) if original_counts[route.name] > 1 else route.name
        for route in routes
    ]

    target_counts = Counter(targets)
    targets = [
        _signature_name(route) if target_counts[target] > 1 else target
        for route, target in zip(routes, targets, strict=True)
    ]
    duplicates = sorted(
        target for target, count in Counter(targets).items() if count > 1
    )
    if duplicates:
        joined = ", ".join(duplicates)
        raise RuntimeError(
            "Effective routes remain indistinguishable after stable qualification: "
            f"{joined}. Give those routes explicit names."
        )
    return targets


def stabilize_effective_route_names(app: FastAPI) -> None:
    """Give every effective route a stable, unique name.

    Included route objects are mutated as well as their lazy effective views so
    ``request.scope['route'].name`` and ``app.url_path_for`` agree.  A route
    object included more than once would require context-specific mutation and
    would leave request-scope observability ambiguous, so that topology fails
    closed instead of receiving registration-order suffixes.
    """
    routes = _effective_routes(app)
    targets = _target_names(routes)
    targets_by_original: defaultdict[int, set[str]] = defaultdict(set)
    for route, target in zip(routes, targets, strict=True):
        targets_by_original[id(route.original_route)].add(target)
    repeated = [
        targets for targets in targets_by_original.values() if len(targets) > 1
    ]
    if repeated:
        raise RuntimeError(
            "A route object is included through multiple effective paths. "
            "Use distinct router instances or explicit context-aware route names."
        )

    changed_owners: dict[int, APIRouter] = {}
    for route, target in zip(routes, targets, strict=True):
        if getattr(route.original_route, "name", None) == target:
            continue
        route.original_route.name = target
        changed_owners[id(route.owner)] = route.owner

    # Nothing above touched FastAPI's lazy include caches, so a first request
    # (or the warm-up thread) builds each effective context exactly once, from
    # the now-canonical original route objects.  Bump the routers whose route
    # names changed anyway: a caller that traversed effective contexts before
    # stabilizing must not keep stale names.
    for owner in changed_owners.values():
        mark_routes_changed = getattr(owner, "_mark_routes_changed", None)
        if callable(mark_routes_changed):
            mark_routes_changed()

    app.openapi_schema = None
    observed_names = [route.name for route in _effective_routes(app)]
    duplicates = sorted(
        name for name, count in Counter(observed_names).items() if count > 1
    )
    if duplicates:
        raise RuntimeError(
            "Effective route-name stabilization failed: " + ", ".join(duplicates)
        )
