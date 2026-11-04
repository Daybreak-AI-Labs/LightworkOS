"""Remember which route serves a path, so a request does not scan them all.

The dashboard registers about 3,700 routes behind 575 top-level entries, and
the router tries them in order on every request: a page registered late paid
6.5-7.4 ms before its handler started. Which entry first matches a request
depends only on its type, method and path (no route here matches on a host
or a header), so the first full match is remembered, and the next request for
the same path runs the router's own dispatch over just that entry. Any change
to the routes (FastAPI counts them) forgets every remembered entry, and a
request that matches nothing in full, a redirect or a 404 or 405, always takes
the ordinary path.
"""
from __future__ import annotations

import logging
from typing import Any

from starlette._utils import get_route_path
from starlette.routing import Host, Match

log = logging.getLogger(__name__)

# Entries this early cost less to scan than to check the route version.
_SCAN_IS_CHEAPER_BELOW = 16
_MAX_REMEMBERED = 4096
# Longer paths are never remembered, which bounds the memory to about 1 MiB
# however many distinct paths arrive (a page's own paths are far shorter).
_MAX_REMEMBERED_PATH = 256
_PATH_ONLY_MODULES = frozenset({"starlette.routing", "fastapi.routing"})


class _OneRoute:
    """The router, seen with only the remembered entry in its route list."""

    __slots__ = ("_router", "routes")

    def __init__(self, router: Any, route: Any) -> None:
        self._router = router
        self.routes = [route]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._router, name)


def _matches_on_path_only(route: Any) -> bool:
    for candidate in (route, getattr(route, "starlette_route", None), getattr(route, "original_route", None)):
        if candidate is None:
            continue
        if isinstance(candidate, Host):
            return False
        if getattr(type(candidate).matches, "__module__", None) not in _PATH_ONLY_MODULES:
            return False
    return True


def _leaves(routes: Any):
    from .route_identity import iter_compatible_route_contexts

    yield from routes
    yield from iter_compatible_route_contexts(routes)


class RememberedRouteDispatch:
    """The router's ASGI entry point, with the first full match remembered."""

    def __init__(self, router: Any, dispatch: Any) -> None:
        self.router = router
        self.dispatch = dispatch  # the router's own dispatch, for everything else
        self.version: Any = None
        self.usable = False
        self.remembered: dict[tuple, tuple[int, Any, Any]] = {}  # (index or -1, route, version)

    def _current_version(self) -> Any:
        routes = self.router.routes
        return (self.router._get_routes_version(), len(routes), id(routes))

    def _revalidate(self, version: Any) -> None:
        self.remembered.clear()
        self.version = version
        try:
            self.usable = all(_matches_on_path_only(route) for route in _leaves(self.router.routes))
        except Exception:  # pragma: no cover - an unknown router shape is never remembered
            log.debug("route dispatch memory disabled", exc_info=True)
            self.usable = False

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.dispatch(scope, receive, send)
            return
        path = get_route_path(scope)
        if len(path) > _MAX_REMEMBERED_PATH:
            await self.dispatch(scope, receive, send)
            return
        key = (scope["type"], scope.get("method"), path)
        known = self.remembered.get(key)
        if known is not None and known[0] < _SCAN_IS_CHEAPER_BELOW:
            # An early entry, or no full match (-1): the ordinary dispatch,
            # which is always right, costs no more than a version check.
            await self.dispatch(scope, receive, send)
            return
        version = self._current_version()
        if version != self.version:
            self._revalidate(version)
        if not self.usable:
            await self.dispatch(scope, receive, send)
            return
        routes = self.router.routes
        if known is None or known[2] != version:
            known = (-1, None, version)
            for index, route in enumerate(routes):
                if route.matches(scope)[0] == Match.FULL:
                    known = (index, route, version)
                    break
            if len(self.remembered) >= _MAX_REMEMBERED:
                self.remembered.clear()
            self.remembered[key] = known
        index, route, _ = known
        if index < 0 or index >= len(routes) or routes[index] is not route or route.matches(scope)[0] != Match.FULL:
            await self.dispatch(scope, receive, send)  # partial, redirect or no match
            return
        scope.setdefault("router", self.router)
        await type(self.router).app(_OneRoute(self.router, route), scope, receive, send)


def install(router: Any) -> bool:
    """Put the remembering dispatch in front of ``router``'s own one."""
    dispatch = router.middleware_stack
    if getattr(dispatch, "__func__", None) is not type(router).app:
        return False  # router-level middleware: leave it as it is
    if not callable(getattr(router, "_get_routes_version", None)):
        return False  # a FastAPI without counted route changes
    router.middleware_stack = RememberedRouteDispatch(router, dispatch)
    return True
