"""Route identity and canonical-link regressions found during user-path QA."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.testclient import TestClient
from maverick_dashboard.route_identity import (
    iter_compatible_route_contexts,
    stabilize_effective_route_names,
)


def _effective_routes() -> Iterator[Any]:
    from maverick_dashboard.app import app

    for route in app.routes:
        effective_route_contexts = getattr(route, "effective_route_contexts", None)
        if callable(effective_route_contexts):
            yield from effective_route_contexts()
        else:
            yield route


def test_compatible_route_traversal_recurses_without_fastapi_helper() -> None:
    nested = APIRouter()

    @nested.get("/nested")
    async def nested_route() -> dict[str, bool]:
        return {"ok": True}

    direct = SimpleNamespace(path="/direct", methods={"GET"})
    legacy_wrapper = SimpleNamespace(original_router=nested)

    routes = list(iter_compatible_route_contexts((direct, legacy_wrapper)))

    assert direct in routes
    assert any(getattr(route, "path", None) == "/nested" for route in routes)


def _effective_value(route: Any, attribute: str) -> Any:
    value = getattr(route, attribute, None)
    if value:
        return value
    starlette_route = getattr(route, "starlette_route", None)
    value = getattr(starlette_route, attribute, None)
    if value:
        return value
    original_route = getattr(route, "original_route", None)
    return getattr(original_route, attribute, None)


def _path_parameter_value(convertor: Any) -> Any:
    candidates = (
        "route-identity-sample",
        "1",
        "00000000-0000-4000-8000-000000000001",
    )
    for candidate in candidates:
        try:
            converted = convertor.convert(candidate)
            convertor.to_string(converted)
        except (AssertionError, TypeError, ValueError):
            continue
        return converted
    raise AssertionError(f"No reverse-routing sample for {type(convertor).__name__}")


def test_all_application_route_names_are_unique() -> None:
    routes = list(_effective_routes())
    names = [
        _effective_value(route, "name")
        for route in routes
        if isinstance(_effective_value(route, "name"), str)
    ]
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)

    assert len(names) > 1_000  # Protect against regressing to top-level-only traversal.
    assert len(names) == len(routes)
    assert duplicates == []


def test_all_effective_route_names_reverse_to_their_effective_paths() -> None:
    from maverick_dashboard.app import app

    checked = 0
    for route in _effective_routes():
        name = _effective_value(route, "name")
        path = _effective_value(route, "path")
        convertors = _effective_value(route, "param_convertors") or {}
        if not isinstance(name, str) or not isinstance(path, str):
            continue
        parameters = {
            parameter: _path_parameter_value(convertor)
            for parameter, convertor in convertors.items()
        }
        expected = route.url_path_for(name, **parameters)
        resolved = app.url_path_for(name, **parameters)

        assert str(resolved) == str(expected), name
        checked += 1

    assert checked > 1_000


def test_stabilizer_aligns_reverse_routing_and_request_scope_names() -> None:
    first_router = APIRouter()
    second_router = APIRouter()

    @first_router.get("/first", name="status")
    async def first_status(request: Request) -> dict[str, str]:
        return {"route_name": request.scope["route"].name}

    @second_router.get("/second", name="status")
    async def second_status(request: Request) -> dict[str, str]:
        return {"route_name": request.scope["route"].name}

    test_app = FastAPI()
    test_app.include_router(first_router)
    test_app.include_router(second_router)
    stabilize_effective_route_names(test_app)

    names_by_path: dict[str, str] = {}
    for route in test_app.routes:
        effective_route_contexts = getattr(route, "effective_route_contexts", None)
        contexts = effective_route_contexts() if callable(effective_route_contexts) else (route,)
        for context in contexts:
            path = _effective_value(context, "path")
            name = _effective_value(context, "name")
            if path in {"/first", "/second"}:
                names_by_path[path] = name

    assert len(set(names_by_path.values())) == 2
    client = TestClient(test_app, base_url="http://127.0.0.1")
    for path, name in names_by_path.items():
        assert str(test_app.url_path_for(name)) == path
        assert client.get(path).json() == {"route_name": name}


def test_external_agent_run_links_use_canonical_goal_route() -> None:
    from pathlib import Path

    from maverick_dashboard import app as dashboard

    template = Path(dashboard.__file__).parent / "templates" / "external_agent_detail.html"
    source = template.read_text(encoding="utf-8")

    assert 'href="/chat/goal/{{ e.goal_id }}"' in source
    assert 'href="/goals/{{ e.goal_id }}"' not in source


def test_flow_designer_create_and_edit_routes_have_distinct_names() -> None:
    from maverick_dashboard.app import app

    names_by_path = {
        route.path: route.name
        for route in app.routes
        if getattr(route, "path", "").startswith("/flows/designer")
    }

    assert names_by_path["/flows/designer"] == "flow_designer_create_page"
    assert names_by_path["/flows/designer/{flow_id}"] == "flow_designer_edit_page"


def _contexts(test_app: FastAPI) -> list[Any]:
    out: list[Any] = []
    for route in test_app.routes:
        effective_route_contexts = getattr(route, "effective_route_contexts", None)
        contexts = effective_route_contexts() if callable(effective_route_contexts) else (route,)
        out.extend(contexts)
    return out


def _nested_collision_app() -> FastAPI:
    inner = APIRouter(prefix="/inner")
    outer = APIRouter()
    top = APIRouter()

    @inner.get("/one", name="status")
    async def inner_status() -> dict[str, str]:
        return {"where": "inner"}

    @outer.get("/two", name="status")
    async def outer_status() -> dict[str, str]:
        return {"where": "outer"}

    @top.get("/three", name="status")
    async def top_status() -> dict[str, str]:
        return {"where": "top"}

    @top.get("/unique", name="only_here")
    async def only_here() -> dict[str, str]:
        return {"where": "top"}

    outer.include_router(inner, prefix="/deep")
    test_app = FastAPI()
    test_app.include_router(outer, prefix="/api")
    test_app.include_router(top)
    return test_app


def test_stabilizer_does_not_materialize_lazy_include_contexts() -> None:
    test_app = _nested_collision_app()
    wrappers = [r for r in test_app.routes if hasattr(r, "effective_route_contexts")]

    stabilize_effective_route_names(test_app)

    # FastAPI >= 0.141 keeps includes lazy; renaming must not have forced the
    # per-route dependant/pydantic rebuild that traversing the contexts costs.
    for wrapper in wrappers:
        assert getattr(wrapper, "_effective_candidates_version", None) is None


def test_stabilizer_names_are_unique_and_agree_with_effective_contexts() -> None:
    test_app = _nested_collision_app()
    stabilize_effective_route_names(test_app)

    names_by_path = {
        _effective_value(c, "path"): _effective_value(c, "name") for c in _contexts(test_app)
    }
    names = list(names_by_path.values())
    assert len(set(names)) == len(names)
    assert names_by_path["/unique"] == "only_here"  # unique names are untouched
    # Three handlers named ``status`` in one module: the qualified module name
    # still collides, so each gets the signature form keyed on its full
    # effective (prefixed) path.
    for path in ("/api/deep/inner/one", "/api/two", "/three"):
        name = names_by_path[path]
        assert name.endswith("test_route_identities.status__get__" + name.rsplit("__", 1)[1]), name
        assert __name__ + ".status__get__" in name
        assert str(test_app.url_path_for(name)) == path
    client = TestClient(test_app, base_url="http://127.0.0.1")
    assert client.get("/api/deep/inner/one").json() == {"where": "inner"}


def test_stabilizer_is_idempotent() -> None:
    test_app = _nested_collision_app()
    stabilize_effective_route_names(test_app)
    first = {_effective_value(c, "path"): _effective_value(c, "name") for c in _contexts(test_app)}
    stabilize_effective_route_names(test_app)
    second = {_effective_value(c, "path"): _effective_value(c, "name") for c in _contexts(test_app)}
    assert first == second


def test_stabilizer_rejects_a_router_included_twice() -> None:
    import pytest

    shared = APIRouter()

    @shared.get("/x", name="status")
    async def shared_status() -> dict[str, bool]:
        return {"ok": True}

    test_app = FastAPI()
    test_app.include_router(shared, prefix="/a")
    test_app.include_router(shared, prefix="/b")
    with pytest.raises(RuntimeError):
        stabilize_effective_route_names(test_app)
